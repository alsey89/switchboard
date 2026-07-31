// Package cli wires the cobra command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/daemon"
	"github.com/alsey89/switchboard/internal/doctor"
	"github.com/alsey89/switchboard/internal/privileged"
	"github.com/alsey89/switchboard/internal/service"
	"github.com/alsey89/switchboard/internal/setup"
)

// Version is stamped via -ldflags "-X .../internal/cli.Version=v0.1.0".
var Version = "0.1.0-dev"

type paths struct {
	configPath string
	dataDir    string
}

func resolvePaths(flagConfig string) (paths, error) {
	dataDir, err := config.DataDir()
	if err != nil {
		return paths{}, err
	}
	cfgPath := flagConfig
	if cfgPath == "" {
		cfgPath, err = config.Path()
		if err != nil {
			return paths{}, err
		}
	}
	return paths{configPath: cfgPath, dataDir: dataDir}, nil
}

// Root builds the command tree.
func Root() *cobra.Command {
	var flagConfig string

	root := &cobra.Command{
		Use:           "switchboard",
		Short:         "Local domains with real HTTPS: app.test → localhost:3000",
		Long:          "Switchboard routes *.test domains to local ports with locally-trusted HTTPS.\nNo /etc/hosts editing; the proxy never runs as root.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&flagConfig, "config", "", "path to config.toml (default ~/.config/switchboard/config.toml)")

	root.AddCommand(
		cmdSetup(&flagConfig),
		cmdStart(&flagConfig),
		cmdSupervise(&flagConfig),
		cmdServe(&flagConfig),
		cmdSuffix(&flagConfig),
		cmdAdd(&flagConfig),
		cmdRemove(&flagConfig),
		cmdList(&flagConfig),
		cmdDoctor(&flagConfig),
		cmdUninstall(&flagConfig),
		cmdDaemon(&flagConfig),
		cmdVersion(),
	)
	return root
}

func cmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "switchboard", Version)
		},
	}
}

func cmdSetup(flagConfig *string) *cobra.Command {
	var noService bool
	c := &cobra.Command{
		Use:   "setup",
		Short: "Get Switchboard working: resolver, trusted CA, and the background service",
		Long: "Do everything needed to make Switchboard work on this machine:\n" +
			"  • create the local CA, constrained to your domain suffix\n" +
			"  • point the OS resolver at Switchboard's DNS\n" +
			"  • trust the CA in your login keychain\n" +
			"  • install the background service so it keeps running\n\n" +
			"`switchboard uninstall` undoes all four. Use --no-service to skip the\n" +
			"last one and run the daemon yourself with `switchboard start`.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := resolvePaths(*flagConfig)
			if err != nil {
				return err
			}
			cfg, err := config.Load(p.configPath)
			if err != nil {
				return err
			}
			res, err := setup.Run(cmd.Context(), cfg, p.dataDir, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, n := range append(res.ResolverNotes, res.TrustNotes...) {
				fmt.Fprintln(out, "  •", n)
			}
			// Install the background service too, unless told not to.
			//
			// Without this, `setup` installed two of the three things
			// `uninstall` removes, and the missing one was the difference
			// between "setup complete ✓" and anything actually working. The
			// gap was discoverable only by running `start`, failing on :443,
			// and reading the remedy — which is a poor way to learn that a
			// step exists.
			//
			// runHint is what still has to be done to get it serving; empty
			// once the service is installed and running.
			runHint := "switchboard daemon install   (or run it yourself: switchboard start)"
			if !noService {
				fmt.Fprintln(out, "\n→ installing the background service…")
				switch err := installService(cmd, cfg, *flagConfig, out); {
				case errors.Is(err, service.ErrUnsupported):
					// No service manager here yet (Linux, Windows). Not a
					// failure of setup — everything setup owns is installed
					// and there is simply nothing to automate with. Pointing
					// at `daemon install` would send them to the command that
					// returns this very error.
					fmt.Fprintln(out, "  no service manager is automated on this platform yet")
					runHint = "switchboard start   (under systemd, a supervisor, or your terminal)"
				case err != nil:
					// Exit non-zero. Printing the failure and returning nil
					// left `switchboard setup` reporting success to any
					// script that checked, on a machine serving nothing.
					fmt.Fprintln(out, "\nthe resolver and CA are installed; the background service is not.")
					fmt.Fprintln(out, "retry just that step with: switchboard daemon install")
					return fmt.Errorf("installing the background service: %w", err)
				default:
					runHint = ""
				}
			}

			fmt.Fprintln(out, "\nsetup complete ✓")
			fmt.Fprintln(out, "\nnext:\n  switchboard add app 3000")
			if runHint != "" {
				fmt.Fprintln(out, "  "+runHint)
			}
			fmt.Fprintf(out, "  open https://app.%s\n", cfg.Suffix)
			return nil
		},
	}
	c.Flags().BoolVar(&noService, "no-service", false,
		"do not install the background service; run the daemon yourself with `switchboard start`")
	return c
}

// installService installs (or restarts) the background service for cfg.
func installService(cmd *cobra.Command, cfg *config.Config, flagConfig string, out io.Writer) error {
	spec, err := service.DefaultSpec(cfg, flagConfig)
	if err != nil {
		return err
	}
	return service.Install(spec, out)
}

func cmdStart(flagConfig *string) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Run the daemon in the foreground (DNS + HTTPS proxy)",
		Long: "Run the daemon in the foreground.\n\n" +
			"Run as yourself, it serves on the ports in your config.\n" +
			"Run as `sudo switchboard start`, it binds :443 and :80 first, drops to your\n" +
			"user, and runs the daemon unprivileged with those sockets already open — so\n" +
			"URLs carry no port. Only the socket-binding parent is ever root; see\n" +
			"docs/adr/0001-binding-privileged-ports-on-macos.md.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() == 0 {
				target, err := privileged.FromSudo()
				if err != nil {
					return err
				}
				return superviseAs(cmd, target, *flagConfig)
			}
			return serve(cmd, *flagConfig)
		},
	}
}

// cmdSupervise is the launchd entry point. It is hidden because it is not a
// thing to run by hand: the identity has to be passed explicitly, and
// `daemon install` is what knows it. Under launchd there is no SUDO_UID to
// derive it from, which is exactly why this exists separately from `start`.
func cmdSupervise(flagConfig *string) *cobra.Command {
	var uid, gid int
	var home string
	c := &cobra.Command{
		Use:    "__supervise",
		Short:  "Internal: bind privileged ports, drop privileges, run the daemon",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, err := privileged.FromFlags(uid, gid, home)
			if err != nil {
				return err
			}
			return superviseAs(cmd, target, *flagConfig)
		},
	}
	c.Flags().IntVar(&uid, "uid", 0, "uid to run the daemon as")
	c.Flags().IntVar(&gid, "gid", 0, "gid to run the daemon as")
	c.Flags().StringVar(&home, "home", "", "home directory of the target user")
	return c
}

// cmdServe is the unprivileged child. Hidden: `start` is the command people
// run, and this one exists so the parent has something to exec that will not
// re-enter the privileged branch.
func cmdServe(flagConfig *string) *cobra.Command {
	return &cobra.Command{
		Use:    "__serve",
		Short:  "Internal: run the daemon, adopting any inherited sockets",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd, *flagConfig)
		},
	}
}

// serve runs the daemon in this process.
func serve(cmd *cobra.Command, flagConfig string) error {
	p, err := resolvePaths(flagConfig)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return daemon.Run(ctx, daemon.Options{
		ConfigPath: p.configPath,
		DataDir:    p.dataDir,
		Version:    Version,
		Log:        log,
	})
}

// superviseAs runs the privileged parent, which execs this same binary as
// the target user.
//
// Note what is *not* resolved here: the config path is passed through
// verbatim rather than expanded. The parent must not read the user's config
// — see the privileged package comment — and resolving a default path would
// mean resolving it against root's home anyway. The child works it out from
// the HOME the parent gives it.
func superviseAs(cmd *cobra.Command, target privileged.Target, flagConfig string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"__serve"}
	if flagConfig != "" {
		args = append(args, "--config", flagConfig)
	}

	log := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(cmd.OutOrStdout(),
		"binding :443 and :80 as root, then dropping to %s (uid %d)\n",
		target.Name, target.UID)

	return privileged.Run(ctx, privileged.Spec{
		Exe:  exe,
		Args: args,
		UID:  target.UID,
		GID:  target.GID,
		Home: target.Home,
		Env:  os.Environ(),
		Log:  log,
	})
}

// cmdSuffix changes the managed domain suffix.
//
// This is a command rather than a config edit because it is an operation, not
// a setting: it rewrites every route, rotates a trusted certificate authority,
// replaces a system resolver file, and invalidates every certificate issued so
// far. Editing `suffix` by hand requires knowing all four, and getting the
// first one wrong makes the config unloadable — which takes `add`, `ls` and
// `doctor` down with it, exactly when they would be most useful.
func cmdSuffix(flagConfig *string) *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "suffix <new-suffix>",
		Short: "Change the managed domain suffix (rewrites routes, re-issues the CA)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			next := strings.TrimPrefix(args[0], ".")
			p, err := resolvePaths(*flagConfig)
			if err != nil {
				return err
			}
			// Lenient: if the user already edited `suffix` by hand and broke
			// the routes, this command is the repair and must still be able to
			// read the file.
			cfg, err := config.LoadLenient(p.configPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			old := cfg.Suffix
			migrated := retargetRoutes(cfg, old, next)
			cfg.Suffix = next
			if err := cfg.Validate(); err != nil {
				return err
			}

			if old == next && migrated == 0 {
				fmt.Fprintf(out, "already using .%s — nothing to do\n", next)
				return nil
			}

			fmt.Fprintf(out, "changing the suffix from .%s to .%s\n", old, next)
			for _, r := range cfg.Routes {
				fmt.Fprintf(out, "  %s → %s\n", r.Domain, r.UpstreamAddr())
			}
			fmt.Fprintln(out, "\nthis will:")
			fmt.Fprintf(out, "  • re-issue the local CA, constrained to .%s\n", next)
			fmt.Fprintf(out, "  • invalidate every certificate issued for .%s\n", old)
			fmt.Fprintf(out, "  • replace /etc/resolver/%s with /etc/resolver/%s\n", old, next)
			if notice := setup.AuthNotice(); len(notice) > 0 {
				fmt.Fprintln(out, "\nyou will be asked to authorize this:")
				for _, n := range notice {
					fmt.Fprintf(out, "  • %s\n", n)
				}
			}
			if !yes {
				fmt.Fprint(out, "\ncontinue? [y/N] ")
				var answer string
				fmt.Fscanln(cmd.InOrStdin(), &answer) //nolint:errcheck
				if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
					fmt.Fprintln(out, "aborted; nothing was changed")
					return nil
				}
			}

			// Save first: setup reads the config to know which suffix to build
			// the CA and resolver file for.
			if err := cfg.Save(p.configPath); err != nil {
				return err
			}
			fmt.Fprintf(out, "\nwrote %s\n", p.configPath)

			if _, err := setup.Run(cmd.Context(), cfg, p.dataDir, out); err != nil {
				return fmt.Errorf("%w\n  The config now says .%s; re-run `switchboard setup` "+
					"once the problem above is resolved", err, next)
			}

			// Restart the service ourselves. Between the config change and the
			// restart the machine is in a state that does not work at all —
			// DNS now sends the new suffix to a daemon still serving the old
			// zone, and the certificates for it no longer exist. Leaving that
			// as a step the user has to remember is leaving them broken.
			restartService(cmd, cfg, *flagConfig, out)

			fmt.Fprintf(out, "\nsuffix is now .%s ✓\n", next)
			return nil
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return c
}

// removeBinaryHint suggests how to remove the executable, based on where it
// is. Getting this wrong is worse than omitting it: telling a Homebrew user
// to `rm` the binary leaves brew believing the cask is still installed.
func removeBinaryHint(exe string) string {
	if strings.Contains(exe, "/Cellar/") || strings.Contains(exe, "/Caskroom/") ||
		strings.HasPrefix(exe, "/opt/homebrew/") || strings.HasPrefix(exe, "/usr/local/Homebrew/") {
		return "brew uninstall switchboard"
	}
	return "sudo rm " + exe
}

// restartService restarts the background service if there is one, so the
// daemon picks up a suffix change. Failures are reported, not returned: the
// suffix change itself has already succeeded and been written to disk, and
// turning "your suffix changed but the service did not restart" into a
// non-zero exit would suggest the whole operation failed.
func restartService(cmd *cobra.Command, cfg *config.Config, flagConfig string, out io.Writer) {
	state, _, err := service.Status()
	if err != nil || state == service.NotInstalled {
		// No managed service. If something is nevertheless answering, it is a
		// foreground `switchboard start` that we cannot restart for them.
		if daemonIsListening(cfg) {
			fmt.Fprintln(out, "\n  a daemon is running but was not installed as a service —")
			fmt.Fprintln(out, "  restart it yourself so it serves the new zone")
		} else {
			fmt.Fprintln(out, "\n  no background service installed; start one with:")
			fmt.Fprintln(out, "    switchboard daemon install")
		}
		return
	}

	fmt.Fprintln(out, "\n→ restarting the background service so it serves the new zone…")
	spec, err := service.DefaultSpec(cfg, flagConfig)
	if err == nil {
		err = service.Install(spec, out)
	}
	if err != nil {
		fmt.Fprintf(out, "  could not restart it: %v\n", err)
		fmt.Fprintln(out, "  the suffix change is saved — restart it with: switchboard daemon install")
	}
}

// daemonIsListening reports whether anything answers on the configured HTTPS
// port, which is how a foreground daemon makes itself known.
func daemonIsListening(cfg *config.Config) bool {
	c, err := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffHTTPSPort())), 400*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close() //nolint:errcheck
	return true
}

// retargetRoutes rewrites route domains from one suffix to another, returning
// how many changed. A domain that does not end in the old suffix is left
// alone — it is not ours to reinterpret, and Validate will reject it with a
// message naming the route.
func retargetRoutes(cfg *config.Config, old, next string) int {
	var n int
	for i := range cfg.Routes {
		d := cfg.Routes[i].Domain
		if !strings.HasSuffix(d, "."+old) {
			continue
		}
		cfg.Routes[i].Domain = strings.TrimSuffix(d, "."+old) + "." + next
		n++
	}
	return n
}

func cmdAdd(flagConfig *string) *cobra.Command {
	var upstream string
	c := &cobra.Command{
		Use:   "add <domain> [port]",
		Short: "Route a domain to a local port (e.g. `switchboard add app 3000`)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths(*flagConfig)
			if err != nil {
				return err
			}
			cfg, err := config.Load(p.configPath)
			if err != nil {
				return err
			}

			r := config.Route{}
			switch {
			case len(args) == 2 && upstream != "":
				return fmt.Errorf("give either a port argument or --upstream, not both")
			case len(args) == 2:
				port, err := strconv.Atoi(args[1])
				if err != nil {
					return fmt.Errorf("port %q is not a number", args[1])
				}
				r.Port = port
			case upstream != "":
				r.Upstream = upstream
			default:
				return fmt.Errorf("missing port: switchboard add %s <port>", args[0])
			}

			domain, err := config.NormalizeDomain(args[0], cfg.Suffix)
			if err != nil {
				return err
			}
			r.Domain = domain

			if _, exists := cfg.FindRoute(domain); exists {
				return fmt.Errorf("%s is already routed — remove it first: switchboard rm %s", domain, domain)
			}
			cfg.Routes = append(cfg.Routes, r)
			if err := cfg.Save(p.configPath); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "https://%s → %s\n", domain, r.UpstreamAddr())
			if !dialable(r.UpstreamAddr()) {
				fmt.Fprintf(out, "  (nothing is listening on %s yet — the route goes live when your server starts)\n", r.UpstreamAddr())
			}
			if !daemonRunning(cfg) {
				fmt.Fprintln(out, "  daemon not running — start it with: switchboard start")
			}
			return nil
		},
	}
	c.Flags().StringVar(&upstream, "upstream", "", "route to host:port instead of a local port")
	return c
}

func cmdRemove(flagConfig *string) *cobra.Command {
	return &cobra.Command{
		Use:     "rm <domain>",
		Aliases: []string{"remove"},
		Short:   "Remove a route",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths(*flagConfig)
			if err != nil {
				return err
			}
			cfg, err := config.Load(p.configPath)
			if err != nil {
				return err
			}
			domain, err := config.NormalizeDomain(args[0], cfg.Suffix)
			if err != nil {
				return err
			}
			kept := cfg.Routes[:0]
			removed := false
			for _, r := range cfg.Routes {
				if r.Domain == domain {
					removed = true
					continue
				}
				kept = append(kept, r)
			}
			if !removed {
				return fmt.Errorf("no route for %s", domain)
			}
			cfg.Routes = kept
			if err := cfg.Save(p.configPath); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", domain)
			return nil
		},
	}
}

func cmdList(flagConfig *string) *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List routes and their status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := resolvePaths(*flagConfig)
			if err != nil {
				return err
			}
			cfg, err := config.Load(p.configPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(cfg.Routes) == 0 {
				fmt.Fprintf(out, "no routes yet — add one: switchboard add app 3000\n")
			} else {
				routes := append([]config.Route(nil), cfg.Routes...)
				sort.Slice(routes, func(i, j int) bool { return routes[i].Domain < routes[j].Domain })
				tw := tabwriter.NewWriter(out, 2, 4, 2, ' ', 0)
				fmt.Fprintln(tw, "DOMAIN\tUPSTREAM\tSTATUS")
				for _, r := range routes {
					status := "down"
					if dialable(r.UpstreamAddr()) {
						status = "up"
					}
					fmt.Fprintf(tw, "https://%s\t%s\t%s\n", r.Domain, r.UpstreamAddr(), status)
				}
				tw.Flush()
			}
			if daemonRunning(cfg) {
				fmt.Fprintf(out, "\ndaemon: running · dashboard: https://%s\n", cfg.DashboardDomain())
			} else {
				fmt.Fprintln(out, "\ndaemon: not running — start it with: switchboard start")
			}
			return nil
		},
	}
}

func cmdDoctor(flagConfig *string) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose common problems (setup state, port conflicts, upstreams)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := resolvePaths(*flagConfig)
			if err != nil {
				return err
			}
			cfg, cfgErr := config.Load(p.configPath)
			checks := doctor.Run(cfg, p.configPath, p.dataDir, cfgErr)

			out := cmd.OutOrStdout()
			failed := false
			for _, c := range checks {
				mark := map[doctor.Status]string{
					doctor.OK: "✓", doctor.Warn: "!", doctor.Fail: "✗", doctor.Skip: "-",
				}[c.Status]
				fmt.Fprintf(out, "%s %-22s %s\n", mark, c.Name, c.Detail)
				if c.Hint != "" && c.Status != doctor.OK {
					fmt.Fprintf(out, "  ↳ %s\n", c.Hint)
				}
				if c.Status == doctor.Fail {
					failed = true
				}
			}
			fmt.Fprintf(out, "\ndashboard (no DNS or TLS needed): http://127.0.0.1:%d\n",
				cfg.EffDashboardPort())
			fmt.Fprintln(out, "\nnote: dig/nslookup bypass the OS resolver — verify with a browser or curl instead")
			if failed {
				return fmt.Errorf("doctor found problems")
			}
			return nil
		},
	}
}

func cmdUninstall(flagConfig *string) *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Undo system setup: background service, resolver, and CA trust; keeps your config file",
		Long: "Undo everything `switchboard setup` and `switchboard daemon install` put on\n" +
			"this system: the background service, the resolver file, and the trusted CA.\n" +
			"Your config file and CA material under ~/.config/switchboard are left alone,\n" +
			"so deleting that directory afterwards is a genuinely full reset.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := resolvePaths(*flagConfig)
			if err != nil {
				return err
			}
			cfg, err := config.Load(p.configPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			// Remove the launchd job first, and before anything else can
			// fail. Leaving it behind made this command's own closing advice
			// wrong: the plist lives in ~/Library/LaunchAgents, so it
			// survived both `switchboard uninstall` and the `rm -rf` this
			// used to suggest — and `rm -rf`ing the config dir while the
			// agent is still loaded leaves launchd respawning a daemon whose
			// config no longer exists. ErrUnsupported just means this
			// platform has no service automation yet, which is not a failure
			// of uninstalling.
			// Best-effort, not a gate. Uninstall exists to get system state
			// back off the machine; aborting here on an unexpected launchd
			// failure would strand the resolver file and the trusted CA —
			// the two things that actually alter how the whole system
			// behaves. Report and keep going. ErrUnsupported is not even a
			// failure: it just means this platform has no service automation.
			removedService, err := service.Uninstall(out)
			if err != nil && !errors.Is(err, service.ErrUnsupported) {
				fmt.Fprintf(out, "  warning: could not remove the background service: %v\n", err)
				fmt.Fprintf(out, "  continuing — remove it by hand, then re-run this command\n")
			}

			removedSetup, err := setup.Remove(cfg, p.dataDir, out)
			if err != nil {
				return err
			}

			if !removedService && !removedSetup {
				fmt.Fprintln(out, "\nnothing to remove — no system setup was in place")
			} else {
				fmt.Fprintln(out, "\nsystem setup removed ✓")
			}
			fmt.Fprintf(out, "  kept: your config and CA files in %s\n", mustDir())
			fmt.Fprintln(out, "        (delete that directory to also discard your routes and CA)")

			// Say that the program is still installed, because "uninstall"
			// does not mean here what it means for a package manager. This
			// command undoes what `setup` and `daemon install` did to the
			// system; removing the binary belongs to whatever installed it,
			// and a program deleting its own executable would be a poor idea
			// besides. Leaving it unsaid means the user reads "uninstall ✓",
			// finds the command still on their PATH, and has to guess which
			// of the two is lying.
			if exe, err := os.Executable(); err == nil {
				fmt.Fprintf(out, "  still installed: the switchboard binary at %s\n", exe)
				fmt.Fprintf(out, "        remove it with: %s\n", removeBinaryHint(exe))
			}
			return nil
		},
	}
}

func mustDir() string {
	d, err := config.Dir()
	if err != nil {
		return "~/.config/switchboard"
	}
	return d
}

func dialable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func daemonRunning(cfg *config.Config) bool {
	return dialable("127.0.0.1:" + strconv.Itoa(cfg.EffHTTPSPort()))
}

func cmdDaemon(flagConfig *string) *cobra.Command {
	c := &cobra.Command{
		Use:   "daemon",
		Short: "Run Switchboard in the background (launchd)",
		Long: "Install Switchboard as a background service so it survives closing your\n" +
			"terminal. It runs as you — no root, no system daemon.",
	}
	c.AddCommand(
		cmdDaemonInstall(flagConfig),
		cmdDaemonUninstall(),
		cmdDaemonStatus(),
		cmdDaemonLogs(),
	)
	return c
}

func cmdDaemonInstall(flagConfig *string) *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install and start the background service (re-run to restart it)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := resolvePaths(*flagConfig)
			if err != nil {
				return err
			}
			// The spec needs the configured ports: Install refuses rather
			// than installing an agent that would crash-loop on a port it
			// cannot bind.
			cfg, err := config.Load(p.configPath)
			if err != nil {
				return err
			}
			spec, err := service.DefaultSpec(cfg, *flagConfig)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "→ installing %s\n", service.Label)
			// Only the launch daemon elevates. A user agent needs nothing, and
			// claiming otherwise would train people to expect a prompt that
			// never comes.
			if spec.Mode == service.ModeDaemon {
				fmt.Fprintln(out, "  :443 and :80 need a privileged parent, so this asks for your")
				fmt.Fprintln(out, "  password in this terminal (sudo). The proxy itself still runs as you.")
			}
			if err := service.Install(spec, out); err != nil {
				return err
			}
			fmt.Fprintf(out, "\nservice installed ✓\n  logs: %s\n  status: switchboard daemon status\n",
				spec.StdoutPath)
			return nil
		},
	}
}

func cmdDaemonUninstall() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the background service (keeps config and CA)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			removed, err := service.Uninstall(out)
			if err != nil {
				return err
			}
			if removed {
				fmt.Fprintln(out, "\nservice removed ✓")
			}
			return nil
		},
	}
}

func cmdDaemonStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the background service is installed and running",
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, plistPath, err := service.Status()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if state == service.NotInstalled {
				fmt.Fprintln(out, "service: not installed")
				fmt.Fprintln(out, "  install it with: switchboard daemon install")
				return nil
			}
			fmt.Fprintf(out, "service: %s\n  plist: %s\n", state, plistPath)
			if logPath := service.InstalledLogPath(); logPath != "" {
				fmt.Fprintf(out, "  logs:  %s\n", logPath)
			}
			return nil
		},
	}
}

func cmdDaemonLogs() *cobra.Command {
	var (
		follow   bool
		lines    int
		pathOnly bool
	)
	c := &cobra.Command{
		Use:   "logs",
		Short: "Show the background service log",
		Long: "Show the background service log.\n\n" +
			"Prints the last few lines by default, because the log is never rotated —\n" +
			"a service that is crash-looping appends to it indefinitely, and the day\n" +
			"you need it most is the day it is largest.\n\n" +
			"Use --path to print the file's location instead, for piping elsewhere.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if lines < 0 {
				// Checked before anything else: a nonsense flag is a nonsense
				// flag whether or not a service is installed, and this is not
				// tail(1), where a leading minus is its own syntax.
				return fmt.Errorf("-n %d selects nothing — pass how many trailing lines to show, e.g. -n 100", lines)
			}
			// The installed plist, not LogPath(): the launch daemon logs
			// outside the user's home, and printing the path a *user agent*
			// would have used sent people to a file that does not exist.
			logPath := service.InstalledLogPath()
			if logPath == "" {
				return errors.New("no service is installed, so there is no log file yet — " +
					"install it with `switchboard daemon install`")
			}
			out := cmd.OutOrStdout()
			if pathOnly {
				fmt.Fprintln(out, logPath)
				return nil
			}

			offset, err := printTail(logPath, lines, out)
			if err != nil {
				if os.IsNotExist(err) && follow {
					// Installed but nothing written yet. Waiting is the useful
					// behaviour here — this is exactly the state someone is in
					// when they run `daemon install` and then watch.
					offset = 0
				} else if os.IsNotExist(err) {
					fmt.Fprintf(out, "%s does not exist yet — the service has not "+
						"written anything.\n", logPath)
					return nil
				} else {
					return err
				}
			}
			if !follow {
				return nil
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "\n--- following %s (ctrl-c to stop) ---\n", logPath)
			return followFile(cmd.Context(), logPath, offset, out)
		},
	}
	c.Flags().BoolVarP(&follow, "follow", "f", false, "keep watching for new output")
	c.Flags().IntVarP(&lines, "lines", "n", 50, "how many trailing lines to show")
	c.Flags().BoolVar(&pathOnly, "path", false, "print the log file's path instead of its contents")
	return c
}
