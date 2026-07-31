// Package cli wires the cobra command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
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
		Long:          "Switchboard routes *.test domains to local ports with locally-trusted HTTPS.\nNo /etc/hosts editing, no root daemon.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&flagConfig, "config", "", "path to config.toml (default ~/.config/switchboard/config.toml)")

	root.AddCommand(
		cmdSetup(&flagConfig),
		cmdStart(&flagConfig),
		cmdSupervise(&flagConfig),
		cmdServe(&flagConfig),
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
	return &cobra.Command{
		Use:   "setup",
		Short: "One-time system setup: resolver + trusted local CA (asks for your password)",
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
			fmt.Fprintln(out, "\nsetup complete ✓")
			for _, n := range append(res.ResolverNotes, res.TrustNotes...) {
				fmt.Fprintln(out, "  •", n)
			}
			fmt.Fprintf(out, "\nnext:\n  switchboard add app %s\n  switchboard start\n  open https://app.%s\n",
				"3000", cfg.Suffix)
			return nil
		},
	}
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

			// Remove the launch agent first, and before anything else can
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
			if _, err := service.Uninstall(out); err != nil && !errors.Is(err, service.ErrUnsupported) {
				fmt.Fprintf(out, "  warning: could not remove the background service: %v\n", err)
				fmt.Fprintf(out, "  continuing — remove it by hand, then re-run this command\n")
			}

			if err := setup.Remove(cfg, p.dataDir, out); err != nil {
				return err
			}
			fmt.Fprintf(out,
				"system setup removed ✓\nconfig and CA files kept in %s — delete that directory for a full reset\n",
				mustDir())
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
		Short: "Run Switchboard in the background (launchd agent)",
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
			if logPath, err := service.LogPath(); err == nil {
				fmt.Fprintf(out, "  logs:  %s\n", logPath)
			}
			return nil
		},
	}
}

func cmdDaemonLogs() *cobra.Command {
	return &cobra.Command{
		Use:   "logs",
		Short: "Print the path of the background service log file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logPath, err := service.LogPath()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), logPath)
			return nil
		},
	}
}
