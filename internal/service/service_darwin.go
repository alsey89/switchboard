package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/netprobe"
)

// SystemPlistPath is where a ModeDaemon definition lives. Root-owned, in the
// system domain: the job starts as root to bind :443 and :80, then drops.
const SystemPlistPath = "/Library/LaunchDaemons/" + Label + ".plist"

// PlistPath is where a ModeAgent definition lives — a *user* agent that runs
// as you and needs no privilege.
func PlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", Label+".plist"), nil
}

// PlistPathFor returns the definition path for a mode.
func PlistPathFor(m Mode) (string, error) {
	if m == ModeDaemon {
		return SystemPlistPath, nil
	}
	return PlistPath()
}

func domainFor(m Mode) string {
	if m == ModeDaemon {
		// The system domain, not gui/<uid>: a LaunchDaemon has no session.
		return "system"
	}
	return domainTarget()
}

func targetFor(m Mode) string { return domainFor(m) + "/" + Label }

func renderPlist(s Spec) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")

	b.WriteString("  <key>Label</key>\n  " + xmlString(Label) + "\n")

	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	b.WriteString("    " + xmlString(s.Exec) + "\n")
	for _, a := range s.Args {
		b.WriteString("    " + xmlString(a) + "\n")
	}
	b.WriteString("  </array>\n")

	b.WriteString("  <key>RunAtLoad</key>\n  <true/>\n")
	// Come back from a crash, stay down after a clean exit — otherwise
	// `switchboard daemon uninstall` and plain SIGTERM would respawn.
	b.WriteString("  <key>KeepAlive</key>\n  <dict>\n")
	b.WriteString("    <key>SuccessfulExit</key>\n    <false/>\n")
	b.WriteString("  </dict>\n")
	// Deliberately no ProcessType key. `Background` throttles the job's I/O
	// and CPU scheduling band, which is wrong for a reverse proxy the
	// browser hits on every page load and HMR websocket message — added
	// latency here would be hard to diagnose from the browser side.
	// `Adaptive` was considered and rejected: it switches bands based on XPC
	// activity, and Switchboard uses no XPC, so it would just sit in
	// Background anyway. Omitting the key gives launchd's default,
	// `Standard`: no throttling, no elevated priority either — the right
	// choice for a latency-sensitive background service that isn't a GUI
	// app. Don't add this key back without re-reading this comment.
	b.WriteString("  <key>StandardOutPath</key>\n  " + xmlString(s.StdoutPath) + "\n")
	b.WriteString("  <key>StandardErrorPath</key>\n  " + xmlString(s.StderrPath) + "\n")

	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func xmlString(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s)) //nolint:errcheck // bytes.Buffer never fails
	return "<string>" + buf.String() + "</string>"
}

// plistDoc mirrors the shape renderPlist writes, for the read side
// (InstalledExec, and the round-trip test). Field names are matched
// case-sensitively against plist <key> values by howett.net/plist — no
// struct tags needed since they already agree. Using a real plist decoder
// here (rather than a hand-rolled string scan) means entity-escaped paths
// come back exactly as they went in, and a malformed plist is rejected
// instead of silently mis-parsed.
type plistDoc struct {
	Label            string
	ProgramArguments []string
	RunAtLoad        bool
	KeepAlive        struct {
		SuccessfulExit bool
	}
	StandardOutPath   string
	StandardErrorPath string
}

func domainTarget() string { return "gui/" + strconv.Itoa(os.Getuid()) }

func serviceTarget() string { return domainTarget() + "/" + Label }

// geteuid is os.Geteuid, indirected so tests can exercise Install's root
// guard without actually running as root.
var geteuid = os.Geteuid

// bootstrapRetryDelay is the base backoff between `launchctl bootstrap`
// retries (see bootstrapWithRetry). A package var so tests can shrink it.
var bootstrapRetryDelay = 200 * time.Millisecond

// bootstrapAttempts bounds the retries in bootstrapWithRetry.
const bootstrapAttempts = 3

// bindProbe is netprobe.Bindable, indirected so tests can exercise the
// privileged-port guard without depending on the machine's real privileges
// (and without actually binding anything).
var bindProbe = netprobe.Bindable

// checkPrivilegedPorts refuses to install an agent that cannot possibly
// start.
//
// macOS enforces the classic Unix restriction: an unprivileged process
// cannot bind a port below 1024. The daemon's defaults are :80 and :443, so
// on a stock configuration `switchboard start` exits 1 at bind time — and
// the launch agent sets KeepAlive{SuccessfulExit: false}, which means
// launchd relaunches it forever (throttled to roughly every 10s), appending
// to an unrotated log the whole time. Installing that is worse than
// refusing to.
//
// Only EACCES/EPERM counts. An in-use port must NOT block the install:
// `daemon install` is documented as "re-run to restart it", so on the happy
// path the daemon we are about to replace is itself holding :443, and
// treating that as fatal would break the documented restart flow.
func checkPrivilegedPorts(s Spec) error {
	for _, p := range s.Ports {
		port, err := strconv.Atoi(portOf(p.Addr))
		if err != nil || port >= 1024 {
			continue
		}
		// In ModeDaemon the privileged parent binds these two as root and
		// hands them over, so a probe failing as the unprivileged installing
		// user says nothing about whether the job will work. Probing anyway
		// would refuse exactly the configuration this mode exists to serve.
		if s.Mode == ModeDaemon && (p.Name == "https" || p.Name == "http") {
			continue
		}
		if err := bindProbe(p.Network, p.Addr); err == nil || !errors.Is(err, os.ErrPermission) {
			continue
		}
		remedy := p.Remedy
		if remedy == "" {
			remedy = "    (raise this listener's port above 1024)"
		}
		return fmt.Errorf("cannot bind %s for %s: permission denied.\n"+
			"  macOS reserves ports below 1024 for root, and the daemon runs as you — so this\n"+
			"  agent would fail at startup and be relaunched by launchd in a loop.\n\n"+
			"  Use a high port instead, in %s:\n\n"+
			"%s\n\n"+
			"  then re-run `switchboard daemon install`. Proxy URLs grow the port\n"+
			"  (https://app.test:8443); that is the documented trade-off.",
			p.Addr, p.Name, configPathFor(s), remedy)
	}
	return nil
}

// configPathFor names the config file in user-facing errors, falling back to
// the conventional location if the Spec somehow lacks one.
func configPathFor(s Spec) string {
	if s.ConfigPath != "" {
		return s.ConfigPath
	}
	if p, err := config.Path(); err == nil {
		return p
	}
	return "~/.config/switchboard/config.toml"
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

// Install writes the plist and bootstraps the agent. Safe to re-run: an
// already-loaded agent is booted out first, so this doubles as "restart".
func Install(s Spec, out io.Writer) error {
	// The daemon must never run as root — that is the whole point of a
	// user agent (see DESIGN.md §5). `sudo switchboard daemon install`
	// would write into /var/root and bootstrap gui/0, a domain the
	// logged-in user generally can't see or manage: `daemon status` run
	// normally afterward would report "not installed", and the install
	// would look like it silently vanished.
	if geteuid() == 0 {
		return errors.New("run `switchboard daemon install` without sudo — a launch agent " +
			"installed as root loads into a different launchd domain (gui/0) than your own " +
			"session, so you'd never see it running. The daemon always runs as you, never as root")
	}

	// Refuse before writing anything: an agent that can't bind its ports
	// doesn't fail, it crash-loops. See checkPrivilegedPorts.
	if err := checkPrivilegedPorts(s); err != nil {
		return err
	}

	plistPath, err := PlistPathFor(s.Mode)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.StdoutPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.StderrPath), 0o755); err != nil {
		return err
	}

	if s.Mode == ModeDaemon {
		return installSystemDaemon(s, plistPath, out)
	}

	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(renderPlist(s)), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", plistPath, err)
	}
	fmt.Fprintf(out, "  wrote %s\n", plistPath)

	if b, err := exec.Command("launchctl", "bootout", serviceTarget()).CombinedOutput(); err != nil {
		// "No such process" just means it wasn't loaded — the common case.
		// Anything else is worth showing, even though it isn't fatal on its
		// own: the bootstrap below is the real test of whether we're in a
		// good state.
		if !strings.Contains(string(b), "No such process") {
			fmt.Fprintf(out, "  (launchctl bootout: %s)\n", strings.TrimSpace(string(b)))
		}
	}

	err = bootstrapWithRetry(out, func() ([]byte, error) {
		return exec.Command("launchctl", "bootstrap", domainTarget(), plistPath).CombinedOutput()
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "  bootstrapped %s\n", serviceTarget())
	return nil
}

// installSystemDaemon writes a root-owned plist and bootstraps it into the
// system domain. Only these two steps elevate, and each is printed before it
// runs — the same contract `switchboard setup` follows, so that a user can
// see exactly what they are consenting to rather than handing the whole
// command root and hoping.
//
// The plist is staged in the user's own directory and installed with
// `install -o root -g wheel -m 0644`. Writing it directly under sudo would
// mean a root-owned file whose contents were produced by a shell redirect,
// and getting the ownership wrong here matters: launchd refuses to load a
// LaunchDaemon that is writable by anyone but root, which is precisely the
// protection that stops a user-writable file from steering a root job.
func installSystemDaemon(s Spec, plistPath string, out io.Writer) error {
	staged, err := os.CreateTemp("", "switchboard-*.plist")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name()) //nolint:errcheck
	if _, err := staged.WriteString(renderPlist(s)); err != nil {
		staged.Close() //nolint:errcheck
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}

	fmt.Fprintf(out, "  installing a launch daemon; this needs your password:\n")
	if err := elevate(out, "install", "-o", "root", "-g", "wheel", "-m", "0644",
		staged.Name(), plistPath); err != nil {
		return fmt.Errorf("installing %s: %w", plistPath, err)
	}
	fmt.Fprintf(out, "  wrote %s (root-owned)\n", plistPath)

	// Booting out a job that isn't loaded is not an error worth reporting.
	_ = elevateQuiet("launchctl", "bootout", targetFor(ModeDaemon))

	err = bootstrapWithRetry(out, func() ([]byte, error) {
		return exec.Command("sudo", "launchctl", "bootstrap", domainFor(ModeDaemon), plistPath).CombinedOutput()
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "  bootstrapped %s\n", targetFor(ModeDaemon))
	fmt.Fprintf(out, "  the proxy runs as uid %d; only the socket-binding parent is root\n", s.UID)
	return nil
}

// elevate runs a command under sudo, printing it first, attached to the
// user's terminal so sudo can prompt.
func elevate(out io.Writer, name string, args ...string) error {
	fmt.Fprintf(out, "  $ sudo %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command("sudo", append([]string{name}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func elevateQuiet(name string, args ...string) error {
	return exec.Command("sudo", append([]string{name}, args...)...).Run()
}

// bootstrapWithRetry retries fn — a `launchctl bootstrap` invocation, or a
// stand-in in tests — a bounded number of times with a short backoff.
//
// `launchctl bootout` is asynchronous: it can return before launchd has
// actually finished tearing the job down, and a bootstrap issued immediately
// after then fails with a transient error (`Bootstrap failed: 5: Input/
// output error`, or `36: Operation now in progress`) even though nothing is
// really wrong. Since Install's bootout-then-bootstrap sequence is exactly
// the documented "re-run to restart it" path, that race is the most likely
// way anyone hits this — worth a few retries before calling it a real
// failure.
func bootstrapWithRetry(out io.Writer, fn func() ([]byte, error)) error {
	var lastErr error
	for i := 0; i < bootstrapAttempts; i++ {
		if i > 0 {
			time.Sleep(bootstrapRetryDelay * time.Duration(i))
		}
		b, err := fn()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("launchctl bootstrap failed: %w\n%s", err, strings.TrimSpace(string(b)))
		if i < bootstrapAttempts-1 {
			fmt.Fprintf(out, "  bootstrap attempt %d/%d failed, retrying: %s\n", i+1, bootstrapAttempts, lastErr)
		}
	}
	return fmt.Errorf("%w\n  the plist is written but not loaded — inspect with "+
		"`launchctl print %s`, or just retry: switchboard daemon install", lastErr, serviceTarget())
}

// Uninstall boots the agent out and removes the plist. removed reports
// whether there was anything to remove, so callers don't claim success for
// a service that was never installed.
// Both modes are always attempted, regardless of what the current config
// would install. Someone who used high ports, then switched to :443, has a
// stale user agent on disk that would fight the new launch daemon for the
// dashboard and DNS ports; uninstall has to clear whatever is actually
// there, not whatever the config implies should be.
func Uninstall(out io.Writer) (removed bool, err error) {
	for _, mode := range []Mode{ModeAgent, ModeDaemon} {
		plistPath, pathErr := PlistPathFor(mode)
		if pathErr != nil {
			err = errors.Join(err, pathErr)
			continue
		}
		if _, statErr := os.Stat(plistPath); os.IsNotExist(statErr) {
			continue
		}
		if rmErr := uninstallOne(mode, plistPath, out); rmErr != nil {
			err = errors.Join(err, rmErr)
			continue
		}
		removed = true
	}
	if !removed && err == nil {
		fmt.Fprintln(out, "  no service was installed")
	}
	return removed, err
}

func uninstallOne(mode Mode, plistPath string, out io.Writer) error {
	if mode == ModeDaemon {
		fmt.Fprintln(out, "  removing the launch daemon; this needs your password:")
		_ = elevateQuiet("launchctl", "bootout", targetFor(mode))
		if err := elevate(out, "rm", "-f", plistPath); err != nil {
			return fmt.Errorf("removing %s: %w", plistPath, err)
		}
		fmt.Fprintf(out, "  removed %s\n", plistPath)
		return nil
	}

	if b, err := exec.Command("launchctl", "bootout", targetFor(mode)).CombinedOutput(); err != nil {
		// "No such process" just means it wasn't running.
		if !strings.Contains(string(b), "No such process") {
			fmt.Fprintf(out, "  (launchctl bootout: %s)\n", strings.TrimSpace(string(b)))
		}
	}
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintf(out, "  removed %s\n", plistPath)
	return nil
}

// Status reports the launch agent's state by combining two independent
// facts: whether the plist exists on disk, and what launchd itself says via
// `launchctl print`. See State's doc for why those two facts don't collapse
// into a single bool.
// The system daemon is checked first: if both exist, it is the one holding
// :443, and reporting the agent instead would describe a job that cannot
// even start.
func Status() (state State, plistPath string, err error) {
	agentPath, err := PlistPath()
	if err != nil {
		return NotInstalled, "", err
	}
	for _, c := range []struct {
		mode Mode
		path string
	}{{ModeDaemon, SystemPlistPath}, {ModeAgent, agentPath}} {
		if _, statErr := os.Stat(c.path); statErr != nil {
			continue
		}
		out, printErr := exec.Command("launchctl", "print", targetFor(c.mode)).CombinedOutput()
		if printErr != nil {
			// launchd doesn't know about this label: the plist exists but was
			// never bootstrapped (or was booted out and not reinstalled).
			return NotLoaded, c.path, nil
		}
		if jobRunning(string(out)) {
			return Running, c.path, nil
		}
		return Loaded, c.path, nil
	}
	return NotInstalled, agentPath, nil
}

// jobRunning inspects `launchctl print <target>` output for evidence of a
// live process. A loaded-but-not-running job (crashed and not yet
// relaunched, or simply not started) omits the pid line; launchctl reports
// `state = running` only while a process is actually up. Checking both the
// state line and the pid line is deliberately redundant — launchctl's
// undocumented output format has drifted across macOS releases before, and
// either signal alone is enough to answer the question we actually care
// about ("is a process up"), so this stays correct even if one of the two
// lines is ever renamed or dropped.
func jobRunning(printOutput string) bool {
	for _, line := range strings.Split(printOutput, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "state = "):
			if strings.TrimSpace(strings.TrimPrefix(line, "state = ")) == "running" {
				return true
			}
		case strings.HasPrefix(line, "pid = "):
			if strings.TrimSpace(strings.TrimPrefix(line, "pid = ")) != "" {
				return true
			}
		}
	}
	return false
}

// InstalledExec returns the binary path recorded in the installed plist, or
// "" if no plist exists or it doesn't parse. Used by doctor to spot a stale
// path after the binary moves (a Homebrew upgrade, say).
// Both modes are inspected, system daemon first, matching Status's
// precedence — otherwise a machine running the launch daemon would have
// doctor reporting on a stale user agent, or on nothing at all.
func InstalledExec() string {
	agentPath, err := PlistPath()
	if err != nil {
		agentPath = ""
	}
	for _, p := range []string{SystemPlistPath, agentPath} {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var doc plistDoc
		if _, err := plist.Unmarshal(b, &doc); err != nil {
			continue
		}
		if len(doc.ProgramArguments) == 0 {
			continue
		}
		return doc.ProgramArguments[0]
	}
	return ""
}
