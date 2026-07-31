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
	"syscall"
	"time"

	"howett.net/plist"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/netprobe"
)

// SystemPlistPath is where a ModeDaemon definition lives. Root-owned, in the
// system domain: the job starts as root to bind :443 and :80, then drops.
//
// A var, not a const, so tests can redirect it. As a const it silently broke
// test isolation: the agent path moves with HOME, but an absolute system path
// does not, so every test touching Status, InstalledExec or Uninstall read the
// developer's real installation — and the uninstall test would have run
// `sudo rm` against it.
var SystemPlistPath = "/Library/LaunchDaemons/" + Label + ".plist"

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
			"session, so you'd never see it running. For :443 it also needs to record your " +
			"uid and home directory, which under sudo would resolve to root's")
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
// StagedExecPath is where the launch daemon's copy of the binary lives.
//
// launchd runs a LaunchDaemon's program as root but only validates the
// *plist's* ownership, never the program's. So a root job whose binary sits
// in a directory the user can write to is a user-to-root escalation: replace
// the file, wait for the next boot. Homebrew's prefix is exactly that —
// /opt/homebrew/bin is drwxrwxr-x owned by the installing user — so shipping
// a cask that points a LaunchDaemon at the installed binary would hand every
// user a password-free path to root on their own machine.
//
// `daemon install` therefore copies the binary somewhere only root can
// modify and points the plist at the copy. /Library/PrivilegedHelperTools is
// Apple's own location for privileged helpers and is root:wheel drwxr-xr-t
// on a stock system.
//
// The cost is that a `brew upgrade` updates the binary on PATH but not this
// copy. doctor compares them and says to re-run `daemon install`; that is a
// visible, recoverable staleness, which is a better failure than a silent
// escalation.
// A var for the same reason as SystemPlistPath.
var StagedExecPath = "/Library/PrivilegedHelperTools/" + Label

// stagePrivilegedBinary copies exe to StagedExecPath as root and verifies
// that nothing but root can modify it — including through any directory
// above it, since a writable parent means the file can simply be replaced.
func stagePrivilegedBinary(exe string, out io.Writer) error {
	dir := filepath.Dir(StagedExecPath)
	if err := elevate(out, "install", "-d", "-o", "root", "-g", "wheel", "-m", "0755", dir); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := elevate(out, "install", "-o", "root", "-g", "wheel", "-m", "0755",
		exe, StagedExecPath); err != nil {
		return fmt.Errorf("staging the daemon binary at %s: %w", StagedExecPath, err)
	}
	return verifyOwnership(StagedExecPath)
}

// verifyOwnership is verifyRootOnlyWritable, indirected like geteuid and
// bindProbe so tests can exercise the staging sequence without needing a
// genuinely root-owned directory to stage into.
var verifyOwnership = verifyRootOnlyWritable

// verifyRootOnlyWritable checks path and every directory above it are owned
// by root and not writable by group or other. Verifying rather than assuming,
// because the safe answer differs by machine: /usr/local is root-owned on
// Apple Silicon but is Homebrew's own prefix on Intel.
func verifyRootOnlyWritable(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot determine the owner of %s", p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s is owned by uid %d, not root. launchd would run it as "+
				"root, so anyone who can write there could take over the machine at the "+
				"next boot", p, st.Uid)
		}
		if perm := fi.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or other (%04o). launchd would run "+
				"it as root, so that is a path to root for any process that can write "+
				"there", p, perm)
		}
		if p == "/" {
			return nil
		}
	}
}

// rootOwned reports whether path exists and belongs to root — i.e. whether
// removing it needs the privilege the user would otherwise have to work out
// for themselves.
func rootOwned(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

func installSystemDaemon(s Spec, plistPath string, out io.Writer) error {
	fmt.Fprintf(out, "  installing a launch daemon; this needs your password:\n")

	// The plist must point at a binary only root can modify — see
	// StagedExecPath. Do this before writing the plist, so a failure here
	// leaves nothing installed rather than a plist naming a binary that was
	// never staged.
	if err := stagePrivilegedBinary(s.Exec, out); err != nil {
		return err
	}
	fmt.Fprintf(out, "  staged %s (root-owned, not writable by you)\n", StagedExecPath)
	s.Exec = StagedExecPath

	plistTmp, err := os.CreateTemp("", "switchboard-*.plist")
	if err != nil {
		return err
	}
	defer os.Remove(plistTmp.Name()) //nolint:errcheck
	if _, err := plistTmp.WriteString(renderPlist(s)); err != nil {
		plistTmp.Close() //nolint:errcheck
		return err
	}
	if err := plistTmp.Close(); err != nil {
		return err
	}

	if err := elevate(out, "install", "-o", "root", "-g", "wheel", "-m", "0644",
		plistTmp.Name(), plistPath); err != nil {
		return fmt.Errorf("installing %s: %w", plistPath, err)
	}
	fmt.Fprintf(out, "  wrote %s (root-owned)\n", plistPath)

	// Booting out a job that isn't loaded is not an error worth reporting.
	_ = elevateQuiet("launchctl", "bootout", targetFor(ModeDaemon))

	err = bootstrapWithRetry(out, func() ([]byte, error) {
		return elevateOutput("launchctl", "bootstrap", domainFor(ModeDaemon), plistPath)
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
//
// A package var so tests can record the privileged sequence rather than run
// it. Everything this package does as root goes through here or
// elevateQuiet, which makes them the two places a test can observe.
var elevate = func(out io.Writer, name string, args ...string) error {
	fmt.Fprintf(out, "  $ sudo %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command("sudo", append([]string{name}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

var elevateQuiet = func(name string, args ...string) error {
	return exec.Command("sudo", append([]string{name}, args...)...).Run()
}

// elevateOutput is the third privileged entry point: same as elevateQuiet but
// returning combined output, which bootstrapWithRetry needs in order to
// report why launchd refused. A var for the same reason as the other two —
// without it, a unit test of the install sequence really does run
// `sudo launchctl bootstrap` against the machine running the tests.
var elevateOutput = func(name string, args ...string) ([]byte, error) {
	return exec.Command("sudo", append([]string{name}, args...)...).CombinedOutput()
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
		// Read the log path off the plist before removing it — afterwards
		// there is nothing left that records where the job was writing.
		logPath := InstalledLogPath()
		_ = elevateQuiet("launchctl", "bootout", targetFor(mode))
		if err := elevate(out, "rm", "-f", plistPath); err != nil {
			return fmt.Errorf("removing %s: %w", plistPath, err)
		}
		fmt.Fprintf(out, "  removed %s\n", plistPath)
		// The staged copy is a root-owned binary the user cannot delete
		// themselves; leaving it behind would be litter they'd need sudo to
		// clean up, in a directory they have no reason to look in.
		if _, err := os.Stat(StagedExecPath); err == nil {
			if err := elevate(out, "rm", "-f", StagedExecPath); err != nil {
				return fmt.Errorf("removing %s: %w", StagedExecPath, err)
			}
			fmt.Fprintf(out, "  removed %s\n", StagedExecPath)
		}
		// launchd creates the log as root, so it is a file the user cannot
		// delete themselves — the same argument as the staged binary, and the
		// reason it lives outside the home directory in the first place. Only
		// root-owned logs are removed: a ModeAgent log sits under
		// ~/.config/switchboard, where `rm -rf` already covers it.
		if logPath != "" && rootOwned(logPath) {
			if err := elevate(out, "rm", "-f", logPath); err != nil {
				// Not fatal. The service is gone either way; a leftover log is
				// litter, not breakage, and failing here would make `uninstall`
				// report an error for something already fully undone.
				fmt.Fprintf(out, "  (could not remove %s: %v)\n", logPath, err)
			} else {
				fmt.Fprintf(out, "  removed %s\n", logPath)
			}
		}
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

// installedPlist decodes whichever service definition is actually on disk,
// system daemon first — matching Status's precedence, so that a machine
// running the launch daemon is never described by a stale user agent left
// over from a high-port configuration.
//
// Reading the installed plist, rather than recomputing what an install
// *would* write, is the point: it is the only source that stays correct when
// the config has changed since the service was installed.
func installedPlist() (plistDoc, bool) {
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
		return doc, true
	}
	return plistDoc{}, false
}

// InstalledExec returns the binary path recorded in the installed plist, or
// "" if no plist exists or it doesn't parse. Used by doctor to spot a stale
// path after the binary moves (a Homebrew upgrade, say).
func InstalledExec() string {
	doc, ok := installedPlist()
	if !ok || len(doc.ProgramArguments) == 0 {
		return ""
	}
	return doc.ProgramArguments[0]
}

// InstalledLogPath returns the file the installed service actually writes to,
// or "" if nothing is installed.
//
// This cannot be derived from LogPath(). The two modes log to different
// places — a launch daemon starts as root, so its log goes to
// /Library/Logs rather than into the user's home (see DefaultSpec) — and
// `daemon logs` and `daemon status` used to print LogPath() unconditionally.
// On the default install, which is the launch daemon, that named a file under
// ~/.config that nothing ever writes to: the one command whose entire job is
// to find the log pointed at the wrong one.
func InstalledLogPath() string {
	doc, ok := installedPlist()
	if !ok {
		return ""
	}
	return doc.StandardOutPath
}
