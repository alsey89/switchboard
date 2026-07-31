package service

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"howett.net/plist"
)

// isolateSystemPaths redirects the absolute /Library paths at temp locations.
//
// Without this the suite reads the developer's own installation: HOME moves
// the launch-agent path, but a hardcoded system path does not move at all. It
// was found the hard way — TestUninstallReportsNothingToRemove, which exists
// to check the "nothing was installed" message, was issuing `sudo rm` against
// the real /Library/LaunchDaemons plist on a machine that had one. It failed
// only because non-interactive sudo refused.
//
// Any test that reaches Status, InstalledExec, Install or Uninstall must call
// this.
func isolateSystemPaths(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	origPlist, origStaged := SystemPlistPath, StagedExecPath
	SystemPlistPath = filepath.Join(dir, "LaunchDaemons", Label+".plist")
	StagedExecPath = filepath.Join(dir, "PrivilegedHelperTools", Label)
	t.Cleanup(func() {
		SystemPlistPath, StagedExecPath = origPlist, origStaged
	})
}

// parsePlist decodes a rendered plist through the same library InstalledExec
// uses. Round-tripping through a real plist parser — rather than substring
// matching the rendered string — is what actually pins well-formedness and
// correct nesting: a plist with SuccessfulExit hoisted to the top level (no
// KeepAlive wrapper) would still contain the literal substrings
// "<key>SuccessfulExit</key>" and "<false/>", but it would decode into a
// different (empty) plistDoc.KeepAlive, which is what these tests check.
func parsePlist(t *testing.T, rendered string) plistDoc {
	t.Helper()
	var doc plistDoc
	if _, err := plist.Unmarshal([]byte(rendered), &doc); err != nil {
		t.Fatalf("rendered plist did not parse as a valid plist: %v\n---\n%s", err, rendered)
	}
	return doc
}

func TestRenderPlist(t *testing.T) {
	spec := Spec{
		Exec:       "/opt/homebrew/bin/switchboard",
		Args:       []string{"start", "--config", "/Users/me/.config/switchboard/config.toml"},
		StdoutPath: "/Users/me/.config/switchboard/logs/daemon.log",
		StderrPath: "/Users/me/.config/switchboard/logs/daemon.log",
	}
	got := renderPlist(spec)

	if !strings.HasPrefix(got, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Error("plist must start with the XML declaration")
	}
	if !strings.HasSuffix(strings.TrimSpace(got), "</plist>") {
		t.Error("plist must end with </plist>")
	}
	if !strings.Contains(got, "<key>RunAtLoad</key>\n  <true/>") {
		t.Errorf("plist must set RunAtLoad, got:\n%s", got)
	}

	doc := parsePlist(t, got)
	if doc.Label != Label {
		t.Errorf("Label = %q, want %q", doc.Label, Label)
	}
	wantArgs := append([]string{spec.Exec}, spec.Args...)
	if len(doc.ProgramArguments) != len(wantArgs) {
		t.Fatalf("ProgramArguments = %v, want %v", doc.ProgramArguments, wantArgs)
	}
	for i, want := range wantArgs {
		if doc.ProgramArguments[i] != want {
			t.Errorf("ProgramArguments[%d] = %q, want %q", i, doc.ProgramArguments[i], want)
		}
	}
	if doc.StandardOutPath != spec.StdoutPath {
		t.Errorf("StandardOutPath = %q, want %q", doc.StandardOutPath, spec.StdoutPath)
	}
	if doc.StandardErrorPath != spec.StderrPath {
		t.Errorf("StandardErrorPath = %q, want %q", doc.StandardErrorPath, spec.StderrPath)
	}

	// The property under test: KeepAlive.SuccessfulExit must be false, and
	// specifically *nested inside KeepAlive* — not a same-named top-level
	// key, which substring matching alone can't tell apart. A clean exit
	// (daemon uninstall, plain SIGTERM) must stay down; a crash must come
	// back.
	if doc.KeepAlive.SuccessfulExit {
		t.Errorf("KeepAlive.SuccessfulExit should be false so a crash restarts the job, got true")
	}
}

// TestRenderPlistOmitsProcessType pins a deliberate decision: no
// ProcessType key at all, so launchd defaults to Standard (no scheduling
// throttling). `Background` would throttle I/O/CPU for this job, adding
// latency to a reverse proxy the browser hits on every request — see the
// comment in renderPlist. This test exists so nobody reinstates the key
// without reading that reasoning first.
func TestRenderPlistOmitsProcessType(t *testing.T) {
	got := renderPlist(Spec{Exec: "/bin/x", Args: []string{"start"}, StdoutPath: "/tmp/o", StderrPath: "/tmp/e"})
	if strings.Contains(got, "ProcessType") {
		t.Errorf("plist must not set ProcessType (Background/Adaptive would throttle a latency-sensitive proxy), got:\n%s", got)
	}

	var raw map[string]interface{}
	if _, err := plist.Unmarshal([]byte(got), &raw); err != nil {
		t.Fatalf("plist did not parse: %v", err)
	}
	if _, ok := raw["ProcessType"]; ok {
		t.Error("decoded plist must not contain a ProcessType key")
	}
}

// TestRenderPlistKeepAliveIsNotTopLevel guards specifically against the
// malformation substring-matching would miss: SuccessfulExit hoisted out of
// KeepAlive entirely. launchd accepts that plist silently and simply never
// restarts a crashed daemon — the exact failure this feature exists to
// prevent.
func TestRenderPlistKeepAliveIsNotTopLevel(t *testing.T) {
	got := renderPlist(Spec{Exec: "/bin/x", Args: []string{"start"}, StdoutPath: "/tmp/o", StderrPath: "/tmp/e"})

	var raw map[string]interface{}
	if _, err := plist.Unmarshal([]byte(got), &raw); err != nil {
		t.Fatalf("plist did not parse: %v", err)
	}
	if _, ok := raw["SuccessfulExit"]; ok {
		t.Error("SuccessfulExit must not be a top-level key — it belongs inside KeepAlive")
	}
	keepAlive, ok := raw["KeepAlive"].(map[string]interface{})
	if !ok {
		t.Fatalf("KeepAlive must be a dict, got %#v", raw["KeepAlive"])
	}
	if _, ok := keepAlive["SuccessfulExit"]; !ok {
		t.Error("KeepAlive must contain SuccessfulExit")
	}
}

// TestRenderPlistEscapesPaths covers every interpolation point — Exec,
// every element of Args, and both log paths — with a mix of the XML
// metacharacters a real path or argument could plausibly contain. Home
// directories with '&' happen; '<', '>', and '"' are rarer but not
// impossible (some CI images, some corporate account provisioning). Any of
// them unescaped produces a plist launchd rejects at parse time or, worse,
// silently truncates.
func TestRenderPlistEscapesPaths(t *testing.T) {
	spec := Spec{
		Exec:       `/Users/a&b/bin/switchboard`,
		Args:       []string{"start", `--config`, `/Users/a&b/<weird>/"config".toml`},
		StdoutPath: `/Users/a&b/logs/<out>.log`,
		StderrPath: `/Users/a&b/logs/"err".log`,
	}
	got := renderPlist(spec)

	for _, raw := range []string{"a&b/bin", "<weird>", `"config"`, "<out>", `"err"`} {
		if strings.Contains(got, raw) {
			t.Errorf("unescaped %q leaked into the plist:\n%s", raw, got)
		}
	}

	doc := parsePlist(t, got)
	if doc.ProgramArguments[0] != spec.Exec {
		t.Errorf("Exec round-tripped to %q, want %q", doc.ProgramArguments[0], spec.Exec)
	}
	wantArgs := spec.Args
	gotArgs := doc.ProgramArguments[1:]
	if len(gotArgs) != len(wantArgs) {
		t.Fatalf("Args round-tripped to %v, want %v", gotArgs, wantArgs)
	}
	for i, want := range wantArgs {
		if gotArgs[i] != want {
			t.Errorf("Args[%d] round-tripped to %q, want %q", i, gotArgs[i], want)
		}
	}
	if doc.StandardOutPath != spec.StdoutPath {
		t.Errorf("StdoutPath round-tripped to %q, want %q", doc.StandardOutPath, spec.StdoutPath)
	}
	if doc.StandardErrorPath != spec.StderrPath {
		t.Errorf("StderrPath round-tripped to %q, want %q", doc.StandardErrorPath, spec.StderrPath)
	}
}

// TestPlistPathStemMatchesLabel pins the constraint launchd silently
// requires: the plist's filename stem must equal the Label key inside it,
// or the job registers under a different name than the file that defines
// it.
func TestPlistPathStemMatchesLabel(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	isolateSystemPaths(t)
	p, err := PlistPath()
	if err != nil {
		t.Fatal(err)
	}
	stem := strings.TrimSuffix(filepath.Base(p), ".plist")
	if stem != Label {
		t.Errorf("plist filename stem %q != Label %q — launchd requires these to match", stem, Label)
	}
}

// TestInstalledExecRoundTrip is the test that would have caught reading the
// escaped form of the executable path back out verbatim: it writes a
// rendered plist (containing a path with an XML metacharacter) to a scratch
// $HOME — never the real ~/Library/LaunchAgents — and asserts InstalledExec
// recovers the exact, unescaped original.
func TestInstalledExecRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	isolateSystemPaths(t) // redirect PlistPath(); never touches the real home dir

	spec := Spec{
		Exec:       `/Users/a&b/<weird "path">/bin/switchboard`,
		Args:       []string{"start"},
		StdoutPath: "/tmp/switchboard-test-out.log",
		StderrPath: "/tmp/switchboard-test-err.log",
	}
	plistPath, err := PlistPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plistPath, []byte(renderPlist(spec)), 0o644); err != nil {
		t.Fatal(err)
	}

	got := InstalledExec()
	if got != spec.Exec {
		t.Errorf("InstalledExec() = %q, want %q (the exact, unescaped path written)", got, spec.Exec)
	}
}

func TestInstalledExecNoPlist(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	isolateSystemPaths(t)
	if got := InstalledExec(); got != "" {
		t.Errorf("InstalledExec() with no plist installed = %q, want empty", got)
	}
}

// TestJobRunningFromPrintOutput feeds jobRunning captured/synthetic
// `launchctl print` output rather than invoking launchctl: the function
// under test is pure, so the property (does this text indicate a live
// process?) is fully checkable without ever loading anything into launchd.
func TestJobRunningFromPrintOutput(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "running with state and pid",
			out:  "gui/501/io.github.alsey89.switchboard = {\n\tstate = running\n\tpid = 4242\n}\n",
			want: true,
		},
		{
			name: "loaded, not running, no pid line",
			out:  "gui/501/io.github.alsey89.switchboard = {\n\tstate = not running\n}\n",
			want: false,
		},
		{
			name: "pid present without a recognizable state line",
			out:  "gui/501/io.github.alsey89.switchboard = {\n\tpid = 555\n}\n",
			want: true,
		},
		{
			name: "loaded but waiting, no pid",
			out:  "gui/501/io.github.alsey89.switchboard = {\n\tstate = waiting\n}\n",
			want: false,
		},
		{
			name: "empty output",
			out:  "",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := jobRunning(c.out); got != c.want {
				t.Errorf("jobRunning(%q) = %v, want %v", c.out, got, c.want)
			}
		})
	}
}

// TestInstallRefusesRoot exercises the root guard without ever running as
// root: geteuid is a package var precisely so this can be redirected in a
// test. The guard must be the very first thing Install does, before any
// filesystem or launchctl interaction — this test relies on that ordering
// implicitly, since it never provides a real plist path or launchctl.
func TestInstallRefusesRoot(t *testing.T) {
	isolateSystemPaths(t) // the guard fires first, but do not rely on ordering for safety
	orig := geteuid
	geteuid = func() int { return 0 }
	defer func() { geteuid = orig }()

	err := Install(Spec{
		Exec:       "/bin/x",
		Args:       []string{"start"},
		StdoutPath: "/tmp/wont-be-touched-out.log",
		StderrPath: "/tmp/wont-be-touched-err.log",
	}, io.Discard)
	if err == nil {
		t.Fatal("Install should refuse to run as root, got nil error")
	}
	if !strings.Contains(err.Error(), "sudo") {
		t.Errorf("root-guard error should mention sudo, got: %v", err)
	}
}

// TestInstallRefusesUnbindablePrivilegedPort is the guard against installing
// a crash-loop. macOS reserves ports below 1024 for root and the daemon runs
// as the user, so with the default :443 the agent exits 1 at bind time — and
// KeepAlive{SuccessfulExit: false} means launchd relaunches it forever,
// appending to an unrotated log. bindProbe is a package var (same style as
// geteuid above) so this runs identically wherever the tests do, including
// somewhere ports below 1024 happen to be bindable.
func TestInstallRefusesUnbindablePrivilegedPort(t *testing.T) {
	orig := bindProbe
	bindProbe = func(_, addr string) error {
		return &net.OpError{Op: "listen", Net: "tcp", Err: os.ErrPermission}
	}
	defer func() { bindProbe = orig }()

	t.Setenv("HOME", t.TempDir())
	isolateSystemPaths(t) // nothing may be written to the real home
	err := Install(Spec{
		Exec:       "/bin/x",
		Args:       []string{"start"},
		StdoutPath: filepath.Join(t.TempDir(), "out.log"),
		StderrPath: filepath.Join(t.TempDir(), "err.log"),
		ConfigPath: "/Users/me/.config/switchboard/config.toml",
		Ports: []GuardedPort{
			{Name: "https", Network: "tcp", Addr: "127.0.0.1:443",
				Remedy: "    http_port  = 8080\n    https_port = 8443"},
			{Name: "http", Network: "tcp", Addr: "127.0.0.1:80",
				Remedy: "    http_port  = 8080\n    https_port = 8443"},
		},
	}, io.Discard)
	if err == nil {
		t.Fatal("Install should refuse a privileged port it cannot bind, got nil error")
	}
	// The message has to be actionable: name the port that failed, and name
	// the escape hatch plus where to set it.
	for _, want := range []string{"127.0.0.1:443", "https_port", "/Users/me/.config/switchboard/config.toml"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal message should mention %q, got:\n%s", want, err)
		}
	}

	// And it must refuse *before* touching the filesystem — otherwise it
	// leaves a plist behind for launchd to find.
	plistPath, perr := PlistPath()
	if perr != nil {
		t.Fatal(perr)
	}
	if _, serr := os.Stat(plistPath); serr == nil {
		t.Errorf("a plist was written at %s despite the refusal", plistPath)
	}
}

// TestInstallAllowsPortInUse pins the narrowness of that guard. `daemon
// install` is documented as "re-run to restart it", so on the happy path the
// daemon being replaced is itself holding :443 and the probe fails with
// EADDRINUSE. Treating that as fatal would break the documented restart
// flow; only EACCES/EPERM may block an install.
func TestInstallAllowsPortInUse(t *testing.T) {
	orig := bindProbe
	bindProbe = func(_, addr string) error {
		return &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
	}
	defer func() { bindProbe = orig }()

	err := checkPrivilegedPorts(Spec{Ports: []GuardedPort{
		{Name: "https", Network: "tcp", Addr: "127.0.0.1:443"},
	}})
	if err != nil {
		t.Errorf("an in-use privileged port must not block a reinstall/restart, got: %v", err)
	}
}

// TestCheckPrivilegedPortsIgnoresHighPorts: the escape hatch has to actually
// work. A user who set https_port = 8443 must be able to install.
func TestCheckPrivilegedPortsIgnoresHighPorts(t *testing.T) {
	orig := bindProbe
	called := false
	bindProbe = func(_, _ string) error {
		called = true
		return os.ErrPermission
	}
	defer func() { bindProbe = orig }()

	err := checkPrivilegedPorts(Spec{Ports: []GuardedPort{
		{Name: "https", Network: "tcp", Addr: "127.0.0.1:8443"},
		{Name: "http", Network: "tcp", Addr: "127.0.0.1:8080"},
	}})
	if err != nil {
		t.Errorf("high ports must not be guarded, got: %v", err)
	}
	if called {
		t.Error("ports >= 1024 should not even be probed")
	}
}

// TestBootstrapWithRetrySucceedsAfterTransientFailures models the
// bootout/bootstrap race directly: fn fails twice (as a just-booted-out job
// would) and succeeds the third time, without ever invoking launchctl.
func TestBootstrapWithRetrySucceedsAfterTransientFailures(t *testing.T) {
	origDelay := bootstrapRetryDelay
	bootstrapRetryDelay = time.Millisecond
	defer func() { bootstrapRetryDelay = origDelay }()

	calls := 0
	err := bootstrapWithRetry(io.Discard, func() ([]byte, error) {
		calls++
		if calls < 3 {
			return []byte("Bootstrap failed: 5: Input/output error"), errors.New("exit status 5")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 attempts before success, got %d", calls)
	}
}

func TestBootstrapWithRetryReturnsActionableErrorAfterExhausted(t *testing.T) {
	origDelay := bootstrapRetryDelay
	bootstrapRetryDelay = time.Millisecond
	defer func() { bootstrapRetryDelay = origDelay }()

	calls := 0
	err := bootstrapWithRetry(io.Discard, func() ([]byte, error) {
		calls++
		return []byte("Bootstrap failed: 5: Input/output error"), errors.New("exit status 5")
	})
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if calls != bootstrapAttempts {
		t.Errorf("expected exactly %d attempts, got %d", bootstrapAttempts, calls)
	}
	if !strings.Contains(err.Error(), "launchctl print") {
		t.Errorf("error should tell the user how to inspect the resulting state, got: %v", err)
	}
}

// TestUninstallReportsNothingToRemove pins the minor fix: uninstalling on a
// machine where nothing was ever installed must say so, not "removed".
func TestUninstallReportsNothingToRemove(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	isolateSystemPaths(t) // no plist exists here

	var buf strings.Builder
	removed, err := Uninstall(&buf)
	if err != nil {
		t.Fatalf("Uninstall on a clean machine should not error, got %v", err)
	}
	if removed {
		t.Error("removed should be false when no plist was installed")
	}
	if strings.Contains(buf.String(), "removed ") {
		t.Errorf("output should not claim anything was removed, got: %s", buf.String())
	}
}

// recordElevated swaps the two privileged entry points for recorders,
// returning the slice the issued commands land in. Nothing runs.
func recordElevated(t *testing.T) *[][]string {
	t.Helper()
	var got [][]string
	origE, origQ, origO := elevate, elevateQuiet, elevateOutput
	elevate = func(_ io.Writer, name string, args ...string) error {
		got = append(got, append([]string{name}, args...))
		return nil
	}
	elevateQuiet = func(name string, args ...string) error {
		got = append(got, append([]string{name}, args...))
		return nil
	}
	elevateOutput = func(name string, args ...string) ([]byte, error) {
		got = append(got, append([]string{name}, args...))
		return nil, nil
	}
	t.Cleanup(func() { elevate, elevateQuiet, elevateOutput = origE, origQ, origO })
	return &got
}

// TestSystemDaemonRunsARootOwnedCopy is the regression test for a
// user-to-root escalation.
//
// launchd runs a LaunchDaemon's program as root but validates only the
// plist's ownership, never the program's. Homebrew's prefix is user-writable
// by design — /opt/homebrew/bin is drwxrwxr-x owned by the installing user —
// so a plist pointing at the installed binary would let anything running as
// that user replace it and own the machine at the next boot, with no password
// prompt anywhere in the sequence.
//
// The plist must therefore name the staged copy, never the original.
func TestSystemDaemonRunsARootOwnedCopy(t *testing.T) {
	isolateSystemPaths(t)
	got := recordElevated(t)

	// The staged path lives under a temp dir here, which can never be
	// root-owned; verifyRootOnlyWritable has its own test.
	origVerify := verifyOwnership
	verifyOwnership = func(string) error { return nil }
	t.Cleanup(func() { verifyOwnership = origVerify })

	const brewPath = "/opt/homebrew/bin/switchboard"
	// installSystemDaemon writes a plist through elevate; capture what it says.
	var written string
	origE := elevate
	elevate = func(w io.Writer, name string, args ...string) error {
		if name == "install" && len(args) > 0 && strings.HasSuffix(args[len(args)-1], ".plist") {
			if b, err := os.ReadFile(args[len(args)-2]); err == nil {
				written = string(b)
			}
		}
		return origE(w, name, args...)
	}

	err := installSystemDaemon(Spec{
		Exec:       brewPath,
		Args:       []string{"__supervise", "--uid", "501"},
		StdoutPath: "/tmp/out.log",
		StderrPath: "/tmp/err.log",
		UID:        501,
	}, SystemPlistPath, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(written, brewPath) {
		t.Errorf("the plist names %s, a path the user can overwrite. launchd runs it "+
			"as root, so that is a password-free path to root.\nplist:\n%s", brewPath, written)
	}
	if !strings.Contains(written, StagedExecPath) {
		t.Errorf("the plist should name the staged copy %s, got:\n%s", StagedExecPath, written)
	}

	// And the copy has to be made before the plist that references it.
	stageAt, plistAt := -1, -1
	for i, cmd := range *got {
		last := cmd[len(cmd)-1]
		switch {
		case cmd[0] == "install" && last == StagedExecPath:
			stageAt = i
		case cmd[0] == "install" && last == SystemPlistPath:
			plistAt = i
		}
	}
	if stageAt < 0 {
		t.Fatalf("the binary was never staged. Commands: %v", *got)
	}
	if plistAt >= 0 && stageAt > plistAt {
		t.Error("the plist is installed before the binary it names is staged; a failure " +
			"in between leaves a root job pointing at nothing")
	}
	// The copy must be root-owned and not writable by anyone else.
	for _, cmd := range *got {
		if cmd[0] == "install" && cmd[len(cmd)-1] == StagedExecPath {
			joined := strings.Join(cmd, " ")
			for _, want := range []string{"-o root", "-g wheel", "-m 0755"} {
				if !strings.Contains(joined, want) {
					t.Errorf("staging command %q must carry %q", joined, want)
				}
			}
		}
	}
}

// TestVerifyRootOnlyWritableRejectsWhatLaunchdWouldAccept: launchd itself
// performs no such check, so this is the only thing standing between a
// user-writable directory and a root job started from it.
func TestVerifyRootOnlyWritableRejectsWhatLaunchdWouldAccept(t *testing.T) {
	// A path under the test's own temp dir is user-owned by construction.
	dir := t.TempDir()
	f := filepath.Join(dir, "switchboard")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := verifyRootOnlyWritable(f)
	if err == nil {
		t.Fatal("a user-owned binary was accepted for a root launch daemon")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Errorf("the error should explain the privilege consequence, got: %v", err)
	}

	// And a genuinely root-only path passes, so the check is not simply
	// refusing everything.
	if err := verifyRootOnlyWritable("/usr/bin/true"); err != nil {
		t.Errorf("/usr/bin/true should pass a root-only check, got: %v", err)
	}
}
