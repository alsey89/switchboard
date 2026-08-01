package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/service"
)

// withStubbedProbes silences the two things these tests are not about: the
// upstream/daemon dial, which otherwise reports on whatever happens to be
// listening on the machine running the suite, and the staged-binary check,
// which otherwise reads the real /Library paths.
func withStubbedProbes(t *testing.T) {
	t.Helper()
	origDial, origStale := dialProbe, stagedStale
	dialProbe = func(string) bool { return false }
	stagedStale = func() (bool, bool) { return false, false }
	t.Cleanup(func() { dialProbe, stagedStale = origDial, origStale })
}

func runCLI(t *testing.T, args ...string) string {
	t.Helper()
	var out strings.Builder
	root := Root()
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.Execute(); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out.String())
	}
	return out.String()
}

func loadTestConfig(t *testing.T, dir string) *config.Config {
	t.Helper()
	cfg, err := config.Load(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestAddChangesThePortOfAnExistingRoute.
//
// Moving a dev server to another port is the most ordinary edit there is, and
// `add` used to answer it with "already routed — remove it first". That made
// the common case two commands and an error message, and the error was the
// only place the second command was named.
func TestAddChangesThePortOfAnExistingRoute(t *testing.T) {
	withStubbedProbes(t)
	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)

	runCLI(t, "add", "app", "3000")
	got := runCLI(t, "add", "app", "3001")

	cfg := loadTestConfig(t, dir)
	if len(cfg.Routes) != 1 {
		t.Fatalf("got %d routes, want 1 — re-adding a name must replace it, not duplicate it: %+v",
			len(cfg.Routes), cfg.Routes)
	}
	if cfg.Routes[0].UpstreamAddr() != "localhost:3001" {
		t.Errorf("route points at %s, want localhost:3001", cfg.Routes[0].UpstreamAddr())
	}
	if !strings.Contains(got, "localhost:3001") {
		t.Errorf("output does not name the new port:\n%s", got)
	}
	if !strings.Contains(got, "was localhost:3000") {
		t.Errorf("output does not say what it replaced, so a mistyped port looks like a "+
			"fresh add:\n%s", got)
	}
}

// TestAddSaysNothingChangedWhenRepeatedVerbatim: running the same `add` twice
// is usually someone checking what a name points at. Reporting a change that
// did not happen teaches them the output cannot be trusted.
func TestAddSaysNothingChangedWhenRepeatedVerbatim(t *testing.T) {
	withStubbedProbes(t)
	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)

	runCLI(t, "add", "app", "3000")
	got := runCLI(t, "add", "app", "3000")

	if !strings.Contains(got, "unchanged") {
		t.Errorf("re-adding the same route should say nothing changed:\n%s", got)
	}
	if strings.Contains(got, "was ") {
		t.Errorf("re-adding the same route reported a replacement that did not happen:\n%s", got)
	}
	if cfg := loadTestConfig(t, dir); len(cfg.Routes) != 1 {
		t.Errorf("got %d routes, want 1", len(cfg.Routes))
	}
}

// TestAddStillRoutesANewName guards the case the replace path could break: a
// name that does not exist yet must still be appended, not swallowed.
func TestAddStillRoutesANewName(t *testing.T) {
	withStubbedProbes(t)
	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)

	runCLI(t, "add", "app", "3000")
	runCLI(t, "add", "api", "4000")

	cfg := loadTestConfig(t, dir)
	if len(cfg.Routes) != 2 {
		t.Fatalf("got %d routes, want 2: %+v", len(cfg.Routes), cfg.Routes)
	}
}

// TestStatusReportsWhatIsServingNotJustWhatLaunchdThinks.
//
// Under the privileged parent the supervisor stays alive across every child
// restart, so a daemon crash-looping on an unreadable config leaves the
// launchd job `running` for as long as it keeps failing. Observed for 90
// seconds straight while nothing was served. `status` is the command people
// run to answer "is it working", so it has to ask the port, not the job.
func TestStatusReportsWhatIsServingNotJustWhatLaunchdThinks(t *testing.T) {
	withStubbedProbes(t)
	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)

	origStatus := serviceStatus
	serviceStatus = func() (service.State, string, error) {
		return service.Running, "/Library/LaunchDaemons/test.plist", nil
	}
	t.Cleanup(func() { serviceStatus = origStatus })

	// dialProbe already returns false from withStubbedProbes: the job is up,
	// nothing is listening.
	got := runCLI(t, "daemon", "status")

	if !strings.Contains(got, "nothing is listening") {
		t.Errorf("status said the job was running without saying nothing was served:\n%s", got)
	}
	if !strings.Contains(got, "switchboard daemon logs") {
		t.Errorf("status reported a broken daemon without naming the command that "+
			"explains why:\n%s", got)
	}
}

// TestStatusSaysServingWhenItIs is the other half: the probe must not cry
// wolf on a healthy machine, or people learn to ignore it.
func TestStatusSaysServingWhenItIs(t *testing.T) {
	withStubbedProbes(t)
	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)

	origStatus, origDial := serviceStatus, dialProbe
	serviceStatus = func() (service.State, string, error) {
		return service.Running, "/Library/LaunchDaemons/test.plist", nil
	}
	dialProbe = func(string) bool { return true }
	t.Cleanup(func() { serviceStatus, dialProbe = origStatus, origDial })

	got := runCLI(t, "daemon", "status")

	if strings.Contains(got, "nothing is listening") {
		t.Errorf("status reported a healthy daemon as broken:\n%s", got)
	}
	if !strings.Contains(got, "serving:") {
		t.Errorf("status never says what is being served:\n%s", got)
	}
}

// TestStaleServiceNoticeReachesEverydayCommands.
//
// `brew upgrade` replaces the binary on PATH and cannot touch the root-owned
// staged copy, so the two drift on every upgrade. doctor has always said so,
// but nobody runs doctor after an upgrade: they upgrade to get a fix, hit the
// same bug against the old daemon, and conclude the fix did not work.
func TestStaleServiceNoticeReachesEverydayCommands(t *testing.T) {
	withStubbedProbes(t)
	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.toml"),
		[]byte("suffix = \"test\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	origStale := stagedStale
	stagedStale = func() (bool, bool) { return true, true }
	t.Cleanup(func() { stagedStale = origStale })

	for _, args := range [][]string{{"ls"}, {"add", "app", "3000"}, {"rm", "app"}} {
		got := runCLI(t, args...)
		if !strings.Contains(got, "daemon install") {
			t.Errorf("`switchboard %s` said nothing about the stale service:\n%s",
				strings.Join(args, " "), got)
		}
	}
}

// TestNoStaleNoticeWhenCurrent: the notice repeats on every command until the
// service is reinstalled, so a false one is worse than none.
func TestNoStaleNoticeWhenCurrent(t *testing.T) {
	withStubbedProbes(t)
	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)

	origStale := stagedStale
	stagedStale = func() (bool, bool) { return false, true }
	t.Cleanup(func() { stagedStale = origStale })

	if got := runCLI(t, "ls"); strings.Contains(got, "older build") {
		t.Errorf("a current service was reported as stale:\n%s", got)
	}
}
