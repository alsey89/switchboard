//go:build darwin

package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/service"
	"github.com/alsey89/switchboard/internal/setup"
)

// TestDaemonLogsRejectsANegativeLineCount.
//
// The count is user-typed; `-n -1` has no meaning here (this is not tail(1),
// where a leading minus is its own syntax). It must come back as an error
// that names the flag — not the unrelated "no service is installed", and not
// the panic it once was.
func TestDaemonLogsRejectsANegativeLineCount(t *testing.T) {
	t.Setenv("SWITCHBOARD_DIR", t.TempDir())
	isolateSystemPathsForCLI(t)

	root := Root()
	root.SetArgs([]string{"daemon", "logs", "-n", "-1"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	if err == nil {
		t.Fatal("a negative -n must be an error")
	}
	if !strings.Contains(err.Error(), "-n") {
		t.Errorf("the error must name the flag at fault, got: %v", err)
	}
}

// TestUninstallSaysTheBinaryIsStillInstalled.
//
// "uninstall" does not mean here what it means for a package manager. This
// command undoes what `setup` and `daemon install` did to the system;
// removing the executable belongs to whatever installed it, and a program
// deleting its own binary would be a poor idea besides.
//
// Left unsaid, the user reads "uninstall ✓", finds the command still on their
// PATH, and has to work out which of the two is lying. That is a real report
// from using it.
func TestUninstallSaysTheBinaryIsStillInstalled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)
	// This drives the real teardown, so every system path it touches has to
	// be redirected first. Without this the test issues `sudo rm` against the
	// machine's own /etc/resolver — it failed here only because
	// non-interactive sudo refuses, which is not a safety mechanism anyone
	// should be relying on.
	isolateSystemPathsForCLI(t)
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("suffix = \"test\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	root := Root()
	root.SetArgs([]string{"uninstall"})
	root.SetOut(&out)
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	if !strings.Contains(got, "still installed") {
		t.Errorf("uninstall must say the binary remains, got:\n%s", got)
	}
	if !strings.Contains(got, "remove it with") {
		t.Errorf("and how to remove it, got:\n%s", got)
	}
	// Nothing was set up, so it must not claim to have removed anything.
	if strings.Contains(got, "system setup removed") {
		t.Errorf("claimed to remove system setup on a machine that had none:\n%s", got)
	}
	if !strings.Contains(got, "nothing to remove") {
		t.Errorf("should say there was nothing to remove, got:\n%s", got)
	}
}

// isolateSystemPathsForCLI redirects every absolute system path the command
// tree can reach, so a test can drive a command end to end without touching
// the machine running it.
func isolateSystemPathsForCLI(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir) // moves the launch-agent plist path

	origResolver := setup.ResolverDir
	origPlist, origStaged := service.SystemPlistPath, service.StagedExecPath
	setup.ResolverDir = filepath.Join(dir, "resolver")
	service.SystemPlistPath = filepath.Join(dir, "LaunchDaemons", "sb.plist")
	service.StagedExecPath = filepath.Join(dir, "PrivilegedHelperTools", "sb")
	t.Cleanup(func() {
		setup.ResolverDir = origResolver
		service.SystemPlistPath, service.StagedExecPath = origPlist, origStaged
	})
}
