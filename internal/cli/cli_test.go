package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/service"
	"github.com/alsey89/switchboard/internal/setup"
)

// TestRetargetRoutesMovesEveryRouteToTheNewSuffix.
//
// Changing the suffix by hand and leaving the routes behind makes the config
// unloadable — which takes `add`, `ls` and `doctor` down with it, exactly
// when they would be most useful. Migrating the routes is the whole reason
// this is a command rather than a config edit.
func TestRetargetRoutesMovesEveryRouteToTheNewSuffix(t *testing.T) {
	cfg := &config.Config{
		Suffix: "test",
		Routes: []config.Route{
			{Domain: "app.test", Port: 3000},
			{Domain: "api.staging.test", Port: 4000},
			{Domain: "switchboard.test", Port: 8484},
		},
	}

	if n := retargetRoutes(cfg, "test", "internal"); n != 3 {
		t.Errorf("migrated %d routes, want 3", n)
	}
	want := []string{"app.internal", "api.staging.internal", "switchboard.internal"}
	for i, w := range want {
		if cfg.Routes[i].Domain != w {
			t.Errorf("route %d = %q, want %q", i, cfg.Routes[i].Domain, w)
		}
	}
}

// TestRetargetRoutesLeavesForeignDomainsAlone: a domain that does not end in
// the old suffix is not ours to reinterpret. Rewriting it would silently
// repoint a route the user wrote deliberately; leaving it lets Validate
// reject it by name, which is a question the user can answer.
func TestRetargetRoutesLeavesForeignDomainsAlone(t *testing.T) {
	cfg := &config.Config{
		Suffix: "test",
		Routes: []config.Route{
			{Domain: "app.test", Port: 3000},
			{Domain: "weird.example.com", Port: 4000},
		},
	}

	if n := retargetRoutes(cfg, "test", "internal"); n != 1 {
		t.Errorf("migrated %d routes, want 1", n)
	}
	if cfg.Routes[1].Domain != "weird.example.com" {
		t.Errorf("a domain outside the old suffix was rewritten to %q", cfg.Routes[1].Domain)
	}
}

// TestRetargetRoutesDoesNotMatchOnASubstring: "attest" ends in the letters
// "test" but is not a subdomain of it. Trimming a bare suffix rather than a
// dotted one would mangle it into "at" + the new suffix.
func TestRetargetRoutesDoesNotMatchOnASubstring(t *testing.T) {
	cfg := &config.Config{
		Suffix: "test",
		Routes: []config.Route{{Domain: "attest", Port: 3000}},
	}

	retargetRoutes(cfg, "test", "internal")
	if cfg.Routes[0].Domain != "attest" {
		t.Errorf("mangled a domain that merely ends in the same letters: %q", cfg.Routes[0].Domain)
	}
}

// TestLoadLenientReadsAConfigLoadWouldReject is what makes the repair
// possible at all: once the suffix is edited by hand, the strict loader fails
// and the command that fixes it cannot be the one that refuses to read it.
func TestLoadLenientReadsAConfigLoadWouldReject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	// Suffix changed, routes left behind — the exact broken state.
	if err := os.WriteFile(path, []byte(
		"suffix = \"internal\"\n\n[[routes]]\n  domain = \"app.test\"\n  port = 3000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := config.Load(path); err == nil {
		t.Fatal("strict Load should reject routes that do not match the suffix")
	} else if !strings.Contains(err.Error(), "switchboard suffix") {
		t.Errorf("the strict error should name the command that migrates routes, got: %v", err)
	}

	cfg, err := config.LoadLenient(path)
	if err != nil {
		t.Fatalf("LoadLenient must read what Load rejects: %v", err)
	}
	if cfg.Suffix != "internal" || len(cfg.Routes) != 1 {
		t.Errorf("LoadLenient returned %+v", cfg)
	}
}

// TestLoadLenientStillRejectsABadSuffix: leniency is about routes only. A
// suffix that would hijack a real namespace must not slip through the one
// loader that skips checks.
func TestLoadLenientStillRejectsABadSuffix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("suffix = \"dev\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadLenient(path); err == nil {
		t.Error("LoadLenient accepted .dev, a real gTLD — hijacking it in the OS " +
			"resolver breaks go.dev and web.dev machine-wide")
	}
}

// TestSuffixWarnsAboutAuthorizationBeforeAsking.
//
// The keychain prompt is a separate window macOS may open behind whatever is
// in front. Someone who confirms and looks away sees nothing happen and
// reasonably concludes the command hung — and an unannounced password prompt
// is the exact shape of the thing people are taught to cancel. Saying it is
// coming, before asking them to commit, costs two lines.
func TestSuffixWarnsAboutAuthorizationBeforeAsking(t *testing.T) {
	if len(setup.AuthNotice()) == 0 {
		t.Skip("this platform elevates nothing during setup")
	}

	dir := t.TempDir()
	t.Setenv("SWITCHBOARD_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.toml"),
		[]byte("suffix = \"test\"\n\n[[routes]]\n  domain = \"app.test\"\n  port = 3000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	root := Root()
	root.SetArgs([]string{"suffix", "internal"})
	root.SetOut(&out)
	root.SetIn(strings.NewReader("n\n")) // decline
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	warnAt := strings.Index(got, "asked to authorize")
	askAt := strings.Index(got, "continue?")
	if warnAt < 0 {
		t.Fatalf("the confirmation never mentions that authorization is coming:\n%s", got)
	}
	if askAt < 0 {
		t.Fatalf("no confirmation prompt:\n%s", got)
	}
	if warnAt > askAt {
		t.Error("the warning comes after the question; by then they have already committed")
	}
	if !strings.Contains(got, "behind other windows") {
		t.Errorf("the notice should say the dialog can open behind other windows — "+
			"that is the part that makes it look hung. Got:\n%s", got)
	}
	// Touch ID is only armed while that dialog has focus. Without this, the
	// prompt looks like it is refusing fingerprint for some reason of its
	// own — which is exactly the wrong conclusion, and one that was drawn
	// and written down before someone noticed the window was behind another.
	if !strings.Contains(got, "Touch ID will not respond") {
		t.Errorf("the notice should say Touch ID needs the window focused. Not that it "+
			"is unavailable — the fingerprint icon is shown either way, it just does "+
			"nothing unfocused. Got:\n%s", got)
	}
	// Declining must change nothing.
	if !strings.Contains(got, "aborted") {
		t.Errorf("declining should abort, got:\n%s", got)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "app.test") {
		t.Error("the config was rewritten despite the user declining")
	}
}

// TestDaemonInstallWarnsOnlyWhenItWillElevate.
//
// The launch daemon needs sudo; a user agent needs nothing at all. Announcing
// a prompt that never arrives is its own small harm — it teaches people to
// expect one, which is exactly the habit that makes an unexpected prompt
// elsewhere look normal.
func TestDaemonInstallWarnsOnlyWhenItWillElevate(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{"stock ports need the parent", config.Default(), true},
		{"high ports need nothing",
			&config.Config{Suffix: "test", HTTPPort: 8080, HTTPSPort: 8443}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SWITCHBOARD_DIR", t.TempDir())
			spec, err := service.DefaultSpec(tc.cfg, "")
			if err != nil {
				t.Fatal(err)
			}
			elevates := spec.Mode == service.ModeDaemon
			if elevates != tc.want {
				t.Errorf("Mode elevates = %v, want %v — the warning is keyed off this",
					elevates, tc.want)
			}
		})
	}
}

// TestRemoveBinaryHintMatchesTheInstaller: telling a Homebrew user to `rm`
// the binary leaves brew believing the cask is still installed, and the next
// `brew upgrade` puts it back. Getting this wrong is worse than omitting it.
func TestRemoveBinaryHintMatchesTheInstaller(t *testing.T) {
	for _, tc := range []struct{ exe, want string }{
		{"/opt/homebrew/bin/switchboard", "brew uninstall"},
		{"/usr/local/Homebrew/bin/switchboard", "brew uninstall"},
		{"/opt/homebrew/Caskroom/switchboard/0.1.0/switchboard", "brew uninstall"},
		{"/usr/local/bin/switchboard", "sudo rm /usr/local/bin/switchboard"},
		{"/Users/me/go/bin/switchboard", "sudo rm /Users/me/go/bin/switchboard"},
	} {
		if got := removeBinaryHint(tc.exe); !strings.Contains(got, tc.want) {
			t.Errorf("removeBinaryHint(%q) = %q, want it to contain %q", tc.exe, got, tc.want)
		}
	}
}
