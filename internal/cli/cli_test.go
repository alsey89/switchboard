package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
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
