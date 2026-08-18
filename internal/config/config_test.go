package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in, tld, want, wantErr string
	}{
		{"app.test", "test", "app.test", ""},
		{"APP.Test.", "test", "app.test", ""},
		{"app", "test", "app.test", ""},              // bare name gets the TLD
		{"api.app.test", "test", "api.app.test", ""}, // nested subdomains fine
		{"app.localhost", "test", "", "must end in"}, // wrong TLD
		{"test", "test", "test.test", ""},            // bare name, even if it equals the TLD
		{".test", "test", "", "needs a label"},       // apex alone
		{"switchboard.test", "test", "", "reserved"}, // dashboard name
		{"bad_label.test", "test", "", "invalid domain label"},
		{"-app.test", "test", "", "invalid domain label"},
		{"", "test", "", "empty"},
		{"app", "dev.example.com", "app.dev.example.com", ""},
		{"api.app.dev.example.com", "dev.example.com", "api.app.dev.example.com", ""},
	}
	for _, c := range cases {
		got, err := NormalizeDomain(c.in, c.tld)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("NormalizeDomain(%q): unexpected error %v", c.in, err)
			} else if got != c.want {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", c.in, got, c.want)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("NormalizeDomain(%q) err = %v, want containing %q", c.in, err, c.wantErr)
		}
	}
}

func TestValidateSuffix(t *testing.T) {
	cases := []struct {
		suffix  string
		wantErr string // substring; "" means valid
	}{
		{"test", ""},
		{"internal", ""},
		{"localhost", ""},
		{"dev.example.com", ""}, // a domain the user owns
		{"home.arpa", ""},       // RFC 8375, multi-label so allowed by the ownership rule
		{"dev", "real gTLD"},
		{"local", "mDNS"},
		{"app", "real gTLD"},
		{"com", "not a reserved name"},
		{"lab", "not a reserved name"},
		{"", "missing suffix"},
		{"bad_label", "bad label"},
		{"-nope", "bad label"},
		{"ok.bad_label", "bad label"},
	}
	for _, c := range cases {
		err := (&Config{Suffix: c.suffix}).Validate()
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("suffix %q: unexpected error %v", c.suffix, err)
		case c.wantErr != "" && err == nil:
			t.Errorf("suffix %q: expected error containing %q, got nil", c.suffix, c.wantErr)
		case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
			t.Errorf("suffix %q: error %q does not contain %q", c.suffix, err, c.wantErr)
		}
	}
}

func TestValidateSuffixErrorsAreActionable(t *testing.T) {
	// A rejection must always name a way forward, or the user is stuck.
	for _, s := range []string{"dev", "local", "com"} {
		err := (&Config{Suffix: s}).Validate()
		if err == nil {
			t.Fatalf("suffix %q should be rejected", s)
		}
		if !strings.Contains(err.Error(), "internal") || !strings.Contains(err.Error(), "dev.example.com") {
			t.Errorf("suffix %q: error should suggest alternatives, got: %v", s, err)
		}
	}
}

func TestValidateRoutes(t *testing.T) {
	c := &Config{Suffix: "test", Routes: []Route{
		{Domain: "app.test", Port: 3000},
		{Domain: "api.test", Upstream: "127.0.0.1:8080"},
	}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	dup := &Config{Suffix: "test", Routes: []Route{
		{Domain: "app.test", Port: 3000},
		{Domain: "APP.test", Port: 3001},
	}}
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate domains should be rejected, got %v", err)
	}

	both := &Config{Suffix: "test", Routes: []Route{{Domain: "a.test", Port: 1, Upstream: "x:1"}}}
	if err := both.Validate(); err == nil {
		t.Error("port+upstream together should be rejected")
	}

	neither := &Config{Suffix: "test", Routes: []Route{{Domain: "a.test"}}}
	if err := neither.Validate(); err == nil {
		t.Error("missing port and upstream should be rejected")
	}
}

// A port outside 1-65535 cannot be bound by anything, so it is caught at
// load time rather than at net.Listen, where the daemon has already started
// tearing itself down. Zero is the field unset and must stay valid.
func TestValidateRejectsImpossiblePorts(t *testing.T) {
	for name, c := range map[string]*Config{
		"http too high":      {Suffix: "test", HTTPPort: 70000},
		"https too high":     {Suffix: "test", HTTPSPort: 65536},
		"dns negative":       {Suffix: "test", DNSPort: -1},
		"dashboard too high": {Suffix: "test", DashboardPort: 99999},
		"dashboard negative": {Suffix: "test", DashboardPort: -8484},
	} {
		t.Run(name, func(t *testing.T) {
			err := c.Validate()
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if !strings.Contains(err.Error(), "out of range") {
				t.Errorf("error should say the port is out of range, got: %v", err)
			}
		})
	}

	// Unset ports and a privileged one both load. The low port is the case
	// worth pinning: the dashboard's PATCH endpoint refuses it, and moving
	// that rule here would make an existing config unreadable.
	for name, c := range map[string]*Config{
		"all unset":          {Suffix: "test"},
		"privileged is fine": {Suffix: "test", DashboardPort: 80, HTTPSPort: 443},
		"top of the range":   {Suffix: "test", DashboardPort: 65535},
	} {
		t.Run(name, func(t *testing.T) {
			if err := c.Validate(); err != nil {
				t.Errorf("valid config rejected: %v", err)
			}
		})
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	c := &Config{Suffix: "test", Routes: []Route{
		{Domain: "app.test", Port: 3000},
		{Domain: "api.test", Upstream: "127.0.0.1:9999"},
	}}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Routes) != 2 || got.Routes[0].Domain != "app.test" || got.Routes[1].Upstream != "127.0.0.1:9999" {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestLoadMissingFileYieldsDefault(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Suffix != DefaultSuffix || len(got.Routes) != 0 {
		t.Errorf("expected default config, got %+v", got)
	}
}

// TestUpstreamAddr pins the difference between the two ways of naming an
// upstream.
//
// The port shorthand must resolve through a name, so the dialer tries both
// IPv4 and IPv6 loopback. It used to hardcode 127.0.0.1, which silently
// produced a dead route for every dev server that binds ::1 only — common
// with Node. The user saw their app working at localhost:3000 and `ls`
// reporting `down`, with nothing connecting the two.
//
// An explicit --upstream is passed through untouched: naming an address is
// how you say you meant that address and not the other one.
func TestUpstreamAddr(t *testing.T) {
	if a := (&Route{Port: 3000}).UpstreamAddr(); a != "localhost:3000" {
		t.Errorf("shorthand = %s, want localhost:3000 — an address pins one "+
			"family and misses servers bound to the other", a)
	}
	if a := (&Route{Upstream: "192.168.1.5:80"}).UpstreamAddr(); a != "192.168.1.5:80" {
		t.Errorf("explicit upstream = %s, want it unchanged", a)
	}
	if a := (&Route{Upstream: "[::1]:3000"}).UpstreamAddr(); a != "[::1]:3000" {
		t.Errorf("explicit IPv6 upstream = %s, want it unchanged", a)
	}
}

// TestSetRouteReplacesRatherThanDuplicating.
//
// A domain resolves to exactly one upstream, so two routes for the same name
// is not a state the proxy can act on. Appending blindly would produce it,
// and which one won would depend on iteration order.
func TestSetRouteReplacesRatherThanDuplicating(t *testing.T) {
	c := &Config{Routes: []Route{
		{Domain: "app.test", Port: 3000},
		{Domain: "api.test", Port: 4000},
	}}

	prev, replaced := c.SetRoute(Route{Domain: "app.test", Port: 3001})

	if !replaced {
		t.Fatal("SetRoute did not report replacing the existing route")
	}
	if prev.Port != 3000 {
		t.Errorf("previous.Port = %d, want 3000 — the caller needs this to say what changed", prev.Port)
	}
	if len(c.Routes) != 2 {
		t.Fatalf("got %d routes, want 2: %+v", len(c.Routes), c.Routes)
	}
	got, _ := c.FindRoute("app.test")
	if got.Port != 3001 {
		t.Errorf("app.test still points at %d", got.Port)
	}
	if other, _ := c.FindRoute("api.test"); other.Port != 4000 {
		t.Errorf("replacing one route disturbed another: api.test = %d", other.Port)
	}
}

// TestSetRouteAppendsANewDomain: the replace path must not swallow names that
// do not exist yet.
func TestSetRouteAppendsANewDomain(t *testing.T) {
	c := &Config{Routes: []Route{{Domain: "app.test", Port: 3000}}}

	prev, replaced := c.SetRoute(Route{Domain: "api.test", Port: 4000})

	if replaced {
		t.Errorf("SetRoute reported replacing a route that did not exist (previous: %+v)", prev)
	}
	if len(c.Routes) != 2 {
		t.Fatalf("got %d routes, want 2: %+v", len(c.Routes), c.Routes)
	}
}

// TestSetRouteChangesTheUpstreamKind covers switching a route between a local
// port and an --upstream host:port. Replacing the struct wholesale is what
// makes this work; merging fields would leave the old Port set and the route
// pointing somewhere neither value describes.
func TestSetRouteChangesTheUpstreamKind(t *testing.T) {
	c := &Config{Routes: []Route{{Domain: "app.test", Port: 3000}}}

	c.SetRoute(Route{Domain: "app.test", Upstream: "192.168.1.5:8080"})

	got, _ := c.FindRoute("app.test")
	if got.Port != 0 {
		t.Errorf("Port survived the switch to --upstream (%d); the route now has two "+
			"sources of truth", got.Port)
	}
	if got.UpstreamAddr() != "192.168.1.5:8080" {
		t.Errorf("UpstreamAddr() = %q, want 192.168.1.5:8080", got.UpstreamAddr())
	}
}

func TestInspectDefaults(t *testing.T) {
	c := Default()
	if !c.InspectEnabled() {
		t.Error("metadata capture should default to on")
	}
	if c.InspectBodies() {
		t.Error("bodies must default to off")
	}
	if got := c.InspectMaxRequests(); got != DefaultInspectMaxRequests {
		t.Errorf("max_requests = %d, want %d", got, DefaultInspectMaxRequests)
	}
	if got := c.InspectMaxBytes(); got != DefaultInspectMaxBytes {
		t.Errorf("max_bytes = %d, want %d", got, DefaultInspectMaxBytes)
	}
	if got := c.InspectMaxBodyBytes(); got != DefaultInspectMaxBodyBytes {
		t.Errorf("max_body_bytes = %d, want %d", got, DefaultInspectMaxBodyBytes)
	}
	if got := c.InspectMaxAge(); got != DefaultInspectMaxAge {
		t.Errorf("max_age = %s, want %s", got, DefaultInspectMaxAge)
	}
}

func TestInspectExplicitlyDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "suffix = \"test\"\n\n[inspect]\nenabled = false\nbodies = true\nmax_requests = 10\nmax_age = \"1h\"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.InspectEnabled() {
		t.Error("enabled = false must survive the load")
	}
	if !c.InspectBodies() {
		t.Error("bodies = true must survive the load")
	}
	if got := c.InspectMaxRequests(); got != 10 {
		t.Errorf("max_requests = %d, want 10", got)
	}
	if got := c.InspectMaxAge(); got != time.Hour {
		t.Errorf("max_age = %s, want 1h", got)
	}
}

func TestInspectRejectsBadSettings(t *testing.T) {
	cases := map[string]string{
		"unparseable age": "max_age = \"soon\"",
		"negative rows":   "max_requests = -1",
		"negative bytes":  "max_bytes = -1",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			body := "suffix = \"test\"\n\n[inspect]\n" + line + "\n"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestVersionChangesWithContent(t *testing.T) {
	a := Version([]byte("suffix = \"test\"\n"))
	b := Version([]byte("suffix = \"test\"\n\n"))
	if a == b {
		t.Fatal("different bytes produced the same version")
	}
	if a != Version([]byte("suffix = \"test\"\n")) {
		t.Fatal("the same bytes produced different versions")
	}
	if len(a) != 16 {
		t.Fatalf("version is %d chars, want 16", len(a))
	}
}

func TestLoadWithVersionMatchesLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "suffix = \"test\"\n\n[[routes]]\ndomain = \"app.test\"\nport = 3000\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, version, err := LoadWithVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if version != Version([]byte(body)) {
		t.Fatalf("version %q does not match the file bytes", version)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Domain != "app.test" {
		t.Fatalf("config did not load: %+v", cfg)
	}

	// Load must stay exactly equivalent. It is called from the daemon, the
	// CLI and doctor, and this refactor must not change any of them.
	plain, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Routes) != len(cfg.Routes) || plain.Suffix != cfg.Suffix {
		t.Fatalf("Load and LoadWithVersion disagree: %+v vs %+v", plain, cfg)
	}
}

// A missing file is not an error. It yields defaults and an empty version,
// so a first write from a fresh install sends "" and matches.
func TestLoadWithVersionMissingFile(t *testing.T) {
	cfg, version, err := LoadWithVersion(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatalf("a missing file should not error: %v", err)
	}
	if version != "" {
		t.Fatalf("version %q, want empty for a missing file", version)
	}
	if cfg.Suffix != DefaultSuffix {
		t.Fatalf("suffix %q, want the default", cfg.Suffix)
	}
}

func TestLoadWithVersionRejectsBrokenToml(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("this is not toml {{{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWithVersion(path); err == nil {
		t.Fatal("expected a parse error")
	}
}
