package config

import (
	"path/filepath"
	"strings"
	"testing"
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

func TestUpstreamAddr(t *testing.T) {
	if a := (&Route{Port: 3000}).UpstreamAddr(); a != "127.0.0.1:3000" {
		t.Errorf("got %s", a)
	}
	if a := (&Route{Upstream: "192.168.1.5:80"}).UpstreamAddr(); a != "192.168.1.5:80" {
		t.Errorf("got %s", a)
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
