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

func TestValidateRejectsFootgunTLDs(t *testing.T) {
	for _, tld := range []string{"local", "dev"} {
		c := &Config{TLD: tld}
		if err := c.Validate(); err == nil {
			t.Errorf("tld %q should be rejected", tld)
		}
	}
}

func TestValidateRoutes(t *testing.T) {
	c := &Config{TLD: "test", Routes: []Route{
		{Domain: "app.test", Port: 3000},
		{Domain: "api.test", Upstream: "127.0.0.1:8080"},
	}}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	dup := &Config{TLD: "test", Routes: []Route{
		{Domain: "app.test", Port: 3000},
		{Domain: "APP.test", Port: 3001},
	}}
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate domains should be rejected, got %v", err)
	}

	both := &Config{TLD: "test", Routes: []Route{{Domain: "a.test", Port: 1, Upstream: "x:1"}}}
	if err := both.Validate(); err == nil {
		t.Error("port+upstream together should be rejected")
	}

	neither := &Config{TLD: "test", Routes: []Route{{Domain: "a.test"}}}
	if err := neither.Validate(); err == nil {
		t.Error("missing port and upstream should be rejected")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	c := &Config{TLD: "test", Routes: []Route{
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
	if got.TLD != DefaultTLD || len(got.Routes) != 0 {
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
