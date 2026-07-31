package service

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
)

// TestDefaultSpecAbsolutizesConfigPath is the regression test for a silent
// failure. launchd runs jobs with a working directory of `/`, so a plist
// saying `--config ./dev.toml` makes the agent look for `/dev.toml` — and
// config.Load treats a missing file as "use defaults" rather than an error,
// so the daemon comes up perfectly healthy serving zero routes on the
// default suffix, and nothing anywhere reports a problem. Absolutizing at
// spec-build time is the only place this can be caught.
func TestDefaultSpecAbsolutizesConfigPath(t *testing.T) {
	t.Setenv("SWITCHBOARD_DIR", t.TempDir())

	spec, err := DefaultSpec(config.Default(), "./dev.toml")
	if err != nil {
		t.Fatal(err)
	}

	if !filepath.IsAbs(spec.ConfigPath) {
		t.Errorf("Spec.ConfigPath = %q, want an absolute path", spec.ConfigPath)
	}
	// And the absolute form is what actually reaches the plist, not just the
	// bookkeeping field.
	idx := -1
	for i, a := range spec.Args {
		if a == "--config" {
			idx = i
			break
		}
	}
	if idx < 0 || idx+1 >= len(spec.Args) {
		t.Fatalf("Args should carry --config <path>, got %v", spec.Args)
	}
	baked := spec.Args[idx+1]
	if !filepath.IsAbs(baked) {
		t.Errorf("--config argument = %q, want an absolute path (launchd's cwd is /)", baked)
	}
	if baked != spec.ConfigPath {
		t.Errorf("--config argument %q disagrees with Spec.ConfigPath %q", baked, spec.ConfigPath)
	}
	if !strings.HasSuffix(baked, "dev.toml") {
		t.Errorf("--config argument %q should still name dev.toml", baked)
	}
}

// TestDefaultSpecAbsolutizesLogPath covers the same hazard on the other
// path in the plist. SWITCHBOARD_DIR is read verbatim from the environment,
// so `SWITCHBOARD_DIR=.sb switchboard daemon install` would otherwise write
// StandardOutPath=".sb/logs/daemon.log" — which launchd resolves against /,
// cannot create, and which silently costs you every log line the daemon
// writes.
func TestDefaultSpecAbsolutizesLogPath(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SWITCHBOARD_DIR", "relative-dir")

	spec, err := DefaultSpec(config.Default(), "")
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"StdoutPath": spec.StdoutPath,
		"StderrPath": spec.StderrPath,
		"ConfigPath": spec.ConfigPath,
	} {
		if !filepath.IsAbs(p) {
			t.Errorf("Spec.%s = %q, want an absolute path", name, p)
		}
	}
}

// TestDefaultSpecOmitsConfigFlagByDefault: with no --config given, the agent
// should resolve the default location itself at startup rather than have one
// frozen into the plist. ConfigPath is still populated, because the
// privileged-port refusal message has to name a file either way.
func TestDefaultSpecOmitsConfigFlagByDefault(t *testing.T) {
	t.Setenv("SWITCHBOARD_DIR", t.TempDir())

	spec, err := DefaultSpec(config.Default(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range spec.Args {
		if a == "--config" {
			t.Errorf("Args should not bake in a --config for the default location, got %v", spec.Args)
		}
	}
	if spec.ConfigPath == "" {
		t.Error("ConfigPath should still be populated for error messages")
	}
}

// TestDefaultSpecCarriesConfiguredPorts: the ports Install guards must come
// from the user's config, not from the defaults, or setting https_port would
// not actually lift the refusal.
func TestDefaultSpecCarriesConfiguredPorts(t *testing.T) {
	t.Setenv("SWITCHBOARD_DIR", t.TempDir())

	spec, err := DefaultSpec(&config.Config{Suffix: "test", HTTPPort: 8080, HTTPSPort: 8443}, "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range spec.Ports {
		got[p.Name] = p.Addr
	}
	if got["https"] != "127.0.0.1:8443" {
		t.Errorf("https port = %q, want 127.0.0.1:8443", got["https"])
	}
	if got["http"] != "127.0.0.1:8080" {
		t.Errorf("http port = %q, want 127.0.0.1:8080", got["http"])
	}
}

// TestDefaultSpecGuardsEveryConfigurableListener pins the production wiring
// the guard depends on. checkPrivilegedPorts only inspects Spec.Ports, so a
// listener missing from that slice is silently unguarded — and the guard's
// whole purpose is to stop `daemon install` from installing a crash-loop.
//
// The first version listed only http and https, reasoning that they are the
// two defaulting below 1024. But every one of these ports is user-settable,
// and `dns_port = 53` produces exactly the crash-loop `https_port = 443`
// does. The defaults are not the threat model; the config file is.
func TestDefaultSpecGuardsEveryConfigurableListener(t *testing.T) {
	t.Setenv("SWITCHBOARD_DIR", t.TempDir())

	cfg := config.Default()
	spec, err := DefaultSpec(cfg, "")
	if err != nil {
		t.Fatal(err)
	}

	// The four listeners internal/daemon actually binds. A fifth added there
	// without being added here would ship unguarded; that is what this catches.
	want := map[string]int{
		"https":     cfg.EffHTTPSPort(),
		"http":      cfg.EffHTTPPort(),
		"DNS":       cfg.EffDNSPort(),
		"dashboard": cfg.EffDashboardPort(),
	}

	got := make(map[string]GuardedPort, len(spec.Ports))
	for _, p := range spec.Ports {
		got[p.Name] = p
	}

	for name, port := range want {
		p, ok := got[name]
		if !ok {
			t.Errorf("listener %q is not guarded — `daemon install` would install "+
				"an agent that cannot bind it", name)
			continue
		}
		if suffix := ":" + strconv.Itoa(port); !strings.HasSuffix(p.Addr, suffix) {
			t.Errorf("guarded port %q has addr %q, want it to end in %q", name, p.Addr, suffix)
		}
		// A refusal naming the wrong config key is worse than none: it sends
		// the user to edit a setting unrelated to the error they are reading.
		if p.Remedy == "" {
			t.Errorf("guarded port %q has no remedy, so a refusal cannot tell the "+
				"user which setting to change", name)
		}
	}

	if len(spec.Ports) != len(want) {
		t.Errorf("got %d guarded ports, want %d — a listener was added or removed "+
			"without updating this test", len(spec.Ports), len(want))
	}
}

// TestDNSGuardProbesUDP is separate because getting it wrong is invisible: a
// tcp probe of the DNS port succeeds on a machine where the udp bind would
// fail, so the guard passes and the agent still crash-loops.
func TestDNSGuardProbesUDP(t *testing.T) {
	t.Setenv("SWITCHBOARD_DIR", t.TempDir())

	spec, err := DefaultSpec(config.Default(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range spec.Ports {
		if p.Name == "DNS" && p.Network != "udp" {
			t.Errorf("DNS guard probes %q; the responder binds udp, so a tcp probe "+
				"would pass while the real bind fails", p.Network)
		}
	}
}
