package doctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/setup"
)

// TestResolverCheckAcceptsExactlyWhatSetupWrites.
//
// The check used to look for its own hand-written substrings
// ("nameserver 127.0.0.1" and "port <n>") rather than asking the package that
// writes the file what it writes. Two copies of one fact drift apart in
// silence and in both directions: a doctor looking for a directive setup no
// longer emits condemns a working machine, and one that has stopped looking
// for a directive setup still needs passes a machine where nothing resolves.
//
// So the fixture comes from setup.ResolverFileContents. Change that function
// and this test follows it; change only the check and this test fails.
func TestResolverCheckAcceptsExactlyWhatSetupWrites(t *testing.T) {
	isolateOSPaths(t)
	cfg := config.Default()

	if err := os.MkdirAll(setup.ResolverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(setup.ResolverDir, cfg.Suffix)
	if err := os.WriteFile(path, []byte(setup.ResolverFileContents(cfg.EffDNSPort())), 0o644); err != nil {
		t.Fatal(err)
	}

	c, ok := findCheck(osChecks(cfg, filepath.Join(t.TempDir(), "root.crt")), "resolver")
	if !ok {
		t.Fatal("no resolver check")
	}
	if c.Status != OK {
		t.Errorf("the file setup writes must satisfy the check doctor makes; got %v: %s",
			c.Status, c.Detail)
	}
}

// TestResolverCheckCatchesAStalePort: the check must still fail when the file
// names a port the daemon is not listening on — the case it exists for, which
// happens whenever dns_port is edited without re-running setup.
func TestResolverCheckCatchesAStalePort(t *testing.T) {
	isolateOSPaths(t)
	cfg := config.Default()

	if err := os.MkdirAll(setup.ResolverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(setup.ResolverDir, cfg.Suffix)
	stale := setup.ResolverFileContents(cfg.EffDNSPort() + 1)
	if err := os.WriteFile(path, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	c, ok := findCheck(osChecks(cfg, filepath.Join(t.TempDir(), "root.crt")), "resolver")
	if !ok {
		t.Fatal("no resolver check")
	}
	if c.Status != Fail {
		t.Errorf("a resolver file naming the wrong port must fail; got %v: %s", c.Status, c.Detail)
	}
}

// TestResolverCheckCatchesAPrefixPort: the wanted port must match a whole
// line, not a substring of one. "port 5353" is a prefix of "port 53535" — the
// default — so someone who sets dns_port = 5353 and forgets to re-run setup
// has a resolver file routing DNS to a port nothing listens on, and a
// substring check reports that machine healthy. TestResolverCheckCatchesAStalePort
// misses this because port+1 does not prefix-collide.
func TestResolverCheckCatchesAPrefixPort(t *testing.T) {
	isolateOSPaths(t)
	cfg := config.Default()
	cfg.DNSPort = 5353

	if err := os.MkdirAll(setup.ResolverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(setup.ResolverDir, cfg.Suffix)
	stale := setup.ResolverFileContents(config.DefaultDNSPort)
	if err := os.WriteFile(path, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	c, ok := findCheck(osChecks(cfg, filepath.Join(t.TempDir(), "root.crt")), "resolver")
	if !ok {
		t.Fatal("no resolver check")
	}
	if c.Status != Fail {
		t.Errorf("a resolver file naming port %d must fail a config wanting %d; got %v: %s",
			config.DefaultDNSPort, cfg.EffDNSPort(), c.Status, c.Detail)
	}
}

// TestResolverCheckMissingFile is the state before `setup` has ever run.
func TestResolverCheckMissingFile(t *testing.T) {
	isolateOSPaths(t)
	c, ok := findCheck(osChecks(config.Default(), filepath.Join(t.TempDir(), "root.crt")), "resolver")
	if !ok {
		t.Fatal("no resolver check")
	}
	if c.Status != Fail {
		t.Errorf("a missing resolver file must fail; got %v", c.Status)
	}
	if c.Hint == "" {
		t.Error("the check must name the fix")
	}
}
