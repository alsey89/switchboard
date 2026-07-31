package privileged

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/listen"
)

// TestPortsAreFixed pins what root is allowed to bind. This is the single
// most important invariant in the package: the moment these come from the
// user's config, a hostile config file turns the parent into "root will bind
// whatever port you name" — it takes an unclaimed privileged port (631, 88,
// 548) and hands the descriptor to a process the attacker controls.
//
// If this test needs changing, the change is a security decision.
func TestPortsAreFixed(t *testing.T) {
	got := Ports()
	want := map[string]int{"https": 443, "http": 80}

	if len(got) != len(want) {
		t.Fatalf("Ports() = %v, want %v", got, want)
	}
	for name, port := range want {
		if got[name] != port {
			t.Errorf("Ports()[%q] = %d, want %d", name, got[name], port)
		}
	}
	// Every name the child knows how to adopt must have a port here, or
	// bindAll fails at runtime with a socket the child then waits for forever.
	for _, name := range listen.Names() {
		if _, ok := got[name]; !ok {
			t.Errorf("listen.Names() includes %q but Ports() has no port for it", name)
		}
	}
}

// TestValidateRefusesRootChild is the guard that keeps the whole design
// honest. Dropping to uid 0 is not dropping privileges; it would run Caddy,
// the TLS stack and the CA as root while every document claims otherwise.
func TestValidateRefusesRootChild(t *testing.T) {
	for _, tc := range []struct {
		name   string
		spec   Spec
		wantIn string
	}{
		{"uid 0", Spec{UID: 0, GID: 20, Exe: "/x", Home: "/h"}, "may hold root"},
		{"gid 0", Spec{UID: 501, GID: 0, Exe: "/x", Home: "/h"}, "may hold root"},
		{"no exe", Spec{UID: 501, GID: 20, Home: "/h"}, "executable"},
		{"no home", Spec{UID: 501, GID: 20, Exe: "/x"}, "home directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.validate()
			if err == nil {
				t.Fatal("validate should have refused")
			}
			// Running the suite as an ordinary user, the not-root check fires
			// first; that is itself a refusal, so only assert the specific
			// message when we got past it.
			if os.Geteuid() == 0 && !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q should mention %q", err, tc.wantIn)
			}
		})
	}
}

// TestValidateRequiresRoot: the parent exists solely to do the one thing an
// ordinary user cannot. Running it unprivileged would bind nothing and then
// exec a child that finds no descriptors.
func TestValidateRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	err := Spec{UID: 501, GID: 20, Exe: "/x", Home: "/h"}.validate()
	if err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("validate as non-root should refuse, got %v", err)
	}
}

// TestChildEnvDropsWhatTheChildMustNotSee.
//
// HOME is the consequential one: leaving root's HOME in place puts the CA
// and config under /var/root, where `switchboard setup` — run as the user —
// will never look, and the daemon then comes up healthy serving nothing.
//
// SUDO_* matters for a subtler reason: setup.Run refuses outright when it
// sees SUDO_USER, so a child that inherited them would break the next
// command the user ran, not this one.
func TestChildEnvDropsWhatTheChildMustNotSee(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"HOME=/var/root",
		"SUDO_USER=alice",
		"SUDO_UID=501",
		"SUDO_GID=20",
		listen.EnvFDs + "=https:9",
		"LANG=en_US.UTF-8",
	}
	got := childEnv(in, "/Users/alice")

	if !slices.Contains(got, "HOME=/Users/alice") {
		t.Errorf("HOME should be the target user's, got %v", got)
	}
	for _, bad := range []string{"HOME=/var/root", "SUDO_USER=alice", "SUDO_UID=501",
		"SUDO_GID=20", listen.EnvFDs + "=https:9"} {
		if slices.Contains(got, bad) {
			t.Errorf("%q should have been stripped from the child environment", bad)
		}
	}
	for _, keep := range []string{"PATH=/usr/bin", "LANG=en_US.UTF-8"} {
		if !slices.Contains(got, keep) {
			t.Errorf("%q should have been passed through", keep)
		}
	}
	// Exactly one HOME, or the child's behaviour depends on which one its
	// libc picks.
	var homes int
	for _, kv := range got {
		if strings.HasPrefix(kv, "HOME=") {
			homes++
		}
	}
	if homes != 1 {
		t.Errorf("child environment has %d HOME entries, want 1", homes)
	}
}

// TestFromSudoRefusesRootAndMissingValues: `sudo switchboard start` is the
// only caller, and every failure here means there is no unprivileged user to
// drop to — which must be an error, never a fallback to running as root.
func TestFromSudoRefusesRootAndMissingValues(t *testing.T) {
	for _, tc := range []struct {
		name           string
		user, uid, gid string
		wantIn         string
	}{
		{"no SUDO_USER", "", "501", "20", "SUDO_USER is not set"},
		{"SUDO_USER is root", "root", "0", "0", "SUDO_USER is not set"},
		{"no SUDO_UID", "alice", "", "20", "SUDO_UID is not set"},
		{"SUDO_UID is 0", "alice", "0", "20", "refusing to run the daemon as root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SUDO_USER", tc.user)
			t.Setenv("SUDO_UID", tc.uid)
			t.Setenv("SUDO_GID", tc.gid)

			_, err := FromSudo()
			if err == nil {
				t.Fatal("FromSudo should have refused")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q should mention %q", err, tc.wantIn)
			}
		})
	}
}

// TestFromFlagsRefusesRoot covers the launchd path, where the identity comes
// from the plist. A plist with --uid 0 must not produce a root daemon.
func TestFromFlagsRefusesRoot(t *testing.T) {
	for _, tc := range []struct{ uid, gid int }{{0, 20}, {501, 0}, {0, 0}, {-1, 20}} {
		if _, err := FromFlags(tc.uid, tc.gid, "/Users/alice"); err == nil {
			t.Errorf("FromFlags(%d, %d) should have refused", tc.uid, tc.gid)
		}
	}
}
