package listen

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

// handover binds a socket, hands the descriptor over the way a privileged
// parent would (dup, then close the original), and returns the address.
func handover(t *testing.T, name string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	f, err := ln.(*net.TCPListener).File() // dups the descriptor
	if err != nil {
		t.Fatal(err)
	}
	// Closing the original is what makes this a real handover rather than a
	// test that would pass even if FromEnv ignored the descriptor entirely:
	// from here on, the socket exists only through the passed fd.
	ln.Close() //nolint:errcheck

	t.Setenv(EnvFDs, name+":"+strconv.Itoa(int(f.Fd())))
	return addr
}

// TestFromEnvAdoptsAPassedSocket is the core of the privileged handover: the
// child must end up serving on a socket it never bound.
func TestFromEnvAdoptsAPassedSocket(t *testing.T) {
	addr := handover(t, HTTPS)

	set, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !set.Any() || !set.Inherited(HTTPS) {
		t.Fatal("the passed socket was not adopted")
	}
	if got := set.Addr(HTTPS); got != addr {
		t.Errorf("inherited address = %q, want %q", got, addr)
	}

	ln, err := set.Listen(HTTPS, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck

	// It must be the *same* socket, not a new one on a different port —
	// Listen falling through to net.Listen would also return a working
	// listener, which is exactly the bug this asserts against.
	if ln.Addr().String() != addr {
		t.Fatalf("Listen returned a fresh socket on %s; the inherited one on %s was dropped",
			ln.Addr(), addr)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		c.Close() //nolint:errcheck
	}()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("the inherited socket is not accepting: %v", err)
	}
	c.Close() //nolint:errcheck
	<-done
}

// TestFromEnvClearsTheVariable: anything the daemon spawns must not inherit
// a descriptor map describing fds that mean nothing in its address space.
func TestFromEnvClearsTheVariable(t *testing.T) {
	handover(t, HTTPS)
	if _, err := FromEnv(); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv(EnvFDs); v != "" {
		t.Errorf("%s survived FromEnv as %q; a child process would try to adopt "+
			"descriptors that are not open in it", EnvFDs, v)
	}
}

// TestFromEnvWithoutTheVariableIsNotAnError: running unprivileged is a
// supported mode, so an absent variable must produce an empty Set rather
// than a failure.
func TestFromEnvWithoutTheVariableIsNotAnError(t *testing.T) {
	t.Setenv(EnvFDs, "")

	set, err := FromEnv()
	if err != nil {
		t.Fatalf("an unprivileged start must not be an error: %v", err)
	}
	if set.Any() {
		t.Error("Set should be empty")
	}
	if set.Inherited(HTTPS) || set.Addr(HTTPS) != "" {
		t.Error("nothing should be reported as inherited")
	}

	// And Listen must fall through to binding normally.
	ln, err := set.Listen(HTTPS, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() //nolint:errcheck
}

func TestFromEnvRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct{ name, spec, wantIn string }{
		{"no colon", "https", "name:fd"},
		{"non-numeric fd", "https:abc", "non-numeric"},
		{"unknown socket name", "gopher:3", "not a socket this daemon accepts"},
		{"not a listening socket", "https:0", "not a listening socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvFDs, tc.spec)
			_, err := FromEnv()
			if err == nil {
				t.Fatalf("FromEnv(%q) should fail", tc.spec)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q should mention %q", err, tc.wantIn)
			}
		})
	}
}

// TestKeepOpenSurvivesClose guards the failure that would be worst in
// production and silent in development: Caddy closes its listeners on every
// config reload, and a closed inherited socket can never be rebound by an
// unprivileged process. The first config edit would take :443 down for good.
func TestKeepOpenSurvivesClose(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close() //nolint:errcheck
	addr := raw.Addr().String()

	wrapped := KeepOpen(raw)
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close should be a no-op, got %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := wrapped.Accept()
		if err != nil {
			t.Errorf("the socket did not survive Close: %v", err)
			return
		}
		c.Close() //nolint:errcheck
	}()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialing after Close failed — the descriptor was really closed: %v", err)
	}
	c.Close() //nolint:errcheck
	<-done
}

// TestNamesAreTheCompleteParentContract pins the list of sockets a
// privileged parent may bind. It is deliberately short: every entry is a
// port that root opens on the user's behalf, so growing this list is a
// security decision and should not happen by accident.
func TestNamesAreTheCompleteParentContract(t *testing.T) {
	want := []string{"https", "http"}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v — adding a socket here widens what root binds", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
