package listen

import (
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
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

// TestCrossProcessHandover is the mechanism the privileged parent depends
// on, exercised for real: a socket bound in this process is served by a
// *different* process that never called Listen.
//
// The in-process tests above can pass even if descriptor inheritance across
// exec were broken, because nothing crosses a process boundary. This one
// cannot: the parent closes its own copy before the child ever answers, so
// if ExtraFiles and the fd numbering did not line up, the dial below fails.
func TestCrossProcessHandover(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperServesInheritedSocket") //nolint:gosec
	cmd.Env = append(os.Environ(), helperEnv+"=1", EnvFDs+"="+HTTPS+":3")
	cmd.ExtraFiles = []*os.File{f} // becomes fd 3 in the child
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill() //nolint:errcheck

	// Close our own listener: from here the socket lives only in the child.
	ln.Close() //nolint:errcheck

	var conn net.Conn
	for i := 0; i < 100; i++ { // the child has to start a whole test binary
		conn, err = net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("nothing is serving %s: the child did not adopt the descriptor: %v", addr, err)
	}
	defer conn.Close() //nolint:errcheck

	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	buf := make([]byte, len(helperReply))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading from the inherited socket: %v", err)
	}
	if string(buf) != helperReply {
		t.Errorf("got %q from the child, want %q", buf, helperReply)
	}
	if err := cmd.Wait(); err != nil {
		t.Errorf("child exited badly: %v", err)
	}
}

const (
	helperEnv   = "SWITCHBOARD_LISTEN_TEST_HELPER"
	helperReply = "inherited-ok"
)

// TestHelperServesInheritedSocket is not a test. It is the child half of
// TestCrossProcessHandover, run by re-executing this test binary — the
// standard way to get a second process without shipping a second program.
func TestHelperServesInheritedSocket(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("helper process for TestCrossProcessHandover")
	}
	set, err := FromEnv()
	if err != nil {
		t.Fatalf("child could not adopt the descriptor: %v", err)
	}
	ln, err := set.Listen(HTTPS, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte(helperReply)) //nolint:errcheck
	conn.Close()                    //nolint:errcheck
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
