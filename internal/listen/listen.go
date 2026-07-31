// Package listen decides where the daemon's listening sockets come from.
//
// The daemon runs unprivileged, but :80 and :443 are privileged on macOS and
// Linux. The resolution (ADR 0001) is that a small privileged parent binds
// those two sockets, drops to the user, and execs the daemon with the
// descriptors already open. The daemon therefore cannot assume it binds its
// own sockets — sometimes it is handed them.
//
// A Set models exactly that: ask for a socket by name, get either the
// inherited one or a freshly bound one. Callers do not branch on which mode
// they are in, which is the point — the privileged path is a property of how
// the process was started, not a fork in the daemon's logic.
//
// Windows needs none of this: it has no privileged-port range, so an
// ordinary user can bind :443 and the Set is always empty there. That is why
// this seam is an interface over "where did this socket come from" rather
// than a macOS-specific mechanism bolted onto startup.
//
// DNS is deliberately not part of the Set. The resolver file names a port
// (/etc/resolver/test says 53535), so the DNS responder never needs :53 and
// therefore never needs privilege. Keeping it out means the privileged
// parent holds exactly two descriptors and nothing about UDP.
package listen

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// EnvFDs names the environment variable a privileged parent uses to tell the
// child which inherited descriptor is which. Format: "https:3,http:4".
//
// The names and numbers travel together because fd numbers alone are
// positional, and a positional contract silently does the wrong thing the
// first time someone reorders the parent's bind calls — it does not fail, it
// serves HTTPS on the plaintext port.
const EnvFDs = "SWITCHBOARD_LISTEN_FDS"

// Names of the sockets a privileged parent may pass. This list is the
// complete set of things the parent is allowed to bind; see Set.Names.
const (
	HTTPS = "https"
	HTTP  = "http"
)

// Set holds the listeners inherited from a privileged parent, if any.
// The zero value is valid and means "inherited nothing" — every Listen call
// then binds normally.
type Set struct {
	inherited map[string]net.Listener
}

// FromEnv builds a Set from the descriptors a privileged parent passed. It
// returns an empty Set (not an error) when the variable is absent, because
// running unprivileged is a supported mode, not a misconfiguration.
//
// The variable is removed from the environment on success so that it cannot
// be inherited a second time by anything the daemon itself spawns.
func FromEnv() (*Set, error) {
	spec := os.Getenv(EnvFDs)
	if spec == "" {
		return &Set{}, nil
	}
	defer os.Unsetenv(EnvFDs) //nolint:errcheck

	s := &Set{inherited: map[string]net.Listener{}}
	for _, part := range strings.Split(spec, ",") {
		name, num, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("%s: %q is not name:fd", EnvFDs, part)
		}
		fd, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("%s: %q has a non-numeric descriptor: %w", EnvFDs, part, err)
		}
		if !known(name) {
			return nil, fmt.Errorf("%s: %q is not a socket this daemon accepts (want %v)",
				EnvFDs, name, Names())
		}
		f := os.NewFile(uintptr(fd), "inherited-"+name)
		if f == nil {
			return nil, fmt.Errorf("%s: descriptor %d for %q is not open", EnvFDs, fd, name)
		}
		ln, err := net.FileListener(f)
		// FileListener dups the descriptor, so the original is ours to close
		// either way; leaving it open would leak one fd per socket.
		f.Close() //nolint:errcheck
		if err != nil {
			return nil, fmt.Errorf("%s: descriptor %d for %q is not a listening socket: %w",
				EnvFDs, fd, name, err)
		}
		s.inherited[name] = ln
	}
	return s, nil
}

// Names lists the sockets a privileged parent may pass, in bind order.
func Names() []string { return []string{HTTPS, HTTP} }

func known(name string) bool {
	for _, n := range Names() {
		if n == name {
			return true
		}
	}
	return false
}

// Listen returns the socket registered under name, or binds addr if none was
// inherited. The returned listener is owned by the caller.
func (s *Set) Listen(name, addr string) (net.Listener, error) {
	if ln, ok := s.inherited[name]; ok {
		return ln, nil
	}
	return net.Listen("tcp", addr)
}

// Inherited reports whether name came from a privileged parent. The daemon
// uses this to know that the configured port for that socket is not in
// force: it did not choose the port, it was handed one.
func (s *Set) Inherited(name string) bool {
	_, ok := s.inherited[name]
	return ok
}

// Any reports whether the daemon is running under a privileged parent at all.
func (s *Set) Any() bool { return len(s.inherited) > 0 }

// Addr returns the address of an inherited socket, for reporting. Empty if
// the socket was not inherited.
func (s *Set) Addr(name string) string {
	if ln, ok := s.inherited[name]; ok {
		return ln.Addr().String()
	}
	return ""
}

// Close releases any inherited listeners that were never claimed. Claimed
// ones belong to their caller.
func (s *Set) Close() {
	for _, ln := range s.inherited {
		ln.Close() //nolint:errcheck
	}
}

// KeepOpen wraps a listener so that Close is a no-op.
//
// This exists for one specific reason. Caddy closes its listeners on every
// config reload and re-opens them from the new config. For a socket Caddy
// bound itself that is correct. For an inherited one it is fatal and
// unrecoverable: the descriptor came from a privileged parent that is no
// longer running as root, so once closed, nothing in this process can ever
// bind :443 again — the first edit to the config file would silently take
// the site down until the whole tree was restarted.
//
// The lifetime of an inherited descriptor belongs to the parent that bound
// it, not to the library that happens to be serving on it.
func KeepOpen(ln net.Listener) net.Listener { return keepOpen{ln} }

type keepOpen struct{ net.Listener }

func (keepOpen) Close() error { return nil }
