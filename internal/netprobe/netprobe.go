// Package netprobe answers one question: can this process bind this address
// right now?
//
// It exists as its own package only because two callers that cannot import
// each other both need the answer. `doctor` reports bindability as a
// diagnostic, and `service` refuses to install a launch agent that would
// crash-loop on an unbindable port — and `doctor` already imports `service`,
// so the helper cannot live in either one without a cycle or a second copy.
package netprobe

import "net"

// Bindable reports whether addr can be bound on the given network ("tcp" or
// "udp"), by actually binding it and immediately closing. It returns the
// underlying error on failure, so callers can distinguish the two cases that
// matter: EACCES/EPERM (a privileged port) unwraps to os.ErrPermission, and
// EADDRINUSE (something else is already there) does not.
//
// This is inherently a point-in-time answer — the port can be taken between
// the probe and the real bind — so treat a nil result as "no known problem",
// not as a reservation.
func Bindable(network, addr string) error {
	if network == "udp" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		return pc.Close()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}
