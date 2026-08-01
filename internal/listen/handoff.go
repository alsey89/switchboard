package listen

import (
	"net"
	"sync"
)

// Handoff owns one listener and lends it out a generation at a time.
//
// It exists because the two things an inherited socket needs are in direct
// conflict. The descriptor belongs to the privileged parent, so nothing here
// may close it (see KeepOpen). But Caddy retires a server by closing its
// listener and waiting for the accept loop to end, so a listener that ignores
// Close leaves the old server accepting forever.
//
// The result was two servers accepting from one socket after every config
// reload, each connection going to whichever won the race. A route edit
// appeared to work and then failed for a fraction of requests, pointing at a
// dead upstream that no longer existed in any config. Intermittent, and it
// looked like the user's own app was flaky.
//
// So exactly one goroutine ever calls Accept on the real socket. Each Next
// returns a listener that receives from it and retires the previous one,
// whose Accept then reports net.ErrClosed — the signal Caddy is waiting for.
// The descriptor is never touched.
type Handoff struct {
	ln net.Listener

	mu     sync.Mutex
	curr   *slot // the live generation, nil once retired
	closed bool

	done chan struct{}
	once sync.Once
}

// slot is the pairing between the accept loop and one generation.
//
// retired is a separate channel rather than closing ch, because the accept
// loop selects on a send to ch: closing the channel it is about to send on
// panics. An unbuffered send only completes when paired with a receive, so a
// generation that takes retired instead never swallows a connection — the
// send simply does not happen and the loop offers it to the next slot.
type slot struct {
	ch      chan net.Conn
	retired chan struct{}
}

// NewHandoff starts the accept loop for ln. Call Close to stop it; ln itself
// is never closed.
func NewHandoff(ln net.Listener) *Handoff {
	h := &Handoff{ln: ln, done: make(chan struct{})}
	go h.accept()
	return h
}

// Next retires the current generation and returns a fresh one.
//
// Callers must take one generation per config load. Two live generations on
// one socket is the bug this type exists to prevent, so there is deliberately
// no way to ask for a second without retiring the first.
func (h *Handoff) Next() net.Listener {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.retireLocked()
	s := &slot{ch: make(chan net.Conn), retired: make(chan struct{})}
	if h.closed {
		// Already shut down. Hand back something that reports closed
		// immediately rather than a listener that blocks forever.
		close(s.retired)
		return &generation{s: s, addr: h.ln.Addr()}
	}
	h.curr = s
	return &generation{s: s, addr: h.ln.Addr()}
}

func (h *Handoff) retireLocked() {
	if h.curr != nil {
		close(h.curr.retired)
		h.curr = nil
	}
}

// Close stops the accept loop and retires the current generation. The
// underlying listener stays open: its lifetime belongs to whoever bound it.
func (h *Handoff) Close() error {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.retireLocked()
		h.mu.Unlock()
		close(h.done)
	})
	return nil
}

func (h *Handoff) accept() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			// The socket itself is gone. Nothing can be served from it
			// again, so retire the generation rather than leave its Accept
			// blocked on a channel no one will ever send to.
			h.mu.Lock()
			h.retireLocked()
			h.mu.Unlock()
			return
		}
		h.deliver(c)
	}
}

// deliver hands c to the live generation, following a handover rather than
// dropping the connection if one happens mid-send. A reload while a request
// is arriving is ordinary timing, not an error.
func (h *Handoff) deliver(c net.Conn) {
	for {
		h.mu.Lock()
		s := h.curr
		h.mu.Unlock()

		if s == nil {
			c.Close() //nolint:errcheck
			return
		}
		select {
		case s.ch <- c:
			return
		case <-s.retired:
			// A new generation took over; offer it to that one instead.
		case <-h.done:
			c.Close() //nolint:errcheck
			return
		}
	}
}

// generation is one lease on the shared socket.
type generation struct {
	s    *slot
	addr net.Addr
}

func (g *generation) Accept() (net.Conn, error) {
	select {
	case c := <-g.s.ch:
		return c, nil
	case <-g.s.retired:
		return nil, net.ErrClosed
	}
}

// Close is a no-op, for the same reason KeepOpen's is: the descriptor belongs
// to the privileged parent. Retirement happens through Handoff.Next, so a
// server that closes its listener still stops accepting.
func (g *generation) Close() error { return nil }

func (g *generation) Addr() net.Addr { return g.addr }
