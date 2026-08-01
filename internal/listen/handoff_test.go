package listen

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// serveCount accepts on ln until it reports an error, counting connections.
func serveCount(ln net.Listener, count *int, mu *sync.Mutex, stopped chan<- error) {
	for {
		c, err := ln.Accept()
		if err != nil {
			stopped <- err
			return
		}
		mu.Lock()
		*count++
		mu.Unlock()
		c.Close() //nolint:errcheck
	}
}

// TestNextRetiresThePreviousGeneration is the whole point of Handoff.
//
// Caddy retires a server by closing its listener and waiting for the accept
// loop to end. An inherited socket cannot be closed, so before this type the
// old loop kept accepting: two servers on one socket, each connection going
// to whichever won the race. Every config reload left a share of traffic
// being served by routing that no longer existed anywhere.
func TestNextRetiresThePreviousGeneration(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close() //nolint:errcheck

	h := NewHandoff(raw)
	defer h.Close() //nolint:errcheck

	var mu sync.Mutex
	oldCount, newCount := 0, 0
	oldStopped := make(chan error, 1)
	newStopped := make(chan error, 1)

	old := h.Next()
	go serveCount(old, &oldCount, &mu, oldStopped)

	// Let the old generation actually reach Accept before superseding it.
	time.Sleep(20 * time.Millisecond)

	next := h.Next()
	go serveCount(next, &newCount, &mu, newStopped)

	select {
	case err := <-oldStopped:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("retired generation ended with %v, want net.ErrClosed — Caddy "+
				"treats that as the signal a server has stopped", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the retired generation is still accepting; two servers now share " +
			"one socket and connections will split between them")
	}

	const dials = 30
	for i := 0; i < dials; i++ {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.Close() //nolint:errcheck
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := newCount >= dials
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	gotOld, gotNew := oldCount, newCount
	mu.Unlock()

	if gotOld != 0 {
		t.Errorf("the retired generation served %d connections, want 0 — this is the "+
			"intermittent stale-route bug", gotOld)
	}
	if gotNew != dials {
		t.Errorf("the live generation served %d of %d connections", gotNew, dials)
	}
}

// TestHandoffNeverClosesTheUnderlyingListener: the descriptor comes from a
// privileged parent this process can no longer become. Closing it means
// nothing can bind :443 again until the whole tree restarts, and the first
// config edit would be what triggers it.
func TestHandoffNeverClosesTheUnderlyingListener(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close() //nolint:errcheck
	addr := raw.Addr().String()

	h := NewHandoff(raw)
	gen := h.Next()
	if err := gen.Close(); err != nil {
		t.Fatalf("generation Close should be a no-op, got %v", err)
	}
	h.Next() // supersede a few times over
	h.Next()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("socket no longer accepts after generations were closed: %v", err)
	}
	c.Close() //nolint:errcheck

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := net.Dial("tcp", addr); err != nil {
		t.Errorf("Handoff.Close closed the inherited descriptor: %v", err)
	} else {
		c.Close() //nolint:errcheck
	}
}

// TestGenerationAfterCloseDoesNotBlock: a Next that arrives after shutdown
// must report closed rather than hand back a listener whose Accept blocks
// forever, which would hang the caller's shutdown instead of ending it.
func TestGenerationAfterCloseDoesNotBlock(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close() //nolint:errcheck

	h := NewHandoff(raw)
	h.Close() //nolint:errcheck

	done := make(chan error, 1)
	go func() {
		_, err := h.Next().Accept()
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after Close returned %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept blocked after Close")
	}
}
