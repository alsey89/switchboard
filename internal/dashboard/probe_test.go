package dashboard

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestProberDialsConcurrently(t *testing.T) {
	p := newProber(time.Minute)
	p.dial = func(string) bool {
		time.Sleep(100 * time.Millisecond)
		return true
	}

	addrs := []string{"a:1", "b:2", "c:3", "d:4", "e:5"}
	start := time.Now()
	got := p.statuses(addrs)
	elapsed := time.Since(start)

	// Serially this is 500ms. Overlapped it is a little over 100ms.
	if elapsed > 300*time.Millisecond {
		t.Errorf("took %v, want the dials to overlap", elapsed)
	}
	if len(got) != len(addrs) {
		t.Fatalf("got %d results, want %d", len(got), len(addrs))
	}
	for _, a := range addrs {
		if !got[a] {
			t.Errorf("%s: got down, want up", a)
		}
	}
}

func TestProberCachesWithinTTL(t *testing.T) {
	p := newProber(time.Minute)
	var calls int32
	p.dial = func(string) bool {
		atomic.AddInt32(&calls, 1)
		return true
	}

	p.statuses([]string{"a:1"})
	p.statuses([]string{"a:1"})

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("dialed %d times, want 1", n)
	}
}

func TestProberRedialsAfterTTL(t *testing.T) {
	p := newProber(5 * time.Second)
	clock := time.Now()
	p.now = func() time.Time { return clock }
	var calls int32
	p.dial = func(string) bool {
		atomic.AddInt32(&calls, 1)
		return true
	}

	p.statuses([]string{"a:1"})
	clock = clock.Add(6 * time.Second)
	p.statuses([]string{"a:1"})

	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("dialed %d times, want 2", n)
	}
}

func TestProberDialsADuplicateUpstreamOnce(t *testing.T) {
	// Two routes may point at the same dev server.
	p := newProber(time.Minute)
	var calls int32
	p.dial = func(string) bool {
		atomic.AddInt32(&calls, 1)
		return true
	}

	got := p.statuses([]string{"a:1", "a:1"})

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("dialed %d times, want 1", n)
	}
	if !got["a:1"] {
		t.Error("a:1 should be up")
	}
}

func TestProberForgetsRemovedUpstreams(t *testing.T) {
	// A daemon that runs for weeks must not keep an entry per address it
	// has ever seen.
	p := newProber(time.Minute)
	p.dial = func(string) bool { return true }

	p.statuses([]string{"a:1", "b:2"})
	p.statuses([]string{"a:1"})

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen["b:2"]; ok {
		t.Error("b:2 is gone from the config and should be gone from the cache")
	}
}
