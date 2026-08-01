package inspect

import (
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRecorderPersistsSubmittedRecords(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{Flush: 5 * time.Millisecond})
	defer r.Close() //nolint:errcheck

	r.Submit(rec(time.Now(), "/one"))

	waitFor(t, "the record to land in the store", func() bool {
		got, err := s.List(Query{Limit: 10})
		return err == nil && len(got) == 1
	})
}

func TestSubmitDoesNotBlockOnAFullBuffer(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	// Buffer of 1 and a drain that is not running yet: the second submit
	// has nowhere to go and must be dropped rather than block the caller.
	r := &Recorder{ch: make(chan *Record, 1), store: s}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			r.Submit(rec(time.Now(), "/x"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked; capture must never back up onto the request path")
	}
	if r.Dropped() == 0 {
		t.Error("drops must be counted, not silent")
	}
}

func TestSubscriberSeesLiveRecordsWithIDs(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{Flush: 5 * time.Millisecond})
	defer r.Close() //nolint:errcheck

	ch, cancel := r.Subscribe()
	defer cancel()

	r.Submit(rec(time.Now(), "/live"))

	select {
	case got := <-ch:
		if got.Path != "/live" {
			t.Errorf("path = %q", got.Path)
		}
		if got.ID == 0 {
			t.Error("subscribers must see the stored ID, so fan-out happens after the insert")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no record reached the subscriber")
	}
}

func TestCancelledSubscriberStopsReceiving(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{Flush: 5 * time.Millisecond})
	defer r.Close() //nolint:errcheck

	ch, cancel := r.Subscribe()
	cancel()

	r.Submit(rec(time.Now(), "/after-cancel"))
	waitFor(t, "the record to be stored", func() bool {
		got, err := s.List(Query{Limit: 10})
		return err == nil && len(got) == 1
	})

	select {
	case _, open := <-ch:
		if open {
			t.Error("a cancelled subscriber should not receive records")
		}
	default:
	}
}

func TestTrimTickEnforcesAgeWithoutTraffic(t *testing.T) {
	// Age off while the row goes in, so Insert's own trim leaves it.
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1 << 30})
	if err := s.Insert([]*Record{rec(time.Now().Add(-3*time.Hour), "/stale")}); err != nil {
		t.Fatal(err)
	}
	// Now turn age on and send no more traffic. Only the ticker can remove
	// the row, which is exactly the case a quiet daemon hits: up for days,
	// nothing arriving, rows aging past the limit with no write to notice.
	s.SetLimits(Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})

	tick := make(chan time.Time)
	r := New(s, Options{Flush: 5 * time.Millisecond, TrimTick: tick})
	defer r.Close() //nolint:errcheck

	tick <- time.Now()
	waitFor(t, "the ticker to trim the stale row", func() bool {
		got, err := s.List(Query{Limit: 10})
		return err == nil && len(got) == 0
	})
}

func TestShutdownFlushesAlreadyQueuedRecords(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	// A flush interval longer than the test run: the only thing that can
	// write these records is shutdown's own drain of the channel, not the
	// periodic timer. This proves Close does not drop what is already
	// queued when it stops the drain goroutine.
	r := New(s, Options{Flush: time.Hour})

	r.Submit(rec(time.Now(), "/a"))
	r.Submit(rec(time.Now(), "/b"))
	r.Submit(rec(time.Now(), "/c"))

	// Same-package white-box shutdown: trigger exactly what Close does to
	// the drain goroutine, without also closing the store, so the store
	// can still be queried afterward to prove the records landed.
	close(r.done)
	r.wg.Wait()

	got, err := s.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("shutdown must flush records already queued; got %d, want 3", len(got))
	}
}

func TestCurrentPointerRoundTrips(t *testing.T) {
	t.Cleanup(func() { SetCurrent(nil) })
	if Current() != nil {
		t.Fatal("Current should start nil")
	}
	s := testStore(t, Limits{MaxRequests: 10, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{})
	defer r.Close() //nolint:errcheck

	SetCurrent(r)
	if Current() != r {
		t.Error("SetCurrent did not take")
	}
	SetCurrent(nil)
	if Current() != nil {
		t.Error("SetCurrent(nil) must clear it; the handler relies on nil meaning pass-through")
	}
}
