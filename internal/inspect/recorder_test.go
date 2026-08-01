package inspect

import (
	"log/slog"
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

	// Prove the subscription is live before touching cancel: cancelling
	// before any record ever flowed would leave ch already closed when the
	// assertions below run, which proves nothing about cancel actually
	// tearing down a live subscription.
	r.Submit(rec(time.Now(), "/before-cancel"))
	select {
	case got := <-ch:
		if got.Path != "/before-cancel" {
			t.Fatalf("path = %q, want /before-cancel", got.Path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no record reached the subscriber before cancelling")
	}

	cancel()

	r.Submit(rec(time.Now(), "/after-cancel"))
	waitFor(t, "the second record to be stored", func() bool {
		got, err := s.List(Query{Limit: 10})
		return err == nil && len(got) == 2
	})

	// A blocking receive with a timeout backstop, not a default branch: a
	// default would succeed the instant nothing is queued, which is true of
	// an open-but-empty channel too and would not prove ch actually closed.
	select {
	case _, open := <-ch:
		if open {
			t.Error("a cancelled subscriber should not receive records")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("a cancelled subscriber's channel must close, not hang open")
	}
}

func TestInsertWithFailedTrimStillReachesSubscribers(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 1, MaxBytes: 1 << 20, MaxAge: time.Hour})

	// One row already at the MaxRequests cap, so once the next insert lands
	// Insert's own Trim has something it must delete.
	if err := s.Insert([]*Record{rec(time.Now(), "/already-there")}); err != nil {
		t.Fatal(err)
	}

	// A trigger that fails every DELETE without touching INSERT. This is
	// exactly the case store.ErrTrimAfterInsert exists for: the batch
	// commits, and only the trim that runs after it fails.
	if _, err := s.db.Exec(`
CREATE TRIGGER no_delete BEFORE DELETE ON requests
BEGIN
  SELECT RAISE(ABORT, 'trim disabled for test');
END;`); err != nil {
		t.Fatal(err)
	}

	r := New(s, Options{Flush: 5 * time.Millisecond})
	defer r.Close() //nolint:errcheck

	ch, cancel := r.Subscribe()
	defer cancel()

	r.Submit(rec(time.Now(), "/trim-fails"))

	select {
	case got := <-ch:
		if got.Path != "/trim-fails" {
			t.Errorf("path = %q, want /trim-fails", got.Path)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a batch whose insert committed but whose trim failed must still reach subscribers")
	}

	// Both rows are really there, not just handed to a subscriber ahead of
	// a rollback: the trigger aborted the delete, so nothing was removed.
	got, err := s.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
}

func TestPanicInDrainStillClosesSubscribers(t *testing.T) {
	// A nil store makes Insert panic (it dereferences the store's fields),
	// which is enough to exercise drain's recover path without needing a
	// real failure deep inside the store.
	r := &Recorder{
		ch:    make(chan *Record, 4),
		store: nil,
		log:   slog.Default(),
		subs:  map[int64]chan *Record{},
		done:  make(chan struct{}),
	}

	ch, cancel := r.Subscribe()
	defer cancel()

	go r.drain(1, time.Hour, nil)
	r.ch <- rec(time.Now(), "/boom")

	select {
	case _, open := <-ch:
		if open {
			t.Error("drain panicked; the subscriber channel must still be closed, not left open")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a panic in drain must still close subscriber channels, not hang them forever")
	}
}

func TestSubscribeAfterShutdownReturnsAnAlreadyClosedChannel(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{Flush: 5 * time.Millisecond})

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	ch, cancel := r.Subscribe()
	defer cancel() // must be a harmless no-op, not a double close

	select {
	case _, open := <-ch:
		if open {
			t.Error("a subscription requested after shutdown must not deliver records")
		}
	default:
		t.Error("a subscription requested after shutdown must be closed already, not merely empty")
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
	// write these records is drain's own shutdown branch draining the
	// channel, not the periodic timer. This proves that branch flushes what
	// is already queued rather than dropping it.
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
