package inspect

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testStore(t *testing.T, lim Limits) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "inspect.db"), lim)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() }) //nolint:errcheck
	return s
}

func rec(at time.Time, path string) *Record {
	return &Record{
		StartedAt:   at,
		Duration:    3 * time.Millisecond,
		Domain:      "app.test",
		Method:      "GET",
		Path:        path,
		Status:      200,
		Proto:       "HTTP/1.1",
		ReqHeaders:  map[string][]string{"Accept": {"*/*"}},
		RespHeaders: map[string][]string{"Content-Type": {"text/plain"}},
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	// Truncated to a whole second, not an arbitrary fixed epoch: the store
	// round-trips StartedAt through UnixMicro, and a whole-second value has
	// no sub-microsecond remainder to lose. It also has to stay inside the
	// MaxAge: time.Hour window above, since Insert trims by age too.
	now := time.Now().Truncate(time.Second).UTC()

	in := rec(now, "/hello?a=1")
	in.ReqBody = []byte("ping")
	in.RespBody = []byte("pong")
	if err := s.Insert([]*Record{in}); err != nil {
		t.Fatal(err)
	}
	if in.ID == 0 {
		t.Fatal("Insert must set the ID")
	}
	if in.SizeBytes == 0 {
		t.Fatal("Insert must set SizeBytes")
	}

	got, err := s.Get(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/hello?a=1" || got.Domain != "app.test" || got.Status != 200 {
		t.Errorf("scalars round-tripped wrong: %+v", got)
	}
	if !got.StartedAt.Equal(now) {
		t.Errorf("StartedAt = %s, want %s", got.StartedAt, now)
	}
	if got.Duration != 3*time.Millisecond {
		t.Errorf("Duration = %s", got.Duration)
	}
	if string(got.ReqBody) != "ping" || string(got.RespBody) != "pong" {
		t.Errorf("bodies round-tripped wrong: %q %q", got.ReqBody, got.RespBody)
	}
	if v := got.ReqHeaders["Accept"]; len(v) != 1 || v[0] != "*/*" {
		t.Errorf("ReqHeaders = %v", got.ReqHeaders)
	}
}

func TestListOmitsBodies(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	in := rec(time.Now(), "/x")
	in.RespBody = []byte("a large body")
	if err := s.Insert([]*Record{in}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].RespBody != nil {
		t.Error("List must not carry bodies; that is what Get is for")
	}
}

func TestTrimByRowCap(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 3, MaxBytes: 1 << 30, MaxAge: time.Hour})
	now := time.Now()
	for i := 0; i < 10; i++ {
		if err := s.Insert([]*Record{rec(now, fmt.Sprintf("/%d", i))}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.List(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("kept %d rows, want 3", len(got))
	}
	if got[0].Path != "/9" {
		t.Errorf("newest is %s, want /9", got[0].Path)
	}
}

func TestTrimByByteCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inspect.db")
	lim := Limits{MaxRequests: 10000, MaxBytes: 900, MaxAge: time.Hour}
	s, err := Open(path, lim)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 40; i++ {
		r := rec(now, fmt.Sprintf("/%d", i))
		r.RespBody = make([]byte, 100)
		if err := s.Insert([]*Record{r}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.List(Query{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	// Each row costs 128 (rowOverhead) + ~18 (req header JSON) + ~31 (resp
	// header JSON) + 100 (body) + len(path) + len("app.test") = 287 bytes.
	// 900 bytes allows exactly 3 of those (861); a fourth would be 1148,
	// over the cap. `> 0` / `< 40` bounds would also pass with a batch size
	// of 2 or 4, so only an exact count pins the one-row-at-a-time eviction.
	if len(got) != 3 {
		t.Fatalf("kept %d rows, want exactly 3", len(got))
	}
	if s.Bytes() > 900 {
		t.Errorf("running total %d exceeds the cap", s.Bytes())
	}

	// The in-memory total only proves something if it matches what is
	// actually on disk. Close and reopen: Open recomputes both totals from
	// a fresh SELECT COUNT(*)/SUM(size_bytes) over the table, so if they
	// still match the pre-close values, deleteAndAccount subtracted exactly
	// what it deleted across every trim in this test rather than drifting.
	preRows, preBytes := s.Rows(), s.Bytes()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path, lim)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck
	if s2.Rows() != preRows {
		t.Errorf("reopened row count = %d, want %d (matches the count before close)", s2.Rows(), preRows)
	}
	if s2.Bytes() != preBytes {
		t.Errorf("reopened byte total = %d, want %d (matches the total before close)", s2.Bytes(), preBytes)
	}
}

// TestTrimStopsOnDriftedCounters proves the byte-cap loop in Trim cannot spin
// forever if the in-memory rows/bytes counters ever overstate what is
// actually on disk — say, rows > 0 against an empty table. The byte
// condition alone (s.Bytes() > lim.MaxBytes) would keep such a loop
// looping forever, issuing DELETEs that free nothing; the no-progress
// guard (deleteAndAccount's returned count hitting zero) has to be the
// thing that stops it.
//
// This kind of drift is reachable in principle from Clear (its DELETE and
// counter reset now happen under one held lock, closing that particular
// window — see Clear and deleteAndAccount), but the guard here is a
// backstop against drift from *any* source, not a test of Clear
// specifically. It runs on the drain goroutine in the recorder (Task 4),
// so a spin here would hang capture entirely rather than just fail loudly.
func TestTrimStopsOnDriftedCounters(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1, MaxAge: time.Hour})
	// Manufacture the drift directly: claim a nonzero row/byte total against
	// a table that is actually empty.
	s.mu.Lock()
	s.rows = 5
	s.bytes = 1000
	s.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- s.Trim(time.Now()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Trim did not return: byte-cap loop spun on drifted counters")
	}
}

func TestTrimByAge(t *testing.T) {
	// MaxAge starts at zero (unbounded) so Insert's own trailing Trim cannot
	// remove /old before this test gets to exercise anything: with a
	// nonzero MaxAge from the start, Insert's internal trim deletes /old
	// immediately and the explicit Trim(now) below never has anything to
	// do, which would prove nothing about Trim's injectable `now`.
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1 << 30})
	now := time.Now()
	if err := s.Insert([]*Record{rec(now.Add(-3*time.Hour), "/old")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert([]*Record{rec(now, "/new")}); err != nil {
		t.Fatal(err)
	}

	// Turn age enforcement on now, via the config-reload path, and trim
	// against the fixed `now` captured above rather than wall-clock time.
	// This is the one place in the suite that actually exercises Trim's
	// `now` parameter as an input rather than always trimming against
	// whatever time.Now() happens to return.
	s.SetLimits(Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})
	if err := s.Trim(now); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "/new" {
		t.Fatalf("kept %d rows %v, want just /new", len(got), got)
	}
}

func TestOpenTrimsStaleRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inspect.db")

	// Age off for the first session, so Insert's own trim leaves the row
	// alone and Open is the only thing that can remove it later. Without
	// this the test passes whether or not Open trims at all.
	s, err := Open(path, Limits{MaxRequests: 1000, MaxBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert([]*Record{rec(time.Now().Add(-25*time.Hour), "/stale")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A daemon that sat idle overnight has stale rows and no writes coming
	// to trigger a trim. Open is the other place age gets enforced.
	s2, err := Open(path, Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck
	got, err := s2.List(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("Open kept %d stale rows", len(got))
	}
}

func TestListFilters(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})
	now := time.Now()
	mk := func(domain, method, path string, status int) *Record {
		r := rec(now, path)
		r.Domain, r.Method, r.Status = domain, method, status
		return r
	}
	all := []*Record{
		mk("app.test", "GET", "/users", 200),
		mk("app.test", "POST", "/users", 404),
		mk("api.test", "GET", "/health", 503),
	}
	for _, r := range all {
		if err := s.Insert([]*Record{r}); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		q    Query
		want int
	}{
		{"domain", Query{Domain: "app.test"}, 2},
		{"method", Query{Method: "POST"}, 1},
		{"exact status", Query{Status: "404"}, 1},
		{"status class", Query{Status: "5xx"}, 1},
		{"path substring", Query{Q: "user"}, 2},
		{"combined", Query{Domain: "app.test", Status: "2xx"}, 1},
		{"no filter", Query{}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := s.List(c.q)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != c.want {
				t.Errorf("got %d rows, want %d", len(got), c.want)
			}
		})
	}
}

func TestListBeforePaginates(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})
	now := time.Now()
	var ids []int64
	for i := 0; i < 5; i++ {
		r := rec(now, fmt.Sprintf("/%d", i))
		if err := s.Insert([]*Record{r}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	// ids[0] is the oldest row ("/0"), ids[4] the newest ("/4"); ids are
	// strictly increasing since AUTOINCREMENT only grows.

	got, err := s.List(Query{Before: ids[3], Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	// Before excludes the boundary row itself (ids[3], "/3") and everything
	// newer, leaving only the three rows strictly older than it: /2, /1, /0.
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3", len(got))
	}
	for _, r := range got {
		if r.ID >= ids[3] {
			t.Errorf("row %s (id %d) is not older than the Before boundary (id %d)", r.Path, r.ID, ids[3])
		}
	}
	if got[0].Path != "/2" {
		t.Errorf("newest row in the page is %s, want /2", got[0].Path)
	}
}

func TestOpenPathWithReservedURICharacters(t *testing.T) {
	// '?' starts a query string, '#' a fragment, and '%' a percent-escape
	// in SQLite's own URI filename syntax. A data directory containing any
	// of them must still open as the literal path it is.
	//
	// This has to check more than "Open returned no error and a row round
	// tripped": an unescaped '?' inside the path gets picked up by the
	// driver's own naive first-'?' split as the start of the query string,
	// which silently corrupts parsing of the real "?_pragma=..." query this
	// package appends — the WAL/busy_timeout pragmas quietly fail to apply
	// instead of erroring, and Open/Insert/List all still "succeed". Only
	// asserting on the pragma's actual effect catches that: confirmed by
	// hand that without escaping the path, this reports "delete", not
	// "wal", with no error anywhere.
	dir := t.TempDir()
	sub := filepath.Join(dir, "weird#dir%100?name")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "inspect.db")

	s, err := Open(path, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	var mode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q — the query string got corrupted by an unescaped path", mode, "wal")
	}

	if err := s.Insert([]*Record{rec(time.Now(), "/x")}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
}

func TestClearEmptiesTheBuffer(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err := s.Insert([]*Record{rec(time.Now(), "/x")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("%d rows survived Clear", len(got))
	}
	if s.Bytes() != 0 {
		t.Errorf("running byte total = %d after Clear, want 0", s.Bytes())
	}
}

// TestInsertAndClearDoNotDeadlock pins the lock ordering between the drain
// goroutine and the dashboard's clear endpoint.
//
// The store runs on a single connection, so "hold a connection, then take
// s.mu" and "hold s.mu, then take a connection" are a classic inversion:
// each side owns what the other is waiting for and neither ever returns.
// Insert is the first order (it begins a transaction, then locks) and Clear
// used to be the second. Every DB-touching method must now take the
// connection first.
//
// The test does not sleep into the window. It starts a batch big enough that
// its transaction stays open for a while, waits for the pool to report the
// connection checked out, and only then clears.
func TestInsertAndClearDoNotDeadlock(t *testing.T) {
	// Zero limits so Trim is a no-op: this test is about the lock order, and
	// a trim pass would only add unrelated work inside the same window.
	s := testStore(t, Limits{})

	const n = 20000
	recs := make([]*Record, n)
	now := time.Now()
	for i := range recs {
		recs[i] = rec(now, fmt.Sprintf("/deadlock/%d", i))
	}

	insertDone := make(chan error, 1)
	go func() { insertDone <- s.Insert(recs) }()

	// Wait until the insert is inside its transaction, which is exactly when
	// it owns the store's only connection. DBStats is how the test observes
	// that instead of guessing at it with a sleep.
	for s.db.Stats().InUse == 0 {
		select {
		case err := <-insertDone:
			// The window this test aims at never opened, so it proved
			// nothing either way. That is a skip, not a failure: a machine
			// fast enough to finish 20,000 inserts before this loop
			// observes the checkout has not regressed anything.
			if err != nil {
				t.Fatalf("insert: %v", err)
			}
			t.Skip("the insert finished before the clear could race it")
		default:
		}
		runtime.Gosched()
	}

	clearDone := make(chan error, 1)
	go func() { clearDone <- s.Clear() }()

	ins, clr := insertDone, clearDone
	deadline := time.After(30 * time.Second)
	for ins != nil || clr != nil {
		select {
		case err := <-ins:
			if err != nil {
				t.Errorf("insert: %v", err)
			}
			ins = nil
		case err := <-clr:
			if err != nil {
				t.Errorf("clear: %v", err)
			}
			clr = nil
		case <-deadline:
			t.Fatalf("deadlock: insert done=%v, clear done=%v", ins == nil, clr == nil)
		}
	}
}
