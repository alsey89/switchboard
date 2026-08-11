package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/inspect"
)

func testServer(t *testing.T) (*Server, *inspect.Recorder) {
	t.Helper()
	st, err := inspect.Open(filepath.Join(t.TempDir(), "inspect.db"),
		inspect.Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r := inspect.New(st, inspect.Options{Flush: 5 * time.Millisecond})
	t.Cleanup(func() { r.Close() }) //nolint:errcheck

	s := New(&config.Config{Suffix: "test"}, "test")
	s.SetInspector(r)
	return s, r
}

func seed(t *testing.T, r *inspect.Recorder, path string) *inspect.Record {
	t.Helper()
	rec := &inspect.Record{
		StartedAt: time.Now(), Duration: time.Millisecond,
		Domain: "app.test", Method: "GET", Path: path, Status: 200,
		Proto: "HTTP/1.1", RespBody: []byte("body bytes"),
		ReqHeaders: map[string][]string{"Accept": {"*/*"}},
	}
	if err := r.Store().Insert([]*inspect.Record{rec}); err != nil {
		t.Fatal(err)
	}
	return rec
}

func do(s *Server, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "switchboard.test"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.mux().ServeHTTP(w, req)
	return w
}

func TestInspectRequestsListsNewestFirst(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/one")
	seed(t, r, "/two")

	w := do(s, "GET", "/api/inspect/requests", nil)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var out struct {
		Requests []struct {
			ID   int64  `json:"id"`
			Path string `json:"path"`
		} `json:"requests"`
		Dropped int64 `json:"dropped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Requests) != 2 {
		t.Fatalf("got %d requests", len(out.Requests))
	}
	if out.Requests[0].Path != "/two" {
		t.Errorf("first is %q, want the newest", out.Requests[0].Path)
	}
}

func TestInspectRequestsFiltersByQuery(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/users")
	seed(t, r, "/health")

	w := do(s, "GET", "/api/inspect/requests?q=user", nil)
	var out struct {
		Requests []struct {
			Path string `json:"path"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Requests) != 1 || out.Requests[0].Path != "/users" {
		t.Fatalf("q=user returned %v", out.Requests)
	}
}

func TestInspectRecordReturnsBodies(t *testing.T) {
	s, r := testServer(t)
	rec := seed(t, r, "/x")

	w := do(s, "GET", "/api/inspect/requests/"+itoa(rec.ID), nil)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out struct {
		RespBody string `json:"resp_body"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.RespBody != "body bytes" {
		t.Errorf("resp_body = %q", out.RespBody)
	}
}

func TestInspectRecordUnknownIDIs404(t *testing.T) {
	s, _ := testServer(t)
	if w := do(s, "GET", "/api/inspect/requests/9999", nil); w.Code != 404 {
		t.Fatalf("status %d, want 404", w.Code)
	}
}

func TestClearRequiresPostAndOrigin(t *testing.T) {
	cases := []struct {
		name   string
		method string
		origin map[string]string
		want   int
	}{
		{"get is refused", "GET", map[string]string{"Origin": "https://switchboard.test"}, http.StatusMethodNotAllowed},
		{"no origin is refused", "POST", nil, http.StatusForbidden},
		{"foreign origin is refused", "POST", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"same origin is allowed", "POST", map[string]string{"Origin": "https://switchboard.test"}, http.StatusNoContent},
		{"loopback origin is allowed", "POST", map[string]string{"Origin": "http://127.0.0.1:8484"}, http.StatusNoContent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, r := testServer(t)
			seed(t, r, "/x")
			if w := do(s, c.method, "/api/inspect/clear", c.origin); w.Code != c.want {
				t.Fatalf("status %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestClearEmptiesTheBuffer(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/x")

	if w := do(s, "POST", "/api/inspect/clear",
		map[string]string{"Origin": "https://switchboard.test"}); w.Code != http.StatusNoContent {
		t.Fatalf("status %d", w.Code)
	}
	got, err := r.Store().List(inspect.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("%d rows survived", len(got))
	}
}

func TestInspectEndpointsRefuseForeignHosts(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/x")

	req := httptest.NewRequest("GET", "/api/inspect/requests", nil)
	req.Host = "evil.example"
	w := httptest.NewRecorder()
	s.mux().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for a foreign Host", w.Code)
	}
}

// TestEveryGuardedRouteRejectsAForeignHost walks s.routes(), the same table
// mux() registers from, rather than a hand-maintained list of paths: a
// route added to routes() without a guard/guardPage wrapper fails this test
// by construction. That is exactly how /api/routes escaped the guard in an
// earlier version of this file — mux()'s route list and this test's route
// list were two separate hand-maintained things, and only one of them got
// updated.
func TestEveryGuardedRouteRejectsAForeignHost(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/x")

	for _, rt := range s.routes() {
		if !rt.guarded {
			continue
		}
		t.Run(rt.pattern, func(t *testing.T) {
			target := rt.pattern
			if strings.HasSuffix(target, "/") {
				target += "1" // land inside the subtree, not just on its root
			}
			req := httptest.NewRequest("GET", target, nil)
			req.Host = "evil.example"
			req.Header.Set("Origin", "https://evil.example")
			w := httptest.NewRecorder()
			s.mux().ServeHTTP(w, req)

			if w.Code != http.StatusNotFound {
				t.Fatalf("status %d, want 404 for a foreign Host", w.Code)
			}
		})
	}
}

// TestInspectPageForeignHostGetsTheNoRoutePage checks guardPage's actual
// behavior, not just its status code: /inspect is a page a user navigates
// to, so a foreign Host should render the same friendly no-route page
// handleRoot uses, not an empty flat 404 body.
func TestInspectPageForeignHostGetsTheNoRoutePage(t *testing.T) {
	s, _ := testServer(t)
	req := httptest.NewRequest("GET", "/inspect", nil)
	req.Host = "evil.example"
	w := httptest.NewRecorder()
	s.mux().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "evil.example") {
		t.Errorf("expected the no-route page naming the host, got: %s", w.Body)
	}
}

func TestInspectEndpointsAre503WithNoRecorder(t *testing.T) {
	cases := []struct {
		name, method, path string
		origin             map[string]string
	}{
		{"list", "GET", "/api/inspect/requests", nil},
		{"detail", "GET", "/api/inspect/requests/1", nil},
		{"clear", "POST", "/api/inspect/clear", map[string]string{"Origin": "https://switchboard.test"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New(&config.Config{Suffix: "test"}, "test")
			if w := do(s, c.method, c.path, c.origin); w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503", w.Code)
			}
		})
	}
}

// TestInspectRequestsAppliesEachQueryParameter guards against the query
// parameters in handleInspectRequests getting transposed — domain into
// Method, before into Limit, and so on — which the single q= test above
// cannot catch, since transposing any of the untested fields would still
// leave that one test green.
func TestInspectRequestsAppliesEachQueryParameter(t *testing.T) {
	s, r := testServer(t)
	mk := func(domain, method, path string, status int) *inspect.Record {
		rec := &inspect.Record{
			StartedAt: time.Now(), Duration: time.Millisecond,
			Domain: domain, Method: method, Path: path, Status: status,
			Proto: "HTTP/1.1",
		}
		if err := r.Store().Insert([]*inspect.Record{rec}); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	mk("a.test", "GET", "/a", 200)
	mk("b.test", "POST", "/b", 404)
	recC := mk("a.test", "POST", "/c", 500)

	cases := []struct {
		name      string
		query     string
		wantPaths []string
	}{
		{"domain filters", "domain=a.test", []string{"/c", "/a"}},
		{"method filters", "method=post", []string{"/c", "/b"}},
		{"status filters", "status=4xx", []string{"/b"}},
		{"domain and method intersect, not either alone", "domain=a.test&method=post", []string{"/c"}},
		{"limit caps the result count", "limit=1", []string{"/c"}},
		{"before paginates past a given id", fmt.Sprintf("before=%d", recC.ID), []string{"/b", "/a"}},
		{"before and limit combine, not swap", fmt.Sprintf("before=%d&limit=1", recC.ID), []string{"/b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := do(s, "GET", "/api/inspect/requests?"+c.query, nil)
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			var out struct {
				Requests []struct {
					Path string `json:"path"`
				} `json:"requests"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, req := range out.Requests {
				got = append(got, req.Path)
			}
			if !reflect.DeepEqual(got, c.wantPaths) {
				t.Errorf("%s: got %v, want %v", c.query, got, c.wantPaths)
			}
		})
	}
}

func TestConsolePageRenders(t *testing.T) {
	s, _ := testServer(t)
	w := do(s, "GET", "/", nil)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	// The history API the page must actually use. Its only data source used
	// to be the stream, whose backfill is 200 rows, so the filters ran over
	// an in-memory array and the other ~96% of a default buffer was
	// unreachable. A filter that matched nothing on screen looked identical
	// to no matching traffic at all.
	//
	// The last two are the render path. render() used to clear #list and
	// rebuild every row, which reset scrollTop to 0 on every live event and
	// so made load older unusable on a proxy with any traffic through it.
	// It now reconciles by record id and restores the scroll anchor.
	for _, want := range []string{
		"EventSource", "/api/inspect/stream", "id=\"list\"",
		"/api/inspect/requests?", "p.set(\"domain\"", "{ before:", "load older",
		"tbody.insertBefore", "list.scrollTop +=",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

func TestConsoleListHasColumnHeaders(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	// Five unlabeled columns is a puzzle, not a table. The header row is
	// built client side, so this asserts the code that builds it. Asserting
	// "<thead>" would never match: it is never in the served source.
	for _, want := range []string{
		`createElement("thead")`,
		`["time", "method", "path", "status", "took"]`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list is missing %q", want)
		}
	}
}

func TestConsoleOffersCopyAsCurl(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	for _, want := range []string{"copy as curl", "navigator.clipboard"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail pane is missing %q", want)
		}
	}
}

// TestConsoleQuotesEveryCurlField pins asCurl's fields to shellQuote. Every
// value it emits came off the wire, so every value must go through
// shellQuote, including the HTTP method: net/http accepts any RFC 7230
// token as a method, and an unquoted r.method let a captured request like
// `GET$(id)` execute when the copied command was pasted into a shell.
func TestConsoleQuotesEveryCurlField(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	for _, want := range []string{
		`shellQuote(r.method)`,
		`shellQuote(k + ": " + v)`,
		`shellQuote(r.req_body)`,
		`shellQuote("https://" + r.domain + r.path)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("asCurl is missing %q", want)
		}
	}
}

func TestConsoleHandlesKeys(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	for _, want := range []string{"ArrowDown", "ArrowUp", "Escape", "keydown"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not handle %q", want)
		}
	}
}

func TestConsoleMarksRedactedHeaders(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	// inspect.Redacted is the exact value the store writes.
	if !strings.Contains(body, inspect.Redacted) {
		t.Errorf("page should know the %q sentinel to mark it", inspect.Redacted)
	}
	if !strings.Contains(body, "bodies = true") {
		t.Error("the redaction note should name the key that turns it off")
	}
}

// TestInspectRedirectsToTheConsole keeps the v0.3 URL working. The README,
// the CHANGELOG and the 0.3.0 release notes all name it, and people have
// bookmarked it.
func TestInspectRedirectsToTheConsole(t *testing.T) {
	s, _ := testServer(t)
	w := do(s, "GET", "/inspect", nil)
	if w.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Errorf("Location %q, want /", got)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

func TestStreamBackfillsThenPushes(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/backfilled")

	srv := httptest.NewServer(s.mux())
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/inspect/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "switchboard.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}

	events := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				events <- strings.TrimPrefix(line, "data: ")
			}
		}
	}()

	// The backfill must arrive without anyone making a new request.
	select {
	case got := <-events:
		if !strings.Contains(got, "/backfilled") {
			t.Errorf("first event = %s, want the backfilled row", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no backfill")
	}

	// A record submitted after the subscription must be pushed.
	r.Submit(&inspect.Record{
		StartedAt: time.Now(), Domain: "app.test", Method: "GET",
		Path: "/pushed", Status: 200, Proto: "HTTP/1.1",
	})
	select {
	case got := <-events:
		if !strings.Contains(got, "/pushed") {
			t.Errorf("second event = %s, want the pushed row", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no live event")
	}
}

func TestStreamIs503WithNoRecorder(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/inspect/stream", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}

// TestStreamDeliversUnderConcurrentSubmits races a burst of submissions
// against connection setup, under -race, and checks every submitted path
// eventually surfaces on the stream via the backfill, the live push, or
// both. n stays under the test store's 100-record cap (inspect_test.go's
// testServer) and the subscriber's 256-slot buffer, so nothing here is
// expected to be evicted or dropped.
func TestStreamDeliversUnderConcurrentSubmits(t *testing.T) {
	s, r := testServer(t)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			r.Submit(&inspect.Record{
				StartedAt: time.Now(), Domain: "app.test", Method: "GET",
				Path: fmt.Sprintf("/race-%d", i), Status: 200, Proto: "HTTP/1.1",
			})
		}
	}()

	srv := httptest.NewServer(s.mux())
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/inspect/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "switchboard.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	events := make(chan string, n*2)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				events <- strings.TrimPrefix(line, "data: ")
			}
		}
		close(events)
	}()

	wg.Wait()

	seen := make(map[string]bool, n)
	deadline := time.After(10 * time.Second)
	for len(seen) < n {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatalf("stream closed early with %d/%d records seen", len(seen), n)
			}
			var row struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal([]byte(ev), &row); err == nil {
				seen[row.Path] = true
			}
		case <-deadline:
			t.Fatalf("timed out with %d/%d records seen, a race dropped one", len(seen), n)
		}
	}
}

// TestInspectEndpointsSurviveAClosedStore reproduces the reload race: the
// pointer swap in SetInspector has no barrier for a reader already in
// flight, so a handler can hold a *Recorder whose *Store a concurrent
// reload has just closed. The endpoints must turn that into a clean 503,
// not a 500 carrying "sql: database is closed", and never panic.
func TestInspectEndpointsSurviveAClosedStore(t *testing.T) {
	s, r := testServer(t)
	rec := seed(t, r, "/x")
	if err := r.Store().Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("list", func(t *testing.T) {
		w := do(s, "GET", "/api/inspect/requests", nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", w.Code)
		}
		if strings.Contains(w.Body.String(), "database is closed") {
			t.Errorf("leaked the driver error: %s", w.Body)
		}
	})

	t.Run("record", func(t *testing.T) {
		w := do(s, "GET", "/api/inspect/requests/"+itoa(rec.ID), nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", w.Code)
		}
		if strings.Contains(w.Body.String(), "database is closed") {
			t.Errorf("leaked the driver error: %s", w.Body)
		}
	})

	t.Run("clear", func(t *testing.T) {
		w := do(s, "POST", "/api/inspect/clear",
			map[string]string{"Origin": "https://switchboard.test"})
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", w.Code)
		}
		if strings.Contains(w.Body.String(), "database is closed") {
			t.Errorf("leaked the driver error: %s", w.Body)
		}
	})

	// stream's backfill query runs before any header is written, so a
	// closed store must turn into the same clean 503 as the other
	// endpoints rather than an SSE response that silently opens with no
	// backfill.
	t.Run("stream", func(t *testing.T) {
		w := do(s, "GET", "/api/inspect/stream", nil)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", w.Code)
		}
		if strings.Contains(w.Body.String(), "database is closed") {
			t.Errorf("leaked the driver error: %s", w.Body)
		}
	})
}

// TestShutdownReturnsWithAnOpenStream pins the daemon's shutdown path.
//
// http.Server.Shutdown waits for active requests to return, and it does not
// cancel their contexts. The SSE handler used to select only on the client
// going away, a record arriving and a 30 second ping, so it never learned
// that the server wanted to stop: a developer with the inspector open in a
// background tab could hold the whole daemon up indefinitely, past the DNS
// teardown and past the WAL checkpoint.
//
// The server's own done channel is what closes that gap. This test drives
// the real *http.Server the stream is running on, so it fails the same way
// the daemon did.
func TestShutdownReturnsWithAnOpenStream(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/x")

	ts := httptest.NewServer(s.mux())
	defer ts.Close()
	// Shutdown must drive the same server the stream is served by, which is
	// what makes this the daemon's situation rather than a no-op.
	s.httpSrv = ts.Config

	req, err := http.NewRequest("GET", ts.URL+"/api/inspect/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "switchboard.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// Registered after ts.Close above so it runs first: an open stream would
	// otherwise hold ts.Close for as long as it held Shutdown.
	defer resp.Body.Close() //nolint:errcheck

	// Read the backfill event, so the handler is past its header write and
	// sitting in the select rather than still setting up. No sleep needed:
	// the read itself is the synchronisation.
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: ") {
			break
		}
	}

	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown blocked on an open inspector stream")
	}
}

// TestStreamOmitsBodiesOnLiveEvents pins the stream's payload shape. The
// backfill comes from Store.List, which never returns bodies, so a live
// event that carried them made the same record arrive in two shapes. It is
// also up to max_body_bytes per record on the wire for a list view that
// never renders one; the page refetches from the detail endpoint instead.
func TestStreamOmitsBodiesOnLiveEvents(t *testing.T) {
	s, r := testServer(t)

	srv := httptest.NewServer(s.mux())
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/inspect/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "switchboard.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	events := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				events <- strings.TrimPrefix(line, "data: ")
			}
		}
	}()

	r.Submit(&inspect.Record{
		StartedAt: time.Now(), Domain: "app.test", Method: "POST",
		Path: "/with-bodies", Status: 200, Proto: "HTTP/1.1",
		ReqBody: []byte("secret request"), RespBody: []byte("secret response"),
	})

	select {
	case got := <-events:
		if !strings.Contains(got, "/with-bodies") {
			t.Fatalf("unexpected first event: %s", got)
		}
		var row struct {
			ID       int64  `json:"id"`
			ReqBody  string `json:"req_body"`
			RespBody string `json:"resp_body"`
		}
		if err := json.Unmarshal([]byte(got), &row); err != nil {
			t.Fatal(err)
		}
		if row.ReqBody != "" || row.RespBody != "" {
			t.Errorf("stream carried bodies: req=%q resp=%q", row.ReqBody, row.RespBody)
		}
		// The bodies must still be reachable, just not over the stream.
		w := do(s, "GET", "/api/inspect/requests/"+itoa(row.ID), nil)
		if !strings.Contains(w.Body.String(), "secret response") {
			t.Errorf("the detail endpoint lost the body: %s", w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no live event")
	}
}
