package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
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

// TestEveryInspectRouteIsGuarded checks each guarded route individually,
// not just one of them: guard() is applied per mux.HandleFunc call, so a
// route added without the wrapper would pass this suite's other tests (they
// all use the dashboard Host) and only show up here, against a foreign Host.
func TestEveryInspectRouteIsGuarded(t *testing.T) {
	routes := []struct {
		method, path string
	}{
		{"GET", "/api/inspect/requests"},
		{"GET", "/api/inspect/requests/1"},
		{"POST", "/api/inspect/clear"},
		{"GET", "/api/inspect/stream"},
		{"GET", "/inspect"},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			s, r := testServer(t)
			seed(t, r, "/x")

			req := httptest.NewRequest(rt.method, rt.path, nil)
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

func TestInspectEndpointsAre503WithNoRecorder(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/inspect/requests", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
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
}
