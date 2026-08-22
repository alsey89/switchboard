package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

const baseConfig = "suffix = \"test\"\n\n[[routes]]\ndomain = \"app.test\"\nport = 3000\n"

// write drives a mutating endpoint with a correct origin and token, so each
// test is about the endpoint's own behavior and not about the guard, which
// origin_test.go already covers exhaustively.
func write(t *testing.T, s *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "switchboard.test"
	req.Header.Set("Origin", "https://switchboard.test")
	req.Header.Set(csrfHeader, s.csrf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.mux().ServeHTTP(w, req)
	return w
}

func TestAddRouteWritesTheFile(t *testing.T) {
	s, path := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"api","port":4000,"version":"`+version+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q, want application/json", ct)
	}

	// The response is the new config, so a client never needs a follow-up
	// read to find out what happened.
	var out readConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Routes) != 2 {
		t.Fatalf("response has %d routes, want 2", len(out.Routes))
	}
	if out.Version == version {
		t.Error("the version did not change after a write")
	}

	// And it is actually on disk, because the daemon reloads from the file
	// and not from anything this handler holds.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "api.test") {
		t.Errorf("the file does not contain the new route:\n%s", b)
	}
}

// A bare name gets the suffix appended, the same way `switchboard add` does.
// Two ways to add a route that disagree about naming would be worse than
// having only one.
func TestAddRouteNormalizesABareName(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"api","port":4000,"version":"`+version+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out readConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, r := range out.Routes {
		if r.Domain == "api.test" {
			return
		}
	}
	t.Errorf("no api.test route: %+v", out.Routes)
}

func TestAddRouteRejectsAStaleVersion(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"api","port":4000,"version":"0000000000000000"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409: %s", w.Code, w.Body)
	}

	// The 409 carries the current config, so the client re-renders without a
	// second round trip.
	var out readConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("409 body is not a config view: %v", err)
	}
	if out.Version == "" || len(out.Routes) != 1 {
		t.Errorf("409 body should be the current config, got %+v", out)
	}
}

func TestAddRouteRejectsADuplicate(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"app.test","port":9999,"version":"`+version+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", w.Code, w.Body)
	}
}

func TestAddRouteRejectsTheReservedDashboardName(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "POST", "/api/routes",
		`{"domain":"switchboard.test","port":9999,"version":"`+version+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", w.Code, w.Body)
	}
}

func TestAddRouteRejectsBadJSON(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	if w := write(t, s, "POST", "/api/routes", "{{{"); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
}

// Two writes racing at the same version. Exactly one must win, and the
// loser must be told rather than silently dropped. This is the whole reason
// the version exists, so it gets a real concurrency test and not a comment.
func TestConcurrentWritesAtTheSameVersionProduceOneWinner(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, domain := range []string{"one", "two"} {
		wg.Add(1)
		go func(i int, domain string) {
			defer wg.Done()
			w := write(t, s, "POST", "/api/routes",
				`{"domain":"`+domain+`","port":4000,"version":"`+version+`"}`)
			codes[i] = w.Code
		}(i, domain)
	}
	wg.Wait()

	var created, conflicted int
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicted++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if created != 1 || conflicted != 1 {
		t.Fatalf("got %d created and %d conflicted, want exactly one of each", created, conflicted)
	}

	// And the file must hold exactly one of them, not a torn merge.
	if got := len(getConfig(t, s).Routes); got != 2 {
		t.Fatalf("%d routes on disk, want 2 (the original plus one winner)", got)
	}
}

func TestEditRouteChangesTheUpstream(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/routes/app.test",
		`{"port":5000,"version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}

	out := getConfig(t, s)
	if len(out.Routes) != 1 {
		t.Fatalf("%d routes, want 1", len(out.Routes))
	}
	// localhost, not 127.0.0.1. Route.UpstreamAddr resolves a bare port via
	// net.JoinHostPort("localhost", port). Only an explicitly set upstream
	// comes back verbatim.
	if out.Routes[0].Upstream != "localhost:5000" {
		t.Errorf("upstream %q, want localhost:5000", out.Routes[0].Upstream)
	}
}

// Renaming has to clear the old shorthand as well as set the new one.
// Leaving Port set while Upstream is also set makes Validate reject the
// whole config, which would be a confusing 422 on the next unrelated write.
func TestEditRouteSwitchingToAnUpstreamClearsThePort(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/routes/app.test",
		`{"upstream":"127.0.0.1:6000","version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if got := getConfig(t, s).Routes[0].Upstream; got != "127.0.0.1:6000" {
		t.Errorf("upstream %q", got)
	}
}

func TestEditRouteRenamesTheDomain(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/routes/app.test",
		`{"domain":"web","version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if got := getConfig(t, s).Routes[0].Domain; got != "web.test" {
		t.Errorf("domain %q, want web.test", got)
	}
}

func TestEditUnknownRouteIs404(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/routes/nope.test",
		`{"port":5000,"version":"`+version+`"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", w.Code, w.Body)
	}
}

func TestDeleteRouteRemovesIt(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "DELETE", "/api/routes/app.test?version="+version, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if got := len(getConfig(t, s).Routes); got != 0 {
		t.Fatalf("%d routes left, want 0", got)
	}
}

func TestDeleteUnknownRouteIs404(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "DELETE", "/api/routes/nope.test?version="+version, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", w.Code, w.Body)
	}
}

func TestDeleteRouteRejectsAStaleVersion(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	w := write(t, s, "DELETE", "/api/routes/app.test?version=0000000000000000", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", w.Code)
	}
}
