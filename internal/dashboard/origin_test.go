package dashboard

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// badWriteHeaders is every way a request can fail the write checks. Each
// case is a real attack shape, not a permutation for its own sake:
//
//   - no origin: a caller that is not a browser page acting for the user,
//     such as curl or a script. Not the form-post case: browsers do send
//     Origin on a cross-origin form post, which is what makes an
//     origin-based defence work at all. Absence is refused rather than read
//     as neutral, because it is not evidence of a good origin. (A sandboxed
//     frame sends Origin: null, a header that is present and fails
//     separately, since url.Parse leaves it with an empty host.)
//   - foreign origin: an ordinary hostile page
//   - loopback on another port: your own dev server, one bad npm dependency
//     deep. This is the case the old sameOrigin let through and the reason
//     sameOriginStrict exists.
//   - right origin, no or wrong token: defence in depth behind the above
func badWriteHeaders(goodToken string) []struct {
	name string
	hdr  map[string]string
} {
	return []struct {
		name string
		hdr  map[string]string
	}{
		{"no origin", map[string]string{"X-Switchboard-CSRF": goodToken}},
		{"foreign origin", map[string]string{
			"Origin": "https://evil.example", "X-Switchboard-CSRF": goodToken}},
		{"loopback on another port", map[string]string{
			"Origin": "http://127.0.0.1:3000", "X-Switchboard-CSRF": goodToken}},
		{"loopback with no port", map[string]string{
			"Origin": "http://127.0.0.1", "X-Switchboard-CSRF": goodToken}},
		{"right origin, no token", map[string]string{
			"Origin": "https://switchboard.test"}},
		{"right origin, wrong token", map[string]string{
			"Origin": "https://switchboard.test", "X-Switchboard-CSRF": "not-the-token"}},
	}
}

// TestEveryMutatingRouteRejectsABadWrite walks s.routes() the same way
// TestEveryGuardedRouteRejectsAForeignHost does, for the same reason: a
// write endpoint added without the mutate wrapper fails this by
// construction rather than by someone remembering to add a case.
func TestEveryMutatingRouteRejectsABadWrite(t *testing.T) {
	s, _ := testServer(t)

	var found int
	for _, rt := range s.routes() {
		if !rt.mutating {
			continue
		}
		found++
		// mutate is not a substitute for guard, and both origin.go and
		// dashboard.go say so. The two table walks skip on different
		// fields, so without this a route could be mutating and unguarded
		// and satisfy them both.
		if !rt.guarded {
			t.Errorf("%s is mutating but not guarded", rt.pattern)
		}
		target := rt.pattern
		if strings.HasSuffix(target, "/") {
			target += "app.test"
		}
		method := rt.method
		if method == "" {
			method = "POST"
		}
		for _, c := range badWriteHeaders(s.csrf) {
			t.Run(rt.pattern+" "+c.name, func(t *testing.T) {
				w := do(s, method, target, c.hdr)
				if w.Code != http.StatusForbidden {
					t.Fatalf("status %d, want 403", w.Code)
				}
			})
		}
	}
	// A vacuous pass is the failure mode this whole test exists to avoid.
	if found == 0 {
		t.Fatal("no mutating routes found; this test proved nothing")
	}
}

func TestGoodOriginAndTokenReachTheHandler(t *testing.T) {
	s, _ := testServer(t)
	hdr := map[string]string{
		"Origin":             "https://switchboard.test",
		"X-Switchboard-CSRF": s.csrf,
	}
	// handleInspectClear with a live recorder answers 204.
	if w := do(s, "POST", "/api/inspect/clear", hdr); w.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", w.Code, w.Body)
	}
}

// Loopback at the dashboard port is the break-glass path and must keep
// working for writes as well as reads. When the resolver file or the CA
// trust is broken, this is the only way to reach the dashboard at all.
func TestLoopbackAtTheDashboardPortIsAllowed(t *testing.T) {
	s, _ := testServer(t)
	hdr := map[string]string{
		"Origin":             "http://127.0.0.1:8484",
		"X-Switchboard-CSRF": s.csrf,
	}
	if w := do(s, "POST", "/api/inspect/clear", hdr); w.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204: %s", w.Code, w.Body)
	}
}

func TestTokenIsPerProcessAndNotEmpty(t *testing.T) {
	a, _ := testServer(t)
	b, _ := testServer(t)
	if a.csrf == "" {
		t.Fatal("token is empty")
	}
	if len(a.csrf) != 64 {
		t.Fatalf("token is %d chars, want 64 hex chars for 32 bytes", len(a.csrf))
	}
	if a.csrf == b.csrf {
		t.Fatal("two servers minted the same token")
	}
}

// TestThePageCarriesTheToken renders the console and looks for the token in
// it. The clear button posts the token back, so a rename of the template
// field would break the button and nothing else would notice: template
// execution errors are discarded on the response, so a missing field shows
// up as a page that stops rendering partway through, not as a failure.
func TestThePageCarriesTheToken(t *testing.T) {
	s, _ := testServer(t)
	w := do(s, "GET", "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	want := `<meta name="switchboard-csrf" content="` + s.csrf + `">`
	if !strings.Contains(w.Body.String(), want) {
		t.Fatalf("the page does not carry the token")
	}
}

// TestTheCheckFollowsTheBoundPort pins the loopback branch to the port the
// listener actually took. Every other loopback case in the suite uses the
// default 8484, so writing that literal into sameOriginStrict would leave
// the whole suite green and break everyone who set dashboard_port.
func TestTheCheckFollowsTheBoundPort(t *testing.T) {
	s, _ := testServer(t)
	s.boundPort = 9999

	at := func(origin string) int {
		return do(s, "POST", "/api/inspect/clear", map[string]string{
			"Origin": origin, "X-Switchboard-CSRF": s.csrf}).Code
	}
	if got := at("http://127.0.0.1:9999"); got != http.StatusNoContent {
		t.Errorf("status %d at the bound port, want 204", got)
	}
	if got := at("http://127.0.0.1:8484"); got != http.StatusForbidden {
		t.Errorf("status %d at the default port, want 403", got)
	}
}

// TestAnUnboundServerAcceptsNoLoopbackOrigin covers the zero value. A Server
// built by New and never started is serving on nothing, so no loopback
// origin can be at its port. Port 0 is the case worth naming: it is what a
// bare comparison against an unset boundPort would have accepted.
func TestAnUnboundServerAcceptsNoLoopbackOrigin(t *testing.T) {
	s, _ := testServer(t)
	s.boundPort = 0
	for _, origin := range []string{"http://127.0.0.1:0", "http://127.0.0.1:8484"} {
		w := do(s, "POST", "/api/inspect/clear", map[string]string{
			"Origin": origin, "X-Switchboard-CSRF": s.csrf})
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", origin, w.Code)
		}
	}
}

// TestStartRecordsThePortItBound is the wiring the two tests above assume.
// It binds port 0, so the only way to learn the real port is to ask the
// listener; parsing the bind string would yield 0 and every loopback write
// would then be refused. The assertion is that the recorded port is one a
// client can actually connect to.
func TestStartRecordsThePortItBound(t *testing.T) {
	s, _ := testServer(t)
	s.boundPort = 0
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) }) //nolint:errcheck
	if s.boundPort == 0 {
		t.Fatal("Start bound a port and recorded nothing")
	}
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(s.boundPort) + "/api/routes")
	if err != nil {
		t.Fatalf("the recorded port is not the one being served: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d from the recorded port, want 200", resp.StatusCode)
	}
}
