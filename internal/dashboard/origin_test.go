package dashboard

import (
	"net/http"
	"strings"
	"testing"
)

// badWriteHeaders is every way a request can fail the write checks. Each
// case is a real attack shape, not a permutation for its own sake:
//
//   - no origin: a form post, which browsers send with no Origin at all
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
