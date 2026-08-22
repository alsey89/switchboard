// Everything that decides whether a state-changing request is allowed.
//
// Kept in one file on purpose. The reasoning is subtle, the failure is
// silent, and a reviewer should be able to read the whole boundary without
// jumping between files. See docs/adr/0004 for the threat model.
package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// csrfHeader is where the page sends the token back.
const csrfHeader = "X-Switchboard-CSRF"

// newCSRFToken mints the per-process token.
//
// A foreign page cannot learn it. Reading the dashboard page cross-origin
// requires CORS, and this server grants none, so an attacker's page can fire
// a request it is unable to read the response to. The token is defence in
// depth behind sameOriginStrict, which is the real gate.
//
// Panics rather than degrading. A crypto/rand failure means the OS entropy
// source is gone, and quietly serving a predictable token would be worse
// than not starting.
func newCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("switchboard: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// sameOriginStrict is the origin check every write must pass.
//
// It is deliberately narrower than the host guard. hostAllowed accepts any
// loopback address, and that is right for reads: when the resolver file or
// the CA trust is broken, http://127.0.0.1:8484 is the only way in, and
// that is exactly the moment you need doctor. Loosening reads is the entire
// point of that allowance.
//
// It is wrong for writes. Every dev server this proxy sits in front of is on
// loopback too, so one bad npm dependency inside your own app would be
// inside the trust boundary and could repoint a route at a server it
// controls.
//
// Writes therefore require the dashboard's own domain, or loopback at the
// dashboard port specifically. Loopback with no explicit port is not the
// dashboard, since the dashboard never runs on 80 or 443.
//
// The port compared against is s.boundPort, the one the listener actually
// took, not cfg.EffDashboardPort(). Those two disagree the moment someone
// edits dashboard_port: the edit hot-reloads into s.cfg, but Start binds
// once and nothing rebinds. Keying on the config would 403 the URL that
// still works and start accepting writes from whatever process happens to
// be on the newly configured port.
func (s *Server) sameOriginStrict(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	host := strings.ToLower(hostOnly(u.Host))
	if host == s.cfg.Load().DashboardDomain() {
		return true
	}
	if !isLoopbackHost(host) {
		return false
	}
	// A Server whose Start never ran is serving on nothing, so no origin
	// can be at its port. Stated rather than left to the comparison, which
	// would otherwise let an origin of ":0" match an unbound server.
	if s.boundPort == 0 {
		return false
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return false
	}
	return port == strconv.Itoa(s.boundPort)
}

// mutate wraps a state-changing handler in the two checks a write needs on
// top of guard. Every entry in routes() marked mutating goes through this,
// and TestEveryMutatingRouteRejectsABadWrite walks the same table to prove
// it, so a new write endpoint cannot quietly skip it.
//
// guard still has to be applied as well. A Host check is necessary for a
// mutating route and was never sufficient on its own, because a Host header
// is something an attacker's page gets to send too.
func (s *Server) mutate(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sameOriginStrict(r) {
			http.Error(w, "bad origin", http.StatusForbidden)
			return
		}
		sent := []byte(r.Header.Get(csrfHeader))
		if subtle.ConstantTimeCompare(sent, []byte(s.csrf)) != 1 {
			http.Error(w, "bad csrf token", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}
