// Package dashboard is the daemon's built-in HTTP handler. The embedded
// Caddy proxies two kinds of traffic here:
//
//   - https://switchboard.<suffix> — the dashboard: live route table + status
//   - any unrouted host under the managed suffix — a friendly "no route" page
//     (this is why DNS answers for every *.test name, routed or not)
//
// It listens on plain HTTP on a loopback port; TLS is Caddy's job.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/inspect"
)

//go:embed templates/*.html
var templateFS embed.FS

var tmpl = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// Server serves the dashboard and no-route pages.
type Server struct {
	cfg     atomic.Pointer[config.Config]
	version string
	httpSrv *http.Server
	insp    atomic.Pointer[inspect.Recorder]
}

func New(cfg *config.Config, version string) *Server {
	s := &Server{version: version}
	s.cfg.Store(cfg)
	return s
}

// SetConfig swaps the config shown by the dashboard (called on hot reload).
func (s *Server) SetConfig(cfg *config.Config) { s.cfg.Store(cfg) }

// SetInspector installs the request recorder the inspector pages read from.
// A nil recorder means the inspector is off and its endpoints answer 503.
func (s *Server) SetInspector(r *inspect.Recorder) { s.insp.Store(r) }

// Start begins serving on bind (e.g. "127.0.0.1:8484").
func (s *Server) Start(bind string) error {
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	s.httpSrv = &http.Server{Handler: s.mux(), ReadHeaderTimeout: 10 * time.Second}
	go s.httpSrv.Serve(ln) //nolint:errcheck // exits on Shutdown
	return nil
}

// routeEntry pairs a mux pattern with its handler and whether the handler
// enforces the Host guard. mux() registers this table, and
// TestEveryGuardedRouteRejectsAForeignHost walks the same table, so a route
// that forgets the guard fails that test by construction. That is exactly
// how /api/routes escaped the guard in the first place: it lived only in
// mux()'s hand-written list, and the equivalent hand-written test list
// never had a reason to know it existed.
type routeEntry struct {
	pattern string
	handler http.HandlerFunc
	guarded bool
}

func (s *Server) routes() []routeEntry {
	return []routeEntry{
		{"/api/routes", s.guard(s.handleAPIRoutes), true},
		{"/api/inspect/requests", s.guard(s.handleInspectRequests), true},
		{"/api/inspect/requests/", s.guard(s.handleInspectRecord), true},
		{"/api/inspect/clear", s.guard(s.handleInspectClear), true},
		{"/api/inspect/stream", s.guard(s.handleInspectStream), true},
		{"/inspect", s.guardPage(s.handleInspectPage), true},
		// handleRoot is its own guard: it needs the "/" vs any-other-path
		// split alongside the host check, and it answers a foreign Host
		// with the no-route page rather than delegating to guardPage.
		{"/", s.handleRoot, false},
	}
}

// mux builds the routing table. Split out from Start so tests can drive the
// real routes without binding a port.
func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		mux.HandleFunc(rt.pattern, rt.handler)
	}
	return mux
}

// hostAllowed reports whether hostport (an HTTP Host header, with or
// without a port) names this dashboard: either its own domain or a direct
// loopback address. guard, guardPage and handleRoot all defer to this one
// predicate instead of each repeating the comparison.
func (s *Server) hostAllowed(hostport string) bool {
	host := strings.ToLower(hostOnly(hostport))
	return host == s.cfg.Load().DashboardDomain() || isLoopbackHost(host)
}

// guard rejects requests whose Host fails hostAllowed with a flat 404: API
// paths have no user reading them, so there is no one for a friendlier
// answer to be for.
//
// guard is necessary for a mutating route but not sufficient by itself —
// see the note on isLoopbackHost below. A route that changes state must
// also check sameOrigin (inspect.go), the way handleInspectClear does;
// guard alone only proves the Host header matched, and a Host header is
// something an attacker's page gets to send too.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}

// guardPage is guard's counterpart for a page a user navigates to directly
// rather than a script fetching JSON: a foreign Host renders the same
// friendly no-route page handleRoot uses, instead of guard's flat 404.
func (s *Server) guardPage(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			s.renderNoRoute(w, s.cfg.Load(), strings.ToLower(hostOnly(r.Host)))
			return
		}
		h(w, r)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// hostOnly strips any :port from an HTTP Host value.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// isLoopbackHost reports whether a Host header names this machine directly.
// The dashboard answers on these as well as on its own domain: when the
// resolver file or the CA trust is broken, http://127.0.0.1:8484 is the only
// way in — which is exactly when you need to read the diagnostics.
//
// A Host check alone was sufficient while every endpoint was read-only,
// because the listener is bound to 127.0.0.1 and nothing off-box can reach
// it directly. It stopped being sufficient the moment the dashboard grew
// its first state-changing endpoint: any web page can simply
// fetch("http://127.0.0.1:port/...") and have the browser send the Host
// header — a CSRF attack that needs no DNS cooperation — or it can rebind
// its own domain name to 127.0.0.1 and point the browser there. Either way,
// a POST from an attacker's page sails through a Host check by itself.
//
// That endpoint landed in inspect.go: handleInspectClear pairs guard with
// sameOrigin, which requires an Origin header that is present and matches.
// Any future mutating route must do the same — a Host check is necessary
// for one but was never sufficient on its own.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	// Strip a single matched [...]  pair for IPv6 literals.
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()

	if !s.hostAllowed(r.Host) {
		s.renderNoRoute(w, cfg, strings.ToLower(hostOnly(r.Host)))
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	type routeView struct {
		Domain, Upstream string
		Up               bool
	}
	data := struct {
		Version string
		Suffix  string
		Routes  []routeView
	}{Version: s.version, Suffix: cfg.Suffix}
	for _, rt := range cfg.Routes {
		data.Routes = append(data.Routes, routeView{
			Domain:   rt.Domain,
			Upstream: rt.UpstreamAddr(),
			Up:       probe(rt.UpstreamAddr()),
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "dashboard.html", data) //nolint:errcheck
}

func (s *Server) renderNoRoute(w http.ResponseWriter, cfg *config.Config, host string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	// host is attacker-ish input (the Host header); html/template escapes it.
	tmpl.ExecuteTemplate(w, "noroute.html", struct { //nolint:errcheck
		Host, Dashboard string
	}{Host: host, Dashboard: cfg.DashboardDomain()})
}

func (s *Server) handleAPIRoutes(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()
	type routeJSON struct {
		Domain   string `json:"domain"`
		Upstream string `json:"upstream"`
		Up       bool   `json:"up"`
	}
	out := struct {
		Version string      `json:"version"`
		Suffix  string      `json:"suffix"`
		Routes  []routeJSON `json:"routes"`
	}{Version: s.version, Suffix: cfg.Suffix, Routes: []routeJSON{}}
	for _, rt := range cfg.Routes {
		out.Routes = append(out.Routes, routeJSON{
			Domain:   rt.Domain,
			Upstream: rt.UpstreamAddr(),
			Up:       probe(rt.UpstreamAddr()),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// probe reports whether something is listening at addr.
func probe(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
