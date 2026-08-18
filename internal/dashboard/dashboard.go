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
	"sync"
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
	probes  *prober
	httpSrv *http.Server
	insp    atomic.Pointer[inspect.Recorder]

	// paths are the filesystem locations the diagnostic and write endpoints
	// need. Injected after New rather than passed to it, matching
	// SetInspector: New is called in tests that have no filesystem, and a
	// handler with no paths answers 503 exactly as an inspector handler does
	// when capture is off.
	paths atomic.Pointer[paths]

	// done is closed by Shutdown, before http.Server.Shutdown runs. It is
	// how a long-lived handler learns the server wants to stop.
	//
	// http.Server.Shutdown waits for active requests to return and never
	// cancels their contexts, so a handler that only watches the client
	// (the SSE stream did) blocks shutdown for as long as the browser tab
	// stays open. An inspector left in a background tab held the whole
	// daemon up: no DNS teardown, no WAL checkpoint, and a second Ctrl-C
	// does nothing because signal.NotifyContext already owns the handler.
	done      chan struct{}
	closeOnce sync.Once
}

func New(cfg *config.Config, version string) *Server {
	s := &Server{version: version, done: make(chan struct{}), probes: newProber(probeTTL)}
	s.cfg.Store(cfg)
	return s
}

// SetConfig swaps the config shown by the dashboard (called on hot reload).
func (s *Server) SetConfig(cfg *config.Config) { s.cfg.Store(cfg) }

// SetInspector installs the request recorder the inspector pages read from.
// A nil recorder means the inspector is off and its endpoints answer 503.
func (s *Server) SetInspector(r *inspect.Recorder) { s.insp.Store(r) }

// paths is what SetPaths stores. A single pointer so the two values are
// always swapped together and a handler can never read one from before a
// reload and one from after.
type paths struct{ configPath, dataDir string }

// SetPaths tells the dashboard where the config file and data directory
// live. Without them the diagnostic and write endpoints answer 503.
func (s *Server) SetPaths(configPath, dataDir string) {
	s.paths.Store(&paths{configPath: configPath, dataDir: dataDir})
}

// pathsOr503 is the paths counterpart to recorder(): it answers the request
// itself when the dependency is absent, so callers stay a two-line guard.
func (s *Server) pathsOr503(w http.ResponseWriter) (*paths, bool) {
	p := s.paths.Load()
	if p == nil {
		http.Error(w, "this daemon was started without filesystem paths",
			http.StatusServiceUnavailable)
		return nil, false
	}
	return p, true
}

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

// routeEntry pairs a mux pattern with its handler and the protections the
// handler is claiming. mux() registers this table, and the guard tests walk
// the same table, so a route that forgets a protection fails those tests by
// construction. That is exactly how /api/routes escaped the guard in the
// first place: it lived only in mux()'s hand-written list, and the
// equivalent hand-written test list never had a reason to know it existed.
type routeEntry struct {
	// method is the HTTP method this entry serves. Empty means any method.
	// Kept separate from pattern rather than folded into it as Go 1.22's
	// "POST /path" syntax, because the guard tests need to build a request
	// from these fields and splitting a string back apart to do it is a
	// parser nobody should have to maintain.
	method   string
	pattern  string
	handler  http.HandlerFunc
	guarded  bool
	mutating bool
}

func (s *Server) routes() []routeEntry {
	return []routeEntry{
		{pattern: "/api/routes", handler: s.guard(s.handleAPIRoutes), guarded: true},
		{pattern: "/api/doctor", handler: s.guard(s.handleDoctor), guarded: true},
		{pattern: "/api/inspect/requests", handler: s.guard(s.handleInspectRequests), guarded: true},
		{pattern: "/api/inspect/requests/", handler: s.guard(s.handleInspectRecord), guarded: true},
		{pattern: "/api/inspect/clear", handler: s.guard(s.handleInspectClear), guarded: true},
		{pattern: "/api/inspect/stream", handler: s.guard(s.handleInspectStream), guarded: true},
		{pattern: "/inspect", handler: s.guardPage(s.handleInspectRedirect), guarded: true},
		// handleRoot is its own guard: it needs the "/" vs any-other-path
		// split alongside the host check, and it answers a foreign Host
		// with the no-route page rather than delegating to guardPage.
		{pattern: "/", handler: s.handleRoot},
	}
}

// mux builds the routing table. Split out from Start so tests can drive the
// real routes without binding a port.
func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		pattern := rt.pattern
		if rt.method != "" {
			pattern = rt.method + " " + pattern
		}
		mux.HandleFunc(pattern, rt.handler)
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

// Shutdown stops serving. It signals long-lived handlers first, then waits
// for http.Server to drain, so a handler that is watching s.done has already
// been told to leave by the time the wait begins. Safe to call twice.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closeOnce.Do(func() { close(s.done) })
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

	data := struct {
		Version string
		Suffix  string
		Routes  []routeView
		// Redacted is rendered into the page script, so inspect.Redacted is
		// the only place the sentinel is written down. The script compares a
		// header value against it to mark the value as redacted, and drops
		// the header from a copied curl command. Two copies of the string
		// would let one side change without the other, and the page would
		// quietly stop recognising a redacted value.
		Redacted string
	}{
		Version:  s.version,
		Suffix:   cfg.Suffix,
		Routes:   s.routeViews(cfg),
		Redacted: inspect.Redacted,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "console.html", data) //nolint:errcheck
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
	out := struct {
		Version string      `json:"version"`
		Suffix  string      `json:"suffix"`
		Routes  []routeView `json:"routes"`
	}{Version: s.version, Suffix: cfg.Suffix, Routes: s.routeViews(cfg)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// routeView is one route as both the console template and /api/routes show
// it. The rail is server rendered on load and refreshed from the API on a
// timer, so the two have to agree field for field. One type with both sets
// of names is how they are kept from drifting; the template reads the Go
// names and the encoder reads the tags.
type routeView struct {
	Domain   string `json:"domain"`
	Upstream string `json:"upstream"`
	Up       bool   `json:"up"`
}

// routeViews pairs every configured route with whether its upstream is up.
// It probes the whole set in one call, which is both what makes the dials
// concurrent and what satisfies statuses' precondition below. Never nil, so
// the JSON encoder writes [] rather than null for a config with no routes.
func (s *Server) routeViews(cfg *config.Config) []routeView {
	addrs := make([]string, len(cfg.Routes))
	for i, rt := range cfg.Routes {
		addrs[i] = rt.UpstreamAddr()
	}
	up := s.probes.statuses(addrs)
	out := make([]routeView, 0, len(cfg.Routes))
	for i, rt := range cfg.Routes {
		out = append(out, routeView{Domain: rt.Domain, Upstream: addrs[i], Up: up[addrs[i]]})
	}
	return out
}
