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

// mux builds the routing table. Split out from Start so tests can drive the
// real routes without binding a port.
func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/routes", s.handleAPIRoutes)
	mux.HandleFunc("/api/inspect/requests", s.guard(s.handleInspectRequests))
	mux.HandleFunc("/api/inspect/requests/", s.guard(s.handleInspectRecord))
	mux.HandleFunc("/api/inspect/clear", s.guard(s.handleInspectClear))
	mux.HandleFunc("/api/inspect/stream", s.guard(s.handleInspectStream))
	mux.HandleFunc("/inspect", s.guard(s.handleInspectPage))
	mux.HandleFunc("/", s.handleRoot)
	return mux
}

// guard rejects requests whose Host is neither the dashboard domain nor a
// direct loopback address.
//
// handleRoot answers a foreign Host with the friendly "no route" page,
// because a browser landing on an unrouted *.test name deserves an
// explanation. An API path does not: there is no user reading it, so it gets
// a flat 404 and no hint that anything is here.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(hostOnly(r.Host))
		if host != s.cfg.Load().DashboardDomain() && !isLoopbackHost(host) {
			http.NotFound(w, r)
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
// This is safe for read-only endpoints because the listener is bound to
// 127.0.0.1: nothing off-box can reach it. It stops being sufficient the
// moment the dashboard grows state-changing endpoints. At that point, two
// attack vectors open: any web page can simply fetch("http://127.0.0.1:port/...")
// and have the browser send the Host header and cookies — a direct CSRF attack
// that requires no DNS cooperation — or it can rebind its own domain name to
// 127.0.0.1 and point the browser there. Both require an Origin check on
// mutations. Foreign Host values are rejected below to keep the attack surface
// small today; the check is necessary but not sufficient once mutations land.
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
	host := strings.ToLower(hostOnly(r.Host))

	if host != cfg.DashboardDomain() && !isLoopbackHost(host) {
		s.renderNoRoute(w, cfg, host)
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
