// Package dashboard is the daemon's built-in HTTP handler. The embedded
// Caddy proxies two kinds of traffic here:
//
//   - https://switchboard.<tld> — the dashboard: live route table + status
//   - any unrouted host under the managed TLD — a friendly "no route" page
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
)

//go:embed templates/*.html
var templateFS embed.FS

var tmpl = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// Server serves the dashboard and no-route pages.
type Server struct {
	cfg     atomic.Pointer[config.Config]
	version string
	httpSrv *http.Server
}

func New(cfg *config.Config, version string) *Server {
	s := &Server{version: version}
	s.cfg.Store(cfg)
	return s
}

// SetConfig swaps the config shown by the dashboard (called on hot reload).
func (s *Server) SetConfig(cfg *config.Config) { s.cfg.Store(cfg) }

// Start begins serving on bind (e.g. "127.0.0.1:8484").
func (s *Server) Start(bind string) error {
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/routes", s.handleAPIRoutes)
	mux.HandleFunc("/", s.handleRoot)
	s.httpSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go s.httpSrv.Serve(ln) //nolint:errcheck // exits on Shutdown
	return nil
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

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()
	host := strings.ToLower(hostOnly(r.Host))

	if host != cfg.DashboardDomain() {
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
		TLD     string
		Routes  []routeView
	}{Version: s.version, TLD: cfg.TLD}
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
		TLD     string      `json:"tld"`
		Routes  []routeJSON `json:"routes"`
	}{Version: s.version, TLD: cfg.TLD, Routes: []routeJSON{}}
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
