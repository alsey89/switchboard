// The config endpoints. Reading is a straight projection of the file plus
// the effective values the accessors resolve. Writing lives here too,
// because the version guard and the read projection have to agree about
// what a config looks like on the wire.
package dashboard

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/alsey89/switchboard/internal/config"
)

// configView is the config on the wire.
//
// It carries both what the file says and what the daemon actually uses.
// Those differ for every unset port, and a settings form needs both: the
// effective value to display, and the file value to know whether the field
// is explicitly set or inherited.
type configView struct {
	Version   string        `json:"version"`
	Suffix    string        `json:"suffix"`
	Routes    []routeView   `json:"routes"`
	Effective effectiveView `json:"effective"`
	Ports     portsView     `json:"ports"`
	Inspect   inspectView   `json:"inspect"`
}

// effectiveView is what the daemon runs with, defaults resolved.
type effectiveView struct {
	HTTPPort      int `json:"httpPort"`
	HTTPSPort     int `json:"httpsPort"`
	DNSPort       int `json:"dnsPort"`
	DashboardPort int `json:"dashboardPort"`
}

// portsView is what the file literally says. Zero means unset, which is a
// different fact from "set to the default" and the one a form needs.
type portsView struct {
	HTTPPort      int `json:"httpPort"`
	HTTPSPort     int `json:"httpsPort"`
	DNSPort       int `json:"dnsPort"`
	DashboardPort int `json:"dashboardPort"`
}

// inspectView resolves the inspect settings through the accessors. Never
// read the struct directly: the zero value of every field means default,
// and Enabled defaults to true.
type inspectView struct {
	Enabled      bool   `json:"enabled"`
	Bodies       bool   `json:"bodies"`
	MaxRequests  int    `json:"maxRequests"`
	MaxBytes     int64  `json:"maxBytes"`
	MaxBodyBytes int    `json:"maxBodyBytes"`
	MaxAge       string `json:"maxAge"`
}

func (s *Server) newConfigView(cfg *config.Config, version string) configView {
	return configView{
		Version: version,
		Suffix:  cfg.Suffix,
		Routes:  s.routeViews(cfg),
		Effective: effectiveView{
			HTTPPort:      cfg.EffHTTPPort(),
			HTTPSPort:     cfg.EffHTTPSPort(),
			DNSPort:       cfg.EffDNSPort(),
			DashboardPort: cfg.EffDashboardPort(),
		},
		Ports: portsView{
			HTTPPort:      cfg.HTTPPort,
			HTTPSPort:     cfg.HTTPSPort,
			DNSPort:       cfg.DNSPort,
			DashboardPort: cfg.DashboardPort,
		},
		Inspect: inspectView{
			Enabled:      cfg.InspectEnabled(),
			Bodies:       cfg.InspectBodies(),
			MaxRequests:  cfg.InspectMaxRequests(),
			MaxBytes:     cfg.InspectMaxBytes(),
			MaxBodyBytes: cfg.InspectMaxBodyBytes(),
			MaxAge:       cfg.InspectMaxAge().String(),
		},
	}
}

// writeConfigView answers with the config as it now stands on disk. Both
// the read endpoint and every successful write end here, so a client never
// has to follow a write with a read to find out what happened.
//
// status is a parameter rather than always 200 because a create answers 201.
// It cannot be left to the caller to WriteHeader first: Content-Type has to
// be set before the status is written, and a caller that got that order
// wrong would send a correct body with no content type and nothing would
// fail loudly.
func (s *Server) writeConfigView(w http.ResponseWriter, status int) bool {
	p, ok := s.pathsOr503(w)
	if !ok {
		return false
	}
	cfg, version, err := config.LoadWithVersion(p.configPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(s.newConfigView(cfg, version)) //nolint:errcheck
	return true
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.writeConfigView(w, http.StatusOK)
}

// writeMu serializes config writes from this process.
//
// It cannot serialize against the CLI, which does its own read-modify-write
// on the same file. That is what the version is for. A CLI write between a
// client's read and its write is caught by the version compare below. A CLI
// write inside this critical section is not, but that window is microseconds
// and the CLI is human paced. Named here so nobody mistakes it for an
// oversight and reaches for a lock file.
var writeMu sync.Mutex

// withConfig runs edit against a freshly read config, under the write lock,
// and saves the result. Every write endpoint goes through it, so no
// individual handler can forget the version guard.
//
// A stale version answers 409 with the current config in the body. The
// client has to re-render anyway, and making it fetch again is a round trip
// for information this response is already holding.
//
// Returns whether the write succeeded. On false it has already answered.
func (s *Server) withConfig(w http.ResponseWriter, wantVersion string, edit func(*config.Config) error) bool {
	p, ok := s.pathsOr503(w)
	if !ok {
		return false
	}

	writeMu.Lock()
	defer writeMu.Unlock()

	cfg, version, err := config.LoadWithVersion(p.configPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if wantVersion != version {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(s.newConfigView(cfg, version)) //nolint:errcheck
		return false
	}
	if err := edit(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return false
	}
	// Validate explicitly before Save. Save validates too, but it returns
	// one error for both a bad edit and a filesystem failure, and those are
	// a 422 and a 500 respectively.
	if err := cfg.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return false
	}
	if err := cfg.Save(p.configPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	return true
}

// decodeBody reads a JSON request body with a size cap. A config write is
// never large, and an uncapped decoder on a loopback listener is still an
// uncapped decoder.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return false
	}
	return true
}
