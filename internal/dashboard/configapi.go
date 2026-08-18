// The config endpoints. Reading is a straight projection of the file plus
// the effective values the accessors resolve. Writing lives here too,
// because the version guard and the read projection have to agree about
// what a config looks like on the wire.
package dashboard

import (
	"encoding/json"
	"net/http"

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
