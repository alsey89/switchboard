// The config endpoints. Reading is a straight projection of the file plus
// the effective values the accessors resolve. Writing lives here too,
// because the version guard and the read projection have to agree about
// what a config looks like on the wire.
package dashboard

import (
	"encoding/json"
	"errors"
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

// configPatch is the wire shape for a settings change.
//
// Every field is a pointer so an absent field is distinguishable from a zero
// one. A settings form that sends one changed field must not silently reset
// everything it left out, and a plain bool cannot express that.
//
// The sudo-tier fields are present on purpose. They are refused with an
// explanation naming the CLI command, which is a better answer than a
// silently ignored field or a 400 that does not say why.
type configPatch struct {
	Version string `json:"version"`

	DashboardPort *int `json:"dashboardPort"`

	Inspect *struct {
		Enabled      *bool   `json:"enabled"`
		Bodies       *bool   `json:"bodies"`
		MaxRequests  *int    `json:"maxRequests"`
		MaxBytes     *int64  `json:"maxBytes"`
		MaxBodyBytes *int    `json:"maxBodyBytes"`
		MaxAge       *string `json:"maxAge"`
	} `json:"inspect"`

	// Refused. See sudoTierRefusal.
	Suffix    *string `json:"suffix"`
	HTTPPort  *int    `json:"httpPort"`
	HTTPSPort *int    `json:"httpsPort"`
	DNSPort   *int    `json:"dnsPort"`
}

// sudoTierRefusal explains why a field cannot be set here and what to run
// instead. These are not arbitrary exclusions:
//
//   - suffix rewrites /etc/resolver and re-issues the CA. Both need sudo,
//     and the CA also needs a keychain authorization.
//   - dns_port is written into the resolver file, so changing it means
//     rewriting a root-owned file.
//   - http_port and https_port do nothing under a launch daemon. The
//     privileged parent hardcodes 443 and 80, because root must never learn
//     a port number from a file any local process can rewrite. See ADR 0001.
func sudoTierRefusal(field string) error {
	switch field {
	case "suffix":
		return errors.New("the suffix rewrites /etc/resolver and re-issues the CA, " +
			"so it needs sudo. Run: switchboard suffix <new-suffix>")
	case "dns_port":
		return errors.New("the DNS port is written into /etc/resolver, so changing it " +
			"needs sudo. Set dns_port in the config file, then run: switchboard setup")
	default:
		return errors.New("the HTTP and HTTPS ports are bound by the privileged parent " +
			"and cannot be set from here. Set them in the config file, then run: " +
			"switchboard daemon install")
	}
}

func (s *Server) handleConfigPatch(w http.ResponseWriter, r *http.Request) {
	var in configPatch
	if !decodeBody(w, r, &in) {
		return
	}
	ok := s.withConfig(w, in.Version, func(cfg *config.Config) error {
		switch {
		case in.Suffix != nil:
			return sudoTierRefusal("suffix")
		case in.DNSPort != nil:
			return sudoTierRefusal("dns_port")
		case in.HTTPPort != nil, in.HTTPSPort != nil:
			return sudoTierRefusal("ports")
		}
		if in.DashboardPort != nil {
			cfg.DashboardPort = *in.DashboardPort
		}
		if in.Inspect != nil {
			if cfg.Inspect == nil {
				cfg.Inspect = &config.InspectConfig{}
			}
			p, c := in.Inspect, cfg.Inspect
			if p.Enabled != nil {
				c.Enabled = p.Enabled
			}
			if p.Bodies != nil {
				c.Bodies = *p.Bodies
			}
			if p.MaxRequests != nil {
				c.MaxRequests = *p.MaxRequests
			}
			if p.MaxBytes != nil {
				c.MaxBytes = *p.MaxBytes
			}
			if p.MaxBodyBytes != nil {
				c.MaxBodyBytes = *p.MaxBodyBytes
			}
			if p.MaxAge != nil {
				c.MaxAge = *p.MaxAge
			}
		}
		return nil
	})
	if !ok {
		return
	}
	s.writeConfigView(w, http.StatusOK)
}
