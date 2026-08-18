// Route writes. Split from configapi.go because routes are a list with their
// own identity and naming rules, while the rest of the config is scalar
// fields. They change for different reasons.
package dashboard

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/alsey89/switchboard/internal/config"
)

// routeBody is the wire shape for creating or editing a route. Port and
// Upstream mirror config.Route, where exactly one of the two is set and
// Validate enforces it.
type routeBody struct {
	Domain   string `json:"domain"`
	Port     int    `json:"port"`
	Upstream string `json:"upstream"`
	Version  string `json:"version"`
}

func (s *Server) handleRouteCreate(w http.ResponseWriter, r *http.Request) {
	var in routeBody
	if !decodeBody(w, r, &in) {
		return
	}
	ok := s.withConfig(w, in.Version, func(cfg *config.Config) error {
		// NormalizeDomain is what `switchboard add` uses. Two ways to add a
		// route that disagreed about bare names would be worse than one.
		// It also rejects the reserved dashboard name.
		domain, err := config.NormalizeDomain(in.Domain, cfg.Suffix)
		if err != nil {
			return err
		}
		for _, rt := range cfg.Routes {
			if rt.Domain == domain {
				return fmt.Errorf("%s already has a route", domain)
			}
		}
		cfg.Routes = append(cfg.Routes, config.Route{
			Domain: domain, Port: in.Port, Upstream: in.Upstream,
		})
		return nil
	})
	if !ok {
		return
	}
	s.writeConfigView(w, http.StatusCreated)
}

// findRoute returns the index of domain in cfg.Routes, or -1.
func findRoute(cfg *config.Config, domain string) int {
	for i, rt := range cfg.Routes {
		if rt.Domain == domain {
			return i
		}
	}
	return -1
}

// routeDomainFromPath pulls the domain out of /api/routes/<domain>. Returns
// "" for a bare /api/routes/ with nothing after it.
func routeDomainFromPath(p string) string {
	return strings.TrimPrefix(p, "/api/routes/")
}

// routeExists reports whether domain currently has a route.
//
// This lookup happens before withConfig, not inside it. Inside, the only way
// to signal "no such route" is to return an error, and withConfig has
// already written a 422 by the time the handler could correct it. A missing
// route is a 404. Doing the lookup first is the only way to say so.
//
// The read is unlocked and could go stale, but withConfig re-checks under
// the lock and answers 409 if the file moved. The worst case is a 404 for a
// route deleted microseconds ago, which is the right answer anyway.
func (s *Server) routeExists(domain string) (bool, bool) {
	p := s.paths.Load()
	if p == nil {
		return false, false
	}
	cfg, _, err := config.LoadWithVersion(p.configPath)
	if err != nil {
		return false, false
	}
	return findRoute(cfg, domain) >= 0, true
}

func (s *Server) handleRouteEdit(w http.ResponseWriter, r *http.Request) {
	target := routeDomainFromPath(r.URL.Path)
	var in routeBody
	if !decodeBody(w, r, &in) {
		return
	}
	if found, ok := s.routeExists(target); ok && !found {
		http.Error(w, "no route for "+target, http.StatusNotFound)
		return
	}

	ok := s.withConfig(w, in.Version, func(cfg *config.Config) error {
		i := findRoute(cfg, target)
		if i < 0 {
			return fmt.Errorf("no route for %s", target)
		}
		if in.Domain != "" {
			domain, err := config.NormalizeDomain(in.Domain, cfg.Suffix)
			if err != nil {
				return err
			}
			if j := findRoute(cfg, domain); j >= 0 && j != i {
				return fmt.Errorf("%s already has a route", domain)
			}
			cfg.Routes[i].Domain = domain
		}
		// Exactly one of Port and Upstream may be set, so setting either one
		// must clear the other. Leaving both would make Validate reject the
		// whole config, and the user would see a 422 about a field they did
		// not touch.
		switch {
		case in.Upstream != "":
			cfg.Routes[i].Upstream = in.Upstream
			cfg.Routes[i].Port = 0
		case in.Port != 0:
			cfg.Routes[i].Port = in.Port
			cfg.Routes[i].Upstream = ""
		}
		return nil
	})
	if !ok {
		return
	}
	s.writeConfigView(w, http.StatusOK)
}

func (s *Server) handleRouteDelete(w http.ResponseWriter, r *http.Request) {
	target := routeDomainFromPath(r.URL.Path)
	if found, ok := s.routeExists(target); ok && !found {
		http.Error(w, "no route for "+target, http.StatusNotFound)
		return
	}

	ok := s.withConfig(w, r.URL.Query().Get("version"), func(cfg *config.Config) error {
		i := findRoute(cfg, target)
		if i < 0 {
			return fmt.Errorf("no route for %s", target)
		}
		cfg.Routes = append(cfg.Routes[:i], cfg.Routes[i+1:]...)
		return nil
	})
	if !ok {
		return
	}
	// 200 with the new config, not 204. The client needs the new version to
	// make its next write, and a 204 would force an immediate read to get it.
	s.writeConfigView(w, http.StatusOK)
}
