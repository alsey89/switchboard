// Route writes. Split from configapi.go because routes are a list with their
// own identity and naming rules, while the rest of the config is scalar
// fields. They change for different reasons.
package dashboard

import (
	"fmt"
	"net/http"

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
