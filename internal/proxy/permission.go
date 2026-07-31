package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(OnDemandPermission{})
}

// OnDemandPermission gates Caddy's on-demand certificate issuance to names
// under Switchboard's managed suffixes. On-demand issuance is what lets an
// *unconfigured* name like whoops.test complete a TLS handshake so the
// proxy can show the friendly "no route" page; this module makes sure the
// local CA never mints a certificate for anything outside the managed
// suffix — e.g. a client connecting to 127.0.0.1:443 with SNI google.com is
// refused at handshake time.
type OnDemandPermission struct {
	// Suffixes are the managed domain suffixes, without leading dots.
	Suffixes []string `json:"suffixes,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (OnDemandPermission) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.permission.switchboard",
		New: func() caddy.Module { return new(OnDemandPermission) },
	}
}

// CertificateAllowed implements caddytls.OnDemandPermission.
func (p *OnDemandPermission) CertificateAllowed(_ context.Context, name string) error {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, s := range p.Suffixes {
		if n == s || strings.HasSuffix(n, "."+s) {
			return nil
		}
	}
	return fmt.Errorf("switchboard: %q is outside the managed suffixes %v", name, p.Suffixes)
}

var _ caddytls.OnDemandPermission = (*OnDemandPermission)(nil)
