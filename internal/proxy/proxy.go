// Package proxy generates Caddy configuration from Switchboard's config and
// drives the embedded Caddy instance. Caddy supplies the reverse proxy, TLS
// termination, the internal PKI (local CA + on-demand per-host certs), and
// hot config reloads; Switchboard's job is only to describe what it wants.
//
// The admin API is left disabled: reloads are in-process caddy.Load calls,
// so there is no management socket to secure or collide with a user's own
// Caddy installation.
package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/caddy/v2/modules/filestorage"

	// Handler modules referenced by the generated config.
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/listen"
)

// mustPort extracts the port from a host:port we built ourselves.
func mustPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

const caName = "Switchboard Local CA"

// Addrs reports the addresses the proxy will actually serve on. When the
// daemon was started by a privileged parent the inherited socket wins over
// the configured port: the daemon did not choose that port, it was handed a
// descriptor already bound to it. Callers use this rather than the config so
// that what they log and link to is what is really true.
func Addrs(cfg *config.Config, set *listen.Set) (httpsAddr, httpAddr string) {
	httpsAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffHTTPSPort()))
	httpAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffHTTPPort()))
	if a := set.Addr(listen.HTTPS); a != "" {
		httpsAddr = a
	}
	if a := set.Addr(listen.HTTP); a != "" {
		httpAddr = a
	}
	return httpsAddr, httpAddr
}

// Generate builds the full Caddy config for the given Switchboard config.
// dataDir is where Caddy keeps state (PKI, certs); it must be writable.
// set carries any listening sockets inherited from a privileged parent.
func Generate(cfg *config.Config, dataDir string, set *listen.Set) (*caddy.Config, error) {
	httpsAddr, httpAddr := Addrs(cfg, set)
	httpsPort := mustPort(httpsAddr)
	httpPort := mustPort(httpAddr)
	listenAddrs := registerInherited(set, map[string]string{
		listen.HTTPS: httpsAddr,
		listen.HTTP:  httpAddr,
	})
	dashAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffDashboardPort()))
	domains := cfg.Domains()

	// --- HTTPS server: explicit routes, then catch-all to the dashboard,
	// which renders the "no route" page for unknown hosts.
	var routes caddyhttp.RouteList
	for _, r := range cfg.Routes {
		routes = append(routes, caddyhttp.Route{
			MatcherSetsRaw: hostMatcher(r.Domain),
			HandlersRaw:    []json.RawMessage{reverseProxyTo(r.UpstreamAddr())},
			Terminal:       true,
		})
	}
	routes = append(routes, caddyhttp.Route{
		HandlersRaw: []json.RawMessage{reverseProxyTo(dashAddr)},
	})

	httpsServer := &caddyhttp.Server{
		Listen:          []string{listenAddrs[listen.HTTPS]},
		Routes:          routes,
		TLSConnPolicies: caddytls.ConnectionPolicies{&caddytls.ConnectionPolicy{}},
		// We manage cert automation and redirects explicitly.
		AutoHTTPS: &caddyhttp.AutoHTTPSConfig{Disabled: true},
		// h1 and h2 only. HTTP/3 would make Caddy bind a UDP socket on the
		// same port, which for :443 is a second privileged bind that the
		// privileged parent would have to hold and hand over. Local browsers
		// negotiate h2 over TLS anyway, so the whole of what h3 buys here is
		// an extra descriptor in the root-owned path.
		Protocols: []string{"h1", "h2"},
	}

	// --- HTTP server: permanent redirect to HTTPS.
	location := "https://{http.request.host}"
	if httpsPort != 443 {
		location += ":" + strconv.Itoa(httpsPort)
	}
	location += "{http.request.uri}"
	httpServer := &caddyhttp.Server{
		Listen:    []string{listenAddrs[listen.HTTP]},
		AutoHTTPS: &caddyhttp.AutoHTTPSConfig{Disabled: true},
		Protocols: []string{"h1"}, // plain-HTTP redirector; silences h2/h3-need-TLS warnings
		Routes: caddyhttp.RouteList{{
			HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(
				caddyhttp.StaticResponse{
					StatusCode: caddyhttp.WeakString("308"),
					Headers:    http.Header{"Location": []string{location}},
				}, "handler", "static_response", nil)},
		}},
	}

	httpApp := caddyhttp.App{
		HTTPPort:  httpPort,
		HTTPSPort: httpsPort,
		Servers: map[string]*caddyhttp.Server{
			"https": httpsServer,
			"http":  httpServer,
		},
	}

	// --- TLS app: internal issuer for everything.
	//  policy 1: eager certs for configured domains (+ dashboard)
	//  policy 2: catch-all on-demand issuance for anything else under the
	//            managed suffixes, gated by our permission module
	internal := caddyconfig.JSONModuleObject(caddytls.InternalIssuer{}, "module", "internal", nil)
	tlsApp := caddytls.TLS{
		CertificatesRaw: caddy.ModuleMap{
			"automate": caddyconfig.JSON(caddytls.AutomateLoader(domains), nil),
		},
		Automation: &caddytls.AutomationConfig{
			Policies: []*caddytls.AutomationPolicy{
				{SubjectsRaw: domains, IssuersRaw: []json.RawMessage{internal}},
				{OnDemand: true, IssuersRaw: []json.RawMessage{internal}},
			},
			OnDemand: &caddytls.OnDemandConfig{
				PermissionRaw: caddyconfig.JSONModuleObject(
					OnDemandPermission{Suffixes: []string{cfg.Suffix}},
					"module", "switchboard", nil),
			},
		},
	}

	// The root is Switchboard's, not Caddy's: we mint it with name
	// constraints (see ca.go) and hand it over, because Caddy's PKI has no
	// way to express them. Caddy still owns the intermediate and the leaves.
	rootPath, err := EnsureRoot(dataDir, cfg.Suffix)
	if err != nil {
		return nil, err
	}

	falseVal := false
	pkiApp := caddypki.PKI{CAs: map[string]*caddypki.CA{
		"local": {
			Name:                   caName,
			RootCommonName:         caName,
			IntermediateCommonName: caName + " - Intermediate",
			Root: &caddypki.KeyPair{
				Certificate: rootPath,
				PrivateKey:  rootKeyPath(dataDir),
				Format:      "pem_file",
			},
			// Trust is installed explicitly by `switchboard setup`, never
			// implicitly at daemon start.
			InstallTrust: &falseVal,
		},
	}}

	cc := &caddy.Config{
		Admin: &caddy.AdminConfig{Disabled: true},
		Logging: &caddy.Logging{Logs: map[string]*caddy.CustomLog{
			"default": {BaseLog: caddy.BaseLog{Level: "WARN"}},
		}},
		StorageRaw: caddyconfig.JSONModuleObject(
			filestorage.FileStorage{Root: caddyStorageDir(dataDir)},
			"module", "file_system", nil),
		AppsRaw: caddy.ModuleMap{
			"http": caddyconfig.JSON(httpApp, nil),
			"tls":  caddyconfig.JSON(tlsApp, nil),
			"pki":  caddyconfig.JSON(pkiApp, nil),
		},
	}
	return cc, nil
}

func hostMatcher(domain string) caddyhttp.RawMatcherSets {
	return caddyhttp.RawMatcherSets{caddy.ModuleMap{
		"host": caddyconfig.JSON(caddyhttp.MatchHost{domain}, nil),
	}}
}

func reverseProxyTo(dial string) json.RawMessage {
	return caddyconfig.JSONModuleObject(reverseproxy.Handler{
		Upstreams: reverseproxy.UpstreamPool{{Dial: dial}},
	}, "handler", "reverse_proxy", nil)
}

// Load generates and (re)loads the Caddy config in-process. Safe to call
// again for hot reloads; Caddy swaps configs gracefully.
func Load(cfg *config.Config, dataDir string, set *listen.Set) error {
	cc, err := Generate(cfg, dataDir, set)
	if err != nil {
		return err
	}
	j, err := json.Marshal(cc)
	if err != nil {
		return fmt.Errorf("marshaling caddy config: %w", err)
	}
	if err := caddy.Load(j, true); err != nil {
		return fmt.Errorf("loading caddy config: %w", err)
	}
	return nil
}

// Stop shuts the embedded Caddy down.
func Stop() error { return caddy.Stop() }

func caddyStorageDir(dataDir string) string { return filepath.Join(dataDir, "caddy") }
