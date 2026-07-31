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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/caddy/v2/modules/filestorage"

	// Handler modules referenced by the generated config.
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"

	"github.com/alsey89/switchboard/internal/config"
)

const caName = "Switchboard Local CA"

// Generate builds the full Caddy config for the given Switchboard config.
// dataDir is where Caddy keeps state (PKI, certs); it must be writable.
func Generate(cfg *config.Config, dataDir string) (*caddy.Config, error) {
	httpsPort := cfg.EffHTTPSPort()
	httpPort := cfg.EffHTTPPort()
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
		Listen:          []string{"127.0.0.1:" + strconv.Itoa(httpsPort)},
		Routes:          routes,
		TLSConnPolicies: caddytls.ConnectionPolicies{&caddytls.ConnectionPolicy{}},
		// We manage cert automation and redirects explicitly.
		AutoHTTPS: &caddyhttp.AutoHTTPSConfig{Disabled: true},
	}

	// --- HTTP server: permanent redirect to HTTPS.
	location := "https://{http.request.host}"
	if httpsPort != 443 {
		location += ":" + strconv.Itoa(httpsPort)
	}
	location += "{http.request.uri}"
	httpServer := &caddyhttp.Server{
		Listen:    []string{"127.0.0.1:" + strconv.Itoa(httpPort)},
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

	falseVal := false
	pkiApp := caddypki.PKI{CAs: map[string]*caddypki.CA{
		"local": {
			Name:                   caName,
			RootCommonName:         caName,
			IntermediateCommonName: caName + " - Intermediate",
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
func Load(cfg *config.Config, dataDir string) error {
	cc, err := Generate(cfg, dataDir)
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

// RootCertPath is where Caddy's internal PKI keeps the root CA certificate.
func RootCertPath(dataDir string) string {
	return filepath.Join(caddyStorageDir(dataDir), "pki", "authorities", "local", "root.crt")
}

// EnsureCA makes sure the local root CA exists without starting any
// listeners: it loads a PKI-only Caddy config, waits for the root
// certificate to land in storage, and shuts down. Used by `setup`, which
// needs the root cert before the daemon has ever run.
func EnsureCA(ctx context.Context, dataDir string) (string, error) {
	rootPath := RootCertPath(dataDir)
	if _, err := os.Stat(rootPath); err == nil {
		return rootPath, nil
	}

	falseVal := false
	cc := &caddy.Config{
		Admin: &caddy.AdminConfig{Disabled: true},
		Logging: &caddy.Logging{Logs: map[string]*caddy.CustomLog{
			"default": {BaseLog: caddy.BaseLog{Level: "ERROR"}},
		}},
		StorageRaw: caddyconfig.JSONModuleObject(
			filestorage.FileStorage{Root: caddyStorageDir(dataDir)},
			"module", "file_system", nil),
		AppsRaw: caddy.ModuleMap{
			"pki": caddyconfig.JSON(caddypki.PKI{CAs: map[string]*caddypki.CA{
				"local": {
					Name:                   caName,
					RootCommonName:         caName,
					IntermediateCommonName: caName + " - Intermediate",
					InstallTrust:           &falseVal,
				},
			}}, nil),
		},
	}
	j, err := json.Marshal(cc)
	if err != nil {
		return "", err
	}
	if err := caddy.Load(j, true); err != nil {
		return "", fmt.Errorf("provisioning CA: %w", err)
	}
	defer caddy.Stop() //nolint:errcheck

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(rootPath); err == nil {
			return rootPath, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("CA root certificate did not appear at %s", rootPath)
}
