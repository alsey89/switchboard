package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
)

// readConfigView is how every config test in this file inspects a response.
// The shape is asserted once here so a field rename shows up as one
// compile error rather than as six silently-zero values.
type readConfigView struct {
	Version string `json:"version"`
	Suffix  string `json:"suffix"`
	Routes  []struct {
		Domain   string `json:"domain"`
		Upstream string `json:"upstream"`
	} `json:"routes"`
	Effective struct {
		HTTPPort      int `json:"httpPort"`
		HTTPSPort     int `json:"httpsPort"`
		DNSPort       int `json:"dnsPort"`
		DashboardPort int `json:"dashboardPort"`
	} `json:"effective"`
	Ports struct {
		HTTPPort      int `json:"httpPort"`
		HTTPSPort     int `json:"httpsPort"`
		DNSPort       int `json:"dnsPort"`
		DashboardPort int `json:"dashboardPort"`
	} `json:"ports"`
	Inspect struct {
		Enabled      bool   `json:"enabled"`
		Bodies       bool   `json:"bodies"`
		MaxRequests  int    `json:"maxRequests"`
		MaxBytes     int64  `json:"maxBytes"`
		MaxBodyBytes int    `json:"maxBodyBytes"`
		MaxAge       string `json:"maxAge"`
	} `json:"inspect"`
}

func getConfig(t *testing.T, s *Server) readConfigView {
	t.Helper()
	w := do(s, "GET", "/api/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	var out readConfigView
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestConfigEndpointReportsFileAndEffectiveValues(t *testing.T) {
	body := "suffix = \"test\"\n\n[[routes]]\ndomain = \"app.test\"\nport = 3000\n"
	s, _ := serverWithPaths(t, body)

	out := getConfig(t, s)

	if out.Version != config.Version([]byte(body)) {
		t.Errorf("version %q does not match the file", out.Version)
	}
	if out.Suffix != "test" {
		t.Errorf("suffix %q, want test", out.Suffix)
	}
	if len(out.Routes) != 1 || out.Routes[0].Domain != "app.test" {
		t.Fatalf("routes: %+v", out.Routes)
	}
	// UpstreamAddr resolves a bare port through "localhost", not 127.0.0.1
	// (see config.Route.UpstreamAddr): a name lets the dialer try both
	// address families, where a hardcoded 127.0.0.1 would miss a server
	// bound to IPv6 loopback only.
	if out.Routes[0].Upstream != "localhost:3000" {
		t.Errorf("upstream %q, want the resolved address", out.Routes[0].Upstream)
	}
	// Effective values are what the daemon actually uses. The file sets no
	// ports, so every one of these must be a default and not a zero.
	if out.Effective.HTTPSPort != config.DefaultHTTPSPort {
		t.Errorf("https port %d, want %d", out.Effective.HTTPSPort, config.DefaultHTTPSPort)
	}
	if out.Effective.DashboardPort != config.DefaultDashboardPort {
		t.Errorf("dashboard port %d, want %d", out.Effective.DashboardPort, config.DefaultDashboardPort)
	}
	// Ports is what the file literally says, so an unset port is zero here
	// even though Effective resolved it to a default. Asserting both halves
	// is the point: a Ports that merely echoed Effective would be useless to
	// a settings form, and would pass a test that only checked Effective.
	if out.Ports.DashboardPort != 0 {
		t.Errorf("file dashboard port %d, want 0 (unset in the file)", out.Ports.DashboardPort)
	}
	if out.Ports.HTTPSPort != 0 {
		t.Errorf("file https port %d, want 0 (unset in the file)", out.Ports.HTTPSPort)
	}
	// Inspect defaults to on. A plain bool cannot tell unset from off, which
	// is why config uses a pointer, and the endpoint must resolve it.
	if !out.Inspect.Enabled {
		t.Error("inspect should default to enabled")
	}
	// The file has no [inspect] block, so every numeric field must come back
	// as the package default rather than the zero value a missing block
	// would otherwise produce.
	if out.Inspect.MaxRequests != config.DefaultInspectMaxRequests {
		t.Errorf("max requests %d, want %d", out.Inspect.MaxRequests, config.DefaultInspectMaxRequests)
	}
	if out.Inspect.MaxBytes != config.DefaultInspectMaxBytes {
		t.Errorf("max bytes %d, want %d", out.Inspect.MaxBytes, config.DefaultInspectMaxBytes)
	}
	if out.Inspect.MaxBodyBytes != config.DefaultInspectMaxBodyBytes {
		t.Errorf("max body bytes %d, want %d", out.Inspect.MaxBodyBytes, config.DefaultInspectMaxBodyBytes)
	}
	if out.Inspect.MaxAge != config.DefaultInspectMaxAge.String() {
		t.Errorf("max age %q, want %q", out.Inspect.MaxAge, config.DefaultInspectMaxAge.String())
	}
}

// A port set in the file appears in Ports as written and in Effective as
// resolved. With no port set the two differ by construction, so this is the
// case that proves Ports is read from the file rather than zeroed.
func TestConfigEndpointReportsAnExplicitPort(t *testing.T) {
	s, _ := serverWithPaths(t, "suffix = \"test\"\ndashboard_port = 9999\n")

	out := getConfig(t, s)
	if out.Ports.DashboardPort != 9999 {
		t.Errorf("file dashboard port %d, want 9999", out.Ports.DashboardPort)
	}
	if out.Effective.DashboardPort != 9999 {
		t.Errorf("effective dashboard port %d, want 9999", out.Effective.DashboardPort)
	}
}

func TestConfigEndpointIs503WithoutPaths(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/config", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}
