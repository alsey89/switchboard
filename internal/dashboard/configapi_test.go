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
	Inspect struct {
		Enabled bool `json:"enabled"`
		Bodies  bool `json:"bodies"`
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
	// Inspect defaults to on. A plain bool cannot tell unset from off, which
	// is why config uses a pointer, and the endpoint must resolve it.
	if !out.Inspect.Enabled {
		t.Error("inspect should default to enabled")
	}
}

func TestConfigEndpointIs503WithoutPaths(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/config", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}
