package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
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

func TestPatchConfigSetsDashboardPort(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/config",
		`{"dashboardPort":9000,"version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	out := getConfig(t, s)
	if out.Effective.DashboardPort != 9000 {
		t.Errorf("dashboard port %d, want 9000", out.Effective.DashboardPort)
	}
}

func TestPatchConfigTurnsTheInspectorOff(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	w := write(t, s, "PATCH", "/api/config",
		`{"inspect":{"enabled":false},"version":"`+version+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}
	if getConfig(t, s).Inspect.Enabled {
		t.Error("inspector should be off")
	}
}

// Omitting a field must leave it alone. A settings form that sends one
// changed field should not silently reset the rest, which is exactly what a
// plain bool would do here.
func TestPatchConfigLeavesOmittedFieldsAlone(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	version := getConfig(t, s).Version

	if w := write(t, s, "PATCH", "/api/config",
		`{"inspect":{"bodies":true},"version":"`+version+`"}`); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	out := getConfig(t, s)
	if !out.Inspect.Bodies {
		t.Error("bodies should be on")
	}
	if !out.Inspect.Enabled {
		t.Error("enabled should still be on; it was not in the request")
	}
	if len(out.Routes) != 1 {
		t.Error("routes should be untouched")
	}
}

// enabled = false explicitly, because the accessor returns true for both
// "unset" and "absent". A test seeded with the default cannot tell a
// preserved value from a dropped one: deleting the guard in
// handleConfigPatch would leave Enabled nil, and nil still reads as true.
func TestPatchConfigLeavesAnExplicitEnabledAlone(t *testing.T) {
	s, _ := serverWithPaths(t, "suffix = \"test\"\n\n[inspect]\nenabled = false\n")
	version := getConfig(t, s).Version

	if w := write(t, s, "PATCH", "/api/config",
		`{"inspect":{"bodies":true},"version":"`+version+`"}`); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	out := getConfig(t, s)
	if !out.Inspect.Bodies {
		t.Error("bodies should be on")
	}
	if out.Inspect.Enabled {
		t.Error("enabled was explicitly false and was not in the request; it should still be false")
	}
}

// The privileged ports and the suffix are not writable here. They need sudo
// or a resolver rewrite, and this endpoint accepting them would silently do
// nothing, which is worse than refusing.
func TestPatchConfigRefusesTheSudoTier(t *testing.T) {
	for _, body := range []string{
		`{"httpsPort":8443,"version":"%s"}`,
		`{"httpPort":8080,"version":"%s"}`,
		`{"dnsPort":5454,"version":"%s"}`,
		`{"suffix":"internal","version":"%s"}`,
	} {
		t.Run(body, func(t *testing.T) {
			s, _ := serverWithPaths(t, baseConfig)
			version := getConfig(t, s).Version
			w := write(t, s, "PATCH", "/api/config", strings.Replace(body, "%s", version, 1))
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status %d, want 422: %s", w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), "switchboard") {
				t.Errorf("the error should name the CLI command to use, got: %s", w.Body)
			}
		})
	}
}

func TestPatchConfigRejectsAStaleVersion(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	w := write(t, s, "PATCH", "/api/config",
		`{"dashboardPort":9000,"version":"0000000000000000"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", w.Code)
	}
}

// A refused field must abort the whole patch, not just its own assignment.
// The sudo-tier switch runs before anything is written, and this is what
// stops a later refactor from quietly reordering that.
func TestPatchConfigRefusingOneFieldWritesNone(t *testing.T) {
	s, _ := serverWithPaths(t, baseConfig)
	before := getConfig(t, s)

	w := write(t, s, "PATCH", "/api/config",
		`{"dashboardPort":9000,"suffix":"internal","version":"`+before.Version+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", w.Code, w.Body)
	}

	after := getConfig(t, s)
	if after.Effective.DashboardPort != before.Effective.DashboardPort {
		t.Errorf("dashboard port moved to %d despite the refusal", after.Effective.DashboardPort)
	}
	if after.Version != before.Version {
		t.Error("the config file changed despite the refusal")
	}
}
