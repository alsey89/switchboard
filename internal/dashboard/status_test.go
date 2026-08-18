package dashboard

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
)

// serverWithPaths is a dashboard wired to a real config file on disk. The
// write and diagnostic endpoints all read from disk rather than from s.cfg,
// so a test that only sets s.cfg proves nothing about them.
func serverWithPaths(t *testing.T, body string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s := New(&config.Config{Suffix: "test"}, "test")
	s.SetPaths(path, dir)
	return s, path
}

func TestDoctorReturnsChecks(t *testing.T) {
	s, _ := serverWithPaths(t, "suffix = \"test\"\n")

	w := do(s, "GET", "/api/doctor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}

	var checks []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &checks); err != nil {
		t.Fatal(err)
	}
	if len(checks) == 0 {
		t.Fatal("doctor returned no checks")
	}
	// Status must be the string, not the int. The SPA should not have to
	// carry a second copy of the Status-to-name mapping.
	for _, c := range checks {
		switch c.Status {
		case "ok", "warn", "FAIL", "skip":
		default:
			t.Errorf("check %q has status %q, want a doctor.Status string", c.Name, c.Status)
		}
	}
}

// Doctor's whole job includes reporting a config that will not parse, so it
// reads the file rather than s.cfg, which by construction only ever holds a
// config that parsed.
func TestDoctorReportsABrokenConfig(t *testing.T) {
	s, _ := serverWithPaths(t, "this is not toml {{{")

	w := do(s, "GET", "/api/doctor", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (a broken config is a finding, not an error)", w.Code)
	}
	if !jsonHasFailingCheck(t, w.Body.Bytes(), "config") {
		t.Errorf("expected a failing config check, got: %s", w.Body)
	}
}

func jsonHasFailingCheck(t *testing.T, body []byte, name string) bool {
	t.Helper()
	var checks []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &checks); err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Name == name && c.Status == "FAIL" {
			return true
		}
	}
	return false
}

func TestDoctorIs503WithoutPaths(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/doctor", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}

// service.Status shells out to launchctl and is macOS-only. On every other
// platform it returns an error alongside NotInstalled, and callers must
// check the error first. The endpoint must report that as "unsupported"
// rather than as a 500, because a Linux user is not experiencing a failure.
func TestServiceEndpointAlwaysAnswers(t *testing.T) {
	s, _ := serverWithPaths(t, "suffix = \"test\"\n")

	w := do(s, "GET", "/api/service", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body)
	}

	var out struct {
		State     string `json:"state"`
		PlistPath string `json:"plistPath"`
		Supported bool   `json:"supported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.State == "" {
		t.Error("state should always be populated, even when unsupported")
	}
}
