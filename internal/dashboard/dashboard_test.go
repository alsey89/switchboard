package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
)

func newBasicServer() *Server {
	return New(&config.Config{
		Suffix: "test",
		Routes: []config.Route{{Domain: "app.test", Port: 3000}},
	}, "test-version")
}

func get(t *testing.T, s *Server, host string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	s.handleRoot(rec, req)
	return rec
}

func TestConsoleServedOnItsOwnDomain(t *testing.T) {
	rec := get(t, newBasicServer(), "switchboard.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// The rail is server rendered so the first paint already has routes.
	// The client refreshes it, but a flash of "no routes" on every load
	// would be worse than the reload it replaces.
	if !strings.Contains(body, "app.test") {
		t.Error("console should list the configured route in the rail")
	}
	// And it is the console, not the old routes-only dashboard.
	for _, want := range []string{`id="list"`, `id="detail"`, `id="rail"`, "EventSource"} {
		if !strings.Contains(body, want) {
			t.Errorf("console is missing %q", want)
		}
	}
	// The rail is the domain filter, and these two halves are how it says so.
	// The row carries the domain it selects, and the filter the query layer
	// reads is a hidden input the rail writes into. Drop either and the
	// domain filter stops working with nothing else on the page changing.
	for _, want := range []string{`data-domain="app.test"`, `<input id="domain" type="hidden">`} {
		if !strings.Contains(body, want) {
			t.Errorf("rail filter contract is missing %q", want)
		}
	}
}

func TestConsoleWithNoRoutesNamesTheAddCommand(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test-version")
	rec := get(t, s, "switchboard.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	// A first run has no routes. This is the new user's first screen and it
	// has to say what to type.
	if !strings.Contains(rec.Body.String(), "switchboard add") {
		t.Error("empty rail should name the add command")
	}
}

func TestDashboardServedOnLoopback(t *testing.T) {
	// These are the addresses that still work when DNS or the CA is broken.
	for _, host := range []string{
		"127.0.0.1:8484", "localhost:8484", "[::1]:8484", "127.0.0.1",
		"LOCALHOST:8484", "::ffff:127.0.0.1", "[::1]",
	} {
		rec := get(t, newBasicServer(), host)
		if rec.Code != http.StatusOK {
			t.Errorf("host %q: got %d, want 200", host, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "app.test") {
			t.Errorf("host %q: should render the dashboard, not the no-route page", host)
		}
	}
}

func TestUnroutedHostGetsNoRoutePage(t *testing.T) {
	rec := get(t, newBasicServer(), "whoops.test")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "whoops.test") {
		t.Error("no-route page should name the host that was asked for")
	}
}

func TestNonLoopbackHostIsNotTreatedAsDashboard(t *testing.T) {
	// DNS rebinding and CSRF: a hostile site resolving itself to 127.0.0.1
	// or a malicious webpage issuing a direct fetch to http://127.0.0.1:port
	// must not be handed the dashboard. These test cases confirm that the guard
	// uses net.ParseIP rather than naive substring matching, so attacks like
	// "localhost.evil.com" do not slip through.
	for _, host := range []string{
		"evil.example.com",      // ordinary foreign host
		"localhost.evil.com",    // rebinding: contains "localhost"
		"127.0.0.1.evil.com",    // rebinding: contains "127.0.0.1"
		"notlocalhost",          // substring trap: looks like localhost
		"localhost.localdomain", // localhost with TLD suffix
	} {
		rec := get(t, newBasicServer(), host)
		if rec.Code != http.StatusNotFound {
			t.Errorf("host %q: got %d, want 404 for a foreign Host", host, rec.Code)
		}
	}
}
