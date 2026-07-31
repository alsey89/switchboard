package doctor

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
)

func findCheck(checks []Check, name string) (Check, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

// TestPrivilegedPortIsNotReportedAsAConflict.
//
// A stock config with the service not yet installed is the single most common
// state doctor will ever be run in, and it used to produce:
//
//	✗ port https  127.0.0.1:443 not bindable: permission denied
//	  ↳ find the conflict: lsof -nP -i:443
//
// There is no conflict. Nothing is holding :443 — an ordinary user may not
// bind it. Sending someone hunting with lsof for a process that does not
// exist is worse than saying nothing, because they will find nothing and
// conclude the tool is broken in some deeper way.
func TestPrivilegedPortIsNotReportedAsAConflict(t *testing.T) {
	orig := bindProbe
	bindProbe = func(network, addr string) error {
		if strings.HasSuffix(addr, ":443") || strings.HasSuffix(addr, ":80") {
			return &net.OpError{Op: "listen", Net: network, Err: os.ErrPermission}
		}
		return nil
	}
	t.Cleanup(func() { bindProbe = orig })

	checks := bindChecks(config.Default())

	c, ok := findCheck(checks, "port https")
	if !ok {
		t.Fatal("no check for the https port")
	}
	if strings.Contains(c.Hint, "lsof") {
		t.Errorf("permission denied is not a conflict; the hint should not send the "+
			"user looking for a process. Got: %q", c.Hint)
	}
	if !strings.Contains(c.Hint, "daemon install") {
		t.Errorf("the hint should name what actually fixes it. Got: %q", c.Hint)
	}
	if !strings.Contains(c.Detail, "reserved for root") {
		t.Errorf("the detail should explain why it cannot bind. Got: %q", c.Detail)
	}
}

// TestRealConflictStillSendsYouToLsof: the lsof advice is right when
// something genuinely holds the port, and that must not be lost.
func TestRealConflictStillSendsYouToLsof(t *testing.T) {
	orig := bindProbe
	bindProbe = func(network, addr string) error {
		return &net.OpError{Op: "listen", Net: network, Err: errors.New("address already in use")}
	}
	t.Cleanup(func() { bindProbe = orig })

	c, ok := findCheck(bindChecks(config.Default()), "port https")
	if !ok {
		t.Fatal("no check for the https port")
	}
	if !strings.Contains(c.Hint, "lsof") {
		t.Errorf("an in-use port is exactly when lsof helps. Got: %q", c.Hint)
	}
}

// TestBindableportsReportOK guards against the checks failing open — a
// diagnostic that says everything is fine regardless is worse than none.
func TestBindablePortsReportOK(t *testing.T) {
	orig := bindProbe
	bindProbe = func(string, string) error { return nil }
	t.Cleanup(func() { bindProbe = orig })

	for _, c := range bindChecks(config.Default()) {
		if c.Status != OK {
			t.Errorf("check %q should be OK when the port binds, got %v", c.Name, c.Status)
		}
	}
}
