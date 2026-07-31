package doctor

import (
	"errors"
	"net"
	"os"
	"runtime"
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
	// What "actually fixes it" depends on the platform: the launchd parent on
	// macOS, setcap on Linux. The content of each branch is pinned in
	// TestAdviceNamesOnlyCommandsThatExistOnThePlatform; here the live check
	// must carry the branch for the platform the test is running on.
	wantFix := "daemon install"
	if runtime.GOOS == "linux" {
		wantFix = "setcap"
	}
	if !strings.Contains(c.Hint, wantFix) {
		t.Errorf("the hint should name what actually fixes it here (%q). Got: %q", wantFix, c.Hint)
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

// TestDownDaemonAdviceNamesSomethingThatWorks.
//
// doctor used to say "run: switchboard start" whenever nothing was listening.
// On a stock config that command cannot bind :443 and fails — so the
// diagnostic's advice was a command that would not work, and the only way
// forward was to read the resulting failure carefully enough to find the real
// remedy buried in it. Someone hit this three times in a row before getting out.
// TestAdviceNamesOnlyCommandsThatExistOnThePlatform.
//
// `daemon install` exists on macOS alone; everywhere else it returns
// ErrUnsupported. Both pieces of doctor advice — the daemon-down remedy and
// the privileged-port hint — used to name it regardless of platform, so a
// Linux user was sent to a command whose only output is that it cannot work.
// CI's first Linux run is what caught it. The helpers take goos as a
// parameter precisely so every branch is exercised from every platform.
func TestAdviceNamesOnlyCommandsThatExistOnThePlatform(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		for _, privileged := range []bool{true, false} {
			remedy := daemonDownRemedy(goos, privileged)
			if strings.Contains(remedy, "daemon install") {
				t.Errorf("daemonDownRemedy(%q, %v) advises `daemon install`, which is "+
					"unsupported there: %q", goos, privileged, remedy)
			}
			if !strings.Contains(remedy, "switchboard start") {
				t.Errorf("daemonDownRemedy(%q, %v) must name the command that works: %q",
					goos, privileged, remedy)
			}
		}
	}
	// Privileged ports on linux need privilege from somewhere; sudo is the
	// one-session answer. Windows has no root-only ports at all.
	if remedy := daemonDownRemedy("linux", true); !strings.Contains(remedy, "sudo switchboard start") {
		t.Errorf("on linux with privileged ports the remedy must include sudo: %q", remedy)
	}
	if remedy := daemonDownRemedy("windows", true); strings.Contains(remedy, "sudo") {
		t.Errorf("windows has no privileged ports, so sudo is noise: %q", remedy)
	}

	hint := privilegedPortHint("linux")
	if strings.Contains(hint, "install the service") || strings.Contains(hint, "daemon install") {
		t.Errorf("the linux privileged-port hint advises installing a service that "+
			"cannot be installed there: %q", hint)
	}
	for _, want := range []string{"setcap", "sudo switchboard start"} {
		if !strings.Contains(hint, want) {
			t.Errorf("the linux privileged-port hint must offer %q: %q", want, hint)
		}
	}
	if hint := privilegedPortHint("darwin"); !strings.Contains(hint, "daemon install") {
		t.Errorf("the darwin privileged-port hint must name `daemon install`: %q", hint)
	}
}

func TestDownDaemonAdviceNamesSomethingThatWorks(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cfg       *config.Config
		wantStart bool
	}{
		{"stock ports cannot be bound by `start`", config.Default(), false},
		{"high ports can", &config.Config{Suffix: "test", HTTPPort: 8080, HTTPSPort: 8443}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateOSPaths(t)
			origBind, origDial := bindProbe, dialProbe
			bindProbe = func(string, string) error { return nil }
			dialProbe = func(string) bool { return false } // nothing listening
			t.Cleanup(func() { bindProbe, dialProbe = origBind, origDial })

			checks := Run(tc.cfg, "/tmp/config.toml", t.TempDir(), nil)
			c, ok := findCheck(checks, "daemon")
			if !ok {
				t.Fatal("no daemon check")
			}
			if runtime.GOOS == "darwin" {
				if !strings.Contains(c.Hint, "daemon install") {
					t.Errorf("the advice should name `daemon install`, which works in both "+
						"cases. Got: %q", c.Hint)
				}
				if got := strings.Contains(c.Hint, "switchboard start"); got != tc.wantStart {
					t.Errorf("mentions `switchboard start` = %v, want %v — on privileged "+
						"ports it cannot bind and fails. Got: %q", got, tc.wantStart, c.Hint)
				}
			} else {
				// No service automation off macOS: `switchboard start` (with
				// sudo when the ports demand it) is the only advice that works.
				if strings.Contains(c.Hint, "daemon install") {
					t.Errorf("`daemon install` is unsupported on %s. Got: %q", runtime.GOOS, c.Hint)
				}
				if !strings.Contains(c.Hint, "switchboard start") {
					t.Errorf("the advice must name `switchboard start`. Got: %q", c.Hint)
				}
			}
		})
	}
}
