// Package doctor diagnoses the usual reasons Switchboard "doesn't work":
// missing setup steps, port conflicts, dead upstreams. Every check returns
// a hint that names the exact fix.
package doctor

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/netprobe"
	"github.com/alsey89/switchboard/internal/proxy"
)

// Status of a single check.
type Status int

const (
	OK Status = iota
	Warn
	Fail
	Skip
)

func (s Status) String() string {
	switch s {
	case OK:
		return "ok"
	case Warn:
		return "warn"
	case Fail:
		return "FAIL"
	default:
		return "skip"
	}
}

// Check is one diagnostic result.
type Check struct {
	Name   string
	Status Status
	Detail string
	Hint   string
}

// Run executes all checks. cfgErr is the error from loading the config, if
// any (doctor should still run the OS checks when the config is broken).
func Run(cfg *config.Config, cfgPath, dataDir string, cfgErr error) []Check {
	var checks []Check

	if cfgErr != nil {
		checks = append(checks, Check{"config", Fail, cfgErr.Error(),
			"fix " + cfgPath + " (or delete it to start over)"})
		cfg = config.Default()
	} else {
		checks = append(checks, Check{"config", OK,
			fmt.Sprintf("%s (%d routes, suffix .%s)", cfgPath, len(cfg.Routes), cfg.Suffix), ""})
	}

	// CA existence, and — separately — whether it is name-constrained. The
	// second check exists because an unconstrained root is not a broken
	// install: everything works perfectly, which is exactly why nobody would
	// notice that the root in their keychain can sign for any site on the
	// internet.
	rootPath := proxy.RootCertPath(dataDir)
	if _, err := os.Stat(rootPath); err == nil {
		checks = append(checks, Check{"local CA", OK, rootPath, ""})

		if err := proxy.RootCoversSuffix(rootPath, cfg.Suffix); err != nil {
			// `setup` alone. It untrusts the old root, deletes it and
			// everything issued under it, and re-issues — in that order (see
			// setup.rotateCA). This used to say `uninstall && setup`, which
			// was a dead end: uninstall deliberately keeps the CA files, so
			// the setup that followed hit this same error again.
			checks = append(checks, Check{"CA name constraints", Fail, err.Error(),
				"run: switchboard setup    (it re-issues the CA)"})
		} else {
			checks = append(checks, Check{"CA name constraints", OK,
				"limited to ." + cfg.Suffix + " (cannot sign for other domains)", ""})
		}
	} else {
		checks = append(checks, Check{"local CA", Fail, "root certificate not found",
			"run: switchboard setup"})
	}

	checks = append(checks, osChecks(cfg, rootPath)...)

	// Daemon liveness: something must be answering on the HTTPS port.
	httpsAddr := "127.0.0.1:" + strconv.Itoa(cfg.EffHTTPSPort())
	daemonUp := dialProbe(httpsAddr)
	if daemonUp {
		checks = append(checks, Check{"daemon", OK, "listening on " + httpsAddr, ""})
	} else {
		// Recommend the thing that actually works. On a stock config
		// `switchboard start` cannot bind :443 and fails — this used to send
		// people to it repeatedly, and the only way out was to read the
		// failure carefully enough to find the real remedy inside it.
		privileged := cfg.EffHTTPSPort() < 1024 || cfg.EffHTTPPort() < 1024
		remedy := daemonDownRemedy(runtime.GOOS, privileged)
		checks = append(checks, Check{"daemon", Fail, "nothing listening on " + httpsAddr, remedy})
		// Only meaningful to test bindability when the daemon is down.
		checks = append(checks, bindChecks(cfg)...)
	}

	// Upstreams.
	for _, r := range cfg.Routes {
		addr := r.UpstreamAddr()
		if dialProbe(addr) {
			checks = append(checks, Check{"upstream " + r.Domain, OK, addr + " is up", ""})
		} else {
			checks = append(checks, Check{"upstream " + r.Domain, Warn, addr + " is not answering",
				"start your dev server on " + addr + " (routes to it come alive automatically)"})
		}
	}

	return checks
}

// bindProbe is netprobe.Bindable, indirected so tests can exercise the
// advice each failure produces without depending on the privileges of the
// machine running them.
var bindProbe = netprobe.Bindable

// daemonDownRemedy names what brings the daemon up on this platform. `daemon
// install` exists on macOS alone — everywhere else it returns ErrUnsupported,
// and advice naming it sends the user to a command whose only output is that
// it cannot work. goos is a parameter, not runtime.GOOS read inline, so every
// branch is testable from every platform; CI's first Linux run caught the
// inline version advising the impossible.
func daemonDownRemedy(goos string, privilegedPorts bool) string {
	if goos == "darwin" {
		if privilegedPorts {
			return "run: switchboard daemon install"
		}
		return "run: switchboard daemon install    (or `switchboard start` to run it in this terminal)"
	}
	// Windows has no root-only ports, so privilege never enters into it.
	if privilegedPorts && goos != "windows" {
		return "run: sudo switchboard start    (:443/:80 are root-only, and there is " +
			"no service automation on this platform yet)"
	}
	return "run: switchboard start    (there is no service automation on this platform yet)"
}

// privilegedPortHint explains a permission-denied bind on a low port, per
// platform. Same rule as daemonDownRemedy: only commands that exist here.
func privilegedPortHint(goos string) string {
	if goos == "linux" {
		return "grant the capability:\n" +
			"    sudo setcap cap_net_bind_service=+ep $(which switchboard)\n" +
			"  or run one session privileged: sudo switchboard start\n" +
			"  or serve on a high port instead — see `switchboard doctor` after editing the config"
	}
	return "this port needs the privileged parent:\n" +
		"    switchboard daemon install    (or `sudo switchboard start` for one session)\n" +
		"  or serve on a high port instead — see `switchboard doctor` after editing the config"
}

func bindChecks(cfg *config.Config) []Check {
	var checks []Check
	for _, p := range []struct {
		name string
		net  string
		addr string
	}{
		{"port http", "tcp", "127.0.0.1:" + strconv.Itoa(cfg.EffHTTPPort())},
		{"port https", "tcp", "127.0.0.1:" + strconv.Itoa(cfg.EffHTTPSPort())},
		{"port dns", "udp", "127.0.0.1:" + strconv.Itoa(cfg.EffDNSPort())},
	} {
		if err := bindProbe(p.net, p.addr); err != nil {
			// "Permission denied" on a port below 1024 is not a conflict, and
			// telling someone to go hunting with lsof for a process that is
			// not there wastes their time on the most common state there is:
			// a stock config with the service not yet installed. Nothing is
			// holding :443 — an ordinary user simply may not bind it.
			if errors.Is(err, os.ErrPermission) {
				checks = append(checks, Check{p.name, Fail,
					p.addr + " is reserved for root, and the daemon runs as you",
					privilegedPortHint(runtime.GOOS)})
				continue
			}
			hint := "find the conflict: lsof -nP -i:" + portOf(p.addr)
			checks = append(checks, Check{p.name, Fail,
				p.addr + " not bindable: " + err.Error(), hint})
		} else {
			checks = append(checks, Check{p.name, OK, p.addr + " available", ""})
		}
	}
	return checks
}

// dialProbe is dialable, indirected for the same reason bindProbe is: without
// it these checks report on whatever happens to be listening on the machine
// running the tests, so a developer with the daemon up sees different results
// from one without it.
var dialProbe = dialable

func dialable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
