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
			checks = append(checks, Check{"CA name constraints", Fail, err.Error(),
				"run: switchboard uninstall && switchboard setup"})
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
	daemonUp := dialable(httpsAddr)
	if daemonUp {
		checks = append(checks, Check{"daemon", OK, "listening on " + httpsAddr, ""})
	} else {
		checks = append(checks, Check{"daemon", Fail, "nothing listening on " + httpsAddr,
			"run: switchboard start"})
		// Only meaningful to test bindability when the daemon is down.
		checks = append(checks, bindChecks(cfg)...)
	}

	// Upstreams.
	for _, r := range cfg.Routes {
		addr := r.UpstreamAddr()
		if dialable(addr) {
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
				hint := "this port needs the privileged parent:\n" +
					"    switchboard daemon install    (or `sudo switchboard start` for one session)\n" +
					"  or serve on a high port instead — see `switchboard doctor` after editing the config"
				if runtime.GOOS == "linux" {
					hint = "grant the capability:\n" +
						"    sudo setcap cap_net_bind_service=+ep $(which switchboard)\n" +
						"  or use a high port, or install the service"
				}
				checks = append(checks, Check{p.name, Fail,
					p.addr + " is reserved for root, and the daemon runs as you", hint})
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
