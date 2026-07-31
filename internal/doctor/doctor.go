// Package doctor diagnoses the usual reasons Switchboard "doesn't work":
// missing setup steps, port conflicts, dead upstreams. Every check returns
// a hint that names the exact fix.
package doctor

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/alsey89/switchboard/internal/config"
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
			fmt.Sprintf("%s (%d routes, tld .%s)", cfgPath, len(cfg.Routes), cfg.TLD), ""})
	}

	// CA existence.
	rootPath := proxy.RootCertPath(dataDir)
	if _, err := os.Stat(rootPath); err == nil {
		checks = append(checks, Check{"local CA", OK, rootPath, ""})
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
		if err := bindable(p.net, p.addr); err != nil {
			hint := "find the conflict: lsof -nP -i:" + portOf(p.addr)
			if runtime.GOOS == "linux" {
				hint += "  (or, for <1024: sudo setcap cap_net_bind_service=+ep $(which switchboard))"
			}
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

func bindable(network, addr string) error {
	switch network {
	case "udp":
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		pc.Close()
	default:
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		ln.Close()
	}
	return nil
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}
