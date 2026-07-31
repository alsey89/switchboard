// Package daemon assembles the pieces — DNS responder, dashboard, embedded
// Caddy — and keeps them in sync with the config file. One unprivileged
// process; see DESIGN.md §3.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/dashboard"
	"github.com/alsey89/switchboard/internal/dnsd"
	"github.com/alsey89/switchboard/internal/proxy"
)

// Options for a daemon run.
type Options struct {
	ConfigPath string
	DataDir    string
	Version    string
	Log        *slog.Logger
}

// Run starts everything and blocks until ctx is canceled or a component
// fails to start. Config changes on disk are hot-reloaded; a broken config
// is reported and the last good one keeps serving.
func Run(ctx context.Context, opts Options) error {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return err
	}

	// DNS.
	dns := dnsd.New([]string{cfg.Suffix})
	dnsBind := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffDNSPort()))
	if err := dns.Start(dnsBind); err != nil {
		return friendlyBindError(err, "DNS", dnsBind, opts.ConfigPath)
	}
	defer dns.Shutdown(context.Background()) //nolint:errcheck
	log.Info("dns responder up", "addr", dnsBind, "suffix", "."+cfg.Suffix)

	// Dashboard.
	dash := dashboard.New(cfg, opts.Version)
	dashBind := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffDashboardPort()))
	if err := dash.Start(dashBind); err != nil {
		return friendlyBindError(err, "dashboard", dashBind, opts.ConfigPath)
	}
	defer dash.Shutdown(context.Background()) //nolint:errcheck

	// Embedded Caddy: proxy + TLS + PKI.
	if err := proxy.Load(cfg, opts.DataDir); err != nil {
		return friendlyBindError(err, "proxy", "127.0.0.1:"+strconv.Itoa(cfg.EffHTTPSPort()), opts.ConfigPath)
	}
	defer proxy.Stop() //nolint:errcheck
	log.Info("proxy up",
		"https", "127.0.0.1:"+strconv.Itoa(cfg.EffHTTPSPort()),
		"routes", len(cfg.Routes),
		"dashboard", "https://"+cfg.DashboardDomain(),
		"dashboard_direct", "http://"+dashBind)

	// Watch the config file for changes. Watch the directory, not the file:
	// editors and our own atomic Save replace the file by rename.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	if err := watcher.Add(filepath.Dir(opts.ConfigPath)); err != nil {
		return err
	}

	var reloadTimer *time.Timer
	reload := make(chan struct{}, 1)
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return nil

		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if filepath.Clean(ev.Name) != filepath.Clean(opts.ConfigPath) {
				continue
			}
			if !ev.Has(fsnotify.Write) && !ev.Has(fsnotify.Create) && !ev.Has(fsnotify.Rename) {
				continue
			}
			// Debounce: editors fire several events per save.
			if reloadTimer != nil {
				reloadTimer.Stop()
			}
			reloadTimer = time.AfterFunc(200*time.Millisecond, func() {
				select {
				case reload <- struct{}{}:
				default:
				}
			})

		case <-reload:
			next, err := config.Load(opts.ConfigPath)
			if err != nil {
				log.Error("config reload failed; keeping previous config", "err", err)
				continue
			}
			if next.Suffix != cfg.Suffix {
				// The DNS zone and resolver file are tied to the suffix; a live
				// switch would silently break resolution. Require a restart.
				log.Error("suffix changed; restart the daemon (and re-run setup) to apply",
					"old", cfg.Suffix, "new", next.Suffix)
				continue
			}
			if err := proxy.Load(next, opts.DataDir); err != nil {
				log.Error("proxy reload failed; keeping previous config", "err", err)
				continue
			}
			cfg = next
			dash.SetConfig(next)
			log.Info("config reloaded", "routes", len(cfg.Routes))

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Warn("config watcher error", "err", err)
		}
	}
}

// listenerRemedy is the config snippet a given listener's permission-denied
// error should suggest. Keyed by the `what` passed to friendlyBindError.
//
// This exists because the advice used to be hardcoded to http_port/https_port
// for every caller, which was right for the proxy and wrong for the other two:
// a user told to set https_port after the DNS responder failed to bind would
// change a setting unrelated to the error they were reading.
var listenerRemedy = map[string]string{
	"proxy":     "    http_port  = 8080\n    https_port = 8443\n\n  URLs then carry the port (https://app.test:8443).",
	"DNS":       "    dns_port = 53535\n\n  The /etc/resolver file must name the same port — re-run `switchboard setup`.",
	"dashboard": "    dashboard_port = 8484",
}

// friendlyBindError decorates bind failures with actionable advice.
// cfgPath is named in the advice, so the user can act on it without first
// having to work out which config file this daemon was started with.
// what must be a key of listenerRemedy.
func friendlyBindError(err error, what, addr, cfgPath string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if errors.Is(err, syscallEADDRINUSE) || strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "bind: address already in use") {
		return fmt.Errorf("%s cannot bind %s: something is already listening there.\n"+
			"  Find it with:  lsof -nP -iTCP:%s -iUDP:%s | grep LISTEN\n"+
			"  Or change the port in the config file and re-run.\n  (%w)",
			what, addr, portOf(addr), portOf(addr), err)
	}
	if strings.Contains(msg, "permission denied") {
		// Do not claim macOS exempts unprivileged processes from the <1024
		// restriction. It does not — that claim used to be printed directly
		// beneath this very error, which made the message self-refuting.
		hint := "  Ports below 1024 are reserved for root, and Switchboard runs as you.\n"
		if runtime.GOOS == "linux" {
			hint += "  Either grant the capability:\n" +
				"    sudo setcap cap_net_bind_service=+ep $(which switchboard)\n" +
				"  or use high ports"
		} else {
			hint += "  Use high ports"
		}
		remedy, ok := listenerRemedy[what]
		if !ok {
			remedy = "    (raise the port for this listener above 1024)"
		}
		return fmt.Errorf("%s cannot bind %s: permission denied.\n"+
			"%s in %s:\n\n"+
			"%s\n  (%w)",
			what, addr, hint, configPathOr(cfgPath), remedy, err)
	}
	return err
}

// configPathOr names the config file for an error message, falling back to
// the conventional location when the daemon was started without one.
func configPathOr(cfgPath string) string {
	if cfgPath != "" {
		return cfgPath
	}
	if p, err := config.Path(); err == nil {
		return p
	}
	return "~/.config/switchboard/config.toml"
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return port
}
