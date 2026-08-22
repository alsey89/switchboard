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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/dashboard"
	"github.com/alsey89/switchboard/internal/dnsd"
	"github.com/alsey89/switchboard/internal/inspect"
	"github.com/alsey89/switchboard/internal/listen"
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

	// Request inspector state, declared and deferred here, first, so its
	// cleanup is the *last* thing that runs on the way out.
	//
	// insp.Close() closes the SQLite handle that insp.Store() hands to the
	// dashboard's history endpoints (Tasks 8/9) and that the proxy's
	// handler submits into via inspect.Current(). Both of those have to
	// stop serving before the store closes, or a request racing shutdown
	// queries a closed database. Defers run last-registered-first, so
	// registering this one before dns/dash/proxy's own defers below is what
	// makes it unwind after all three of theirs have already run.
	//
	// SetCurrent(nil) runs before Close() for a second reason: a record
	// submitted after Close() returns would sit in the recorder's channel
	// forever, drained by nobody and counted by nothing. Clearing the
	// pointer first makes the handler skip Submit entirely once shutdown
	// starts.
	var insp *inspect.Recorder
	defer func() {
		inspect.SetCurrent(nil)
		if insp != nil {
			insp.Close() //nolint:errcheck
		}
	}()

	// Sockets a privileged parent bound for us, if we were started by one.
	// Empty otherwise, in which case everything below binds normally.
	set, err := listen.FromEnv()
	if err != nil {
		return err
	}

	// Under a privileged parent, a missing config file is fatal rather than
	// "use the defaults".
	//
	// A launch daemon starts at boot, before anyone logs in — and on a
	// FileVault Mac the user's home directory does not exist yet at that
	// point. config.Load treats a missing file as "use defaults", so the
	// daemon would come up perfectly healthy serving zero routes, watching a
	// directory that is not there. Nothing would ever recover it: the user
	// logs in, their config appears, and the running daemon never notices.
	//
	// Exiting non-zero instead puts the problem where the retry logic already
	// lives. The parent backs off and respawns, and the daemon comes up
	// properly within thirty seconds of the home directory appearing.
	if set.Any() {
		if _, statErr := os.Stat(opts.ConfigPath); statErr != nil {
			return fmt.Errorf("config file %s is not readable yet: %w\n"+
				"  Started by launchd at boot, this is expected until the user's home "+
				"directory is available (FileVault decrypts it at login).\n"+
				"  The supervising parent will retry.", opts.ConfigPath, statErr)
		}
	}

	cfg, cfgVersion, err := config.LoadWithVersion(opts.ConfigPath)
	if err != nil {
		return err
	}

	if set.Any() {
		log.Info("running under a privileged parent",
			"https", set.Addr(listen.HTTPS), "http", set.Addr(listen.HTTP))
		// The config's port settings did not choose these sockets and cannot
		// change them. Saying so is not pedantry: a user who edits
		// https_port here would otherwise watch it take effect on nothing,
		// with no error and no clue why.
		for _, w := range ignoredPortSettings(cfg, set) {
			log.Warn("config setting has no effect under a privileged parent", "setting", w)
		}
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
	dash.SetPaths(opts.ConfigPath, opts.DataDir)
	// No SetApplied here. Nothing is proxying yet, and applied is the claim
	// that the running daemon is serving this exact file. The gap is
	// normally milliseconds, but on a first run proxy.Load mints and
	// installs the CA and can sit on a keychain dialog for as long as the
	// user takes to answer it. The dashboard is already up and reachable
	// through that whole wait, saying applied:true about a proxy that has
	// not loaded. The call moved to just after proxy.Load returns.
	dashBind := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffDashboardPort()))
	if err := dash.Start(dashBind); err != nil {
		return friendlyBindError(err, "dashboard", dashBind, opts.ConfigPath)
	}
	// Bounded, not context.Background(). The dashboard's own Shutdown tells
	// its long-lived handlers to leave before it waits for them, so this
	// deadline should never be reached — it is here so that a future handler
	// that forgets to watch that signal costs five seconds at shutdown
	// instead of hanging the daemon and everything registered to unwind
	// after it.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dash.Shutdown(ctx) //nolint:errcheck
	}()

	// Request inspector. Every failure here is a warning, never a return:
	// the proxy is the product, and a broken inspector must not be the
	// reason it does not start. ensureInspector must run before proxy.Load:
	// that call is what puts the switchboard_inspect handler into Caddy's
	// config, and the handler reads inspect.Current() on its first request.
	//
	// It returns the failure as well as logging it. Not starting is not the
	// same as not mattering: the inspector's settings are one of the things
	// this config file can turn on, so a user who enables it and gets a
	// warning in a log nobody reads would be told the config is applied
	// while the inspector endpoints answer 503. The caller feeds this into
	// SetApplied so the dashboard says what actually happened.
	ensureInspector := func(c *config.Config) error {
		if !c.InspectEnabled() {
			if insp != nil {
				// Tear down in the same order as shutdown, and for the
				// same reason: stop the handler submitting and stop the
				// dashboard reading before the store closes, so neither
				// can touch it once it does.
				//
				// inspect.db stays on disk — this only closes the handle,
				// it does not delete the file. "Off" stops capture and
				// stops the UI serving what was captured; it must not
				// destroy what the user already recorded. Re-enabling and
				// reloading reopens the same file and brings the history
				// back.
				inspect.SetCurrent(nil)
				dash.SetInspector(nil)
				insp.Close() //nolint:errcheck
				insp = nil
				log.Info("inspector down", "reason", "disabled by config reload")
			}
			return nil
		}
		if insp != nil {
			insp.SetOptions(c.InspectBodies(), c.InspectMaxBodyBytes())
			insp.Store().SetLimits(inspectLimits(c))
			return nil
		}
		// The data directory itself is normally created by proxy.Load's
		// EnsureRoot — but ensureInspector runs before that call, so on a
		// brand new install nothing has created it yet. Without this,
		// inspect.Open fails on every first run with SQLite's own
		// "unable to open database file", and capture never turns on
		// until something else (a later reload) creates the directory.
		if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
			log.Warn("inspector disabled: cannot create its data directory", "path", opts.DataDir, "err", err)
			return fmt.Errorf("the inspector is enabled but its data directory %s "+
				"could not be created, so capture is off: %w", opts.DataDir, err)
		}
		dbPath := filepath.Join(opts.DataDir, "inspect.db")
		st, err := inspect.Open(dbPath, inspectLimits(c))
		if err != nil {
			log.Warn("inspector disabled: cannot open its database", "path", dbPath, "err", err)
			return fmt.Errorf("the inspector is enabled but its database %s could not be "+
				"opened, so capture is off: %w", dbPath, err)
		}
		insp = inspect.New(st, inspect.Options{
			Bodies:       c.InspectBodies(),
			MaxBodyBytes: c.InspectMaxBodyBytes(),
			Log:          log,
		})
		inspect.SetCurrent(insp)
		dash.SetInspector(insp)
		log.Info("inspector up", "db", dbPath, "bodies", c.InspectBodies())
		return nil
	}
	inspErr := ensureInspector(cfg)

	// Embedded Caddy: proxy + TLS + PKI.
	httpsAddr, _ := proxy.Addrs(cfg, set)
	if err := proxy.Load(cfg, opts.DataDir, set); err != nil {
		return friendlyBindError(err, "proxy", httpsAddr, opts.ConfigPath)
	}
	defer proxy.Stop() //nolint:errcheck
	// Now the file is really being served, so now it can be called applied.
	// inspErr rather than nil: the inspector is part of what this file
	// configures, and a config whose inspector could not start is not a
	// config the daemon is running as written.
	dash.SetApplied(cfgVersion, inspErr)
	log.Info("proxy up",
		"https", httpsAddr,
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
			next, nextVersion, err := config.LoadWithVersion(opts.ConfigPath)
			if err != nil {
				log.Error("config reload failed; keeping previous config", "err", err)
				// No version to report: the file did not parse, so there is
				// no version, and nothing to call applied or unapplied.
				//
				// The proxy keeps serving the last good config. The
				// dashboard does not show it: GET /api/config re-reads the
				// file on every request, so it answers 500 for as long as
				// the file is broken. That is the honest answer, because
				// there is no config to return. /api/doctor reads the file
				// separately and reports the parse failure as a check, so
				// the diagnostic that explains this 500 still works.
				continue
			}
			if next.Suffix != cfg.Suffix {
				// The DNS zone and resolver file are tied to the suffix; a live
				// switch would silently break resolution. Require a restart.
				log.Error("suffix changed; restart the daemon (and re-run setup) to apply",
					"old", cfg.Suffix, "new", next.Suffix)
				dash.SetApplied(nextVersion, errors.New(
					"the suffix changed; restart the daemon and re-run setup to apply it"))
				continue
			}
			if err := proxy.Load(next, opts.DataDir, set); err != nil {
				log.Error("proxy reload failed; keeping previous config", "err", err)
				dash.SetApplied(nextVersion, err)
				continue
			}
			cfg = next
			dash.SetConfig(next)
			// enabled can flip either way in a reload, and ensureInspector
			// handles both: it opens the store the first time it is turned
			// on, so a user who starts with it off does not have to
			// restart the daemon to use it, and it tears the recorder
			// down (without deleting inspect.db) the moment it is turned
			// off, so the dashboard stops serving what was captured.
			//
			// Its outcome is what gets reported. Turning the inspector on is
			// a write this API offers, so a reload where the proxy took the
			// new routes but the inspector refused to open is not applied,
			// however green the proxy half looks.
			dash.SetApplied(nextVersion, ensureInspector(next))
			log.Info("config reloaded", "routes", len(cfg.Routes))

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Warn("config watcher error", "err", err)
		}
	}
}

// inspectLimits translates config settings into the store's limits.
func inspectLimits(c *config.Config) inspect.Limits {
	return inspect.Limits{
		MaxRequests: c.InspectMaxRequests(),
		MaxBytes:    c.InspectMaxBytes(),
		MaxAge:      c.InspectMaxAge(),
	}
}

// ignoredPortSettings names the config keys the user has set that cannot
// take effect because the corresponding socket was inherited rather than
// bound. Only keys explicitly set are reported — an unset key defaulting to
// 443 is not the user asking for anything.
func ignoredPortSettings(cfg *config.Config, set *listen.Set) []string {
	var out []string
	if cfg.HTTPSPort != 0 && set.Inherited(listen.HTTPS) {
		out = append(out, "https_port")
	}
	if cfg.HTTPPort != 0 && set.Inherited(listen.HTTP) {
		out = append(out, "http_port")
	}
	return out
}

// listenerRemedy is the config snippet a given listener's permission-denied
// error should suggest. Keyed by the `what` passed to friendlyBindError.
//
// This exists because the advice used to be hardcoded to http_port/https_port
// for every caller, which was right for the proxy and wrong for the other two:
// a user told to set https_port after the DNS responder failed to bind would
// change a setting unrelated to the error they were reading.
var listenerRemedy = map[string]string{
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
		return fmt.Errorf("%s cannot bind %s: permission denied.\n"+
			"  Ports below 1024 are reserved for root, and the daemon runs as you.\n\n"+
			"%s\n  (%w)",
			what, addr, privilegeAdvice(what, cfgPath), err)
	}
	return err
}

// privilegeAdvice is what to do about a port below 1024, which differs by
// listener because only two of them can be handed over by the privileged
// parent.
//
// The proxy's advice used to offer high ports and nothing else. That was
// right when high ports were the only working configuration, and became
// wrong the moment the privileged parent shipped — it answered "how do I
// serve :443?" with "don't", while the supported way to do exactly that went
// unmentioned. The first person to hit this after the parent landed was told
// to reconfigure rather than to run one command.
func privilegeAdvice(what, cfgPath string) string {
	if what == "proxy" {
		advice := "  Either let the privileged parent bind them for you — it drops to your\n" +
			"  user immediately, so the proxy still does not run as root:\n\n" +
			"    sudo switchboard start        (this session)\n" +
			"    switchboard daemon install    (every session, started by launchd)\n"
		if runtime.GOOS == "linux" {
			advice += "\n  or grant the capability to the binary:\n\n" +
				"    sudo setcap cap_net_bind_service=+ep $(which switchboard)\n"
		}
		return advice + "\n  or serve on high ports instead, in " + configPathOr(cfgPath) + ":\n\n" +
			"    http_port  = 8080\n    https_port = 8443\n\n" +
			"  URLs then carry the port (https://app.test:8443)."
	}

	// DNS and the dashboard are never inherited: the resolver file names a
	// port, so DNS has no reason to want :53, and the dashboard is loopback
	// only. For these the port really is the whole answer.
	remedy, ok := listenerRemedy[what]
	if !ok {
		remedy = "    (raise the port for this listener above 1024)"
	}
	return "  Use a high port in " + configPathOr(cfgPath) + ":\n\n" + remedy
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
