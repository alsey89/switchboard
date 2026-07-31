// Package service installs Switchboard as a background service so the daemon
// survives closing your terminal. On macOS that is a launchd *user agent* in
// ~/Library/LaunchAgents: it runs as you, needs no privilege, and preserves
// the project's "no root daemon" property (see DESIGN.md §5).
package service

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/alsey89/switchboard/internal/config"
)

// Label is the launchd job label and the plist filename stem.
const Label = "io.github.alsey89.switchboard"

// ErrUnsupported is returned by every entry point on platforms without
// service automation yet — Windows (v0.4) and Linux (v0.5); see DESIGN.md §6.
// Exported so callers doing a best-effort teardown (`switchboard uninstall`)
// can tell "there is no service manager here" apart from a real failure.
var ErrUnsupported = errors.New(
	"background service installation is macOS-only so far — run `switchboard start` " +
		"under systemd, a supervisor, or your terminal in the meantime")

// State is the launch agent's status, modeled as four explicit values
// rather than an "installed"/"running" pair of bools. A plist can exist on
// disk without ever having been bootstrapped, and launchd can report a job
// loaded with no process running (it crashed and hasn't been relaunched
// yet, or RunAtLoad simply hasn't fired). Collapsing those distinct facts
// into two bools previously produced "running" for a merely-loaded job and
// "loaded but not running" for a job that was never loaded at all — the
// exact failure this feature exists to surface. Platforms without service
// support (service_other.go) always report NotInstalled alongside a
// non-nil error; callers must check the error first.
type State int

const (
	NotInstalled State = iota // no plist on disk
	NotLoaded                 // plist on disk, but launchd doesn't have the job
	Loaded                    // launchd has the job, but no process is running
	Running                   // launchd has the job and a process is running
)

func (s State) String() string {
	switch s {
	case NotInstalled:
		return "not installed"
	case NotLoaded:
		return "installed but not loaded"
	case Loaded:
		return "loaded but not running"
	case Running:
		return "running"
	default:
		return "unknown"
	}
}

// Spec describes the service to install.
//
// Every path in a Spec must be absolute. launchd runs jobs with a working
// directory of `/`, so a relative path baked into the plist resolves against
// the filesystem root — and `config.Load` treats a missing file as "use
// defaults" rather than an error, so the agent would come up healthy with
// zero routes and never report a thing. DefaultSpec is responsible for the
// absolutization; see its comment.
type Spec struct {
	// Exec is the absolute path to the switchboard binary.
	Exec string
	// Args are the arguments after the executable path.
	Args []string
	// StdoutPath and StderrPath are absolute log file paths.
	StdoutPath string
	StderrPath string
	// ConfigPath is the absolute path of the config file the installed agent
	// will read. Recorded separately from Args because error messages need
	// to name it even in the default case, where no --config is baked in.
	ConfigPath string
	// Ports are the listeners the daemon will need to open. Install probes
	// the privileged ones before writing a plist — see checkPrivilegedPorts.
	Ports []GuardedPort
}

// GuardedPort is one listener Install checks before installing an agent that
// would need it.
type GuardedPort struct {
	// Name is how the port is described to the user ("https", "http").
	Name string
	// Network is "tcp" or "udp".
	Network string
	// Addr is the full bind address, e.g. "127.0.0.1:443".
	Addr string
	// Remedy is the config snippet to suggest when this port is refused.
	// Per-port because the advice differs: telling a user whose dns_port
	// failed to set https_port sends them to an unrelated setting.
	Remedy string
}

// LogPath returns the daemon log file, under the config dir so that
// `rm -rf ~/.config/switchboard` remains a full reset. Always absolute:
// SWITCHBOARD_DIR is taken verbatim from the environment and may well be
// relative, and this path is written into the plist (see Spec).
func LogPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(filepath.Join(dir, "logs", "daemon.log"))
	if err != nil {
		return "", err
	}
	return abs, nil
}

// DefaultSpec builds the Spec for the currently-running binary. configPath
// may be empty, meaning "use the default location".
//
// configPath is made absolute before it reaches the plist. `switchboard
// --config ./dev.toml daemon install` otherwise writes a plist saying
// `--config ./dev.toml`, which launchd resolves against `/` — and a missing
// config file is not an error, so the agent starts cleanly serving nothing.
func DefaultSpec(cfg *config.Config, configPath string) (Spec, error) {
	exe, err := os.Executable()
	if err != nil {
		return Spec{}, err
	}
	logPath, err := LogPath()
	if err != nil {
		return Spec{}, err
	}

	// Resolve the config path for the message side even when it is the
	// default and no flag gets baked in.
	resolved := configPath
	if resolved == "" {
		if resolved, err = config.Path(); err != nil {
			return Spec{}, err
		}
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return Spec{}, err
	}

	args := []string{"start"}
	if configPath != "" {
		args = append(args, "--config", resolved)
	}

	if cfg == nil {
		cfg = config.Default()
	}
	return Spec{
		Exec:       exe,
		Args:       args,
		StdoutPath: logPath,
		StderrPath: logPath,
		ConfigPath: resolved,
		// Every configurable listener is guarded, not just the two that are
		// below 1024 by default. dns_port and dashboard_port default high
		// (53535, 8484) but are user-settable, and `dns_port = 53` installs
		// exactly the same crash-loop that `https_port = 443` does.
		Ports: []GuardedPort{
			{Name: "https", Network: "tcp", Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffHTTPSPort())),
				Remedy: "    http_port  = 8080\n    https_port = 8443"},
			{Name: "http", Network: "tcp", Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffHTTPPort())),
				Remedy: "    http_port  = 8080\n    https_port = 8443"},
			{Name: "DNS", Network: "udp", Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffDNSPort())),
				Remedy: "    dns_port = 53535\n\n  then re-run `switchboard setup` so /etc/resolver names the same port"},
			{Name: "dashboard", Network: "tcp", Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.EffDashboardPort())),
				Remedy: "    dashboard_port = 8484"},
		},
	}, nil
}
