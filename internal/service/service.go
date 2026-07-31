// Package service installs Switchboard as a background service so the daemon
// survives closing your terminal. On macOS that is a launchd *user agent* in
// ~/Library/LaunchAgents: it runs as you, needs no privilege, and preserves
// the project's "no root daemon" property (see DESIGN.md §5).
package service

import (
	"os"
	"path/filepath"

	"github.com/alsey89/switchboard/internal/config"
)

// Label is the launchd job label and the plist filename stem.
const Label = "io.github.alsey89.switchboard"

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
type Spec struct {
	// Exec is the absolute path to the switchboard binary.
	Exec string
	// Args are the arguments after the executable path.
	Args []string
	// StdoutPath and StderrPath are absolute log file paths.
	StdoutPath string
	StderrPath string
}

// LogPath returns the daemon log file, under the config dir so that
// `rm -rf ~/.config/switchboard` remains a full reset.
func LogPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "logs", "daemon.log"), nil
}

// DefaultSpec builds the Spec for the currently-running binary.
// configPath may be empty, meaning "use the default location".
func DefaultSpec(configPath string) (Spec, error) {
	exe, err := os.Executable()
	if err != nil {
		return Spec{}, err
	}
	logPath, err := LogPath()
	if err != nil {
		return Spec{}, err
	}
	args := []string{"start"}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	return Spec{
		Exec:       exe,
		Args:       args,
		StdoutPath: logPath,
		StderrPath: logPath,
	}, nil
}
