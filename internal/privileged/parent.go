// Package privileged implements the small root component described in
// ADR 0001: it binds the two privileged ports, drops to an ordinary user,
// and execs the daemon with those sockets already open.
//
// The whole point is how little is in here. Everything that parses untrusted
// input — the TLS stack, the reverse proxy, Caddy and its dependency tree,
// the certificate authority — runs in the child, as the user. This process
// binds two sockets and supervises a subprocess. It reads no configuration
// file, parses no network traffic, and exposes no IPC surface.
//
// Two properties are load-bearing and easy to lose in a later edit:
//
//   - The ports are hardcoded (see Ports). They must never come from the
//     user-writable config. A config-driven parent is a "root will bind
//     whatever port you name" primitive: a hostile config setting
//     https_port = 631 makes root take CUPS's port and hand it to the
//     process the attacker controls. The dangerous ports are the unclaimed
//     ones, not the ones already in use.
//
//   - The target user is passed in explicitly, never inferred here. Under
//     launchd there is no SUDO_UID to infer from, and a parent that guesses
//     would either fail or fall back to something wrong.
package privileged

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/alsey89/switchboard/internal/listen"
)

// Ports is the complete set of privileged ports this process will ever bind.
// It is a constant of the program, not a setting. See the package comment.
func Ports() map[string]int {
	return map[string]int{
		listen.HTTPS: 443,
		listen.HTTP:  80,
	}
}

// Spec describes the child to run and the user to run it as.
type Spec struct {
	// Exe and Args are the child command. Exe should be an absolute path.
	Exe  string
	Args []string

	// UID and GID are the unprivileged identity to drop to. Required, and
	// required to be non-root.
	UID, GID int

	// Home is the target user's home directory. Passed as HOME so the child
	// resolves its config and data directories under the user's home rather
	// than under /var/root.
	Home string

	// Env is the child's environment, minus HOME and the descriptor map,
	// which are set here.
	Env []string

	Log *slog.Logger
}

func (s Spec) validate() error {
	if os.Geteuid() != 0 {
		return errors.New("the privileged parent must run as root — it exists to bind " +
			"ports 80 and 443, which is the one thing an ordinary user cannot do")
	}
	if s.UID == 0 || s.GID == 0 {
		return fmt.Errorf("refusing to run the daemon as uid %d/gid %d: the daemon runs "+
			"the proxy, the TLS stack and the CA, and none of that may hold root", s.UID, s.GID)
	}
	if s.Exe == "" {
		return errors.New("no daemon executable given")
	}
	if s.Home == "" {
		return errors.New("no home directory given for the target user; the child would " +
			"resolve its config under root's home")
	}
	return nil
}

// Run binds the privileged ports, then supervises the child until ctx is
// canceled or the child exits deliberately.
func Run(ctx context.Context, spec Spec) error {
	log := spec.Log
	if log == nil {
		log = slog.Default()
	}
	if err := spec.validate(); err != nil {
		return err
	}

	// Bind first, while we still have the privilege to do it. Anything that
	// fails here fails before a child exists, which keeps the error legible.
	files, fdSpec, err := bindAll(log)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range files {
			f.Close() //nolint:errcheck
		}
	}()

	return supervise(ctx, spec, files, fdSpec, log)
}

// bindAll opens every privileged port and returns the files to pass to the
// child, in the order they will occupy ExtraFiles, plus the name:fd map that
// tells the child which is which.
func bindAll(log *slog.Logger) ([]*os.File, string, error) {
	var files []*os.File
	var parts []string

	ports := Ports()
	for i, name := range listen.Names() {
		port, ok := ports[name]
		if !ok {
			return nil, "", fmt.Errorf("no privileged port defined for %q", name)
		}
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, f := range files {
				f.Close() //nolint:errcheck
			}
			return nil, "", fmt.Errorf("binding %s: %w", addr, err)
		}
		f, err := ln.(*net.TCPListener).File()
		// The listener's own descriptor is not the one we pass — File()
		// returns a dup — so close it here. The socket stays open through f.
		ln.Close() //nolint:errcheck
		if err != nil {
			for _, g := range files {
				g.Close() //nolint:errcheck
			}
			return nil, "", fmt.Errorf("taking the descriptor for %s: %w", addr, err)
		}
		files = append(files, f)
		// ExtraFiles[i] becomes fd 3+i in the child.
		parts = append(parts, name+":"+strconv.Itoa(3+i))
		log.Info("bound privileged port", "socket", name, "addr", addr)
	}
	return files, strings.Join(parts, ","), nil
}

// supervise runs the child, restarting it with backoff if it dies
// unexpectedly. launchd only sees this process, so restarting the daemon is
// our job — and doing it here rather than by exiting is what keeps :443
// bound across a crash instead of leaving it free for something else to take.
func supervise(ctx context.Context, spec Spec, files []*os.File, fdSpec string, log *slog.Logger) error {
	const (
		minBackoff    = 1 * time.Second
		maxBackoff    = 30 * time.Second
		healthyPeriod = 60 * time.Second
	)
	backoff := minBackoff

	for {
		started := time.Now()
		code, err := runChild(ctx, spec, files, fdSpec, log)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		if code == 0 {
			// A clean exit is a deliberate stop. Exiting zero ourselves lets
			// launchd's KeepAlive{SuccessfulExit:false} leave the whole tree
			// down, which is what the user asked for.
			log.Info("daemon exited cleanly; stopping")
			return nil
		}

		if time.Since(started) > healthyPeriod {
			backoff = minBackoff // it was up and working; this is a fresh fault
		}
		log.Error("daemon exited unexpectedly; restarting",
			"code", code, "after", backoff)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runChild starts one instance and waits for it. It returns the exit code, or
// an error only for failures that retrying cannot fix.
func runChild(ctx context.Context, spec Spec, files []*os.File, fdSpec string, log *slog.Logger) (int, error) {
	cmd := exec.Command(spec.Exe, spec.Args...) //nolint:gosec // Exe is our own binary
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = files
	cmd.Env = append(childEnv(spec.Env, spec.Home), listen.EnvFDs+"="+fdSpec)
	cmd.Dir = spec.Home
	cmd.SysProcAttr = credential(spec.UID, spec.GID)

	if err := cmd.Start(); err != nil {
		// Failing to exec at all is a configuration fault (wrong path, wrong
		// uid), not a transient one. Retrying would spin forever.
		return 0, fmt.Errorf("starting the daemon as uid %d: %w", spec.UID, err)
	}
	log.Info("daemon started", "pid", cmd.Process.Pid, "uid", spec.UID)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 0, nil
	case <-ctx.Done():
		log.Info("stopping daemon", "pid", cmd.Process.Pid)
		signalChild(cmd)
		select {
		case <-done:
		case <-time.After(stopGrace):
			log.Warn("daemon did not stop; killing", "pid", cmd.Process.Pid, "after", stopGrace)
			killChild(cmd)
			<-done
		}
		return 0, nil
	}
}

// stopGrace is how long the daemon gets to shut down cleanly. Caddy drains
// connections on stop, so this is not instant, but it must stay well under
// launchd's own patience for a job that has been told to stop.
const stopGrace = 10 * time.Second

// childEnv strips the variables the child must not inherit and sets HOME to
// the target user's. Leaving root's HOME in place would put the CA and the
// config under /var/root, where `switchboard setup` — run as the user —
// would never look.
func childEnv(env []string, home string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		switch {
		case strings.HasPrefix(kv, "HOME="),
			strings.HasPrefix(kv, listen.EnvFDs+"="),
			// SUDO_* describe how *this* process was elevated. They are
			// meaningless to the child and actively misleading: `setup`
			// refuses to run when it sees SUDO_USER.
			strings.HasPrefix(kv, "SUDO_"):
			continue
		}
		out = append(out, kv)
	}
	return append(out, "HOME="+home)
}
