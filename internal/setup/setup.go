// Package setup performs the one-time, privileged system configuration:
// pointing the OS resolver at Switchboard's DNS for the managed TLD, and
// installing the local root CA into the system trust store.
//
// Philosophy: the daemon itself always runs unprivileged. Only these
// one-shot steps elevate, each as a separate, visible command (printed
// before it runs), so the user can see exactly what they are consenting to.
// On macOS that is one `sudo` prompt here — for the resolver file — plus a
// keychain authorization for the CA, which is macOS's Security framework
// rather than sudo and needs no root at all. Serving :80/:443 adds a third
// moment, in `daemon install`, which sets up the privileged parent that binds
// those sockets and immediately drops to the user (ADR 0001). On high ports
// there is no third and nothing privileged runs.
package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/proxy"
)

// Result reports what setup did, for the CLI to summarize.
type Result struct {
	RootCertPath  string
	ResolverNotes []string
	TrustNotes    []string
}

// Run performs setup for the current OS. Out receives progress lines.
func Run(ctx context.Context, cfg *config.Config, dataDir string, out io.Writer) (*Result, error) {
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		return nil, fmt.Errorf("run `switchboard setup` without sudo — it will ask for " +
			"your password only for the steps that need it. Running the whole command as " +
			"root would create the CA under root's home instead of yours")
	}

	// 1. Make sure the CA exists (unprivileged; must happen before trust).
	// Switchboard mints this root itself rather than asking Caddy for one,
	// so that it can carry name constraints — see internal/proxy/ca.go. A
	// side benefit is that setup no longer has to boot Caddy at all.
	fmt.Fprintln(out, "→ ensuring local root CA exists…")
	rootPath, err := proxy.EnsureRoot(dataDir, cfg.Suffix)
	if errors.Is(err, proxy.ErrRootSuffixMismatch) {
		// The suffix changed since the CA was minted. The root's name
		// constraint names one suffix, so it cannot legitimately sign for the
		// new one — every certificate would be rejected by the browser, and
		// the failure would read as a TLS bug rather than a configuration
		// change.
		//
		// setup is the right place to fix this and the daemon is not: this
		// rotates a trusted root, which must be a deliberate act. Running
		// `switchboard setup` after editing `suffix` is exactly that; a daemon
		// doing it on a config reload would not be.
		if rootPath, err = rotateCA(cfg, dataDir, out); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "  CA root: %s\n", rootPath)
	fmt.Fprintf(out, "  constrained to .%s — it cannot sign for any other domain\n", cfg.Suffix)

	res := &Result{RootCertPath: rootPath}

	// 2. Resolver: OS-specific (may print manual instructions on
	//    not-yet-automated platforms).
	fmt.Fprintf(out, "→ pointing the OS resolver for .%s at 127.0.0.1:%d…\n", cfg.Suffix, cfg.EffDNSPort())
	notes, err := installResolver(cfg.Suffix, cfg.EffDNSPort(), out)
	if err != nil {
		return nil, err
	}
	res.ResolverNotes = notes

	// 3. Trust store: OS-specific.
	fmt.Fprintln(out, "→ installing the root CA into the system trust store…")
	trustNotes, err := installTrust(rootPath, out)
	if err != nil {
		return nil, err
	}
	res.TrustNotes = trustNotes

	return res, nil
}

// rotateCA replaces a root CA whose name constraint no longer matches the
// configured suffix.
//
// The order matters and is the whole reason this is a function rather than
// three lines. Trust in the old root is removed *first*: if the files were
// deleted first and the process died before the keychain was touched, the
// user would be left with a trusted root whose certificate we can no longer
// find on disk to identify — untrusting it would then be a manual job in
// Keychain Access.
func rotateCA(cfg *config.Config, dataDir string, out io.Writer) (string, error) {
	oldPath := proxy.RootCertPath(dataDir)

	fmt.Fprintf(out, "  the suffix changed, so the CA has to be re-issued:\n")
	fmt.Fprintf(out, "    the existing root is constrained to a different domain and cannot\n")
	fmt.Fprintf(out, "    sign for .%s — every certificate would be rejected.\n", cfg.Suffix)

	fmt.Fprintln(out, "  removing trust in the old root…")
	if err := removeTrust(oldPath, out); err != nil {
		return "", fmt.Errorf("removing trust in the old root CA: %w", err)
	}

	// The old suffix's resolver file has to go too, and the old root is the
	// only record of which suffix that was. Left behind, it keeps telling the
	// OS to send that entire namespace to our DNS responder — which no longer
	// answers for it. The effect is machine-wide and silent: names under the
	// old suffix stop resolving altogether instead of falling through to
	// normal DNS, and nothing in the tool mentions the file that is doing it.
	for _, old := range proxy.RootSuffixes(oldPath) {
		if old == cfg.Suffix {
			continue
		}
		fmt.Fprintf(out, "  removing the resolver file for the previous suffix .%s…\n", old)
		if err := removeResolver(old, out); err != nil {
			return "", fmt.Errorf("removing the resolver file for .%s: %w", old, err)
		}
	}

	fmt.Fprintln(out, "  deleting the old CA and every certificate issued under it…")
	if err := proxy.RemoveCA(dataDir); err != nil {
		return "", err
	}

	rootPath, err := proxy.EnsureRoot(dataDir, cfg.Suffix)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(out, "  re-issued.")
	return rootPath, nil
}

// Remove undoes Run (leaves config and CA files on disk).
func Remove(cfg *config.Config, dataDir string, out io.Writer) error {
	if err := removeResolver(cfg.Suffix, out); err != nil {
		return err
	}
	return removeTrust(proxy.RootCertPath(dataDir), out)
}

// runVisible prints a command, then runs it attached to the user's terminal
// (so sudo can prompt). Commands are elevated with sudo unless already root.
//
// A package var, not a plain func, so tests can record the elevated commands
// this package issues without running them. Everything privileged Switchboard
// does on macOS goes through here, which makes it the one place a test can
// assert on the sequence.
var runVisible = func(out io.Writer, name string, args ...string) error {
	if os.Geteuid() != 0 && name != "sudo" {
		args = append([]string{name}, args...)
		name = "sudo"
	}
	fmt.Fprintf(out, "  $ %s %s\n", name, joinArgs(args))
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runVisibleUnprivileged is runVisible without the sudo. It exists because
// installing the local CA no longer needs root: trust goes into the user's
// own keychain rather than the system one, so elevating would be asking for
// a privilege the operation does not use.
//
// It still prints the command, for the same reason the elevated one does —
// the user should be able to read what is about to touch their keychain.
var runVisibleUnprivileged = func(out io.Writer, name string, args ...string) error {
	fmt.Fprintf(out, "  $ %s %s\n", name, joinArgs(args))
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func joinArgs(args []string) string {
	s := ""
	for i, a := range args {
		if i > 0 {
			s += " "
		}
		s += a
	}
	return s
}
