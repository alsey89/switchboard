// Package setup performs the one-time, privileged system configuration:
// pointing the OS resolver at Switchboard's DNS for the managed TLD, and
// installing the local root CA into the system trust store.
//
// Philosophy: the daemon itself always runs unprivileged. Only these
// one-shot steps elevate, each as a separate, visible command (printed
// before it runs), so the user can see exactly what they are consenting to.
// On macOS that is two `sudo` prompts today — and only because the daemon is
// confined to high ports. Binding :80/:443 needs privilege from somewhere,
// and resolving that (ADR 0001) is expected to add a third one-time step.
package setup

import (
	"context"
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
	fmt.Fprintln(out, "→ ensuring local root CA exists…")
	rootPath, err := proxy.EnsureCA(ctx, dataDir)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "  CA root: %s\n", rootPath)

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

// Remove undoes Run (leaves config and CA files on disk).
func Remove(cfg *config.Config, dataDir string, out io.Writer) error {
	if err := removeResolver(cfg.Suffix, out); err != nil {
		return err
	}
	return removeTrust(proxy.RootCertPath(dataDir), out)
}

// runVisible prints a command, then runs it attached to the user's terminal
// (so sudo can prompt). Commands are elevated with sudo unless already root.
func runVisible(out io.Writer, name string, args ...string) error {
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
