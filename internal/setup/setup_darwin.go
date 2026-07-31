package setup

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// macOS: /etc/resolver/<suffix> tells mDNSResponder to send queries for that
// suffix to our DNS server — including on a custom port, which is why the
// daemon never needs to fight over :53. (puma-dev ships the same pattern.)
// A multi-label suffix works the same way: /etc/resolver/dev.example.com
// matches that domain and all its subdomains.

func resolverFilePath(suffix string) string { return filepath.Join("/etc/resolver", suffix) }

// ResolverFileContents is exported for doctor to compare against.
func ResolverFileContents(dnsPort int) string {
	return fmt.Sprintf("nameserver 127.0.0.1\nport %d\n", dnsPort)
}

func installResolver(suffix string, dnsPort int, out io.Writer) ([]string, error) {
	path := resolverFilePath(suffix)
	contents := ResolverFileContents(dnsPort)

	// Write via a temp file + sudo install: keeps the elevated step to a
	// single, inspectable command instead of a shell pipeline.
	tmp, err := os.CreateTemp("", "switchboard-resolver-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(contents); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()

	if err := runVisible(out, "install", "-m", "0644", "-o", "root", "-g", "wheel", tmp.Name(), path); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}

	// Nudge mDNSResponder so the new resolver file is picked up immediately.
	if err := runVisible(out, "killall", "-HUP", "mDNSResponder"); err != nil {
		// Non-fatal: macOS also notices the file on its own, eventually.
		fmt.Fprintf(out, "  (could not HUP mDNSResponder: %v — a reboot or a few minutes will also do)\n", err)
	}

	return []string{
		fmt.Sprintf("resolver file: %s", path),
		"verify with: scutil --dns | grep -A2 " + suffix,
		"note: dig/nslookup bypass /etc/resolver — test with a browser or curl",
	}, nil
}

func removeResolver(suffix string, out io.Writer) error {
	path := resolverFilePath(suffix)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	if err := runVisible(out, "rm", "-f", path); err != nil {
		return err
	}
	runVisible(out, "killall", "-HUP", "mDNSResponder") //nolint:errcheck
	return nil
}

const systemKeychain = "/Library/Keychains/System.keychain"

func installTrust(rootPath string, out io.Writer) ([]string, error) {
	if err := runVisible(out, "security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", systemKeychain, rootPath); err != nil {
		return nil, fmt.Errorf("installing CA into System keychain: %w", err)
	}
	notes := []string{"root CA trusted in the System keychain"}
	if firefoxPresent() {
		notes = append(notes,
			"Firefox: recent versions read the system trust store; if you run an older "+
				"one, enable security.enterprise_roots.enabled in about:config")
	}
	return notes, nil
}

func removeTrust(rootPath string, out io.Writer) error {
	if _, err := os.Stat(rootPath); os.IsNotExist(err) {
		return nil
	}
	return runVisible(out, "security", "remove-trusted-cert", "-d", rootPath)
}

func firefoxPresent() bool {
	if _, err := os.Stat("/Applications/Firefox.app"); err == nil {
		return true
	}
	_, err := exec.LookPath("firefox")
	return err == nil
}
