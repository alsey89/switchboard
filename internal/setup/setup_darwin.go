package setup

import (
	"crypto/sha1" //nolint:gosec // not a security primitive here: this is the fingerprint format `security` indexes certificates by
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// sha1Sum wraps the hash so the nolint above sits in one place.
func sha1Sum(b []byte) []byte {
	sum := sha1.Sum(b) //nolint:gosec // see import comment
	return sum[:]
}

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

	// /etc/resolver does not exist on a stock macOS install — it is created by
	// whatever first wants split DNS, and on a machine that has never run
	// puma-dev, Valet or a VPN client, that is us. Without this, `install`
	// fails with a message naming its own temp file
	// ("install: /etc/resolver/INS@GsvEMH: No such file or directory"), which
	// points nowhere near the actual cause.
	//
	// -d is idempotent, so this is safe where the directory already exists.
	if err := runVisible(out, "install", "-d", "-m", "0755", "-o", "root", "-g", "wheel",
		filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

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
	if err := runVisible(out, "security", "remove-trusted-cert", "-d", rootPath); err != nil {
		return err
	}

	// remove-trusted-cert clears the *trust setting* and leaves the
	// certificate itself in the keychain. That made `uninstall` print "system
	// setup removed" while a CA certificate stayed installed system-wide —
	// inert, since it is no longer trusted, but litter that accumulates one
	// copy per install/uninstall cycle, and enough to make a presence-based
	// trust check report success forever after. doctor was doing exactly that.
	//
	// Deleting by SHA-1 rather than by name: `delete-certificate -c` matches
	// on the common name, and every Switchboard root ever generated on this
	// machine shares one. Deleting the specific certificate we installed is
	// the only version of this that cannot remove someone else's.
	sum, err := certSHA1(rootPath)
	if err != nil {
		fmt.Fprintf(out, "  (could not fingerprint %s to remove it from the keychain: %v)\n", rootPath, err)
		return nil
	}
	if err := runVisible(out, "security", "delete-certificate", "-Z", sum, systemKeychain); err != nil {
		// Non-fatal: trust is already gone, which is the part that matters for
		// safety. Say so rather than failing the whole uninstall.
		fmt.Fprintf(out, "  (the certificate is untrusted but still in the keychain; "+
			"remove it with: sudo security delete-certificate -Z %s %s)\n", sum, systemKeychain)
	}
	return nil
}

// certSHA1 is the fingerprint `security` uses to identify a certificate.
func certSHA1(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s is not a PEM certificate", path)
	}
	return strings.ToUpper(hex.EncodeToString(sha1Sum(block.Bytes))), nil
}

func firefoxPresent() bool {
	if _, err := os.Stat("/Applications/Firefox.app"); err == nil {
		return true
	}
	_, err := exec.LookPath("firefox")
	return err == nil
}
