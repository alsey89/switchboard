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

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/proxy"
)

// isTrusted is proxy.IsTrusted, indirected so tests can exercise the
// trust-removal path without a real keychain — genuinely trusting a
// certificate needs an authorization dialog a test cannot answer.
var isTrusted = proxy.IsTrusted

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

// ResolverDir is /etc/resolver, as a var so tests can redirect it.
//
// Exported because the isolation is needed from other packages too: a CLI
// test that drives `switchboard uninstall` end to end reaches this path, and
// without a way to redirect it the test issues `sudo rm` against the real
// /etc/resolver of whatever machine runs the suite.
//
// As a literal it made tests depend on the developer's own machine:
// removeResolver short-circuits when the file does not exist, so an assertion
// that the old suffix's file is removed passed or failed according to what
// happened to be in /etc/resolver at the time. That is the third test in this
// package to be caught reaching real system paths.
var ResolverDir = "/etc/resolver"

func resolverFilePath(suffix string) string { return filepath.Join(ResolverDir, suffix) }

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

// systemSetupPresent reports whether anything setup installed is still on the
// machine. Used so `uninstall` does not announce success for a machine that
// was already clean — which is indistinguishable, to the reader, from having
// actually undone something.
func systemSetupPresent(cfg *config.Config, dataDir string) bool {
	if _, err := os.Stat(resolverFilePath(cfg.Suffix)); err == nil {
		return true
	}
	trusted, err := isTrusted(proxy.RootCertPath(dataDir))
	return err == nil && trusted
}

// AuthNotice describes the authorization prompts a `setup` will produce, so
// callers can warn before starting rather than let them arrive unannounced.
//
// The keychain one is worth calling out specifically. It is a separate window
// that macOS may open behind whatever is in front, so someone who confirms and
// looks away sees nothing happen and reasonably concludes it hung. An
// unannounced password prompt is also the exact shape of the thing people are
// taught to cancel.
//
// The focus note is not padding. The dialog shows the Touch ID prompt whether
// or not it has focus, but the sensor is only armed while it is frontmost —
// so an unfocused dialog displays a fingerprint icon that does nothing. That
// was mistaken first for macOS rationing Touch ID on a schedule of its own,
// and then for the prompt not offering it at all. Both were wrong in the same
// direction: the icon is there, it just will not respond.
//
// The counts are deliberately vague. sudo caches its timestamp and macOS
// reuses keychain authorizations under rules of its own, so a precise promise
// would be wrong often enough to be worse than none.
func AuthNotice() []string {
	return []string{
		"in this terminal, for the system files (sudo)",
		"in a macOS dialog window, for the keychain — it can open behind other windows;" +
			" click it to focus, or Touch ID will not respond",
	}
}

// userKeychain resolves the login keychain — the user's own trust domain.
//
// Switchboard installs its CA here rather than in /Library/Keychains/
// System.keychain, and the difference is a privilege one. The system store
// requires root and grants trust to every account and system service on the
// machine. The login keychain requires no root at all and grants trust to
// the one user who asked for it, which is the only one who needs it: the
// daemon runs as you, and so does your browser.
//
// Verified on macOS 15 that curl, Go's verifier (which is what `doctor`
// uses) and a real TLS handshake all honour user-domain trust. Python and
// Node do not — but they do not honour the system store either, since both
// ship their own CA bundles; that is unchanged either way and needs
// NODE_EXTRA_CA_CERTS or equivalent.
func userKeychain() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	// login.keychain-db since Sierra; the older name is still accepted on
	// machines upgraded across that boundary.
	for _, name := range []string{"login.keychain-db", "login.keychain"} {
		p := filepath.Join(home, "Library", "Keychains", name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no login keychain found in %s/Library/Keychains", home)
}

func installTrust(rootPath string, out io.Writer) ([]string, error) {
	kc, err := userKeychain()
	if err != nil {
		return nil, err
	}
	// No sudo: this touches the user's own keychain. macOS still asks for
	// authorization — that dialog is the Security framework, not sudo, and
	// it is what makes "trust a new certificate authority" a deliberate act
	// rather than something a script can do silently.
	if err := runVisibleUnprivileged(out, "security", "add-trusted-cert", "-r", "trustRoot",
		"-k", kc, rootPath); err != nil {
		return nil, fmt.Errorf("installing CA into your login keychain: %w", err)
	}
	notes := []string{"root CA trusted in your login keychain (no root required)"}
	if firefoxPresent() {
		notes = append(notes,
			"Firefox: recent versions read the platform trust store; if you run an older "+
				"one, enable security.enterprise_roots.enabled in about:config")
	}
	return notes, nil
}

func removeTrust(rootPath string, out io.Writer) error {
	if _, err := os.Stat(rootPath); os.IsNotExist(err) {
		return nil
	}
	kc, err := userKeychain()
	if err != nil {
		return err
	}

	// What matters is whether the certificate ends up untrusted, not whether
	// `security` exits zero. Those differ in both directions:
	//
	//   - Removing trust that was never granted exits 1 with "The specified
	//     item could not be found in the keychain". That is the desired end
	//     state, not a failure — and treating it as one made `setup` abort
	//     mid-rotation on a machine where the old root simply was not trusted.
	//
	//   - The reverse matters more. A root trusted in the *system* keychain by
	//     an older version cannot be untrusted from the user domain, so the
	//     command can fail while the certificate stays trusted. Silently
	//     continuing there would delete the file and strand a trusted root
	//     that nothing on disk can identify any more.
	//
	// So: attempt it, then check.
	sum, sumErr := certSHA1(rootPath)
	if trusted, tErr := isTrusted(rootPath); tErr == nil && trusted {
		runVisibleUnprivileged(out, "security", "remove-trusted-cert", rootPath) //nolint:errcheck

		if stillTrusted, tErr := isTrusted(rootPath); tErr == nil && stillTrusted {
			hint := ""
			if sumErr == nil {
				hint = fmt.Sprintf("\n  If it was trusted system-wide by an older version, remove it with:\n"+
					"    sudo security delete-certificate -Z %s /Library/Keychains/System.keychain", sum)
			}
			return fmt.Errorf("the root CA at %s is still trusted after trying to remove it.%s",
				rootPath, hint)
		}
	} else {
		fmt.Fprintln(out, "  (the old root was not trusted; nothing to remove)")
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
	if sumErr != nil {
		fmt.Fprintf(out, "  (could not fingerprint %s to remove it from the keychain: %v)\n", rootPath, sumErr)
		return nil
	}

	// Only attempt the delete if the certificate is actually there. Otherwise
	// `security` prints its own failure and we print a second, wronger one:
	// the previous version claimed the certificate was "untrusted but still
	// in the keychain" when the truth was that it had never been in this
	// keychain at all.
	present, presErr := certInKeychain(sum, kc)
	if presErr == nil && !present {
		return nil
	}
	runVisibleUnprivileged(out, "security", "delete-certificate", "-Z", sum, kc) //nolint:errcheck

	// Same rule as trust removal: report what is true afterwards, not what
	// the command returned.
	if still, err := certInKeychain(sum, kc); err == nil && still {
		fmt.Fprintf(out, "  (the certificate is untrusted but still in the keychain; "+
			"remove it with: security delete-certificate -Z %s %s)\n", sum, kc)
	}
	return nil
}

// certInKeychain reports whether a certificate with the given SHA-1
// fingerprint is present in a keychain.
//
// `security find-certificate` has no search-by-hash, so this lists the
// fingerprints it does have and looks for ours. Matching on the hash rather
// than the common name matters: every Switchboard root ever generated on a
// machine shares a name, and the question here is about one specific
// certificate.
var certInKeychain = func(sha1hex, keychain string) (bool, error) {
	out, err := exec.Command("security", "find-certificate", "-a", "-Z", keychain).Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToUpper(string(out)), strings.ToUpper(sha1hex)), nil
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
