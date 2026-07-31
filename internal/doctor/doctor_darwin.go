package doctor

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/service"
)

func osChecks(cfg *config.Config, rootCertPath string) []Check {
	var checks []Check

	// /etc/resolver/<suffix> present and pointing at our DNS port.
	resolverPath := filepath.Join("/etc/resolver", cfg.Suffix)
	b, err := os.ReadFile(resolverPath)
	switch {
	case os.IsNotExist(err):
		checks = append(checks, Check{"resolver", Fail, resolverPath + " missing",
			"run: switchboard setup"})
	case err != nil:
		checks = append(checks, Check{"resolver", Warn, err.Error(), ""})
	default:
		content := string(b)
		wantPort := "port " + strconv.Itoa(cfg.EffDNSPort())
		if strings.Contains(content, "nameserver 127.0.0.1") && strings.Contains(content, wantPort) {
			checks = append(checks, Check{"resolver", OK, resolverPath + " → 127.0.0.1 " + wantPort, ""})
		} else {
			checks = append(checks, Check{"resolver", Fail,
				resolverPath + " exists but doesn't match the configured dns_port",
				"re-run: switchboard setup"})
		}
	}

	// Is the root CA actually trusted?
	//
	// This used to ask `security find-certificate` whether a certificate with
	// our name was *present*, which is a different question and answers it
	// wrongly in the case that matters. `security remove-trusted-cert` clears
	// the trust setting but leaves the certificate in the keychain — so
	// straight after `switchboard uninstall`, doctor reported "trust ✓" on a
	// machine where nothing was trusted at all. The one question doctor exists
	// to answer for "why is my browser warning me" was the one it got wrong.
	//
	// Verifying the certificate against the system pool asks exactly what a
	// TLS client asks, and cannot be satisfied by an untrusted leftover.
	if _, err := os.Stat(rootCertPath); err == nil {
		switch trusted, err := systemTrusts(rootCertPath); {
		case err != nil:
			checks = append(checks, Check{"trust", Warn,
				"could not check the system trust store: " + err.Error(), ""})
		case trusted:
			checks = append(checks, Check{"trust", OK, "root CA trusted in the System keychain", ""})
		default:
			checks = append(checks, Check{"trust", Fail,
				"root CA is not trusted by the system (browsers will warn)",
				"run: switchboard setup"})
		}
	}

	// Background service: a plist pointing at a binary that has since moved
	// (a Homebrew upgrade, a rebuild elsewhere) fails silently at boot.
	if state, plistPath, err := service.Status(); err == nil && state != service.NotInstalled {
		exe := service.InstalledExec()

		// Name the shape that is actually installed. doctor said "launch
		// agent" unconditionally, which on the launch-daemon path told the
		// user no privilege was involved while a root process was supervising
		// the tree. A diagnostic that misreports the privilege model is worse
		// than one that says nothing about it.
		kind := "launch agent"
		if plistPath == service.SystemPlistPath {
			kind = "launch daemon"
		}

		switch {
		case exe == "":
			checks = append(checks, Check{"service", Warn,
				"could not read the executable path from " + plistPath,
				"reinstall it: switchboard daemon install"})
		case !fileExists(exe):
			checks = append(checks, Check{"service", Fail,
				kind + " points at " + exe + ", which no longer exists",
				"repoint it: switchboard daemon install"})
		case state == service.Running:
			checks = append(checks, Check{"service", OK, kind + " running (" + exe + ")", ""})
		case state == service.Loaded:
			checks = append(checks, Check{"service", Warn, kind + " loaded but not running (" + exe + ")",
				"check the log: switchboard daemon logs"})
		default: // service.NotLoaded
			checks = append(checks, Check{"service", Warn, "plist installed but not loaded by launchd (" + exe + ")",
				"reinstall it: switchboard daemon install"})
		}

		// The launch daemon runs a root-owned copy of the binary, not the one
		// on your PATH (see service.StagedExecPath). That is deliberate, but
		// it means `brew upgrade` updates one and not the other — so the
		// staleness has to be visible, or you would debug a fixed bug against
		// a daemon still running the old build.
		if kind == "launch daemon" {
			if current, err := os.Executable(); err == nil {
				same, cmpErr := sameContents(current, service.StagedExecPath)
				switch {
				case cmpErr != nil:
					// Not worth a check of its own; the exe checks above
					// already cover a missing or unreadable staged binary.
				case !same:
					checks = append(checks, Check{"service version", Warn,
						"the running daemon is a different build from " + current,
						"pick up the new binary: switchboard daemon install"})
				}
			}
		}

		// On the privileged path, say what is and is not running as root.
		// This is the claim the whole design rests on, and doctor is where
		// someone would go to check it rather than take the README's word.
		if kind == "launch daemon" && state == service.Running {
			if uid := serveProcessUser(); uid != "" {
				status, advice := OK, ""
				if uid == "root" || uid == "0" {
					status = Fail
					advice = "this should never happen — report it"
				}
				checks = append(checks, Check{"privilege", status,
					"proxy running as " + uid + "; only the socket-binding parent is root", advice})
			}
		}
	}

	return checks
}

// systemTrusts reports whether the system trust store accepts the
// certificate at path as a valid anchor.
//
// It verifies the certificate against itself as its own root: a
// self-signed CA verifies only if the platform verifier already trusts it,
// which is the same test a browser applies. Caddy's PKI uses this exact
// check for the same purpose.
func systemTrusts(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, fmt.Errorf("%s is not a PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	// Empty VerifyOptions means "use the system roots". A name-constrained
	// root permits its own subject, so no DNSName is supplied — this asks
	// only whether the anchor is trusted, not whether it may sign a host.
	chains, err := cert.Verify(x509.VerifyOptions{})
	return len(chains) > 0 && err == nil, nil
}

// sameContents reports whether two files are byte-identical. Sizes are
// compared first because the binary is ~64MB and differing sizes settle it
// without reading either file — which is the common case after an upgrade.
func sameContents(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	if fa.Size() != fb.Size() {
		return false, nil
	}
	ha, err := fileSum(a)
	if err != nil {
		return false, err
	}
	hb, err := fileSum(b)
	if err != nil {
		return false, err
	}
	return ha == hb, nil
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// serveProcessUser reports the user running the unprivileged daemon child, or
// "" if it cannot be determined.
//
// It matches on the `__serve` subcommand rather than on the binary name: the
// parent is the same binary, so matching the name would find whichever
// process ps happened to list first — and the answer that matters is
// specifically the one holding the TLS stack and the CA.
func serveProcessUser() string {
	out, err := exec.Command("ps", "-axo", "user=,command=").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		cmd := strings.Join(fields[1:], " ")
		if strings.Contains(cmd, "switchboard __serve") && !strings.Contains(cmd, "ps -axo") {
			return fields[0]
		}
	}
	return ""
}
