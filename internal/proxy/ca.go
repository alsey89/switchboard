package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Switchboard mints its own root CA rather than letting Caddy's internal PKI
// generate one. The reason is X.509 name constraints.
//
// The root ends up in the system trust store, which means a browser will
// accept anything it signs. An unconstrained root is therefore a
// sign-anything-for-anyone capability sitting on the user's disk: whoever
// gets the key can mint a certificate for their bank that the machine
// believes. Caddy's PKI exposes no way to set nameConstraints, but it does
// accept a supplied root (caddypki.CA.Root), so we generate one with
// PermittedDNSDomains pinned to the managed suffix and hand it over. Caddy
// still creates and rotates the intermediate and the leaves beneath it.
//
// Constraints on a root are enforced by macOS, NSS/Firefox, Chrome's
// verifier, and Go's crypto/x509 — see TestRootConstraintIsEnforced, which
// asserts the whole chain is rejected for a domain outside the suffix.
//
// This is a bound on the damage, not a fix for a leaked key: within the
// suffix the key is still absolute. It turns "can impersonate your bank"
// into "can impersonate your own dev machine", which is the difference
// between a system-wide compromise and a local one.

// rootLifetime matches Caddy's own default for internal roots. The root is
// re-created by `switchboard setup`, so the ceiling is a backstop rather
// than a rotation schedule.
const rootLifetime = 10 * 365 * 24 * time.Hour

// pkiDir holds the Switchboard-generated root. It sits beside Caddy's
// storage rather than inside it: Caddy owns everything under caddy/, and a
// file we write into another component's storage tree is a file that
// component is entitled to delete.
func pkiDir(dataDir string) string { return filepath.Join(dataDir, "pki") }

// RootCertPath is the local root CA certificate — the file `setup` installs
// into the system trust store.
func RootCertPath(dataDir string) string { return filepath.Join(pkiDir(dataDir), "root.crt") }

// rootKeyPath is the matching private key. Never leaves this machine.
func rootKeyPath(dataDir string) string { return filepath.Join(pkiDir(dataDir), "root.key") }

// ErrRootSuffixMismatch reports a root whose name constraints do not cover
// the configured suffix. Recoverable only by removing trust in the old root
// and generating a new one, which is `switchboard uninstall && switchboard
// setup` — we do not perform trust-store surgery implicitly.
var ErrRootSuffixMismatch = errors.New("the local root CA does not cover this domain suffix")

// EnsureRoot creates the name-constrained root CA if it does not yet exist,
// and verifies an existing one still covers suffix. Returns the cert path.
func EnsureRoot(dataDir, suffix string) (string, error) {
	certPath, keyPath := RootCertPath(dataDir), rootKeyPath(dataDir)

	if _, err := os.Stat(certPath); err == nil {
		if err := RootCoversSuffix(certPath, suffix); err != nil {
			return "", err
		}
		return certPath, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	certDER, key, err := newConstrainedRoot(suffix, time.Now())
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(pkiDir(dataDir), 0o700); err != nil {
		return "", err
	}
	// Key first, and 0600: a root certificate with no key is inert, but a
	// key with no certificate still signs. If we are interrupted between the
	// two writes, the harmless ordering is the one that leaves no key behind
	// that a later run would treat as already-provisioned.
	if err := writeFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", err
	}
	if err := writeFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		return "", err
	}
	return certPath, nil
}

// RootCoversSuffix reports whether the root at certPath is constrained in a
// way that permits suffix. An unconstrained root fails: a root with no
// constraints is exactly what this design exists to avoid, so silently
// accepting one would let a pre-existing root defeat the whole mechanism.
func RootCoversSuffix(certPath, suffix string) error {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("%s is not a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if !cert.PermittedDNSDomainsCritical && len(cert.PermittedDNSDomains) == 0 {
		return fmt.Errorf("%w: %s has no name constraints at all, so it can sign "+
			"certificates for any domain. Remove it with `switchboard uninstall` "+
			"and re-run `switchboard setup` to generate a constrained one",
			ErrRootSuffixMismatch, certPath)
	}
	for _, d := range cert.PermittedDNSDomains {
		if d == suffix {
			return nil
		}
	}
	return fmt.Errorf("%w: %s permits %v, but the configured suffix is %q. "+
		"Run `switchboard uninstall` then `switchboard setup` to re-issue it",
		ErrRootSuffixMismatch, certPath, cert.PermittedDNSDomains, suffix)
}

// newConstrainedRoot builds the self-signed root. now is a parameter so the
// test can pin validity windows.
func newConstrainedRoot(suffix string, now time.Time) ([]byte, *ecdsa.PrivateKey, error) {
	if suffix == "" {
		return nil, nil, errors.New("cannot constrain a root to an empty suffix")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// Excluding every IP range matters as much as permitting the one DNS
	// suffix. Name constraints are per-type: a certificate carrying only an
	// IP SAN is unaffected by a dNSName constraint, so without these two
	// lines a leaked key could still mint a trusted certificate for
	// https://<any-address>.
	_, allIPv4, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return nil, nil, err
	}
	_, allIPv6, err := net.ParseCIDR("::/0")
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caName},
		NotBefore:             now.Add(-1 * time.Hour), // clock skew
		NotAfter:              now.Add(rootLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,

		PermittedDNSDomains:         []string{suffix},
		PermittedDNSDomainsCritical: true,
		ExcludedIPRanges:            []*net.IPNet{allIPv4, allIPv6},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return der, key, nil
}

// writeFile writes atomically-ish with an explicit mode, because os.WriteFile
// applies the mode only when creating and we care about the key's 0600.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	return os.Rename(tmp, path)
}
