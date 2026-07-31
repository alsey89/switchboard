package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRootConstraintIsEnforced is the test the whole design rests on. It is
// not enough that the root carries a nameConstraints extension — the
// extension has to actually cause verification to fail for a domain outside
// the suffix, through a realistic root → intermediate → leaf chain, which is
// the shape Caddy's PKI builds.
//
// If this test ever fails, the honest conclusion is that name constraints
// are not buying what the ADR claims and the root is once again a
// sign-anything capability.
func TestRootConstraintIsEnforced(t *testing.T) {
	rootCert, rootKey := mustRoot(t, "test")
	interCert, interKey := mustIntermediate(t, rootCert, rootKey)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	inters.AddCert(interCert)

	for _, tc := range []struct {
		name    string
		dnsName string
		wantOK  bool
	}{
		{"inside the suffix", "app.test", true},
		{"the suffix itself", "test", true},
		{"deep inside the suffix", "api.staging.app.test", true},
		{"a real domain", "www.google.com", false},
		{"a lookalike that only ends in the label", "evil.notatest", false},
		{"another reserved TLD we do not manage", "app.internal", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := mustLeaf(t, interCert, interKey, tc.dnsName)
			_, err := leaf.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: inters,
				DNSName:       tc.dnsName,
				CurrentTime:   time.Now(),
			})
			if tc.wantOK && err != nil {
				t.Fatalf("verifying %q should succeed, got: %v", tc.dnsName, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("verifying %q succeeded — the name constraint is not being "+
					"enforced, so a leaked root key can impersonate any site", tc.dnsName)
			}
		})
	}
}

// TestRootExcludesIPAddresses covers the gap a dNSName-only constraint
// leaves: name constraints are per-type, so a certificate whose SAN is an IP
// rather than a hostname is untouched by PermittedDNSDomains.
func TestRootExcludesIPAddresses(t *testing.T) {
	rootCert, rootKey := mustRoot(t, "test")
	interCert, interKey := mustIntermediate(t, rootCert, rootKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "9.9.9.9"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("9.9.9.9")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, interCert, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	inters.AddCert(interCert)

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inters, CurrentTime: time.Now(),
	}); err == nil {
		t.Fatal("a certificate for an IP address verified against our root — " +
			"ExcludedIPRanges is not doing its job, so the root can still be used " +
			"to MITM anything reachable by address")
	}
}

// TestEnsureRootIsIdempotentAndConstrained checks the on-disk behaviour: the
// first call writes a constrained root, the second reuses it rather than
// silently minting a second one (which would leave an orphaned trusted root
// in the user's keychain every time the daemon started).
func TestEnsureRootIsIdempotentAndConstrained(t *testing.T) {
	dir := t.TempDir()

	path, err := EnsureRoot(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if path != RootCertPath(dir) {
		t.Errorf("EnsureRoot returned %q, want %q", path, RootCertPath(dir))
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := EnsureRoot(dir, "test"); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("EnsureRoot regenerated the root on a second call; the old one " +
			"would stay trusted in the system keychain forever")
	}

	// The private key must not be group- or world-readable.
	info, err := os.Stat(filepath.Join(dir, "pki", "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("root key mode = %o, want 600 — this key signs certificates the "+
			"whole system trusts", perm)
	}
}

// TestEnsureRootRefusesASuffixItDoesNotCover is the guard against a silent
// downgrade: changing `suffix` in the config must not leave the daemon using
// a root that cannot legitimately sign for the new suffix. Browsers would
// reject every certificate, and the failure would look like a TLS bug rather
// than a configuration one.
func TestEnsureRootRefusesASuffixItDoesNotCover(t *testing.T) {
	dir := t.TempDir()
	if _, err := EnsureRoot(dir, "test"); err != nil {
		t.Fatal(err)
	}

	_, err := EnsureRoot(dir, "internal")
	if err == nil {
		t.Fatal("EnsureRoot accepted a suffix the existing root does not permit")
	}
	if !errors.Is(err, ErrRootSuffixMismatch) {
		t.Errorf("error should be ErrRootSuffixMismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "switchboard setup") {
		t.Errorf("the error must tell the user how to recover, got: %v", err)
	}
}

// TestRootCoversSuffixRejectsAnUnconstrainedRoot: a root without constraints
// must be treated as unusable rather than as "constraints not required". A
// pre-existing unconstrained root is precisely the thing being retired, so
// accepting one would let it survive an upgrade untouched.
func TestRootCoversSuffixRejectsAnUnconstrainedRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Legacy Unconstrained Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(rootLifetime),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := RootCertPath(dir)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}

	err = RootCoversSuffix(path, "test")
	if err == nil {
		t.Fatal("an unconstrained root was accepted")
	}
	if !strings.Contains(err.Error(), "any domain") {
		t.Errorf("the error should say why an unconstrained root is dangerous, got: %v", err)
	}
}

// --- helpers ---------------------------------------------------------------

func mustRoot(t *testing.T, suffix string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	der, key, err := newConstrainedRoot(suffix, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// mustIntermediate mimics what Caddy's PKI does beneath our root: an
// unconstrained intermediate. That is the realistic case — the intermediate
// asserts nothing, so all the protection has to come from the root.
func mustIntermediate(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: caName + " - Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func mustLeaf(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, dnsName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
