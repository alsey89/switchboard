package setup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// recordCommands swaps runVisible for a recorder, returning the slice the
// issued commands land in. Nothing is executed.
func recordCommands(t *testing.T) *[][]string {
	t.Helper()
	var got [][]string
	orig := runVisible
	runVisible = func(_ io.Writer, name string, args ...string) error {
		got = append(got, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() { runVisible = orig })
	return &got
}

// TestInstallResolverCreatesTheDirectoryFirst is the regression test for a
// bug that reached a real machine: `/etc/resolver` does not exist on a stock
// macOS install. It is created by whatever first wants split DNS — puma-dev,
// Valet, a VPN client — and on a machine that has run none of those, that is
// us.
//
// Without the mkdir, `install` fails with a message naming its own temp file:
//
//	install: /etc/resolver/INS@GsvEMH: No such file or directory
//
// which names neither the directory nor anything a user could act on. And it
// failed on exactly the machines that matter most — the ones doing this for
// the first time.
func TestInstallResolverCreatesTheDirectoryFirst(t *testing.T) {
	got := recordCommands(t)

	if _, err := installResolver("test", 53535, io.Discard); err != nil {
		t.Fatal(err)
	}

	mkdirAt, writeAt := -1, -1
	for i, cmd := range *got {
		switch {
		case cmd[0] == "install" && slices.Contains(cmd, "-d"):
			if !slices.Contains(cmd, "/etc/resolver") {
				t.Errorf("the mkdir should target /etc/resolver, got %v", cmd)
			}
			mkdirAt = i
		case cmd[0] == "install" && slices.Contains(cmd, "/etc/resolver/test"):
			writeAt = i
		}
	}

	if mkdirAt < 0 {
		t.Fatalf("setup never creates /etc/resolver; on a machine without it every "+
			"first run fails. Commands issued: %v", *got)
	}
	if writeAt < 0 {
		t.Fatalf("the resolver file is never written. Commands issued: %v", *got)
	}
	if mkdirAt > writeAt {
		t.Errorf("the directory is created at step %d but written to at step %d — "+
			"the write happens first and fails", mkdirAt, writeAt)
	}
}

// TestInstallResolverWritesRootOwnedFiles: /etc/resolver steers DNS
// system-wide, so a file there that the user can rewrite would let any local
// process redirect name resolution for the whole machine.
func TestInstallResolverWritesRootOwnedFiles(t *testing.T) {
	got := recordCommands(t)

	if _, err := installResolver("test", 53535, io.Discard); err != nil {
		t.Fatal(err)
	}

	for _, cmd := range *got {
		if cmd[0] != "install" {
			continue
		}
		joined := strings.Join(cmd, " ")
		for _, want := range []string{"-o root", "-g wheel"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%q should carry %q — /etc/resolver controls DNS for the "+
					"whole machine", joined, want)
			}
		}
	}
}

// TestResolverFileNamesTheConfiguredPort: the resolver file and the DNS
// responder have to agree on the port, and nothing at runtime checks that
// they do — the failure is a name that silently does not resolve.
func TestResolverFileNamesTheConfiguredPort(t *testing.T) {
	contents := ResolverFileContents(15353)
	if !strings.Contains(contents, "port 15353") {
		t.Errorf("resolver contents %q should name port 15353", contents)
	}
	if !strings.Contains(contents, "nameserver 127.0.0.1") {
		t.Errorf("resolver contents %q should point at loopback", contents)
	}
}

// writeTestCert writes a throwaway self-signed certificate and returns its
// path plus the SHA-1 fingerprint `security` would index it by.
func writeTestCert(t *testing.T) (path, sha1hex string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Switchboard Local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(der) //nolint:gosec // matching `security`'s index format
	return path, strings.ToUpper(hex.EncodeToString(sum[:]))
}

// TestRemoveTrustDeletesTheCertificateNotJustTheTrustSetting is the
// regression test for an uninstall that lied.
//
// `security remove-trusted-cert` clears the trust setting and leaves the
// certificate in the keychain. `switchboard uninstall` printed "system setup
// removed ✓" while a CA certificate stayed installed system-wide — inert,
// but accumulating a copy per install/uninstall cycle, and enough to make
// any presence-based trust check report success forever after. Which is
// exactly what doctor was doing.
func TestRemoveTrustDeletesTheCertificateNotJustTheTrustSetting(t *testing.T) {
	got := recordCommands(t)
	certPath, want := writeTestCert(t)

	if err := removeTrust(certPath, io.Discard); err != nil {
		t.Fatal(err)
	}

	untrustAt, deleteAt := -1, -1
	for i, cmd := range *got {
		if cmd[0] != "security" || len(cmd) < 2 {
			continue
		}
		switch cmd[1] {
		case "remove-trusted-cert":
			untrustAt = i
		case "delete-certificate":
			deleteAt = i
			if !slices.Contains(cmd, "-Z") {
				t.Errorf("delete by fingerprint, not by name: every Switchboard root "+
					"shares a common name, so -c could remove a different one. Got %v", cmd)
			}
			if !slices.Contains(cmd, want) {
				t.Errorf("delete-certificate should name the fingerprint %s of the cert "+
					"being removed, got %v", want, cmd)
			}
		}
	}

	if untrustAt < 0 {
		t.Error("trust setting is never removed")
	}
	if deleteAt < 0 {
		t.Fatalf("the certificate itself is never deleted; uninstall would leave it in "+
			"the keychain. Commands: %v", *got)
	}
	if untrustAt > deleteAt {
		t.Error("the certificate is deleted before its trust setting is removed; if the " +
			"delete succeeds and the untrust does not, a trust setting is left orphaned")
	}
}

// TestRemoveTrustOnAMissingCertIsANoop: `uninstall` is run on machines in
// every state, including ones where setup never completed.
func TestRemoveTrustOnAMissingCertIsANoop(t *testing.T) {
	got := recordCommands(t)

	if err := removeTrust(filepath.Join(t.TempDir(), "absent.crt"), io.Discard); err != nil {
		t.Fatalf("removing trust for a cert that does not exist should be a no-op, got %v", err)
	}
	if len(*got) != 0 {
		t.Errorf("nothing should have been run, got %v", *got)
	}
}
