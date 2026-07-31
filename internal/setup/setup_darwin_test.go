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

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/proxy"
)

// recordCommands swaps runVisible for a recorder, returning the slice the
// issued commands land in. Nothing is executed.
// isolateResolverDir points /etc/resolver at a temp directory. Any test that
// reaches installResolver or removeResolver must call it, or it is asserting
// against whatever the machine running the suite happens to have — which is
// how this was found: the rotation test passed or failed depending on whether
// /etc/resolver/test existed at that moment.
func isolateResolverDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := resolverDir
	resolverDir = dir
	t.Cleanup(func() { resolverDir = orig })
	return dir
}

// recordCommands captures both runners. They are recorded distinguishably:
// an elevated command is prefixed "sudo", because whether a step needs root
// is exactly what several of these tests are asserting.
func recordCommands(t *testing.T) *[][]string {
	t.Helper()
	var got [][]string
	origV, origU := runVisible, runVisibleUnprivileged
	runVisible = func(_ io.Writer, name string, args ...string) error {
		got = append(got, append([]string{"sudo", name}, args...))
		return nil
	}
	runVisibleUnprivileged = func(_ io.Writer, name string, args ...string) error {
		got = append(got, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() { runVisible, runVisibleUnprivileged = origV, origU })
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
	isolateResolverDir(t)
	got := recordCommands(t)

	if _, err := installResolver("test", 53535, io.Discard); err != nil {
		t.Fatal(err)
	}

	mkdirAt, writeAt := -1, -1
	for i, cmd := range *got {
		switch {
		case cmd[0] == "sudo" && cmd[1] == "install" && slices.Contains(cmd, "-d"):
			if !slices.Contains(cmd, resolverDir) {
				t.Errorf("the mkdir should target %s, got %v", resolverDir, cmd)
			}
			mkdirAt = i
		case cmd[0] == "sudo" && cmd[1] == "install" && slices.Contains(cmd, filepath.Join(resolverDir, "test")):
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
	isolateResolverDir(t)
	got := recordCommands(t)

	if _, err := installResolver("test", 53535, io.Discard); err != nil {
		t.Fatal(err)
	}

	for _, cmd := range *got {
		if cmd[0] != "sudo" || cmd[1] != "install" {
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
	pretendInstalled(t)

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

// pretendInstalled stands in for a keychain that holds the certificate and
// trusts it, and stops doing so once the corresponding removal command runs.
//
// A test cannot genuinely trust a certificate — that needs an authorization
// dialog nobody can answer — but the code deliberately reports state rather
// than exit codes, so the stub has to model the state changing. That is what
// makes the after-the-fact checks in removeTrust testable at all.
func pretendInstalled(t *testing.T) {
	t.Helper()
	trusted, present := true, true
	origT, origP, origU := isTrusted, certInKeychain, runVisibleUnprivileged
	isTrusted = func(string) (bool, error) { return trusted, nil }
	certInKeychain = func(string, string) (bool, error) { return present, nil }
	runVisibleUnprivileged = func(w io.Writer, name string, args ...string) error {
		if name == "security" && len(args) > 0 {
			switch args[0] {
			case "remove-trusted-cert":
				trusted = false
			case "delete-certificate":
				present = false
			}
		}
		return origU(w, name, args...)
	}
	t.Cleanup(func() {
		isTrusted, certInKeychain, runVisibleUnprivileged = origT, origP, origU
	})
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

// TestTrustDoesNotRequireRoot pins the privilege reduction.
//
// Switchboard used to install its CA into /Library/Keychains/System.keychain,
// which needs root and grants trust to every account and system service on
// the machine. It goes into the user's login keychain instead: no root, and
// trust for the one user who asked for it — which is the only one who needs
// it, since both the daemon and the browser run as them.
//
// Verified on macOS 15 that curl, Go's verifier and a real TLS handshake all
// honour user-domain trust. Python and Node do not, but they do not honour
// the system store either — both ship their own CA bundles.
//
// If a future edit reaches for sudo here, it is asking for a privilege the
// operation demonstrably does not use.
func TestTrustDoesNotRequireRoot(t *testing.T) {
	certPath, _ := writeTestCert(t)

	for _, tc := range []struct {
		name string
		run  func(*[][]string) error
	}{
		{"install", func(*[][]string) error {
			_, err := installTrust(certPath, io.Discard)
			return err
		}},
		{"remove", func(*[][]string) error {
			pretendInstalled(t)
			return removeTrust(certPath, io.Discard)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := recordCommands(t)
			if err := tc.run(got); err != nil {
				t.Fatal(err)
			}
			if len(*got) == 0 {
				t.Fatal("no commands were issued")
			}
			for _, cmd := range *got {
				if cmd[0] == "sudo" {
					t.Errorf("trust is a user-keychain operation and must not elevate, got: %v", cmd)
				}
				if slices.Contains(cmd, "/Library/Keychains/System.keychain") {
					t.Errorf("the system keychain grants trust to every account on the "+
						"machine and needs root; use the login keychain. Got: %v", cmd)
				}
			}
		})
	}
}

// TestTrustTargetsTheLoginKeychain: `security` defaults are contextual, so
// the keychain is named explicitly rather than left to the default search
// list — which is what a test can actually pin.
func TestTrustTargetsTheLoginKeychain(t *testing.T) {
	got := recordCommands(t)
	certPath, _ := writeTestCert(t)

	if _, err := installTrust(certPath, io.Discard); err != nil {
		t.Fatal(err)
	}
	var named bool
	for _, cmd := range *got {
		for _, a := range cmd {
			if strings.Contains(a, "login.keychain") {
				named = true
			}
		}
	}
	if !named {
		t.Errorf("add-trusted-cert should name the login keychain explicitly, got: %v", *got)
	}
}

// TestRotateCAOrdersTrustRemovalBeforeDeletion covers a suffix change, which
// is a supported config edit that used to dead-end.
//
// Changing `suffix` leaves a root whose name constraint names the old one, so
// it cannot legitimately sign for the new one — and EnsureRoot refuses. The
// error told the user to run `uninstall` then `setup`, which does not work:
// uninstall deliberately keeps the CA files, so setup hits the identical wall.
// Advice that loops is worse than no advice.
//
// The ordering asserted here is the part that matters. Trust must be removed
// while the certificate is still on disk: it is what identifies the cert to
// the keychain. Delete the files first and a crash in between strands a
// trusted root that can now only be found by hand in Keychain Access.
func TestRotateCAOrdersTrustRemovalBeforeDeletion(t *testing.T) {
	dir := t.TempDir()
	resolvers := isolateResolverDir(t)
	// The old suffix's resolver file has to exist for its removal to be
	// attempted at all — removeResolver short-circuits when it does not.
	if err := os.WriteFile(filepath.Join(resolvers, "test"), []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A root constrained to "test", while the config now asks for "internal".
	if _, err := proxy.EnsureRoot(dir, "test"); err != nil {
		t.Fatal(err)
	}
	oldRoot, err := os.ReadFile(proxy.RootCertPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	// Something for Caddy's storage, to prove it is cleared too: a leaf that
	// chains to the old root would be served under a root nobody trusts.
	caddyDir := filepath.Join(dir, "caddy", "certificates", "local", "app.test")
	if err := os.MkdirAll(caddyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(caddyDir, "app.test.crt")
	if err := os.WriteFile(stale, []byte("stale leaf"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Both runners must be stubbed. rotateCA removes the *old* suffix's
	// resolver file, which is an elevated `rm` — an earlier version of this
	// test left runVisible live and tried to delete /etc/resolver/test from
	// the machine running the suite. It failed only because non-interactive
	// sudo refuses.
	var seq int
	var trustRemovedAt, resolverRemovedAt int
	var certExistedAtTrustRemoval bool
	stillTrusted := true

	origV, origU := runVisible, runVisibleUnprivileged
	origT, origP := isTrusted, certInKeychain
	isTrusted = func(string) (bool, error) { return stillTrusted, nil }
	certInKeychain = func(string, string) (bool, error) { return false, nil }
	runVisible = func(_ io.Writer, name string, args ...string) error {
		seq++
		if name == "rm" {
			resolverRemovedAt = seq
			for _, a := range args {
				if strings.HasPrefix(a, resolvers) && !strings.HasSuffix(a, "/test") {
					t.Errorf("removed the wrong resolver file: %v", args)
				}
			}
		}
		return nil
	}
	runVisibleUnprivileged = func(_ io.Writer, name string, args ...string) error {
		seq++
		if name == "security" && len(args) > 0 && args[0] == "remove-trusted-cert" {
			trustRemovedAt = seq
			stillTrusted = false
			_, err := os.Stat(proxy.RootCertPath(dir))
			certExistedAtTrustRemoval = err == nil
		}
		return nil
	}
	t.Cleanup(func() {
		runVisible, runVisibleUnprivileged = origV, origU
		isTrusted, certInKeychain = origT, origP
	})

	newPath, err := rotateCA(&config.Config{Suffix: "internal"}, dir, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if trustRemovedAt == 0 {
		t.Error("trust in the old root was never removed; it would stay trusted forever")
	}
	if !certExistedAtTrustRemoval {
		t.Error("the old certificate was deleted before its trust was removed — the " +
			"keychain entry can no longer be identified from disk")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("Caddy's storage survived the rotation; leaves chaining to the old " +
			"intermediate would be served under a root nobody trusts")
	}
	// The old suffix's resolver file must go. Left behind it keeps sending
	// that whole namespace to a DNS responder that no longer answers for it,
	// so those names stop resolving machine-wide instead of falling through.
	if resolverRemovedAt == 0 {
		t.Error("the previous suffix's resolver file was never removed; .test would " +
			"keep resolving to a daemon that no longer serves it")
	}

	newRoot, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(newRoot) == string(oldRoot) {
		t.Fatal("the root was not actually re-issued")
	}
	if err := proxy.RootCoversSuffix(newPath, "internal"); err != nil {
		t.Errorf("the new root should cover the new suffix: %v", err)
	}
}

// TestRemoveTrustToleratesTrustThatWasNeverGranted is the regression test for
// an abort found by following the tool's own instructions.
//
// `security remove-trusted-cert` exits 1 with "The specified item could not
// be found in the keychain" when there was no trust setting to remove. That
// is the desired end state, not a failure — but it was treated as one, so
// `setup` aborted mid-rotation on a machine where the old root simply was not
// trusted in the user domain.
func TestRemoveTrustToleratesTrustThatWasNeverGranted(t *testing.T) {
	got := recordCommands(t)
	certPath, _ := writeTestCert(t)
	// No pretendTrusted here: the certificate is genuinely untrusted, which
	// is exactly the situation that used to abort.

	if err := removeTrust(certPath, io.Discard); err != nil {
		t.Fatalf("removing trust that was never granted must succeed, got: %v", err)
	}
	for _, cmd := range *got {
		if len(cmd) > 1 && cmd[1] == "remove-trusted-cert" {
			t.Error("nothing was trusted, so remove-trusted-cert should not have run at all")
		}
	}
}

// TestRemoveTrustRefusesToProceedWhileStillTrusted is the other direction,
// and the dangerous one.
//
// A root trusted in the *system* keychain by an older version cannot be
// untrusted from the user domain: the command fails and the certificate stays
// trusted. Continuing would delete the file and strand a trusted root that
// nothing on disk can identify — removable only by hand in Keychain Access.
//
// Checking the exit code cannot tell these apart. Checking the outcome can.
func TestRemoveTrustRefusesToProceedWhileStillTrusted(t *testing.T) {
	recordCommands(t)
	certPath, _ := writeTestCert(t)

	origT, origP := isTrusted, certInKeychain
	isTrusted = func(string) (bool, error) { return true, nil } // never becomes false
	certInKeychain = func(string, string) (bool, error) { return false, nil }
	t.Cleanup(func() { isTrusted, certInKeychain = origT, origP })

	err := removeTrust(certPath, io.Discard)
	if err == nil {
		t.Fatal("removeTrust reported success while the certificate is still trusted")
	}
	if !strings.Contains(err.Error(), "still trusted") {
		t.Errorf("the error should say the certificate is still trusted, got: %v", err)
	}
	if !strings.Contains(err.Error(), "System.keychain") {
		t.Errorf("the error should name the likely cause and the recovery command, got: %v", err)
	}
}

// TestRemoveTrustSaysNothingWhenTheCertWasNeverInThisKeychain is the third
// regression in the same family, and the reason the family is worth naming:
// every one came from reporting what a command returned instead of what the
// system is.
//
// Deleting a certificate that is not in this keychain fails, and the failure
// used to produce a second, wronger claim on top of `security`'s own — that
// the certificate was "untrusted but still in the keychain", when it had
// never been in that keychain at all. Someone following that advice would run
// a command that cannot work, against a keychain that does not hold it.
func TestRemoveTrustSaysNothingWhenTheCertWasNeverInThisKeychain(t *testing.T) {
	got := recordCommands(t)
	certPath, _ := writeTestCert(t)

	origT, origP := isTrusted, certInKeychain
	isTrusted = func(string) (bool, error) { return false, nil }              // not trusted
	certInKeychain = func(string, string) (bool, error) { return false, nil } // and not present
	t.Cleanup(func() { isTrusted, certInKeychain = origT, origP })

	var buf strings.Builder
	if err := removeTrust(certPath, &buf); err != nil {
		t.Fatal(err)
	}

	for _, cmd := range *got {
		if len(cmd) > 1 && cmd[1] == "delete-certificate" {
			t.Error("delete-certificate ran against a keychain that does not hold the " +
				"certificate; `security` fails and the output is pure noise")
		}
	}
	if strings.Contains(buf.String(), "still in the keychain") {
		t.Errorf("claimed the certificate is still in the keychain when it was never "+
			"there. Output:\n%s", buf.String())
	}
}
