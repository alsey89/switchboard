package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/inspect"
	"github.com/alsey89/switchboard/internal/listen"
	"github.com/alsey89/switchboard/internal/proxy"
)

// Integration test: boots the real daemon (DNS responder, embedded Caddy
// with the internal PKI, dashboard) on loopback high ports, then talks to
// it like a browser would — TLS verified against the generated root CA.
// This runs fine on any OS/CI; no privileged ports, no system changes.

const (
	tHTTPPort  = 18080
	tHTTPSPort = 18443
	tDNSPort   = 15353
	tDashPort  = 18484
)

// tSuffixInternal and tSuffixLocalhost are the two other reserved suffixes
// (see config.ReservedSuffixes), reserved here for any test that verifies a
// certificate against the daemon's minted root CA.
//
// This is not bureaucracy for its own sake. Caddy's on-demand certificate
// cache (certCache in modules/caddytls/tls.go) is a package-level variable,
// not scoped to one *caddy.Config or one daemon.Run call. caddy.Stop() only
// evicts entries that were under explicit certificate management; an
// on-demand-issued cert never was, so it survives in that global cache
// after Stop() returns. A second daemon boot in the same test process that
// requests a certificate for a domain name it has seen before gets served
// the *first* boot's cert — signed by the *first* boot's root — verified
// against the *second* boot's root pool, which fails with something like
// "x509: certificate signed by unknown authority". Confirmed with a
// minimal repro: two sequential proxy.Load/proxy.Stop cycles with the same
// suffix reproduce the exact failure; giving the second one a different
// suffix (and therefore different domain names) does not.
//
// This is issue #25. It is a real defect, but it lives in vendored Caddy
// and only manifests when more than one full daemon boots in one OS
// process — something that only ever happens in this test binary, never in
// production, where one process serves for the whole life of the daemon.
// Patching it out is out of scope here; giving each cert-verifying test in
// this package its own domain names is enough to stop the cache from ever
// serving a stale cert to the wrong root, and it is the fix that keeps
// every test running under a plain `go test ./...` rather than gating any
// of them out.
const (
	tSuffixInternal  = "internal"
	tSuffixLocalhost = "localhost"
)

type testEnv struct {
	cfgPath string
	cfg     *config.Config
	dataDir string
	rootCAs *x509.CertPool
	cancel  context.CancelFunc
	done    chan error
}

// startOpts customizes startEnv for tests that need to observe the daemon's
// logs, tamper with the data directory before the daemon starts, or use a
// suffix other than the shared default.
type startOpts struct {
	// poisonDataDir, when set, runs after the data directory is created but
	// before the daemon starts. It exists to break one thing the data
	// directory holds (e.g. the inspector's database file) without
	// disturbing the rest (the proxy's PKI files), which is the only way to
	// prove a broken inspector does not take the proxy down with it.
	poisonDataDir func(t *testing.T, dataDir string)
	log           *slog.Logger

	// suffix overrides the default "test" suffix. Any test that verifies a
	// certificate against the minted root CA (as opposed to just booting
	// the daemon) must use a suffix no other such test in this package
	// uses — see the comment on tSuffixInternal/tSuffixLocalhost for why.
	suffix string
}

func startEnv(t *testing.T, routes []config.Route) *testEnv {
	t.Helper()
	return startEnvOpts(t, routes, startOpts{})
}

func startEnvOpts(t *testing.T, routes []config.Route, o startOpts) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	dataDir := filepath.Join(dir, "data")

	suffix := o.suffix
	if suffix == "" {
		suffix = "test"
	}
	cfg := &config.Config{
		Suffix:        suffix,
		HTTPPort:      tHTTPPort,
		HTTPSPort:     tHTTPSPort,
		DNSPort:       tDNSPort,
		DashboardPort: tDashPort,
		Routes:        routes,
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	if o.poisonDataDir != nil {
		if err := os.MkdirAll(dataDir, 0o755); err != nil {
			t.Fatal(err)
		}
		o.poisonDataDir(t, dataDir)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{ConfigPath: cfgPath, DataDir: dataDir, Version: "test", Log: o.log})
	}()

	// Wait for the HTTPS listener, then load the root CA it minted.
	waitFor(t, func() bool { return dialable("127.0.0.1", tHTTPSPort) }, 30*time.Second,
		"daemon HTTPS listener")
	rootPEM, err := os.ReadFile(proxy.RootCertPath(dataDir))
	if err != nil {
		cancel()
		t.Fatalf("reading root CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		cancel()
		t.Fatal("root CA PEM did not parse")
	}

	env := &testEnv{cfgPath: cfgPath, cfg: cfg, dataDir: dataDir, rootCAs: pool, cancel: cancel, done: done}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("daemon exited with error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("daemon did not shut down in time")
		}
	})

	// An accepting socket is not a working TLS stack. Caddy's internal PKI
	// finishes preparing its issuer after the listener starts accepting, so a
	// request sent in that window loses the race and comes back
	// `tls: internal error` — a failure that says nothing about the thing
	// under test. Waiting on dialable() alone made this flaky in CI, where it
	// failed on both runners while passing locally eight times running.
	//
	// The dashboard domain is the readiness signal because every config has
	// one, whatever routes the caller asked for, and serving it end to end
	// proves the one thing the port check does not: that the CA can issue.
	gate := env.client()
	gate.Timeout = 2 * time.Second
	waitFor(t, func() bool {
		resp, err := gate.Get(fmt.Sprintf("https://%s:%d/", cfg.DashboardDomain(), tHTTPSPort))
		if err != nil {
			return false
		}
		resp.Body.Close() //nolint:errcheck
		return true
	}, 30*time.Second, "daemon able to issue a certificate")

	return env
}

// client returns an *http.Client that sends every connection to the
// daemon's loopback port while keeping the requested hostname for SNI and
// Host — the moral equivalent of the OS resolver pointing *.test at
// 127.0.0.1.
func (e *testEnv) client() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: e.rootCAs},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			},
		},
	}
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	// A local "dev server" that echoes what it saw.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"path":  r.URL.Path,
			"host":  r.Host,
			"proto": r.Header.Get("X-Forwarded-Proto"),
		})
	}))
	defer upstream.Close()
	upstreamAddr := strings.TrimPrefix(upstream.URL, "http://")

	env := startEnv(t, []config.Route{{Domain: "app.test", Upstream: upstreamAddr}})
	client := env.client()

	t.Run("proxies with verified TLS and forwarded headers", func(t *testing.T) {
		resp, err := client.Get(fmt.Sprintf("https://app.test:%d/hello", tHTTPSPort))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		var seen map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&seen); err != nil {
			t.Fatal(err)
		}
		if seen["path"] != "/hello" {
			t.Errorf("path = %q", seen["path"])
		}
		// Host must be preserved to the upstream; scheme reported as https.
		if got := seen["host"]; got != fmt.Sprintf("app.test:%d", tHTTPSPort) {
			t.Errorf("upstream saw Host %q", got)
		}
		if seen["proto"] != "https" {
			t.Errorf("X-Forwarded-Proto = %q, want https", seen["proto"])
		}
	})

	t.Run("unknown host gets on-demand cert and no-route page", func(t *testing.T) {
		resp, err := client.Get(fmt.Sprintf("https://unrouted.test:%d/", tHTTPSPort))
		if err != nil {
			t.Fatal(err) // a TLS failure here means on-demand issuance broke
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status %d, want 404", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "unrouted.test") {
			t.Errorf("no-route page should name the host, got: %.200s", body)
		}
	})

	t.Run("SNI outside managed TLD is refused a certificate", func(t *testing.T) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp",
			fmt.Sprintf("127.0.0.1:%d", tHTTPSPort),
			&tls.Config{ServerName: "google.com", RootCAs: env.rootCAs})
		if err == nil {
			conn.Close()
			t.Fatal("handshake for google.com should fail: the local CA must never mint certs outside .test")
		}
	})

	t.Run("dashboard serves route table and API", func(t *testing.T) {
		resp, err := client.Get(fmt.Sprintf("https://switchboard.test:%d/", tHTTPSPort))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !strings.Contains(string(body), "app.test") {
			t.Errorf("dashboard status %d, body should list app.test", resp.StatusCode)
		}

		resp2, err := client.Get(fmt.Sprintf("https://switchboard.test:%d/api/routes", tHTTPSPort))
		if err != nil {
			t.Fatal(err)
		}
		defer resp2.Body.Close()
		var api struct {
			Routes []struct {
				Domain string `json:"domain"`
				Up     bool   `json:"up"`
			} `json:"routes"`
		}
		if err := json.NewDecoder(resp2.Body).Decode(&api); err != nil {
			t.Fatal(err)
		}
		if len(api.Routes) != 1 || api.Routes[0].Domain != "app.test" || !api.Routes[0].Up {
			t.Errorf("api routes = %+v", api.Routes)
		}
	})

	t.Run("http redirects to https", func(t *testing.T) {
		resp, err := client.Get(fmt.Sprintf("http://app.test:%d/x?y=1", tHTTPPort))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusPermanentRedirect {
			t.Fatalf("status %d, want 308", resp.StatusCode)
		}
		want := fmt.Sprintf("https://app.test:%d/x?y=1", tHTTPSPort)
		if loc := resp.Header.Get("Location"); loc != want {
			t.Errorf("Location = %q, want %q", loc, want)
		}
	})

	t.Run("hot reload picks up new routes", func(t *testing.T) {
		second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "second upstream") //nolint:errcheck
		}))
		defer second.Close()

		env.cfg.Routes = append(env.cfg.Routes, config.Route{
			Domain:   "two.test",
			Upstream: strings.TrimPrefix(second.URL, "http://"),
		})
		if err := env.cfg.Save(env.cfgPath); err != nil {
			t.Fatal(err)
		}

		waitFor(t, func() bool {
			resp, err := client.Get(fmt.Sprintf("https://two.test:%d/", tHTTPSPort))
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode == 200 && strings.Contains(string(body), "second upstream")
		}, 15*time.Second, "hot-reloaded route to answer")
	})
}

// TestInspectorFailureNeverBlocksTheDaemon proves the daemon's central
// promise about the inspector: a broken inspector is a warning, never a
// reason the proxy does not start.
//
// The inspector's database path is pre-occupied by a directory, which
// fails inspect.Open exactly like an unwritable data directory or a
// corrupt file would. Nothing else in the data directory is touched, so
// the proxy's own use of it (the PKI files) still succeeds — this is what
// isolates "the inspector broke" from "the whole data directory broke",
// and proves the failure is contained rather than merely unexercised.
func TestInspectorFailureNeverBlocksTheDaemon(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok") //nolint:errcheck
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	env := startEnvOpts(t, []config.Route{{Domain: "app." + tSuffixInternal, Upstream: strings.TrimPrefix(upstream.URL, "http://")}},
		startOpts{
			suffix: tSuffixInternal,
			log:    slog.New(slog.NewTextHandler(&logs, nil)),
			poisonDataDir: func(t *testing.T, dataDir string) {
				t.Helper()
				// inspect.Open will try to create/open a file here; a
				// directory in its place makes that fail without touching
				// dataDir/pki, which the proxy needs to start at all.
				if err := os.MkdirAll(filepath.Join(dataDir, "inspect.db"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
		})

	resp, err := env.client().Get(fmt.Sprintf("https://app.%s:%d/hello", tSuffixInternal, tHTTPSPort))
	if err != nil {
		t.Fatalf("the proxy must still serve traffic with capture off: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Errorf("status = %d, body = %q, want 200 and the upstream body", resp.StatusCode, body)
	}

	if inspect.Current() != nil {
		t.Error("capture should be off when the inspector's database cannot be opened")
	}
	if !strings.Contains(logs.String(), "inspector disabled") {
		t.Errorf("expected a warning naming the inspector disabled, got log:\n%s", logs.String())
	}
}

// TestReloadAppliesNewInspectorLimits proves a config reload actually
// reaches the store, not just the recorder's in-memory options. It sends
// real traffic through the proxy (rather than calling Recorder.Submit
// directly) so the assertion covers the whole path: handler to recorder to
// store.
func TestReloadAppliesNewInspectorLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok") //nolint:errcheck
	}))
	defer upstream.Close()

	env := startEnvOpts(t, []config.Route{{Domain: "app." + tSuffixLocalhost, Upstream: strings.TrimPrefix(upstream.URL, "http://")}},
		startOpts{suffix: tSuffixLocalhost})
	client := env.client()

	get := func() {
		resp, err := client.Get(fmt.Sprintf("https://app.%s:%d/x", tSuffixLocalhost, tHTTPSPort))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close() //nolint:errcheck
	}

	for i := 0; i < 10; i++ {
		get()
	}
	waitFor(t, func() bool {
		r := inspect.Current()
		return r != nil && r.Store().Rows() >= 10
	}, 15*time.Second, "10 requests captured")

	env.cfg.Inspect = &config.InspectConfig{MaxRequests: 3}
	if err := env.cfg.Save(env.cfgPath); err != nil {
		t.Fatal(err)
	}

	// Each poll sends one more request: the first one to land after the
	// reload actually applies triggers the store's insert-then-trim and
	// should bring the row count down to the new cap in one step.
	waitFor(t, func() bool {
		get()
		r := inspect.Current()
		return r != nil && r.Store().Rows() <= 3
	}, 15*time.Second, "row count trimmed to the reloaded max_requests")
}

// TestReloadDisablingInspectorTearsDownButKeepsTheFile guards the owner
// decision on the finding raised in review: reloading `enabled` from true
// to false used to leave the recorder running forever — inspect.Current()
// stayed non-nil, the dashboard's stored recorder stayed non-nil, and the
// SQLite handle stayed open — even though proxy.Generate had already
// stopped putting the handler on any route. Once Tasks 8/9 land, that would
// have meant a user who turns capture off still sees the dashboard serving
// previously captured requests, headers and bodies included, out of a
// database nothing ever closes.
//
// The fix must not go too far the other way: turning it off must not
// delete inspect.db. This test proves both halves — the teardown on
// disable, and that the file (and its data) survives to be picked back up
// on the next enable.
func TestReloadDisablingInspectorTearsDownButKeepsTheFile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	// A multi-label suffix passes config's validateSuffix unconditionally
	// (it is read as "a domain you own"), so it needs no entry in the
	// three-suffix rotation the other cert-verifying tests share, and
	// cannot collide with any of them over Caddy's package-level cert
	// cache (see tSuffixInternal/tSuffixLocalhost above for why that
	// matters).
	const suffix = "toggle.test"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok") //nolint:errcheck
	}))
	defer upstream.Close()

	env := startEnvOpts(t, []config.Route{{Domain: "app." + suffix, Upstream: strings.TrimPrefix(upstream.URL, "http://")}},
		startOpts{suffix: suffix})
	client := env.client()

	resp, err := client.Get(fmt.Sprintf("https://app.%s:%d/hello", suffix, tHTTPSPort))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck

	waitFor(t, func() bool {
		r := inspect.Current()
		return r != nil && r.Store().Rows() >= 1
	}, 15*time.Second, "the request to be captured")

	// Keep a handle to the live recorder before disabling it: Trim against
	// it after the reload is a direct check that *this* store's *sql.DB was
	// actually closed, not just that some new state looks right.
	before := inspect.Current()

	disabled := false
	env.cfg.Inspect = &config.InspectConfig{Enabled: &disabled}
	if err := env.cfg.Save(env.cfgPath); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool { return inspect.Current() == nil }, 15*time.Second,
		"the recorder to be torn down once the reload disables it")

	if err := before.Store().Trim(time.Now()); err == nil {
		t.Error("the old recorder's store should be closed once the inspector is disabled by a reload")
	}

	// The file must still be there, with the row intact: open it directly,
	// the way the daemon would on its next start.
	dbPath := filepath.Join(env.dataDir, "inspect.db")
	st, err := inspect.Open(dbPath, inspect.Limits{})
	if err != nil {
		t.Fatalf("inspect.db should still be on disk and openable after being disabled: %v", err)
	}
	rows := st.Rows()
	if err := st.Close(); err != nil {
		t.Errorf("closing the reopened store: %v", err)
	}
	if rows < 1 {
		t.Fatalf("disabling the inspector must not delete captured rows, got %d rows", rows)
	}

	// Re-enable: the daemon should pick the same file back up, history
	// included, through the running recorder — not just via a side-channel
	// open like the check above.
	enabled := true
	env.cfg.Inspect = &config.InspectConfig{Enabled: &enabled}
	if err := env.cfg.Save(env.cfgPath); err != nil {
		t.Fatal(err)
	}

	waitFor(t, func() bool {
		r := inspect.Current()
		return r != nil && r.Store().Rows() >= 1
	}, 15*time.Second, "the inspector to come back with its history intact")
}

// TestShutdownClosesInspectorStoreAfterEverythingElse guards the ordering
// hazard found in review: Recorder.Close() closes the same SQLite handle
// the dashboard's history endpoints read from (Store()), so the daemon
// must stop serving before it closes the store — otherwise a request
// racing shutdown could query a closed database. It also guards
// SetCurrent(nil) running before Close(): skip that and a record submitted
// in the shutdown window sits in the channel forever, counted by nothing.
//
// This does not yet have a dashboard endpoint to race against (Tasks 8/9
// add those), so it checks what is observable now: that Current() is nil
// before Run returns, and that the store is fully closed and safely
// reopenable the instant Run returns — proving Close() ran to completion
// rather than mid-flight or not at all.
func TestShutdownClosesInspectorStoreAfterEverythingElse(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Setenv(listen.EnvFDs, "")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	dataDir := filepath.Join(dir, "data")
	// Suffix "test" is safe to share with TestEndToEnd here: this test never
	// verifies a certificate (it shuts down before making any HTTPS
	// request), so it never touches Caddy's cross-process cert cache and
	// cannot collide with it. See tSuffixInternal/tSuffixLocalhost above for
	// the tests that do need to care.
	cfg := &config.Config{
		Suffix:        "test",
		HTTPPort:      tHTTPPort,
		HTTPSPort:     tHTTPSPort,
		DNSPort:       tDNSPort,
		DashboardPort: tDashPort,
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			ConfigPath: cfgPath,
			DataDir:    dataDir,
			Version:    "test",
			Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()

	waitFor(t, func() bool { return inspect.Current() != nil }, 15*time.Second, "inspector up")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon exited with error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not shut down in time")
	}

	if inspect.Current() != nil {
		t.Error("SetCurrent(nil) must run before Close(), or a submit racing shutdown " +
			"would sit in the channel forever")
	}

	st, err := inspect.Open(filepath.Join(dataDir, "inspect.db"), inspect.Limits{})
	if err != nil {
		t.Fatalf("the store should be cleanly closed and reopenable once Run returns: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Errorf("closing the reopened store: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func dialable(host string, port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// TestFriendlyBindErrorAdvisesTheRightSetting guards a defect that reads as a
// typo but sends users to the wrong file. friendlyBindError is shared by all
// four listeners, and its permission-denied branch used to hardcode
// http_port/https_port — so a DNS responder that failed to bind advised
// changing the proxy's ports, a setting with no bearing on the error.
//
// Each listener must be advised about its own setting, and must not be
// advised about another's.
func TestFriendlyBindErrorAdvisesTheRightSetting(t *testing.T) {
	denied := &net.OpError{Op: "listen", Net: "tcp", Err: os.ErrPermission}

	for _, tc := range []struct {
		what    string
		want    string
		notWant []string
	}{
		{what: "proxy", want: "https_port", notWant: []string{"dns_port", "dashboard_port"}},
		{what: "DNS", want: "dns_port", notWant: []string{"https_port", "dashboard_port"}},
		{what: "dashboard", want: "dashboard_port", notWant: []string{"https_port", "dns_port"}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			err := friendlyBindError(denied, tc.what, "127.0.0.1:443", "/tmp/config.toml")
			if err == nil {
				t.Fatal("permission denied should produce a decorated error")
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.want) {
				t.Errorf("%s advice should name %q, got:\n%s", tc.what, tc.want, msg)
			}
			for _, nw := range tc.notWant {
				if strings.Contains(msg, nw) {
					t.Errorf("%s advice should not mention %q — that is another "+
						"listener's setting. Got:\n%s", tc.what, nw, msg)
				}
			}
			// The failing address and the config file are what make it actionable.
			if !strings.Contains(msg, "127.0.0.1:443") || !strings.Contains(msg, "/tmp/config.toml") {
				t.Errorf("%s advice must name the address and the config file, got:\n%s", tc.what, msg)
			}
		})
	}
}

// TestProxyAdviceOffersThePrivilegedParentFirst is the regression test for
// advice that went stale the moment the feature it should recommend shipped.
//
// Before the privileged parent, "use high ports" was the only working answer
// for :443 and the message said so. Afterwards it was still the only thing
// the message said — so the first person to run `switchboard start` on a
// stock config was told to reconfigure the tool rather than to run the one
// command that does what they asked for. Answering "how do I serve :443?"
// with "don't" is worse than a wrong answer; it hides a working one.
func TestProxyAdviceOffersThePrivilegedParentFirst(t *testing.T) {
	denied := &net.OpError{Op: "listen", Net: "tcp", Err: os.ErrPermission}
	msg := friendlyBindError(denied, "proxy", "127.0.0.1:443", "/tmp/config.toml").Error()

	for _, want := range []string{"sudo switchboard start", "switchboard daemon install"} {
		if !strings.Contains(msg, want) {
			t.Errorf("proxy advice must offer %q, got:\n%s", want, msg)
		}
	}
	// High ports stay on offer — they are a supported configuration, not a
	// workaround — but must not be the only thing suggested.
	if !strings.Contains(msg, "https_port = 8443") {
		t.Errorf("proxy advice should still mention high ports as an alternative, got:\n%s", msg)
	}
	if strings.Index(msg, "sudo switchboard start") > strings.Index(msg, "https_port") {
		t.Error("high ports are listed before the privileged parent; the parent is " +
			"what actually does what the user asked for")
	}
	// The parent is only worth recommending if the sentence that recommends
	// it is true about privilege.
	if !strings.Contains(msg, "does not run as root") {
		t.Errorf("advice to run something under sudo must say what stays unprivileged, got:\n%s", msg)
	}
}

// TestFriendlyBindErrorPassesThroughUnknownCauses: only the two causes with
// real advice get decorated. Anything else must reach the user unchanged
// rather than wearing a misleading privileged-port explanation.
func TestFriendlyBindErrorPassesThroughUnknownCauses(t *testing.T) {
	orig := fmt.Errorf("some unrelated failure")
	if got := friendlyBindError(orig, "proxy", "127.0.0.1:8443", ""); got != orig {
		t.Errorf("unknown cause should pass through unchanged, got: %v", got)
	}
	if got := friendlyBindError(nil, "proxy", "127.0.0.1:8443", ""); got != nil {
		t.Errorf("nil error should stay nil, got: %v", got)
	}
}

// TestSupervisedRunRefusesAMissingConfig covers a failure that only happens
// at boot on someone else's machine, which is the worst kind to leave
// untested.
//
// A launch daemon starts before anyone logs in, and on a FileVault Mac the
// user's home directory does not exist at that moment. config.Load treats a
// missing file as "use the defaults", so the daemon would come up healthy,
// serve zero routes, and watch a directory that is not there — and it would
// never recover once the user logged in and their config appeared.
//
// Under a privileged parent this must be a non-zero exit instead, so the
// parent's existing backoff retries until the home directory shows up.
func TestSupervisedRunRefusesAMissingConfig(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	ln.Close()      //nolint:errcheck

	t.Setenv(listen.EnvFDs, listen.HTTPS+":"+strconv.Itoa(int(f.Fd())))

	missing := filepath.Join(t.TempDir(), "not-yet", "config.toml")
	err = Run(context.Background(), Options{
		ConfigPath: missing,
		DataDir:    t.TempDir(),
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("a supervised daemon with no config file must exit non-zero; " +
			"coming up with zero routes would look healthy and never recover")
	}
	if !strings.Contains(err.Error(), "not readable yet") {
		t.Errorf("error should explain the boot-order cause, got: %v", err)
	}
}

// TestUnsupervisedRunStillDefaults: the same missing file is fine when
// nobody handed us sockets. `switchboard start` before `switchboard add` has
// always worked and must keep working.
func TestUnsupervisedRunStillDefaults(t *testing.T) {
	t.Setenv(listen.EnvFDs, "")

	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	missing := filepath.Join(dir, "config.toml")

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{
			ConfigPath: missing,
			DataDir:    t.TempDir(),
			Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()

	// Give it long enough to get past config loading and fail on something
	// else if it were going to; the ports will collide on a busy machine, so
	// only the "not readable yet" refusal is treated as a failure here.
	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil && strings.Contains(err.Error(), "not readable yet") {
			t.Fatal("an unsupervised daemon must still fall back to defaults " +
				"when no config file exists")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
