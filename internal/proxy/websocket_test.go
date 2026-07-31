package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/proxy"
)

// TestWebSocketUpgradeThroughProxy is the regression guard for Vite/Next HMR:
// a websocket client reaching https://app.test must be proxied to the upstream
// and exchange frames in both directions.
func TestWebSocketUpgradeThroughProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("provisions a local CA and starts embedded Caddy; skipped with -short")
	}

	upstreamAddr := startEchoWebSocketServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstreamAddr)
	if err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	cfg := &config.Config{
		Suffix:        "test",
		HTTPPort:      freePort(t),
		HTTPSPort:     freePort(t),
		DashboardPort: freePort(t),
		Routes:        []config.Route{{Domain: "app.test", Upstream: "127.0.0.1:" + upstreamPort}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	if err := proxy.Load(cfg, dataDir); err != nil {
		t.Fatalf("loading caddy config: %v", err)
	}
	t.Cleanup(func() { proxy.Stop() }) //nolint:errcheck

	httpsAddr := fmt.Sprintf("127.0.0.1:%d", cfg.EffHTTPSPort())
	pool := waitForRootCA(t, dataDir)
	waitForListener(t, httpsAddr)

	ws := dialWebSocketThroughProxy(t, httpsAddr, pool)
	defer ws.Close()

	if _, err := ws.Write([]byte("hmr-update")); err != nil {
		t.Fatalf("writing a frame through the proxy: %v", err)
	}
	if err := ws.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := ws.Read(buf)
	if err != nil {
		t.Fatalf("reading a frame through the proxy: %v", err)
	}
	if got, want := string(buf[:n]), "echo:hmr-update"; got != want {
		t.Errorf("round trip gave %q, want %q", got, want)
	}
}

// startEchoWebSocketServer stands in for a dev server's HMR endpoint: it
// completes a real websocket handshake and echoes each frame back prefixed.
func startEchoWebSocketServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           websocket.Handler(echoFrames),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go srv.Serve(ln) //nolint:errcheck // closed by cleanup
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func echoFrames(ws *websocket.Conn) {
	defer ws.Close()
	buf := make([]byte, 512)
	for {
		n, err := ws.Read(buf)
		if err != nil {
			return
		}
		if _, err := ws.Write([]byte("echo:" + string(buf[:n]))); err != nil {
			return
		}
	}
}

// dialWebSocketThroughProxy connects to wss://app.test/hmr while actually
// dialing httpsAddr, so the test needs no resolver file and no DNS. Handing a
// raw TLS conn to the websocket client also forces HTTP/1.1: ALPN advertises
// only http/1.1, so h2 — which has no 101 upgrade — never gets negotiated.
//
// The retry loop absorbs the window where Caddy is listening but has not yet
// minted the leaf certificate for app.test; it is not masking flakiness in the
// proxy itself.
func dialWebSocketThroughProxy(t *testing.T, httpsAddr string, pool *x509.CertPool) *websocket.Conn {
	t.Helper()
	wsCfg, err := websocket.NewConfig("wss://app.test/hmr", "https://app.test")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		raw, err := net.DialTimeout("tcp", httpsAddr, 5*time.Second)
		if err != nil {
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName: "app.test",
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		})
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		ws, err := websocket.NewClient(wsCfg, tlsConn)
		if err != nil {
			tlsConn.Close()
			lastErr = err
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return ws
	}
	t.Fatalf("could not establish a websocket through the proxy: %v", lastErr)
	return nil
}

func waitForRootCA(t *testing.T, dataDir string) *x509.CertPool {
	t.Helper()
	path := proxy.RootCertPath(dataDir)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		pem, err := os.ReadFile(path)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				return pool
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("root CA never appeared at %s", path)
	return nil
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
