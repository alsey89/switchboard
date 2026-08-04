package inspect

import (
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is the Caddy middleware that captures proxied requests. It carries
// no configuration: everything it needs comes from the process-wide recorder,
// which outlives the config reloads that re-provision this module.
type Handler struct{}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.switchboard_inspect",
		New: func() caddy.Module { return new(Handler) },
	}
}

// ServeHTTP times the request, learns its status and size, and hands a
// record to the recorder. It must never change what the client sees and
// never add latency, so the only work on the response path is counting
// bytes, and the hand-off is a non-blocking send.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rec := Current()
	if rec == nil {
		return next.ServeHTTP(w, r)
	}

	start := time.Now()
	bodies := rec.Bodies()
	maxBody := rec.MaxBodyBytes()

	var reqBody *capReader
	if r.Body != nil {
		reqBody = newCapReader(r.Body, bodyCap(bodies, maxBody))
		r.Body = reqBody
	}

	ww := &watcher{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}}
	if bodies {
		ww.body = newCapWriter(nilWriter{}, maxBody)
	}

	// An HTTP/2 extended CONNECT websocket (RFC 8441) never sees a 101: Caddy
	// answers the client's CONNECT with a plain 200 once the backend accepts
	// the upgrade (reverseproxy/streaming.go). Only h1/h2 are enabled here
	// (see proxy.go), so ProtoMajor == 2 is the only extended-connect case
	// that can reach this handler; h3 detects the upgrade differently and
	// does not apply.
	h2Websocket := r.ProtoMajor == 2 && r.Method == http.MethodConnect &&
		r.Header.Get(":protocol") == "websocket"

	// An upgraded connection blocks in next until the socket dies. Recording
	// it on return would mean an HMR websocket shows up in the inspector an
	// hour after it opened, so it is recorded the moment the upgrade lands
	// and never again. That moment is a 101 for a plain HTTP/1.1 Upgrade, or
	// a 200 for the HTTP/2 extended-CONNECT case above; either way the wire
	// status is stored as-is and Upgraded is what marks the row, not the
	// status number.
	ww.onHeader = func(status int) {
		upgraded := status == http.StatusSwitchingProtocols ||
			(h2Websocket && status == http.StatusOK)
		if !upgraded {
			return
		}
		ww.emitted = true
		// The live bodies flag is passed through, not forced to false.
		// buildRecord suppresses the body itself for an upgraded row, which
		// keeps both spec rules true at once: no body is ever captured for
		// an upgraded connection, and bodies-on still means headers are
		// copied as sent. Forcing false here satisfied the first rule by
		// breaking the second, and the person it broke it for — someone
		// debugging a handshake with bodies on — is exactly the person who
		// needs Cookie and Sec-WebSocket-Protocol unredacted.
		rec.Submit(buildRecord(r, ww, reqBody, start, time.Now(), bodies, true, nil))
	}

	err := next.ServeHTTP(ww, r)
	if ww.emitted {
		return err
	}
	// A panic here (a bug deeper in reverse_proxy, say) unwinds through this
	// point without ever reaching a Submit call, so that request produces no
	// record. That is intentional, not an oversight: Caddy's own connection
	// handling already surfaces the panic (logs it and aborts the
	// connection), and recovering here to emit one would come at a real
	// cost. A recover-and-repanic loses the original stack, which is the
	// thing that makes a panic actionable, and http.ErrAbortHandler is a
	// sentinel net/http treats specially for a handler that aborts on
	// purpose - naively recovering it would fabricate an error record for
	// every one of those.
	rec.Submit(buildRecord(r, ww, reqBody, start, time.Now(), bodies, false, err))
	return err
}

func bodyCap(bodies bool, maxBody int) int {
	if !bodies {
		return 0
	}
	return maxBody
}

func buildRecord(r *http.Request, ww *watcher, reqBody *capReader,
	start, end time.Time, bodies, upgraded bool, err error) *Record {

	status := ww.status
	if status == 0 {
		// A failed proxy attempt (no upstream, a dial timeout) never calls
		// WriteHeader; reverse_proxy returns a HandlerError carrying the
		// real status instead, and the default-to-200 rule below is for a
		// handler that legitimately wrote nothing, not for this. "Backend
		// isn't running" is the single most common failure a local dev
		// proxy sees, and it must not show up in the inspector as a 200.
		var he caddyhttp.HandlerError
		if errors.As(err, &he) && he.StatusCode != 0 {
			status = he.StatusCode
		} else {
			status = http.StatusOK
		}
	}

	// Body capture on also turns redaction off: once bodies are being
	// written to disk, keeping Authorization or Cookie values out of the
	// header copy next to them buys nothing. This is a real side effect of
	// a flag named "bodies", not just a header-copying detail.
	copyHeaders := RedactHeaders
	if bodies {
		copyHeaders = CopyHeaders
	}

	out := &Record{
		StartedAt:   start,
		Duration:    end.Sub(start),
		Domain:      hostOnly(r.Host),
		Method:      r.Method,
		Path:        r.URL.RequestURI(),
		Status:      status,
		Proto:       r.Proto,
		Upgraded:    upgraded,
		RespBytes:   ww.written,
		ReqHeaders:  copyHeaders(r.Header),
		RespHeaders: copyHeaders(ww.Header()),
	}
	if err != nil {
		out.Error = err.Error()
	}
	// An upgraded connection never has its payload captured, whatever the
	// bodies flag says. What follows a 101 is a websocket frame stream, not
	// a request body with an end, and this record is written the moment the
	// upgrade lands — so anything the cap readers happen to be holding at
	// that instant is a fragment of a handshake, not a body.
	//
	// Only the body is suppressed. Header copying above still follows the
	// bodies flag, because the reason bodies-on drops redaction has nothing
	// to do with whether this particular row is an upgrade.
	captureBodies := bodies && !upgraded

	if reqBody != nil {
		out.ReqBytes = reqBody.total()
		if captureBodies {
			out.ReqBody = reqBody.captured()
		}
	}
	if captureBodies && ww.body != nil {
		out.RespBody = ww.body.captured()
	}
	return out
}

// hostOnly strips any :port from an HTTP Host value.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// watcher counts what the response wrote and notices the status.
//
// It embeds Caddy's ResponseWriterWrapper rather than http.ResponseWriter so
// that Hijack, Flush and Unwrap keep working. A websocket upgrade goes
// through Hijack, and getting that wrong would break every HMR connection on
// the machine.
type watcher struct {
	*caddyhttp.ResponseWriterWrapper

	status   int
	written  int64
	body     *capWriter
	emitted  bool
	onHeader func(status int)
}

func (w *watcher) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		if w.onHeader != nil {
			w.onHeader(code)
		}
	}
	w.ResponseWriterWrapper.WriteHeader(code)
}

func (w *watcher) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriterWrapper.Write(p)
	w.written += int64(n)
	if w.body != nil && n > 0 {
		w.body.Write(p[:n]) //nolint:errcheck // nilWriter never fails
	}
	return n, err
}

// ReadFrom shadows the io.ReaderFrom that *caddyhttp.ResponseWriterWrapper
// promotes. That promoted version writes straight to the underlying
// ResponseWriter, bypassing Write and with it every line of instrumentation
// above: written would stay at 0, no response body would be captured, and an
// implicit 200 would never be recorded. Wrapping w in an anonymous
// io.Writer-only struct is what stops io.Copy from rediscovering this same
// ReadFrom method on w and recursing into itself.
func (w *watcher) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{w}, r)
}

// nilWriter is the sink under a capWriter used only for capture: the real
// bytes have already gone to the client by then.
type nilWriter struct{}

func (nilWriter) Write(p []byte) (int, error) { return len(p), nil }

var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ http.ResponseWriter         = (*watcher)(nil)

	// The load-bearing contract is Unwrap, not http.ResponseWriter above:
	// Flush and Hijack only reach the real socket through it (see
	// http.ResponseController). This guard fails the build if the
	// ResponseWriterWrapper embed is ever dropped, instead of silently
	// breaking SSE and websockets.
	_ interface{ Unwrap() http.ResponseWriter } = (*watcher)(nil)
)
