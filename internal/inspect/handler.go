package inspect

import (
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

	// An upgraded connection blocks in next until the socket dies. Recording
	// it on return would mean an HMR websocket shows up in the inspector an
	// hour after it opened, so it is recorded the moment the 101 lands and
	// never again.
	ww.onHeader = func(status int) {
		if status != http.StatusSwitchingProtocols {
			return
		}
		ww.emitted = true
		rec.Submit(buildRecord(r, ww, reqBody, start, time.Now(), bodies, true, nil))
	}

	err := next.ServeHTTP(ww, r)
	if ww.emitted {
		return err
	}
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
		status = http.StatusOK
	}

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
	if reqBody != nil {
		out.ReqBytes = reqBody.total()
		if bodies {
			out.ReqBody = reqBody.captured()
		}
	}
	if bodies && ww.body != nil {
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

// nilWriter is the sink under a capWriter used only for capture: the real
// bytes have already gone to the client by then.
type nilWriter struct{}

func (nilWriter) Write(p []byte) (int, error) { return len(p), nil }

var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ http.ResponseWriter         = (*watcher)(nil)
)
