package inspect

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// withRecorder installs a recorder for the duration of a test.
func withRecorder(t *testing.T, opts Options) *Recorder {
	t.Helper()
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if opts.Flush == 0 {
		opts.Flush = 5 * time.Millisecond
	}
	r := New(s, opts)
	SetCurrent(r)
	t.Cleanup(func() {
		SetCurrent(nil)
		r.Close() //nolint:errcheck
	})
	return r
}

func nextFunc(fn http.HandlerFunc) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fn(w, r)
		return nil
	})
}

func TestHandlerRecordsANormalRequest(t *testing.T) {
	r := withRecorder(t, Options{})

	h := Handler{}
	req := httptest.NewRequest("GET", "http://app.test/hello?a=1", nil)
	req.Header.Set("Authorization", "Bearer hunter2")
	rw := httptest.NewRecorder()

	err := h.ServeHTTP(rw, req, nextFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(201)
		io.WriteString(w, "hi") //nolint:errcheck
	}))
	if err != nil {
		t.Fatal(err)
	}
	if rw.Code != 201 || rw.Body.String() != "hi" {
		t.Fatalf("client got %d %q; the handler must not alter the response", rw.Code, rw.Body)
	}

	var got *Record
	waitFor(t, "the request to be recorded", func() bool {
		rows, err := r.Store().List(Query{Limit: 10})
		if err != nil || len(rows) != 1 {
			return false
		}
		got = rows[0]
		return true
	})

	if got.Method != "GET" || got.Path != "/hello?a=1" || got.Status != 201 {
		t.Errorf("recorded %+v", got)
	}
	if got.Domain != "app.test" {
		t.Errorf("domain = %q, want app.test with no port", got.Domain)
	}
	if got.RespBytes != 2 {
		t.Errorf("RespBytes = %d, want 2", got.RespBytes)
	}
	if v := got.ReqHeaders["Authorization"]; len(v) != 1 || v[0] != Redacted {
		t.Errorf("Authorization = %v, want it redacted", v)
	}
	if got.Duration <= 0 {
		t.Error("Duration should be positive")
	}
}

func TestHandlerRecordsAnUpgradeImmediately(t *testing.T) {
	r := withRecorder(t, Options{})

	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		h := Handler{}
		req := httptest.NewRequest("GET", "http://app.test/ws", nil)
		req.Header.Set("Upgrade", "websocket")
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req, nextFunc(func(w http.ResponseWriter, _ *http.Request) { //nolint:errcheck
			w.WriteHeader(http.StatusSwitchingProtocols)
			// Stand in for a websocket that stays open. The record must
			// already exist while this is still blocked.
			<-release
		}))
	}()

	waitFor(t, "the upgrade to be recorded before the connection closes", func() bool {
		rows, err := r.Store().List(Query{Limit: 10})
		return err == nil && len(rows) == 1 && rows[0].Upgraded
	})

	close(release)
	<-done

	rows, err := r.Store().List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("an upgraded connection produced %d rows, want exactly 1", len(rows))
	}
}

func TestHandlerCapturesBodiesOnlyWhenEnabled(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		r := withRecorder(t, Options{})
		serve(t, strings.NewReader("request body"), "response body")
		got := firstRecord(t, r)
		if got.ReqBody != nil || got.RespBody != nil {
			t.Errorf("bodies captured with capture off: %q %q", got.ReqBody, got.RespBody)
		}
		if got.ReqBytes != int64(len("request body")) {
			t.Errorf("ReqBytes = %d, want the size even with capture off", got.ReqBytes)
		}
	})

	t.Run("on and truncated", func(t *testing.T) {
		r := withRecorder(t, Options{Bodies: true, MaxBodyBytes: 4})
		serve(t, strings.NewReader("request body"), "response body")
		got := firstRecord(t, r)
		if string(got.ReqBody) != "requ" {
			t.Errorf("ReqBody = %q, want it truncated to 4 bytes", got.ReqBody)
		}
		if string(got.RespBody) != "resp" {
			t.Errorf("RespBody = %q, want it truncated to 4 bytes", got.RespBody)
		}
	})

	t.Run("headers are not redacted when bodies are on", func(t *testing.T) {
		r := withRecorder(t, Options{Bodies: true, MaxBodyBytes: 64})
		h := Handler{}
		req := httptest.NewRequest("GET", "http://app.test/x", nil)
		req.Header.Set("Cookie", "sid=abc")
		if err := h.ServeHTTP(httptest.NewRecorder(), req, nextFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(200)
		})); err != nil {
			t.Fatal(err)
		}
		got := firstRecord(t, r)
		if v := got.ReqHeaders["Cookie"]; len(v) != 1 || v[0] != "sid=abc" {
			t.Errorf("Cookie = %v, want the real value once bodies are on", v)
		}
	})
}

func serve(t *testing.T, body io.Reader, respBody string) {
	t.Helper()
	h := Handler{}
	req := httptest.NewRequest("POST", "http://app.test/x", body)
	err := h.ServeHTTP(httptest.NewRecorder(), req, nextFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) //nolint:errcheck
		io.WriteString(w, respBody) //nolint:errcheck
	}))
	if err != nil {
		t.Fatal(err)
	}
}

func firstRecord(t *testing.T, r *Recorder) *Record {
	t.Helper()
	var got *Record
	waitFor(t, "a record", func() bool {
		rows, err := r.Store().List(Query{Limit: 10})
		if err != nil || len(rows) == 0 {
			return false
		}
		full, err := r.Store().Get(rows[0].ID)
		if err != nil {
			return false
		}
		got = full
		return true
	})
	return got
}

func TestHandlerPassesThroughWithNoRecorder(t *testing.T) {
	SetCurrent(nil)
	h := Handler{}
	rw := httptest.NewRecorder()
	err := h.ServeHTTP(rw, httptest.NewRequest("GET", "http://app.test/x", nil),
		nextFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(204)
		}))
	if err != nil {
		t.Fatal(err)
	}
	if rw.Code != 204 {
		t.Fatalf("status = %d; a nil recorder must be a clean pass-through", rw.Code)
	}
}

func TestHandlerRecordsImplicit200(t *testing.T) {
	r := withRecorder(t, Options{})

	h := Handler{}
	req := httptest.NewRequest("GET", "http://app.test/x", nil)
	err := h.ServeHTTP(httptest.NewRecorder(), req, nextFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok") //nolint:errcheck
	}))
	if err != nil {
		t.Fatal(err)
	}

	got := firstRecord(t, r)
	if got.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200 for a handler that never calls WriteHeader", got.Status)
	}
}

func TestHandlerRecordsExactlyOnceWhenNextErrors(t *testing.T) {
	r := withRecorder(t, Options{})

	h := Handler{}
	wantErr := errors.New("boom")
	req := httptest.NewRequest("GET", "http://app.test/x", nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		return wantErr
	})

	err := h.ServeHTTP(httptest.NewRecorder(), req, next)
	if !errors.Is(err, wantErr) {
		t.Fatalf("ServeHTTP error = %v, want %v passed through unchanged", err, wantErr)
	}

	got := firstRecord(t, r)
	if got.Error != wantErr.Error() {
		t.Errorf("Error = %q, want %q", got.Error, wantErr.Error())
	}

	rows, lerr := r.Store().List(Query{Limit: 10})
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(rows) != 1 {
		t.Fatalf("next returning an error produced %d records, want exactly 1", len(rows))
	}
}

func TestHandlerRecordsTheRealStatusOnAFailedProxyAttempt(t *testing.T) {
	r := withRecorder(t, Options{})

	h := Handler{}
	req := httptest.NewRequest("GET", "http://app.test/x", nil)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		// This is what reverse_proxy returns when the upstream refuses the
		// connection: no WriteHeader call, just a HandlerError carrying the
		// real status. Defaulting that to 200 would hide the single most
		// common failure in a local dev proxy.
		return caddyhttp.Error(http.StatusBadGateway, errors.New("dial tcp: connection refused"))
	})

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err == nil {
		t.Fatal("expected ServeHTTP to pass the HandlerError through")
	}

	got := firstRecord(t, r)
	if got.Status != http.StatusBadGateway {
		t.Errorf("Status = %d, want %d recovered from the HandlerError", got.Status, http.StatusBadGateway)
	}
}

func TestHandlerFlushReachesTheUnderlyingWriter(t *testing.T) {
	withRecorder(t, Options{})

	h := Handler{}
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://app.test/x", nil)
	err := h.ServeHTTP(rw, req, nextFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// A real SSE or streaming handler flushes through
		// http.ResponseController, never a direct type assertion, and that
		// call has to make it past the watcher wrapper to the recorder that
		// actually implements Flush.
		if ferr := http.NewResponseController(w).Flush(); ferr != nil {
			t.Errorf("Flush through the wrapper: %v", ferr)
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !rw.Flushed {
		t.Error("Flush did not reach the underlying ResponseRecorder")
	}
}

func TestHandlerReadFromStillGoesThroughWrite(t *testing.T) {
	r := withRecorder(t, Options{Bodies: true, MaxBodyBytes: 64})

	h := Handler{}
	req := httptest.NewRequest("GET", "http://app.test/x", nil)
	err := h.ServeHTTP(httptest.NewRecorder(), req, nextFunc(func(w http.ResponseWriter, _ *http.Request) {
		// io.Copy prefers src.WriteTo, then dst.ReadFrom, then a plain
		// Write loop. strings.Reader implements WriteTo, which would take
		// that first branch and hide a broken ReadFrom entirely, so the
		// source is stripped down to a bare io.Reader to force io.Copy onto
		// dst's ReadFrom - the same path a real io.Reader without WriteTo
		// (an os.File's body, a network conn) would take.
		//
		// *caddyhttp.ResponseWriterWrapper promotes a ReadFrom that writes
		// straight to the underlying ResponseWriter; watcher must shadow it
		// or this bypasses every counter and the body tee.
		src := struct{ io.Reader }{strings.NewReader("copied body")}
		io.Copy(w, src) //nolint:errcheck
	}))
	if err != nil {
		t.Fatal(err)
	}

	got := firstRecord(t, r)
	if got.RespBytes != int64(len("copied body")) {
		t.Errorf("RespBytes = %d, want %d; io.Copy must not bypass Write", got.RespBytes, len("copied body"))
	}
	if string(got.RespBody) != "copied body" {
		t.Errorf("RespBody = %q, want %q captured through the ReadFrom shadow", got.RespBody, "copied body")
	}
}

func TestHandlerRecordsAnHTTP2ExtendedConnectWebSocketImmediately(t *testing.T) {
	r := withRecorder(t, Options{})

	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		h := Handler{}
		// RFC 8441: an HTTP/2 websocket arrives as a CONNECT with a
		// :protocol pseudo-header, and Caddy accepts it with a plain 200,
		// never a 101. See streaming.go's handleUpgradeResponse.
		req := httptest.NewRequest(http.MethodConnect, "app.test:443", nil)
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		req.Header.Set(":protocol", "websocket")
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req, nextFunc(func(w http.ResponseWriter, _ *http.Request) { //nolint:errcheck
			w.WriteHeader(http.StatusOK)
			// Stand in for a websocket that stays open. The record must
			// already exist while this is still blocked.
			<-release
		}))
	}()

	waitFor(t, "the extended-CONNECT upgrade to be recorded before the connection closes", func() bool {
		rows, err := r.Store().List(Query{Limit: 10})
		return err == nil && len(rows) == 1 && rows[0].Upgraded
	})

	close(release)
	<-done

	rows, err := r.Store().List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("an h2 extended-connect upgrade produced %d rows, want exactly 1", len(rows))
	}
	if rows[0].Status != http.StatusOK {
		t.Errorf("Status = %d, want 200: that is the real wire status Caddy writes for RFC 8441, "+
			"Upgraded is what marks the row", rows[0].Status)
	}
}
