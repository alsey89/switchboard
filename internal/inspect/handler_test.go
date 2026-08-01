package inspect

import (
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
