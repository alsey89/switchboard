package inspect

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRedactHeadersHidesCredentials(t *testing.T) {
	h := http.Header{
		"Authorization": {"Bearer hunter2"},
		"COOKIE":        {"sid=abc"},
		"X-Api-Key":     {"k1", "k2"},
		"Content-Type":  {"application/json"},
	}
	got := RedactHeaders(h)

	for _, name := range []string{"Authorization", "COOKIE", "X-Api-Key"} {
		vs, ok := got[name]
		if !ok {
			t.Fatalf("%s should be kept as a name", name)
		}
		if len(vs) != 1 || vs[0] != Redacted {
			t.Errorf("%s = %v, want [%s]", name, vs, Redacted)
		}
	}
	if got := got["Content-Type"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("Content-Type = %v, want it untouched", got)
	}
}

func TestRedactHeadersDoesNotAliasTheOriginal(t *testing.T) {
	h := http.Header{"X-Trace": {"one"}}
	got := RedactHeaders(h)
	got["X-Trace"][0] = "mutated"
	if h.Get("X-Trace") != "one" {
		t.Error("redaction wrote through to the caller's header map")
	}
}

func TestCapWriterPassesEveryByteThrough(t *testing.T) {
	var sink bytes.Buffer
	w := newCapWriter(&sink, 4)

	if _, err := io.WriteString(w, "hello world"); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "hello world" {
		t.Errorf("client saw %q, want the whole body", sink.String())
	}
	if string(w.captured()) != "hell" {
		t.Errorf("captured %q, want the first 4 bytes", w.captured())
	}
}

func TestCapWriterWithZeroCapCapturesNothing(t *testing.T) {
	var sink bytes.Buffer
	w := newCapWriter(&sink, 0)
	if _, err := io.WriteString(w, "hello"); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "hello" {
		t.Errorf("client saw %q", sink.String())
	}
	if len(w.captured()) != 0 {
		t.Errorf("captured %q, want nothing", w.captured())
	}
}

func TestCapReaderReturnsEveryByteAndCountsThem(t *testing.T) {
	r := newCapReader(io.NopCloser(strings.NewReader("hello world")), 4)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Errorf("reader returned %q, want the whole body", got)
	}
	if string(r.captured()) != "hell" {
		t.Errorf("captured %q, want the first 4 bytes", r.captured())
	}
	if r.total() != 11 {
		t.Errorf("total = %d, want 11", r.total())
	}
}
