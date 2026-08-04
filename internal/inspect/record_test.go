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

// TestCapWriterExactlyAtCapThenMore writes exactly cap bytes in one call,
// then more in a second call. captured() must stop growing at cap, and the
// underlying writer must still see every byte from both calls.
func TestCapWriterExactlyAtCapThenMore(t *testing.T) {
	var sink bytes.Buffer
	w := newCapWriter(&sink, 4)

	if _, err := io.WriteString(w, "hell"); err != nil {
		t.Fatal(err)
	}
	if string(w.captured()) != "hell" {
		t.Errorf("captured %q after exact-cap write, want %q", w.captured(), "hell")
	}

	if _, err := io.WriteString(w, "o world"); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "hello world" {
		t.Errorf("client saw %q, want the whole body", sink.String())
	}
	if string(w.captured()) != "hell" {
		t.Errorf("captured %q after the cap was already full, want it to stay %q", w.captured(), "hell")
	}
}

// TestCapWriterStraddleAcrossCalls writes cap-1 bytes, then 2 bytes, so the
// cap boundary falls in the middle of the second call. captured() must land
// exactly on cap, not cap+1, and every byte must still reach the sink.
func TestCapWriterStraddleAcrossCalls(t *testing.T) {
	var sink bytes.Buffer
	w := newCapWriter(&sink, 4)

	if _, err := io.WriteString(w, "hel"); err != nil { // cap-1 bytes
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "lo world"); err != nil { // straddles the boundary
		t.Fatal(err)
	}
	if sink.String() != "hello world" {
		t.Errorf("client saw %q, want the whole body", sink.String())
	}
	if string(w.captured()) != "hell" {
		t.Errorf("captured %q, want exactly %q at the boundary", w.captured(), "hell")
	}
}

// TestCapWriterPassthroughContinuesAfterCapReached checks that once the cap
// is full, further separate writes capture nothing more but still pass
// every byte through untouched.
func TestCapWriterPassthroughContinuesAfterCapReached(t *testing.T) {
	var sink bytes.Buffer
	w := newCapWriter(&sink, 4)

	if _, err := io.WriteString(w, "hell"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "o "); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "world"); err != nil {
		t.Fatal(err)
	}
	if sink.String() != "hello world" {
		t.Errorf("client saw %q, want the whole body across all three calls", sink.String())
	}
	if string(w.captured()) != "hell" {
		t.Errorf("captured %q, want it unchanged once the cap is full", w.captured())
	}
}

// TestCapReaderExactlyAtCapThenMore is capWriter's exact-cap case, for the
// read side: a Read that returns exactly cap bytes, followed by another
// Read. captured() must stop growing at cap, and every byte read must still
// be returned to the caller.
func TestCapReaderExactlyAtCapThenMore(t *testing.T) {
	r := newCapReader(io.NopCloser(strings.NewReader("hello world")), 4)

	first := make([]byte, 4)
	n, err := io.ReadFull(r, first)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(first) != "hell" {
		t.Fatalf("first read = %q, want %q", first[:n], "hell")
	}
	if string(r.captured()) != "hell" {
		t.Errorf("captured %q after exact-cap read, want %q", r.captured(), "hell")
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "o world" {
		t.Errorf("remaining read = %q, want %q", rest, "o world")
	}
	if string(r.captured()) != "hell" {
		t.Errorf("captured %q after the cap was already full, want it to stay %q", r.captured(), "hell")
	}
	if r.total() != 11 {
		t.Errorf("total = %d, want 11", r.total())
	}
}

// TestCapReaderStraddleAcrossCalls is capWriter's straddle case, for the
// read side: a Read of cap-1 bytes, then a Read that crosses the boundary.
// captured() must land exactly on cap, not cap+1.
func TestCapReaderStraddleAcrossCalls(t *testing.T) {
	r := newCapReader(io.NopCloser(strings.NewReader("hello world")), 4)

	first := make([]byte, 3) // cap-1 bytes
	n, err := io.ReadFull(r, first)
	if err != nil {
		t.Fatal(err)
	}
	if string(first[:n]) != "hel" {
		t.Fatalf("first read = %q, want %q", first[:n], "hel")
	}

	rest, err := io.ReadAll(r) // straddles the boundary
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "lo world" {
		t.Errorf("remaining read = %q, want %q", rest, "lo world")
	}
	if string(r.captured()) != "hell" {
		t.Errorf("captured %q, want exactly %q at the boundary", r.captured(), "hell")
	}
	if r.total() != 11 {
		t.Errorf("total = %d, want 11", r.total())
	}
}

// TestCapReaderPassthroughContinuesAfterCapReached checks that once the cap
// is full, further separate Read calls capture nothing more but still
// return every byte to the caller.
func TestCapReaderPassthroughContinuesAfterCapReached(t *testing.T) {
	r := newCapReader(io.NopCloser(strings.NewReader("hello world")), 4)

	first := make([]byte, 4)
	if _, err := io.ReadFull(r, first); err != nil {
		t.Fatal(err)
	}

	second := make([]byte, 2)
	if _, err := io.ReadFull(r, second); err != nil {
		t.Fatal(err)
	}
	if string(second) != "o " {
		t.Fatalf("second read = %q, want %q", second, "o ")
	}

	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "world" {
		t.Errorf("remaining read = %q, want %q", rest, "world")
	}
	if string(r.captured()) != "hell" {
		t.Errorf("captured %q, want it unchanged once the cap is full", r.captured())
	}
	if r.total() != 11 {
		t.Errorf("total = %d, want 11", r.total())
	}
}
