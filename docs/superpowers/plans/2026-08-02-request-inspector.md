# Switchboard v0.3 — Request Inspector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture every proxied request into a bounded SQLite ring buffer and show it live in the dashboard, without putting disk I/O on the request path and without ever being able to stop the proxy from starting.

**Architecture:** A custom Caddy middleware module sits ahead of `reverse_proxy` in each user route. It times the request, wraps the writer to learn the status and byte count, and does a non-blocking send onto an in-process channel. One drain goroutine batches those records into SQLite, trims the buffer, and fans out to Server-Sent Events subscribers. The recorder is owned by the daemon, not by Caddy, because every config reload re-provisions handler instances and the SQLite handle has to outlive that.

**Tech Stack:** Go, embedded Caddy v2, `modernc.org/sqlite` (pure Go, no CGo), `database/sql`, Server-Sent Events, `html/template`, vanilla JS.

**Spec:** [2026-08-02-inspector-design.md](../specs/2026-08-02-inspector-design.md). Read it before Task 1. Where this plan and the spec disagree, the spec is wrong and should be corrected.

## Global Constraints

- **Go version:** whatever `go.mod` declares. Do not pin one anywhere else.
- **`CGO_ENABLED=0` stays true.** `.goreleaser.yaml:14` sets it and builds darwin and linux for amd64 and arm64 from one runner. Do not add a CGo dependency. This is why the driver is `modernc.org/sqlite` and not `mattn/go-sqlite3`.
- **Exactly one new module: `modernc.org/sqlite`.** Nothing else. The live feed is SSE precisely so that no WebSocket module is needed.
- **`THIRD_PARTY_NOTICES` must be regenerated** with `make notices` in the same commit that adds the dependency. CI diffs it and fails if it is stale (`.github/workflows/ci.yml:23-27`).
- **`gofmt -l .` must be empty.** CI fails on unformatted files.
- **`go vet ./...` must pass.**
- **The inspector may never prevent the daemon from starting.** Every failure path logs a warning and runs with capture off. The proxy is the product.
- **Capture never blocks a proxied request.** The channel send is non-blocking. A full channel drops the record and increments a counter.
- **Bodies are off by default** and, when on, are captured by write-through tee. Never buffer a response to capture it.
- **Redaction is best effort and the docs must say so.** Never write "prevents".
- **Prose style for docs, changelog, and commit bodies:** short sentences, little jargon, no em dashes.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`). No AI attribution in messages. There is no tracking issue for this feature, so no `Closes #N` footer. Open one first if you want the link.
- **Branch:** `feat/inspector`, already created, spec already committed there.
- **Commit after every task.**
- **Known flake:** `TestEndToEnd` fails when run more than once in a process (issue #25). Do not attribute a failure there to this work without checking that first.

---

## File Structure

**Create:**

| Path | Responsibility |
|---|---|
| `internal/inspect/record.go` | `Record` type, header redaction, capped body tee reader and writer. Pure, no I/O. |
| `internal/inspect/record_test.go` | Tests for the above. |
| `internal/inspect/store.go` | SQLite. Schema, batch insert, three-way trim, queries. Knows nothing about HTTP or Caddy. |
| `internal/inspect/store_test.go` | Tests for the above. |
| `internal/inspect/recorder.go` | The bus. Non-blocking submit, drain goroutine, batching, subscriber fan-out, trim ticker, process-wide current pointer. |
| `internal/inspect/recorder_test.go` | Tests for the above. |
| `internal/inspect/handler.go` | The Caddy middleware module `http.handlers.switchboard_inspect`. |
| `internal/inspect/handler_test.go` | Tests for the above. |
| `internal/dashboard/inspect.go` | Inspector HTTP endpoints and the SSE stream. |
| `internal/dashboard/inspect_test.go` | Tests for the above. |
| `internal/dashboard/templates/inspect.html` | The split-pane page. |
| `internal/proxy/inspect_test.go` | Asserts the handler lands in user routes and not in the dashboard catch-all. |

**Modify:**

| Path | Change |
|---|---|
| `internal/config/config.go` | `[inspect]` section, defaults, accessors, validation. |
| `internal/config/config_test.go` | Tests for the above. |
| `internal/proxy/proxy.go:78-88` | Prepend the inspect handler to each user route when enabled. |
| `internal/dashboard/dashboard.go:47-58,101-112` | Route the new paths. Extract the host guard out of `handleRoot`. |
| `internal/daemon/daemon.go:100-118,160-179` | Open the store, own the recorder, keep it in step with reloads, shut it down. |
| `internal/daemon/daemon_test.go:37-44,145` | Record `dataDir` on `testEnv`. Add the end-to-end capture test. |
| `DESIGN.md:227,357` | SSE not WebSocket. Route mutation moved out of v0.3. |
| `README.md` | Inspector section. |
| `docs/ARCHITECTURE.md` | New subsystem, new file on disk, loopback boundary now covers captured traffic. |
| `CHANGELOG.md` | New version heading. |
| `THIRD_PARTY_NOTICES` | Regenerated. |

---

### Task 1: Config surface

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `config.InspectConfig` struct; `(*Config).InspectEnabled() bool`, `.InspectBodies() bool`, `.InspectMaxRequests() int`, `.InspectMaxBytes() int64`, `.InspectMaxBodyBytes() int`, `.InspectMaxAge() time.Duration`. Every later task reads settings only through these accessors, never off the struct.

- [ ] **Step 1: Write the failing test**

Append to `internal/config/config_test.go`:

```go
func TestInspectDefaults(t *testing.T) {
	c := Default()
	if !c.InspectEnabled() {
		t.Error("metadata capture should default to on")
	}
	if c.InspectBodies() {
		t.Error("bodies must default to off")
	}
	if got := c.InspectMaxRequests(); got != DefaultInspectMaxRequests {
		t.Errorf("max_requests = %d, want %d", got, DefaultInspectMaxRequests)
	}
	if got := c.InspectMaxBytes(); got != DefaultInspectMaxBytes {
		t.Errorf("max_bytes = %d, want %d", got, DefaultInspectMaxBytes)
	}
	if got := c.InspectMaxBodyBytes(); got != DefaultInspectMaxBodyBytes {
		t.Errorf("max_body_bytes = %d, want %d", got, DefaultInspectMaxBodyBytes)
	}
	if got := c.InspectMaxAge(); got != DefaultInspectMaxAge {
		t.Errorf("max_age = %s, want %s", got, DefaultInspectMaxAge)
	}
}

func TestInspectExplicitlyDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "suffix = \"test\"\n\n[inspect]\nenabled = false\nbodies = true\nmax_requests = 10\nmax_age = \"1h\"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.InspectEnabled() {
		t.Error("enabled = false must survive the load")
	}
	if !c.InspectBodies() {
		t.Error("bodies = true must survive the load")
	}
	if got := c.InspectMaxRequests(); got != 10 {
		t.Errorf("max_requests = %d, want 10", got)
	}
	if got := c.InspectMaxAge(); got != time.Hour {
		t.Errorf("max_age = %s, want 1h", got)
	}
}

func TestInspectRejectsBadSettings(t *testing.T) {
	cases := map[string]string{
		"unparseable age": "max_age = \"soon\"",
		"negative rows":   "max_requests = -1",
		"negative bytes":  "max_bytes = -1",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			body := "suffix = \"test\"\n\n[inspect]\n" + line + "\n"
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}
```

Add `"time"` to the test file's imports if it is not already there.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestInspect -v`
Expected: FAIL to compile, `c.InspectEnabled undefined`.

- [ ] **Step 3: Add the config struct and defaults**

In `internal/config/config.go`, add `"time"` to the imports. Add the field to `Config` after `DashboardPort` and before `Routes`:

```go
	// Inspect configures the request inspector. Absent means defaults,
	// which is metadata capture on and bodies off.
	Inspect *InspectConfig `toml:"inspect,omitempty"`
```

Then, after the `Route` type:

```go
// InspectConfig configures the request inspector. A nil *InspectConfig and a
// zero-valued one both mean "all defaults", so the accessors below are the
// only supported way to read these.
type InspectConfig struct {
	// Enabled turns metadata capture on or off. Pointer, not bool: the
	// default is true, and a plain bool cannot tell "unset" from "off".
	Enabled *bool `toml:"enabled,omitempty"`

	// Bodies captures request and response bodies. It also stops header
	// redaction. Both effects, not one: someone who asked for the payload
	// has already asked for the credentials in it, and a redacted Cookie
	// next to a full session body is a confusing half measure.
	Bodies bool `toml:"bodies,omitzero"`

	MaxRequests  int   `toml:"max_requests,omitzero"`
	MaxBytes     int64 `toml:"max_bytes,omitzero"`
	MaxBodyBytes int   `toml:"max_body_bytes,omitzero"`

	// MaxAge is a Go duration string. It is the one knob here that is not a
	// number, because "168h" is checkable at a glance and 604800 is not.
	MaxAge string `toml:"max_age,omitempty"`
}
```

Add to the `Defaults` const block:

```go
	DefaultInspectMaxRequests  = 5000
	DefaultInspectMaxBytes     = 64 << 20 // 64 MiB
	DefaultInspectMaxBodyBytes = 64 << 10 // 64 KiB
```

`MaxAge` cannot be a const of type `time.Duration` in that block without changing its type, so declare it separately below the block:

```go
// DefaultInspectMaxAge bounds how long captured traffic sits on disk. The
// row and byte caps cannot catch the quiet case: a lightly used route
// leaves a handful of rows that nothing ever pushes out.
const DefaultInspectMaxAge = 7 * 24 * time.Hour
```

- [ ] **Step 4: Add the accessors**

Below the existing `orDefault` helper:

```go
// Inspector settings. Read these, never the struct: the zero value of every
// field means "default", and Enabled defaults to true.

func (c *Config) InspectEnabled() bool {
	if c.Inspect == nil || c.Inspect.Enabled == nil {
		return true
	}
	return *c.Inspect.Enabled
}

func (c *Config) InspectBodies() bool {
	return c.Inspect != nil && c.Inspect.Bodies
}

func (c *Config) InspectMaxRequests() int {
	if c.Inspect == nil {
		return DefaultInspectMaxRequests
	}
	return orDefault(c.Inspect.MaxRequests, DefaultInspectMaxRequests)
}

func (c *Config) InspectMaxBytes() int64 {
	if c.Inspect == nil || c.Inspect.MaxBytes == 0 {
		return DefaultInspectMaxBytes
	}
	return c.Inspect.MaxBytes
}

func (c *Config) InspectMaxBodyBytes() int {
	if c.Inspect == nil {
		return DefaultInspectMaxBodyBytes
	}
	return orDefault(c.Inspect.MaxBodyBytes, DefaultInspectMaxBodyBytes)
}

// InspectMaxAge returns the parsed max_age. Validate has already proved the
// string parses, so a bad value here can only come from a Config built in
// code, and falling back to the default beats panicking in the daemon.
func (c *Config) InspectMaxAge() time.Duration {
	if c.Inspect == nil || c.Inspect.MaxAge == "" {
		return DefaultInspectMaxAge
	}
	d, err := time.ParseDuration(c.Inspect.MaxAge)
	if err != nil || d <= 0 {
		return DefaultInspectMaxAge
	}
	return d
}
```

- [ ] **Step 5: Add validation**

In `Validate`, immediately before the closing `return nil`:

```go
	if err := c.Inspect.validate(); err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
```

And the method, next to `validateUpstream`:

```go
func (i *InspectConfig) validate() error {
	if i == nil {
		return nil
	}
	if i.MaxRequests < 0 {
		return fmt.Errorf("max_requests %d cannot be negative", i.MaxRequests)
	}
	if i.MaxBytes < 0 {
		return fmt.Errorf("max_bytes %d cannot be negative", i.MaxBytes)
	}
	if i.MaxBodyBytes < 0 {
		return fmt.Errorf("max_body_bytes %d cannot be negative", i.MaxBodyBytes)
	}
	if i.MaxAge != "" {
		d, err := time.ParseDuration(i.MaxAge)
		if err != nil {
			return fmt.Errorf("max_age %q is not a duration (try \"168h\"): %w", i.MaxAge, err)
		}
		if d <= 0 {
			return fmt.Errorf("max_age %q must be positive", i.MaxAge)
		}
	}
	return nil
}
```

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/config/ -v`
Expected: PASS, including the pre-existing tests. If `TestLegacyTLDKeyStillLoads` or any round-trip test breaks, the cause is `Save` now emitting an `[inspect]` table. It should not, because the field is a nil pointer with `omitempty`. If it does, that is a real bug in the tag, not a reason to edit the test.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add inspect config section

Metadata capture defaults to on, bodies to off. Enabled is a *bool
because the default is true and a plain bool cannot tell unset from off.
max_age is a duration string so it reads as 168h and not 604800."
```

---

### Task 2: Record, redaction, capped bodies

**Files:**
- Create: `internal/inspect/record.go`
- Test: `internal/inspect/record_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `inspect.Record` struct; `inspect.RedactHeaders(http.Header) map[string][]string`; `inspect.Redacted` constant; `inspect.newCapReader(io.ReadCloser, int) *capReader` and `inspect.newCapWriter(io.Writer, int) *capWriter`, both unexported, used only by `handler.go` in Task 5.

- [ ] **Step 1: Write the failing test**

Create `internal/inspect/record_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/inspect/ -v`
Expected: FAIL, no such package or `undefined: RedactHeaders`.

- [ ] **Step 3: Write the implementation**

Create `internal/inspect/record.go`:

```go
// Package inspect captures proxied requests into a bounded SQLite ring
// buffer and feeds them to the dashboard live.
//
// The pieces, in dependency order:
//
//   - record.go   the captured event, redaction, capped body copies
//   - store.go    SQLite: schema, batch insert, trim, queries
//   - recorder.go the bus between the request path and the store
//   - handler.go  the Caddy middleware that does the capturing
//
// Nothing here is allowed to slow down or break a proxied request. The
// handler's hand-off to the recorder is a non-blocking channel send, body
// capture is a write-through tee rather than a buffer, and every failure
// path degrades to capturing nothing.
package inspect

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// Redacted replaces the value of a credential-bearing header.
const Redacted = "[redacted]"

// Record is one captured request.
type Record struct {
	ID        int64
	StartedAt time.Time
	Duration  time.Duration

	Domain string
	Method string
	Path   string // path plus query
	Status int
	Proto  string

	// Upgraded marks a connection that became a WebSocket or similar. Those
	// are recorded once, at the upgrade, not when the connection finally
	// closes. See handler.go for why.
	Upgraded bool

	ReqBytes  int64
	RespBytes int64
	Error     string

	ReqHeaders  map[string][]string
	RespHeaders map[string][]string

	// Bodies are nil unless capture is enabled, and are truncated to
	// max_body_bytes when it is.
	ReqBody  []byte
	RespBody []byte

	// SizeBytes is this row's cost against the byte cap. The store sets it.
	SizeBytes int64
}

// sensitiveHeaders are the headers whose values are replaced when redaction
// is on, which is whenever body capture is off.
//
// This is a deny-list, so it is best effort. A custom token header will go
// through it untouched. Documentation must say this reduces exposure, not
// that it prevents it.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
}

// RedactHeaders copies h, replacing the values of credential-bearing
// headers. Names are always kept: knowing a Cookie was sent is useful and
// costs nothing.
func RedactHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		if sensitiveHeaders[strings.ToLower(k)] {
			out[k] = []string{Redacted}
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// CopyHeaders copies h with no redaction, for when the user has explicitly
// turned body capture on.
func CopyHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// capWriter copies the first cap bytes written through it into a buffer
// while passing every byte straight to w.
//
// It is a tee, not a buffer, and that is the whole point. Buffering a
// response to capture it would break server-sent events and stall large
// downloads, which is not a price a debugging feature gets to charge.
type capWriter struct {
	w   io.Writer
	buf []byte
	cap int
}

func newCapWriter(w io.Writer, capacity int) *capWriter {
	return &capWriter{w: w, cap: capacity}
}

func (c *capWriter) Write(p []byte) (int, error) {
	if room := c.cap - len(c.buf); room > 0 {
		take := len(p)
		if take > room {
			take = room
		}
		c.buf = append(c.buf, p[:take]...)
	}
	return c.w.Write(p)
}

func (c *capWriter) captured() []byte { return c.buf }

// capReader is capWriter's counterpart for a request body. It hands every
// byte to the caller and keeps the first cap of them.
type capReader struct {
	r   io.ReadCloser
	buf []byte
	cap int
	n   int64
}

func newCapReader(r io.ReadCloser, capacity int) *capReader {
	return &capReader{r: r, cap: capacity}
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if room := c.cap - len(c.buf); room > 0 && n > 0 {
		take := n
		if take > room {
			take = room
		}
		c.buf = append(c.buf, p[:take]...)
	}
	return n, err
}

func (c *capReader) Close() error { return c.r.Close() }

func (c *capReader) captured() []byte { return c.buf }
func (c *capReader) total() int64     { return c.n }
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/inspect/ -v`
Expected: PASS, five tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/inspect/record.go internal/inspect/record_test.go
git commit -m "feat: add inspector record type and capture primitives

Header redaction is a deny-list, so it is best effort and the docs say
so. Body capture is a write-through tee rather than a buffer. Buffering
a response to capture it would break SSE and stall large downloads."
```

---

### Task 3: The SQLite store

**Files:**
- Create: `internal/inspect/store.go`
- Test: `internal/inspect/store_test.go`
- Modify: `go.mod`, `go.sum`, `THIRD_PARTY_NOTICES`

**Interfaces:**
- Consumes: `Record` from Task 2.
- Produces: `inspect.Limits{MaxRequests int, MaxBytes int64, MaxAge time.Duration}`; `inspect.Open(path string, lim Limits) (*Store, error)`; `(*Store).Insert(recs []*Record) error` (sets each `Record.ID` and `Record.SizeBytes` in place); `(*Store).Trim(now time.Time) error`; `(*Store).SetLimits(Limits)`; `(*Store).List(Query) ([]*Record, error)`; `(*Store).Get(id int64) (*Record, error)`; `(*Store).Clear() error`; `(*Store).Close() error`; `inspect.Query{Domain, Method, Status, Q string; Before int64; Limit int}`.

- [ ] **Step 1: Add the dependency**

```bash
go get modernc.org/sqlite
make notices
```

`make notices` regenerates `THIRD_PARTY_NOTICES`. CI diffs that file, so skipping this fails the build later with an error that looks unrelated.

- [ ] **Step 2: Write the failing test**

Create `internal/inspect/store_test.go`:

```go
package inspect

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T, lim Limits) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "inspect.db"), lim)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() }) //nolint:errcheck
	return s
}

func rec(at time.Time, path string) *Record {
	return &Record{
		StartedAt:   at,
		Duration:    3 * time.Millisecond,
		Domain:      "app.test",
		Method:      "GET",
		Path:        path,
		Status:      200,
		Proto:       "HTTP/1.1",
		ReqHeaders:  map[string][]string{"Accept": {"*/*"}},
		RespHeaders: map[string][]string{"Content-Type": {"text/plain"}},
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	now := time.Unix(1_700_000_000, 0).UTC()

	in := rec(now, "/hello?a=1")
	in.ReqBody = []byte("ping")
	in.RespBody = []byte("pong")
	if err := s.Insert([]*Record{in}); err != nil {
		t.Fatal(err)
	}
	if in.ID == 0 {
		t.Fatal("Insert must set the ID")
	}
	if in.SizeBytes == 0 {
		t.Fatal("Insert must set SizeBytes")
	}

	got, err := s.Get(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/hello?a=1" || got.Domain != "app.test" || got.Status != 200 {
		t.Errorf("scalars round-tripped wrong: %+v", got)
	}
	if !got.StartedAt.Equal(now) {
		t.Errorf("StartedAt = %s, want %s", got.StartedAt, now)
	}
	if got.Duration != 3*time.Millisecond {
		t.Errorf("Duration = %s", got.Duration)
	}
	if string(got.ReqBody) != "ping" || string(got.RespBody) != "pong" {
		t.Errorf("bodies round-tripped wrong: %q %q", got.ReqBody, got.RespBody)
	}
	if v := got.ReqHeaders["Accept"]; len(v) != 1 || v[0] != "*/*" {
		t.Errorf("ReqHeaders = %v", got.ReqHeaders)
	}
}

func TestListOmitsBodies(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	in := rec(time.Now(), "/x")
	in.RespBody = []byte("a large body")
	if err := s.Insert([]*Record{in}); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].RespBody != nil {
		t.Error("List must not carry bodies; that is what Get is for")
	}
}

func TestTrimByRowCap(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 3, MaxBytes: 1 << 30, MaxAge: time.Hour})
	now := time.Now()
	for i := 0; i < 10; i++ {
		if err := s.Insert([]*Record{rec(now, fmt.Sprintf("/%d", i))}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.List(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("kept %d rows, want 3", len(got))
	}
	if got[0].Path != "/9" {
		t.Errorf("newest is %s, want /9", got[0].Path)
	}
}

func TestTrimByByteCap(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 10000, MaxBytes: 900, MaxAge: time.Hour})
	now := time.Now()
	for i := 0; i < 40; i++ {
		r := rec(now, fmt.Sprintf("/%d", i))
		r.RespBody = make([]byte, 100)
		if err := s.Insert([]*Record{r}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.List(Query{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("byte cap trimmed everything")
	}
	if len(got) >= 40 {
		t.Fatalf("kept %d rows, byte cap did not bite", len(got))
	}
	if s.Bytes() > 900 {
		t.Errorf("running total %d exceeds the cap", s.Bytes())
	}
}

func TestTrimByAge(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})
	now := time.Now()
	if err := s.Insert([]*Record{rec(now.Add(-3*time.Hour), "/old")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Insert([]*Record{rec(now, "/new")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Trim(now); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "/new" {
		t.Fatalf("kept %d rows %v, want just /new", len(got), got)
	}
}

func TestOpenTrimsStaleRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inspect.db")

	// Age off for the first session, so Insert's own trim leaves the row
	// alone and Open is the only thing that can remove it later. Without
	// this the test passes whether or not Open trims at all.
	s, err := Open(path, Limits{MaxRequests: 1000, MaxBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert([]*Record{rec(time.Now().Add(-25*time.Hour), "/stale")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A daemon that sat idle overnight has stale rows and no writes coming
	// to trigger a trim. Open is the other place age gets enforced.
	s2, err := Open(path, Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck
	got, err := s2.List(Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("Open kept %d stale rows", len(got))
	}
}

func TestListFilters(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})
	now := time.Now()
	mk := func(domain, method, path string, status int) *Record {
		r := rec(now, path)
		r.Domain, r.Method, r.Status = domain, method, status
		return r
	}
	all := []*Record{
		mk("app.test", "GET", "/users", 200),
		mk("app.test", "POST", "/users", 404),
		mk("api.test", "GET", "/health", 503),
	}
	for _, r := range all {
		if err := s.Insert([]*Record{r}); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		q    Query
		want int
	}{
		{"domain", Query{Domain: "app.test"}, 2},
		{"method", Query{Method: "POST"}, 1},
		{"exact status", Query{Status: "404"}, 1},
		{"status class", Query{Status: "5xx"}, 1},
		{"path substring", Query{Q: "user"}, 2},
		{"combined", Query{Domain: "app.test", Status: "2xx"}, 1},
		{"no filter", Query{}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := s.List(c.q)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != c.want {
				t.Errorf("got %d rows, want %d", len(got), c.want)
			}
		})
	}
}

func TestClearEmptiesTheBuffer(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err := s.Insert([]*Record{rec(time.Now(), "/x")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	got, err := s.List(Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("%d rows survived Clear", len(got))
	}
	if s.Bytes() != 0 {
		t.Errorf("running byte total = %d after Clear, want 0", s.Bytes())
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/inspect/ -run TestStore -v`
Expected: FAIL to compile, `undefined: Open`.

- [ ] **Step 4: Write the store**

Create `internal/inspect/store.go`:

```go
package inspect

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS requests (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at   INTEGER NOT NULL,
  duration_us  INTEGER NOT NULL,
  domain       TEXT    NOT NULL,
  method       TEXT    NOT NULL,
  path         TEXT    NOT NULL,
  status       INTEGER NOT NULL,
  proto        TEXT    NOT NULL,
  upgraded     INTEGER NOT NULL DEFAULT 0,
  req_bytes    INTEGER NOT NULL DEFAULT 0,
  resp_bytes   INTEGER NOT NULL DEFAULT 0,
  error        TEXT    NOT NULL DEFAULT '',
  req_headers  TEXT    NOT NULL DEFAULT '{}',
  resp_headers TEXT    NOT NULL DEFAULT '{}',
  req_body     BLOB,
  resp_body    BLOB,
  size_bytes   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_started ON requests(started_at);
`

// rowOverhead approximates the fixed cost of a row's scalar columns against
// the byte cap. It does not have to be exact. It has to stop a buffer of
// millions of tiny rows from reporting itself as nearly empty.
const rowOverhead = 128

// Limits bound the ring buffer. All three are enforced, in this order: age,
// then rows, then bytes.
type Limits struct {
	MaxRequests int
	MaxBytes    int64
	MaxAge      time.Duration
}

// Store is the SQLite ring buffer.
//
// It keeps the row count and the byte total in memory so that trimming
// after every batch does not mean a SUM() over the table. DELETE ...
// RETURNING gives back exactly what was removed, so the totals stay exact
// without ever rescanning.
type Store struct {
	db *sql.DB

	mu    sync.Mutex
	lim   Limits
	rows  int
	bytes int64
}

// Open opens or creates the buffer at path and trims it to the limits.
//
// The trim on open is not belt and braces. It is the only thing that
// enforces max_age for a daemon that was shut down over a weekend: nothing
// else runs until traffic arrives.
func Open(path string, lim Limits) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	// One connection. Writes come from a single goroutine in batches and
	// reads are small indexed queries over a few thousand rows, so there is
	// nothing to gain from a pool and one less question about which
	// connection a PRAGMA applied to.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("creating schema in %s: %w", path, err)
	}

	s := &Store{db: db, lim: lim}
	row := db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM requests`)
	if err := row.Scan(&s.rows, &s.bytes); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("reading buffer size from %s: %w", path, err)
	}
	if err := s.Trim(time.Now()); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("trimming %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// SetLimits swaps the limits, for a config reload. The next trim applies
// them.
func (s *Store) SetLimits(lim Limits) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lim = lim
}

// Bytes reports the running byte total. Exported for tests and for the
// dashboard's status line.
func (s *Store) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytes
}

// Rows reports the running row count.
func (s *Store) Rows() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows
}

// Insert writes a batch and trims. Each record's ID and SizeBytes are filled
// in on the way through.
func (s *Store) Insert(recs []*Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	stmt, err := tx.Prepare(`
INSERT INTO requests (started_at, duration_us, domain, method, path, status,
                      proto, upgraded, req_bytes, resp_bytes, error,
                      req_headers, resp_headers, req_body, resp_body, size_bytes)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck

	var added int64
	for _, r := range recs {
		reqHdr := marshalHeaders(r.ReqHeaders)
		respHdr := marshalHeaders(r.RespHeaders)
		r.SizeBytes = int64(rowOverhead + len(reqHdr) + len(respHdr) +
			len(r.ReqBody) + len(r.RespBody) + len(r.Path) + len(r.Domain))

		res, err := stmt.Exec(
			r.StartedAt.UnixMicro(), r.Duration.Microseconds(), r.Domain,
			r.Method, r.Path, r.Status, r.Proto, boolToInt(r.Upgraded),
			r.ReqBytes, r.RespBytes, r.Error, reqHdr, respHdr,
			nilIfEmpty(r.ReqBody), nilIfEmpty(r.RespBody), r.SizeBytes)
		if err != nil {
			return err
		}
		if id, err := res.LastInsertId(); err == nil {
			r.ID = id
		}
		added += r.SizeBytes
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	s.mu.Lock()
	s.rows += len(recs)
	s.bytes += added
	s.mu.Unlock()

	return s.Trim(time.Now())
}

// Trim enforces all three limits. Age first, because it is the cheapest and
// the most likely to make the other two moot.
func (s *Store) Trim(now time.Time) error {
	s.mu.Lock()
	lim := s.lim
	s.mu.Unlock()

	if lim.MaxAge > 0 {
		cutoff := now.Add(-lim.MaxAge).UnixMicro()
		if err := s.deleteAndAccount(
			`DELETE FROM requests WHERE started_at < ? RETURNING size_bytes`, cutoff); err != nil {
			return err
		}
	}

	if lim.MaxRequests > 0 {
		if excess := s.Rows() - lim.MaxRequests; excess > 0 {
			if err := s.deleteAndAccount(
				`DELETE FROM requests WHERE id IN
				 (SELECT id FROM requests ORDER BY id ASC LIMIT ?) RETURNING size_bytes`,
				excess); err != nil {
				return err
			}
		}
	}

	if lim.MaxBytes > 0 {
		// Chunked rather than computed: a running window sum in SQL would be
		// clever, and this loop runs a handful of times at most because the
		// row cap has already bounded the table.
		for s.Bytes() > lim.MaxBytes && s.Rows() > 0 {
			if err := s.deleteAndAccount(
				`DELETE FROM requests WHERE id IN
				 (SELECT id FROM requests ORDER BY id ASC LIMIT 64) RETURNING size_bytes`); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteAndAccount runs a DELETE ... RETURNING size_bytes and subtracts
// exactly what it removed from the running totals.
func (s *Store) deleteAndAccount(query string, args ...any) error {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close() //nolint:errcheck

	var n int
	var freed int64
	for rows.Next() {
		var size int64
		if err := rows.Scan(&size); err != nil {
			return err
		}
		n++
		freed += size
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.rows -= n
	s.bytes -= freed
	if s.rows < 0 {
		s.rows = 0
	}
	if s.bytes < 0 {
		s.bytes = 0
	}
	s.mu.Unlock()
	return nil
}

// Clear empties the buffer.
func (s *Store) Clear() error {
	if _, err := s.db.Exec(`DELETE FROM requests`); err != nil {
		return err
	}
	s.mu.Lock()
	s.rows, s.bytes = 0, 0
	s.mu.Unlock()
	return nil
}

// Query filters a List. The zero value returns the newest rows unfiltered.
type Query struct {
	Domain string
	Method string
	Status string // "404" or "4xx"
	Q      string // path substring, case-insensitive
	Before int64  // return rows with a lower id; 0 means newest
	Limit  int    // default 200, capped at 500
}

const listColumns = `id, started_at, duration_us, domain, method, path, status,
                     proto, upgraded, req_bytes, resp_bytes, error,
                     req_headers, resp_headers, size_bytes`

// List returns matching records, newest first, without bodies. Bodies can be
// large and a list view never shows them; Get is for one record in full.
func (s *Store) List(q Query) ([]*Record, error) {
	var where []string
	var args []any

	if q.Domain != "" {
		where = append(where, "domain = ?")
		args = append(args, q.Domain)
	}
	if q.Method != "" {
		where = append(where, "method = ?")
		args = append(args, strings.ToUpper(q.Method))
	}
	if cond, arg, ok := statusCondition(q.Status); ok {
		where = append(where, cond)
		args = append(args, arg...)
	}
	if q.Q != "" {
		where = append(where, "path LIKE ? ESCAPE '\\'")
		args = append(args, "%"+escapeLike(q.Q)+"%")
	}
	if q.Before > 0 {
		where = append(where, "id < ?")
		args = append(args, q.Before)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}

	sqlText := `SELECT ` + listColumns + ` FROM requests`
	if len(where) > 0 {
		sqlText += " WHERE " + strings.Join(where, " AND ")
	}
	sqlText += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := []*Record{}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one record with its bodies.
func (s *Store) Get(id int64) (*Record, error) {
	row := s.db.QueryRow(`SELECT `+listColumns+`, req_body, resp_body
	                      FROM requests WHERE id = ?`, id)
	var (
		r          Record
		startedAt  int64
		durationUS int64
		upgraded   int
		reqHdr     string
		respHdr    string
	)
	err := row.Scan(&r.ID, &startedAt, &durationUS, &r.Domain, &r.Method,
		&r.Path, &r.Status, &r.Proto, &upgraded, &r.ReqBytes, &r.RespBytes,
		&r.Error, &reqHdr, &respHdr, &r.SizeBytes, &r.ReqBody, &r.RespBody)
	if err != nil {
		return nil, err
	}
	r.StartedAt = time.UnixMicro(startedAt).UTC()
	r.Duration = time.Duration(durationUS) * time.Microsecond
	r.Upgraded = upgraded != 0
	r.ReqHeaders = unmarshalHeaders(reqHdr)
	r.RespHeaders = unmarshalHeaders(respHdr)
	return &r, nil
}

func scanRecord(rows *sql.Rows) (*Record, error) {
	var (
		r          Record
		startedAt  int64
		durationUS int64
		upgraded   int
		reqHdr     string
		respHdr    string
	)
	if err := rows.Scan(&r.ID, &startedAt, &durationUS, &r.Domain, &r.Method,
		&r.Path, &r.Status, &r.Proto, &upgraded, &r.ReqBytes, &r.RespBytes,
		&r.Error, &reqHdr, &respHdr, &r.SizeBytes); err != nil {
		return nil, err
	}
	r.StartedAt = time.UnixMicro(startedAt).UTC()
	r.Duration = time.Duration(durationUS) * time.Microsecond
	r.Upgraded = upgraded != 0
	r.ReqHeaders = unmarshalHeaders(reqHdr)
	r.RespHeaders = unmarshalHeaders(respHdr)
	return &r, nil
}

// statusCondition turns "404" or "4xx" into a WHERE fragment. Anything else
// is ignored rather than rejected: a filter the user cannot see is not worth
// a 400.
func statusCondition(s string) (string, []any, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "", nil, false
	}
	if len(s) == 3 && strings.HasSuffix(s, "xx") {
		if d, err := strconv.Atoi(s[:1]); err == nil && d >= 1 && d <= 9 {
			return "status >= ? AND status < ?", []any{d * 100, (d + 1) * 100}, true
		}
		return "", nil, false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return "status = ?", []any{n}, true
	}
	return "", nil, false
}

// escapeLike neutralises the wildcards in a user-supplied substring so that
// searching for "a_b" does not match "axb".
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func marshalHeaders(h map[string][]string) string {
	if len(h) == 0 {
		return "{}"
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func unmarshalHeaders(s string) map[string][]string {
	if s == "" || s == "{}" {
		return map[string][]string{}
	}
	var out map[string][]string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return map[string][]string{}
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nilIfEmpty(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/inspect/ -v`
Expected: PASS, all store tests plus the record tests from Task 2.

- [ ] **Step 6: Verify the build stayed CGo-free**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success. If this fails, the wrong SQLite driver got pulled in and the release build is broken.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./...
git add go.mod go.sum THIRD_PARTY_NOTICES internal/inspect/store.go internal/inspect/store_test.go
git commit -m "feat: add the inspector's SQLite ring buffer

Bounded three ways: age, rows, bytes. Age is enforced on open too,
because a daemon that sat idle over a weekend has stale rows and no
writes coming to trigger a trim.

Row count and byte total are kept in memory and corrected from DELETE
... RETURNING, so trimming after every batch never rescans the table.

Driver is modernc.org/sqlite. The release build is CGO_ENABLED=0 across
four targets from one runner and that is worth more than the speed."
```

---

### Task 4: The recorder

**Files:**
- Create: `internal/inspect/recorder.go`
- Test: `internal/inspect/recorder_test.go`

**Interfaces:**
- Consumes: `Record`, `Store` from Tasks 2 and 3.
- Produces: `inspect.Recorder`; `inspect.New(*Store, Options) *Recorder`; `(*Recorder).Submit(*Record)`; `(*Recorder).Subscribe() (<-chan *Record, func())`; `(*Recorder).Dropped() int64`; `(*Recorder).Store() *Store`; `(*Recorder).Bodies() bool`; `(*Recorder).MaxBodyBytes() int`; `(*Recorder).SetOptions(bodies bool, maxBody int)`; `(*Recorder).Close() error`; `inspect.Current() *Recorder`; `inspect.SetCurrent(*Recorder)`; `inspect.Options{Bodies bool, MaxBodyBytes, Buffer, Batch int, Flush time.Duration, TrimTick <-chan time.Time}`.

- [ ] **Step 1: Write the failing test**

Create `internal/inspect/recorder_test.go`:

```go
package inspect

import (
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRecorderPersistsSubmittedRecords(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{Flush: 5 * time.Millisecond})
	defer r.Close() //nolint:errcheck

	r.Submit(rec(time.Now(), "/one"))

	waitFor(t, "the record to land in the store", func() bool {
		got, err := s.List(Query{Limit: 10})
		return err == nil && len(got) == 1
	})
}

func TestSubmitDoesNotBlockOnAFullBuffer(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	// Buffer of 1 and a drain that is not running yet: the second submit
	// has nowhere to go and must be dropped rather than block the caller.
	r := &Recorder{ch: make(chan *Record, 1), store: s}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			r.Submit(rec(time.Now(), "/x"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked; capture must never back up onto the request path")
	}
	if r.Dropped() == 0 {
		t.Error("drops must be counted, not silent")
	}
}

func TestSubscriberSeesLiveRecordsWithIDs(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{Flush: 5 * time.Millisecond})
	defer r.Close() //nolint:errcheck

	ch, cancel := r.Subscribe()
	defer cancel()

	r.Submit(rec(time.Now(), "/live"))

	select {
	case got := <-ch:
		if got.Path != "/live" {
			t.Errorf("path = %q", got.Path)
		}
		if got.ID == 0 {
			t.Error("subscribers must see the stored ID, so fan-out happens after the insert")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no record reached the subscriber")
	}
}

func TestCancelledSubscriberStopsReceiving(t *testing.T) {
	s := testStore(t, Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{Flush: 5 * time.Millisecond})
	defer r.Close() //nolint:errcheck

	ch, cancel := r.Subscribe()
	cancel()

	r.Submit(rec(time.Now(), "/after-cancel"))
	waitFor(t, "the record to be stored", func() bool {
		got, err := s.List(Query{Limit: 10})
		return err == nil && len(got) == 1
	})

	select {
	case _, open := <-ch:
		if open {
			t.Error("a cancelled subscriber should not receive records")
		}
	default:
	}
}

func TestTrimTickEnforcesAgeWithoutTraffic(t *testing.T) {
	// Age off while the row goes in, so Insert's own trim leaves it.
	s := testStore(t, Limits{MaxRequests: 1000, MaxBytes: 1 << 30})
	if err := s.Insert([]*Record{rec(time.Now().Add(-3*time.Hour), "/stale")}); err != nil {
		t.Fatal(err)
	}
	// Now turn age on and send no more traffic. Only the ticker can remove
	// the row, which is exactly the case a quiet daemon hits: up for days,
	// nothing arriving, rows aging past the limit with no write to notice.
	s.SetLimits(Limits{MaxRequests: 1000, MaxBytes: 1 << 30, MaxAge: time.Hour})

	tick := make(chan time.Time)
	r := New(s, Options{Flush: 5 * time.Millisecond, TrimTick: tick})
	defer r.Close() //nolint:errcheck

	tick <- time.Now()
	waitFor(t, "the ticker to trim the stale row", func() bool {
		got, err := s.List(Query{Limit: 10})
		return err == nil && len(got) == 0
	})
}

func TestCurrentPointerRoundTrips(t *testing.T) {
	t.Cleanup(func() { SetCurrent(nil) })
	if Current() != nil {
		t.Fatal("Current should start nil")
	}
	s := testStore(t, Limits{MaxRequests: 10, MaxBytes: 1 << 20, MaxAge: time.Hour})
	r := New(s, Options{})
	defer r.Close() //nolint:errcheck

	SetCurrent(r)
	if Current() != r {
		t.Error("SetCurrent did not take")
	}
	SetCurrent(nil)
	if Current() != nil {
		t.Error("SetCurrent(nil) must clear it; the handler relies on nil meaning pass-through")
	}
}
```

Delete the stray empty `func TestSubmitNeverBlocksWhenTheBufferIsFull() {}` line before running. It is listed here only because it is the kind of leftover that compiles and does nothing.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/inspect/ -run "Recorder|Submit|Subscriber|Trim Tick|Current" -v`
Expected: FAIL to compile, `undefined: New`.

- [ ] **Step 3: Write the recorder**

Create `internal/inspect/recorder.go`:

```go
package inspect

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// current is the process-wide recorder the Caddy handler talks to.
//
// A Caddy module cannot be handed a Go pointer through JSON config, but the
// stronger reason for a package-level pointer is lifecycle: every
// `switchboard add` reloads the Caddy config and re-provisions every handler
// instance, while the recorder owns a SQLite handle, an in-flight batch and
// a set of live subscribers. All of that has to outlive a config reload, so
// it cannot be owned by a module Caddy is free to throw away.
//
// nil means "not capturing", and every caller treats it as pass-through.
var current atomic.Pointer[Recorder]

// Current returns the active recorder, or nil when capture is off.
func Current() *Recorder { return current.Load() }

// SetCurrent installs the active recorder. The daemon calls this before it
// loads the proxy config, and clears it on shutdown.
func SetCurrent(r *Recorder) { current.Store(r) }

// Options configure a Recorder. The zero value is usable: it means bodies
// off, default buffer sizes and a real one hour trim ticker.
type Options struct {
	Bodies       bool
	MaxBodyBytes int

	Buffer int           // channel depth, default 1024
	Batch  int           // max records per insert, default 64
	Flush  time.Duration // max wait before writing a partial batch, default 100ms

	// TrimTick replaces the internal one hour ticker. Tests inject a channel
	// so they do not have to wait an hour.
	TrimTick <-chan time.Time

	Log *slog.Logger
}

// Recorder is the bus between the request path and the store.
//
// Submit is called from Caddy's request goroutines and never blocks. One
// drain goroutine owns all the writing and all the fan-out.
type Recorder struct {
	ch    chan *Record
	store *Store
	log   *slog.Logger

	dropped atomic.Int64
	bodies  atomic.Bool
	maxBody atomic.Int64

	mu     sync.Mutex
	subs   map[int64]chan *Record
	nextID int64

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// New starts a recorder writing into store.
func New(store *Store, opts Options) *Recorder {
	if opts.Buffer <= 0 {
		opts.Buffer = 1024
	}
	if opts.Batch <= 0 {
		opts.Batch = 64
	}
	if opts.Flush <= 0 {
		opts.Flush = 100 * time.Millisecond
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}

	r := &Recorder{
		ch:    make(chan *Record, opts.Buffer),
		store: store,
		log:   opts.Log,
		subs:  map[int64]chan *Record{},
		done:  make(chan struct{}),
	}
	r.bodies.Store(opts.Bodies)
	r.maxBody.Store(int64(opts.MaxBodyBytes))

	tick := opts.TrimTick
	var ticker *time.Ticker
	if tick == nil {
		ticker = time.NewTicker(time.Hour)
		tick = ticker.C
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if ticker != nil {
			defer ticker.Stop()
		}
		r.drain(opts.Batch, opts.Flush, tick)
	}()
	return r
}

// Submit hands a record to the recorder. It never blocks: a full buffer
// drops the record and counts it. Losing a row is a nuisance. Adding
// latency to somebody's dev request is not acceptable.
func (r *Recorder) Submit(rec *Record) {
	select {
	case r.ch <- rec:
	default:
		r.dropped.Add(1)
	}
}

// Dropped reports how many records were lost to a full buffer.
func (r *Recorder) Dropped() int64 { return r.dropped.Load() }

// Store returns the underlying buffer, for history queries.
func (r *Recorder) Store() *Store { return r.store }

// Bodies reports whether body capture is on.
func (r *Recorder) Bodies() bool { return r.bodies.Load() }

// MaxBodyBytes is the per-body capture cap.
func (r *Recorder) MaxBodyBytes() int { return int(r.maxBody.Load()) }

// SetOptions updates the settings a config reload can change.
func (r *Recorder) SetOptions(bodies bool, maxBody int) {
	r.bodies.Store(bodies)
	r.maxBody.Store(int64(maxBody))
}

// Subscribe returns a channel of newly stored records and a function to stop
// receiving. The channel is closed when the subscription ends, whether the
// caller cancelled it or the recorder dropped a slow reader.
func (r *Recorder) Subscribe() (<-chan *Record, func()) {
	ch := make(chan *Record, 256)

	r.mu.Lock()
	r.nextID++
	id := r.nextID
	r.subs[id] = ch
	r.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			r.mu.Lock()
			if c, ok := r.subs[id]; ok {
				delete(r.subs, id)
				close(c)
			}
			r.mu.Unlock()
		})
	}
}

// publish fans a batch out to subscribers. A subscriber that cannot keep up
// is dropped rather than slowed down: its channel closes, and because the
// feed is SSE the browser reconnects on its own and backfills from the
// store. Nothing here is allowed to block the drain loop.
func (r *Recorder) publish(recs []*Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, ch := range r.subs {
		for _, rec := range recs {
			select {
			case ch <- rec:
			default:
				delete(r.subs, id)
				close(ch)
				goto next
			}
		}
	next:
	}
}

// drain owns every write. It batches to keep the transaction count down and
// flushes on a timer so a single request does not sit unwritten.
func (r *Recorder) drain(batchSize int, flush time.Duration, tick <-chan time.Time) {
	defer func() {
		// A panic in here would silently stop all capture. Log it and let
		// the daemon keep proxying, which is the only thing that matters.
		if p := recover(); p != nil {
			r.log.Error("inspector recorder stopped after a panic", "panic", p)
		}
	}()

	batch := make([]*Record, 0, batchSize)
	timer := time.NewTimer(flush)
	defer timer.Stop()

	write := func() {
		if len(batch) == 0 {
			return
		}
		if err := r.store.Insert(batch); err != nil {
			r.log.Warn("inspector could not write a batch", "err", err, "records", len(batch))
		} else {
			r.publish(batch)
		}
		batch = batch[:0]
	}

	for {
		select {
		case rec := <-r.ch:
			batch = append(batch, rec)
			if len(batch) >= batchSize {
				write()
			}

		case <-timer.C:
			write()
			timer.Reset(flush)

		case now := <-tick:
			// Trim on a clock, not only on traffic. A daemon that stays up
			// for a week with three quiet days in the middle would otherwise
			// hold rows well past max_age.
			if err := r.store.Trim(now); err != nil {
				r.log.Warn("inspector could not trim", "err", err)
			}

		case <-r.done:
			// Drain what is already queued, then stop.
			for {
				select {
				case rec := <-r.ch:
					batch = append(batch, rec)
					continue
				default:
				}
				break
			}
			write()
			r.mu.Lock()
			for id, ch := range r.subs {
				delete(r.subs, id)
				close(ch)
			}
			r.mu.Unlock()
			return
		}
	}
}

// Close stops the drain goroutine, flushes what is queued and closes the
// store.
func (r *Recorder) Close() error {
	r.closeOnce.Do(func() { close(r.done) })
	r.wg.Wait()
	return r.store.Close()
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/inspect/ -v -race`
Expected: PASS. The `-race` flag matters here: this is the first concurrent code in the package.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/inspect/recorder.go internal/inspect/recorder_test.go
git commit -m "feat: add the inspector recorder

Submit is a non-blocking channel send. A full buffer drops the record
and counts it. Losing a row is a nuisance, adding latency to somebody's
dev request is not acceptable.

One drain goroutine owns all writing and all fan-out, so subscribers see
records only after they have an ID. A subscriber that cannot keep up is
dropped rather than slowed down. The feed is SSE, so the browser
reconnects and backfills on its own.

The recorder lives in a package-level pointer because every config
reload re-provisions Caddy's handler instances and the SQLite handle has
to outlive that."
```

---

### Task 5: The Caddy handler module

**Files:**
- Create: `internal/inspect/handler.go`
- Test: `internal/inspect/handler_test.go`

**Interfaces:**
- Consumes: `Record`, `newCapReader`, `newCapWriter`, `RedactHeaders`, `CopyHeaders`, `Current()` from Tasks 2 and 4.
- Produces: `inspect.Handler` struct, registered with Caddy as `http.handlers.switchboard_inspect`. Task 6 marshals a zero `Handler{}` into the proxy config.

- [ ] **Step 1: Write the failing test**

Create `internal/inspect/handler_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/inspect/ -run TestHandler -v`
Expected: FAIL to compile, `undefined: Handler`.

- [ ] **Step 3: Write the handler**

Create `internal/inspect/handler.go`:

```go
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
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/inspect/ -v -race`
Expected: PASS.

If `TestHandlerRecordsAnUpgradeImmediately` fails because `httptest.ResponseRecorder` does not support `Hijack`, that is fine and expected: the test never hijacks, it only writes a 101 and blocks. If it fails for any other reason, check that `watcher.WriteHeader` calls `onHeader` before delegating.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/inspect/handler.go internal/inspect/handler_test.go
git commit -m "feat: add the switchboard_inspect Caddy handler

Times the request, counts the response, hands a record to the recorder
with a non-blocking send. Never changes what the client sees.

Upgraded connections are recorded when the 101 lands, not when the
handler returns. next blocks until the socket dies, so recording on
return would mean an HMR websocket appears in the inspector an hour
after it opened.

Wraps Caddy's ResponseWriterWrapper so Hijack and Flush keep working.
Getting that wrong would break every HMR connection on the machine."
```

---

### Task 6: Wire the handler into the proxy config

**Files:**
- Modify: `internal/proxy/proxy.go:78-88`
- Test: `internal/proxy/inspect_test.go` (create)

**Interfaces:**
- Consumes: `inspect.Handler` from Task 5, `(*Config).InspectEnabled()` from Task 1.
- Produces: nothing new. `proxy.Generate` output changes shape.

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/inspect_test.go`:

```go
package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/listen"
)

// handlerIDs returns the "handler" value of each handler in each route of
// the https server, in order.
func handlerIDs(t *testing.T, cfg *config.Config, dir string) [][]string {
	t.Helper()
	cc, err := Generate(cfg, dir, &listen.Set{})
	if err != nil {
		t.Fatal(err)
	}
	var apps struct {
		HTTP struct {
			Servers map[string]struct {
				Routes []struct {
					Handle []map[string]json.RawMessage `json:"handle"`
				} `json:"routes"`
			} `json:"servers"`
		} `json:"http"`
	}
	raw, err := json.Marshal(map[string]json.RawMessage{"http": cc.AppsRaw["http"]})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &apps); err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, rt := range apps.HTTP.Servers["https"].Routes {
		var ids []string
		for _, h := range rt.Handle {
			var id string
			if err := json.Unmarshal(h["handler"], &id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		out = append(out, ids)
	}
	return out
}

func TestInspectHandlerRunsBeforeTheProxyOnUserRoutes(t *testing.T) {
	cfg := &config.Config{Suffix: "test", Routes: []config.Route{{Domain: "app.test", Port: 3000}}}
	got := handlerIDs(t, cfg, t.TempDir())

	if len(got) != 2 {
		t.Fatalf("got %d routes, want the user route plus the dashboard catch-all", len(got))
	}
	want := []string{"switchboard_inspect", "reverse_proxy"}
	if strings.Join(got[0], ",") != strings.Join(want, ",") {
		t.Errorf("user route handlers = %v, want %v", got[0], want)
	}
}

func TestInspectHandlerIsNotOnTheDashboardCatchAll(t *testing.T) {
	cfg := &config.Config{Suffix: "test", Routes: []config.Route{{Domain: "app.test", Port: 3000}}}
	got := handlerIDs(t, cfg, t.TempDir())

	last := got[len(got)-1]
	for _, id := range last {
		if id == "switchboard_inspect" {
			t.Fatal("the catch-all is the dashboard; instrumenting it makes the inspector record itself, feed included")
		}
	}
}

func TestInspectHandlerAbsentWhenDisabled(t *testing.T) {
	off := false
	cfg := &config.Config{
		Suffix:  "test",
		Inspect: &config.InspectConfig{Enabled: &off},
		Routes:  []config.Route{{Domain: "app.test", Port: 3000}},
	}
	for _, route := range handlerIDs(t, cfg, t.TempDir()) {
		for _, id := range route {
			if id == "switchboard_inspect" {
				t.Fatal("disabled means not in the config at all, not inserted and idle")
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestInspect -v`
Expected: FAIL, `user route handlers = [reverse_proxy], want [switchboard_inspect reverse_proxy]`.

- [ ] **Step 3: Modify the route builder**

In `internal/proxy/proxy.go`, add the import:

```go
	"github.com/alsey89/switchboard/internal/inspect"
```

Replace the user-route loop at lines 78 to 85 with:

```go
	var routes caddyhttp.RouteList
	for _, r := range cfg.Routes {
		// The inspector goes on user routes only. The dashboard catch-all
		// below is deliberately left alone: instrumenting it would make the
		// inspector record itself, live feed included, and the buffer would
		// fill with its own traffic.
		var handlers []json.RawMessage
		if cfg.InspectEnabled() {
			handlers = append(handlers, inspectHandler())
		}
		handlers = append(handlers, reverseProxyTo(r.UpstreamAddr()))

		routes = append(routes, caddyhttp.Route{
			MatcherSetsRaw: hostMatcher(r.Domain),
			HandlersRaw:    handlers,
			Terminal:       true,
		})
	}
```

And next to `reverseProxyTo`:

```go
func inspectHandler() json.RawMessage {
	return caddyconfig.JSONModuleObject(inspect.Handler{}, "handler", "switchboard_inspect", nil)
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/proxy/ -v`
Expected: PASS, including the existing `websocket_test.go` and `ca_test.go`.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/proxy/proxy.go internal/proxy/inspect_test.go
git commit -m "feat: run the inspector on user routes

Ahead of reverse_proxy on each configured route, and nowhere near the
dashboard catch-all. Instrumenting the catch-all would make the
inspector record itself, feed included.

Disabled means the handler is not in the generated config at all,
rather than inserted and told to do nothing."
```

---

### Task 7: Daemon wiring

**Files:**
- Modify: `internal/daemon/daemon.go`

**Interfaces:**
- Consumes: `inspect.Open`, `inspect.New`, `inspect.SetCurrent`, `(*Recorder).SetOptions`, `(*Store).SetLimits` from Tasks 3 and 4; the config accessors from Task 1.
- Produces: `dash.SetInspector(*inspect.Recorder)`, which Task 8 implements on the dashboard side. Write that call now and stub the method in Task 8, or reorder if you prefer; this plan assumes the stub lands here.

- [ ] **Step 1: Add the inspector stub on the dashboard**

The daemon needs somewhere to hand the recorder. Add to `internal/dashboard/dashboard.go`, on the `Server` struct:

```go
	insp    atomic.Pointer[inspect.Recorder]
```

and the setter, after `SetConfig`:

```go
// SetInspector installs the request recorder the inspector pages read from.
// A nil recorder means the inspector is off and its endpoints answer 503.
func (s *Server) SetInspector(r *inspect.Recorder) { s.insp.Store(r) }
```

Add the import `"github.com/alsey89/switchboard/internal/inspect"`.

- [ ] **Step 2: Add the inspector lifecycle to the daemon**

In `internal/daemon/daemon.go`, add `"github.com/alsey89/switchboard/internal/inspect"` to the imports, then insert this after the dashboard block (currently ending at line 106) and **before** `proxy.Load`:

```go
	// Request inspector. Every failure here is a warning, never a return:
	// the proxy is the product, and a broken inspector must not be the
	// reason it does not start.
	var insp *inspect.Recorder
	defer func() {
		inspect.SetCurrent(nil)
		if insp != nil {
			insp.Close() //nolint:errcheck
		}
	}()
	ensureInspector := func(c *config.Config) {
		if !c.InspectEnabled() {
			return
		}
		if insp != nil {
			insp.SetOptions(c.InspectBodies(), c.InspectMaxBodyBytes())
			insp.Store().SetLimits(inspectLimits(c))
			return
		}
		dbPath := filepath.Join(opts.DataDir, "inspect.db")
		st, err := inspect.Open(dbPath, inspectLimits(c))
		if err != nil {
			log.Warn("inspector disabled: cannot open its database", "path", dbPath, "err", err)
			return
		}
		insp = inspect.New(st, inspect.Options{
			Bodies:       c.InspectBodies(),
			MaxBodyBytes: c.InspectMaxBodyBytes(),
			Log:          log,
		})
		inspect.SetCurrent(insp)
		dash.SetInspector(insp)
		log.Info("inspector up", "db", dbPath, "bodies", c.InspectBodies())
	}
	ensureInspector(cfg)
```

The ordering is not incidental. `inspect.SetCurrent` has to run before `proxy.Load`, because `proxy.Load` is what puts the handler into Caddy's config and the handler reads the pointer on its first request.

Add the helper at the bottom of the file, next to `ignoredPortSettings`:

```go
// inspectLimits translates config settings into the store's limits.
func inspectLimits(c *config.Config) inspect.Limits {
	return inspect.Limits{
		MaxRequests: c.InspectMaxRequests(),
		MaxBytes:    c.InspectMaxBytes(),
		MaxAge:      c.InspectMaxAge(),
	}
}
```

- [ ] **Step 3: Keep the inspector in step with reloads**

In the reload branch, after `dash.SetConfig(next)` (line 178):

```go
			// enabled can flip either way in a reload. ensureInspector opens
			// the store the first time it is turned on, so a user who starts
			// with it off does not have to restart the daemon to use it.
			ensureInspector(next)
```

- [ ] **Step 4: Verify the daemon still starts and stops cleanly**

Run: `go test ./internal/daemon/ -run TestUnsupervisedRunStillDefaults -v`
Expected: PASS.

Run: `go build ./... && go vet ./...`
Expected: success.

- [ ] **Step 5: Manual smoke test**

```bash
make build
./switchboard daemon --help
```
Expected: the help text prints. This only proves the wiring compiles and the binary runs; the real check is Task 11.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/daemon/daemon.go internal/dashboard/dashboard.go
git commit -m "feat: own the inspector from the daemon

The recorder is created before the proxy loads, because the handler
reads the process-wide pointer on its first request.

Every failure is a warning and never a return. A broken inspector must
not be the reason the proxy does not start.

Reloads can flip enabled either way, so the store opens on the first
reload that turns it on. Starting with it off does not mean restarting
the daemon to use it."
```

---

### Task 8: Inspector history API

**Files:**
- Create: `internal/dashboard/inspect.go`
- Test: `internal/dashboard/inspect_test.go`
- Modify: `internal/dashboard/dashboard.go:47-58,101-112`

**Interfaces:**
- Consumes: `inspect.Recorder`, `inspect.Query`, `inspect.Record` from Tasks 3 and 4.
- Produces: the handlers `handleInspectRequests`, `handleInspectRecord`, `handleInspectClear`; the shared `(*Server).guard` wrapper; `(*Server).sameOrigin`.

- [ ] **Step 1: Write the failing test**

Create `internal/dashboard/inspect_test.go`:

```go
package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/inspect"
)

func testServer(t *testing.T) (*Server, *inspect.Recorder) {
	t.Helper()
	st, err := inspect.Open(filepath.Join(t.TempDir(), "inspect.db"),
		inspect.Limits{MaxRequests: 100, MaxBytes: 1 << 20, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r := inspect.New(st, inspect.Options{Flush: 5 * time.Millisecond})
	t.Cleanup(func() { r.Close() }) //nolint:errcheck

	s := New(&config.Config{Suffix: "test"}, "test")
	s.SetInspector(r)
	return s, r
}

func seed(t *testing.T, r *inspect.Recorder, path string) *inspect.Record {
	t.Helper()
	rec := &inspect.Record{
		StartedAt: time.Now(), Duration: time.Millisecond,
		Domain: "app.test", Method: "GET", Path: path, Status: 200,
		Proto: "HTTP/1.1", RespBody: []byte("body bytes"),
		ReqHeaders: map[string][]string{"Accept": {"*/*"}},
	}
	if err := r.Store().Insert([]*inspect.Record{rec}); err != nil {
		t.Fatal(err)
	}
	return rec
}

func do(s *Server, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "switchboard.test"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.mux().ServeHTTP(w, req)
	return w
}

func TestInspectRequestsListsNewestFirst(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/one")
	seed(t, r, "/two")

	w := do(s, "GET", "/api/inspect/requests", nil)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var out struct {
		Requests []struct {
			ID   int64  `json:"id"`
			Path string `json:"path"`
		} `json:"requests"`
		Dropped int64 `json:"dropped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Requests) != 2 {
		t.Fatalf("got %d requests", len(out.Requests))
	}
	if out.Requests[0].Path != "/two" {
		t.Errorf("first is %q, want the newest", out.Requests[0].Path)
	}
}

func TestInspectRequestsFiltersByQuery(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/users")
	seed(t, r, "/health")

	w := do(s, "GET", "/api/inspect/requests?q=user", nil)
	var out struct {
		Requests []struct {
			Path string `json:"path"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Requests) != 1 || out.Requests[0].Path != "/users" {
		t.Fatalf("q=user returned %v", out.Requests)
	}
}

func TestInspectRecordReturnsBodies(t *testing.T) {
	s, r := testServer(t)
	rec := seed(t, r, "/x")

	w := do(s, "GET", "/api/inspect/requests/"+itoa(rec.ID), nil)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out struct {
		RespBody string `json:"resp_body"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.RespBody != "body bytes" {
		t.Errorf("resp_body = %q", out.RespBody)
	}
}

func TestInspectRecordUnknownIDIs404(t *testing.T) {
	s, _ := testServer(t)
	if w := do(s, "GET", "/api/inspect/requests/9999", nil); w.Code != 404 {
		t.Fatalf("status %d, want 404", w.Code)
	}
}

func TestClearRequiresPostAndOrigin(t *testing.T) {
	cases := []struct {
		name   string
		method string
		origin map[string]string
		want   int
	}{
		{"get is refused", "GET", map[string]string{"Origin": "https://switchboard.test"}, http.StatusMethodNotAllowed},
		{"no origin is refused", "POST", nil, http.StatusForbidden},
		{"foreign origin is refused", "POST", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"same origin is allowed", "POST", map[string]string{"Origin": "https://switchboard.test"}, http.StatusNoContent},
		{"loopback origin is allowed", "POST", map[string]string{"Origin": "http://127.0.0.1:8484"}, http.StatusNoContent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, r := testServer(t)
			seed(t, r, "/x")
			if w := do(s, c.method, "/api/inspect/clear", c.origin); w.Code != c.want {
				t.Fatalf("status %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestClearEmptiesTheBuffer(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/x")

	if w := do(s, "POST", "/api/inspect/clear",
		map[string]string{"Origin": "https://switchboard.test"}); w.Code != http.StatusNoContent {
		t.Fatalf("status %d", w.Code)
	}
	got, err := r.Store().List(inspect.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("%d rows survived", len(got))
	}
}

func TestInspectEndpointsRefuseForeignHosts(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/x")

	req := httptest.NewRequest("GET", "/api/inspect/requests", nil)
	req.Host = "evil.example"
	w := httptest.NewRecorder()
	s.mux().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for a foreign Host", w.Code)
	}
}

func TestInspectEndpointsAre503WithNoRecorder(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/inspect/requests", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
```

Add `"strconv"` to that file's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dashboard/ -run TestInspect -v`
Expected: FAIL to compile, `s.mux undefined`.

- [ ] **Step 3: Extract the mux and the host guard**

In `internal/dashboard/dashboard.go`, replace the body of `Start` from `mux := http.NewServeMux()` through the `mux.HandleFunc` lines with a call to a new method, so tests can exercise routing without binding a port:

```go
// Start begins serving on bind (e.g. "127.0.0.1:8484").
func (s *Server) Start(bind string) error {
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	s.httpSrv = &http.Server{Handler: s.mux(), ReadHeaderTimeout: 10 * time.Second}
	go s.httpSrv.Serve(ln) //nolint:errcheck // exits on Shutdown
	return nil
}

// mux builds the routing table. Split out from Start so tests can drive the
// real routes without binding a port.
func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/routes", s.handleAPIRoutes)
	mux.HandleFunc("/api/inspect/requests", s.guard(s.handleInspectRequests))
	mux.HandleFunc("/api/inspect/requests/", s.guard(s.handleInspectRecord))
	mux.HandleFunc("/api/inspect/clear", s.guard(s.handleInspectClear))
	mux.HandleFunc("/api/inspect/stream", s.guard(s.handleInspectStream))
	mux.HandleFunc("/inspect", s.guard(s.handleInspectPage))
	mux.HandleFunc("/", s.handleRoot)
	return mux
}

// guard rejects requests whose Host is neither the dashboard domain nor a
// direct loopback address.
//
// handleRoot answers a foreign Host with the friendly "no route" page,
// because a browser landing on an unrouted *.test name deserves an
// explanation. An API path does not: there is no user reading it, so it gets
// a flat 404 and no hint that anything is here.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(hostOnly(r.Host))
		if host != s.cfg.Load().DashboardDomain() && !isLoopbackHost(host) {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}
```

- [ ] **Step 4: Write the endpoints**

Create `internal/dashboard/inspect.go`:

```go
package dashboard

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/alsey89/switchboard/internal/inspect"
)

// recordJSON is the wire shape of a captured request. Bodies are strings
// because that is what a browser can show; captured bytes that are not valid
// UTF-8 are replaced rather than dropped, so a binary body still reads as
// "something was here" instead of vanishing.
type recordJSON struct {
	ID          int64               `json:"id"`
	StartedAt   string              `json:"started_at"`
	DurationMS  float64             `json:"duration_ms"`
	Domain      string              `json:"domain"`
	Method      string              `json:"method"`
	Path        string              `json:"path"`
	Status      int                 `json:"status"`
	Proto       string              `json:"proto"`
	Upgraded    bool                `json:"upgraded"`
	ReqBytes    int64               `json:"req_bytes"`
	RespBytes   int64               `json:"resp_bytes"`
	Error       string              `json:"error,omitempty"`
	ReqHeaders  map[string][]string `json:"req_headers,omitempty"`
	RespHeaders map[string][]string `json:"resp_headers,omitempty"`
	ReqBody     string              `json:"req_body,omitempty"`
	RespBody    string              `json:"resp_body,omitempty"`
}

func toJSON(r *inspect.Record) recordJSON {
	return recordJSON{
		ID:          r.ID,
		StartedAt:   r.StartedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		DurationMS:  float64(r.Duration.Microseconds()) / 1000,
		Domain:      r.Domain,
		Method:      r.Method,
		Path:        r.Path,
		Status:      r.Status,
		Proto:       r.Proto,
		Upgraded:    r.Upgraded,
		ReqBytes:    r.ReqBytes,
		RespBytes:   r.RespBytes,
		Error:       r.Error,
		ReqHeaders:  r.ReqHeaders,
		RespHeaders: r.RespHeaders,
		ReqBody:     string(r.ReqBody),
		RespBody:    string(r.RespBody),
	}
}

// recorder returns the active recorder, or writes a 503 and reports false.
func (s *Server) recorder(w http.ResponseWriter) (*inspect.Recorder, bool) {
	rec := s.insp.Load()
	if rec == nil {
		http.Error(w, "the inspector is off", http.StatusServiceUnavailable)
		return nil, false
	}
	return rec, true
}

func (s *Server) handleInspectRequests(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.recorder(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)

	rows, err := rec.Store().List(inspect.Query{
		Domain: q.Get("domain"),
		Method: q.Get("method"),
		Status: q.Get("status"),
		Q:      q.Get("q"),
		Before: before,
		Limit:  limit,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out := struct {
		Requests []recordJSON `json:"requests"`
		Dropped  int64        `json:"dropped"`
	}{Requests: []recordJSON{}, Dropped: rec.Dropped()}
	for _, row := range rows {
		out.Requests = append(out.Requests, toJSON(row))
	}
	writeJSON(w, out)
}

func (s *Server) handleInspectRecord(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.recorder(w)
	if !ok {
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/inspect/requests/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	row, err := rec.Store().Get(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, toJSON(row))
}

// handleInspectClear empties the buffer.
//
// This is the dashboard's only state-changing endpoint, so it states its
// rule rather than inheriting one. POST only, and Origin must be present and
// match. An absent Origin is refused rather than trusted: browsers always
// send it on fetch, so refusing absence closes the simple-request CSRF hole
// that loopback alone does not.
//
// What it destroys is captured traffic. No route, no trust setting, no
// config. When route mutation lands it will need this same check, harder.
func (s *Server) handleInspectClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if !s.sameOrigin(r) {
		http.Error(w, "bad origin", http.StatusForbidden)
		return
	}
	rec, ok := s.recorder(w)
	if !ok {
		return
	}
	if err := rec.Store().Clear(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sameOrigin reports whether the request carries an Origin naming this
// dashboard. A missing Origin is not same-origin.
func (s *Server) sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	host := strings.ToLower(hostOnly(u.Host))
	return host == s.cfg.Load().DashboardDomain() || isLoopbackHost(host)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
```

- [ ] **Step 5: Add a temporary stream and page stub**

`mux()` references two handlers that arrive in Tasks 9 and 10. Add them now so the package compiles:

```go
func (s *Server) handleInspectStream(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleInspectPage(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
```

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/dashboard/ -v`
Expected: PASS, including the existing dashboard tests.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/dashboard/inspect.go internal/dashboard/inspect_test.go internal/dashboard/dashboard.go
git commit -m "feat: add the inspector history API

List, detail and clear, all behind the same Host guard as the rest of
the dashboard. API paths answer a foreign Host with a flat 404 rather
than the friendly no-route page: there is no user reading it.

Clear is the dashboard's first state-changing endpoint, so it states its
rule. POST only, and Origin must be present and match. An absent Origin
is refused rather than trusted, which closes the simple-request CSRF
hole that loopback alone does not."
```

---

### Task 9: The live SSE feed

**Files:**
- Modify: `internal/dashboard/inspect.go`
- Test: `internal/dashboard/inspect_test.go`

**Interfaces:**
- Consumes: `(*Recorder).Subscribe` from Task 4.
- Produces: `handleInspectStream`, replacing the stub from Task 8.

- [ ] **Step 1: Write the failing test**

Append to `internal/dashboard/inspect_test.go`:

```go
func TestStreamBackfillsThenPushes(t *testing.T) {
	s, r := testServer(t)
	seed(t, r, "/backfilled")

	srv := httptest.NewServer(s.mux())
	defer srv.Close()

	req, err := http.NewRequest("GET", srv.URL+"/api/inspect/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "switchboard.test"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}

	events := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") {
				events <- strings.TrimPrefix(line, "data: ")
			}
		}
	}()

	// The backfill must arrive without anyone making a new request.
	select {
	case got := <-events:
		if !strings.Contains(got, "/backfilled") {
			t.Errorf("first event = %s, want the backfilled row", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no backfill")
	}

	// A record submitted after the subscription must be pushed.
	r.Submit(&inspect.Record{
		StartedAt: time.Now(), Domain: "app.test", Method: "GET",
		Path: "/pushed", Status: 200, Proto: "HTTP/1.1",
	})
	select {
	case got := <-events:
		if !strings.Contains(got, "/pushed") {
			t.Errorf("second event = %s, want the pushed row", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no live event")
	}
}

func TestStreamIs503WithNoRecorder(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test")
	if w := do(s, "GET", "/api/inspect/stream", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}
```

Add `"bufio"` and `"strings"` to the test file's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dashboard/ -run TestStream -v`
Expected: FAIL, `Content-Type = "text/plain; charset=utf-8"` from the 501 stub.

- [ ] **Step 3: Replace the stub**

In `internal/dashboard/inspect.go`, delete the `handleInspectStream` stub and add:

```go
// handleInspectStream is the live feed.
//
// Server-sent events, not a websocket. The feed only ever goes one way, so a
// bidirectional protocol would buy nothing and cost a dependency. SSE also
// reconnects on its own, which is what makes dropping a slow subscriber a
// safe thing to do: the browser comes back and backfills.
func (s *Server) handleInspectStream(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.recorder(w)
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Subscribe before backfilling. The other order has a hole: a request
	// arriving between the query and the subscription is in neither.
	ch, cancel := rec.Subscribe()
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	backfill, err := rec.Store().List(inspect.Query{Limit: 200})
	if err == nil {
		// List is newest first; replay oldest first so the client can append.
		for i := len(backfill) - 1; i >= 0; i-- {
			sendEvent(w, toJSON(backfill[i]))
		}
		flusher.Flush()
	}

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case rec, open := <-ch:
			if !open {
				// Dropped for falling behind. Closing here is the whole
				// point: EventSource reconnects and backfills.
				return
			}
			sendEvent(w, toJSON(rec))
			flusher.Flush()

		case <-ping.C:
			io.WriteString(w, ": ping\n\n") //nolint:errcheck
			flusher.Flush()
		}
	}
}

func sendEvent(w http.ResponseWriter, v recordJSON) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	io.WriteString(w, "data: ") //nolint:errcheck
	w.Write(b)                  //nolint:errcheck
	io.WriteString(w, "\n\n")   //nolint:errcheck
}
```

Add `"io"` and `"time"` to the file's imports.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/dashboard/ -v -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/dashboard/inspect.go internal/dashboard/inspect_test.go
git commit -m "feat: stream captured requests over SSE

One way only, so a websocket would buy nothing and cost a dependency.

Subscribe happens before the backfill query. The other order drops any
request that arrives between the two.

A subscriber that falls behind gets its channel closed. EventSource
reconnects on its own and backfills, so the worst case is a gap, not a
stalled recorder."
```

---

### Task 10: The inspector page

**Files:**
- Create: `internal/dashboard/templates/inspect.html`
- Modify: `internal/dashboard/inspect.go`, `internal/dashboard/templates/dashboard.html`

**Interfaces:**
- Consumes: the endpoints from Tasks 8 and 9.
- Produces: `handleInspectPage`, replacing the stub.

- [ ] **Step 1: Write the failing test**

Append to `internal/dashboard/inspect_test.go`:

```go
func TestInspectPageRenders(t *testing.T) {
	s, _ := testServer(t)
	w := do(s, "GET", "/inspect", nil)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"EventSource", "/api/inspect/stream", "id=\"list\""} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dashboard/ -run TestInspectPageRenders -v`
Expected: FAIL, `status 501`.

- [ ] **Step 3: Write the template**

Create `internal/dashboard/templates/inspect.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Switchboard inspector</title>
<style>
  :root { color-scheme: light dark;
    --fg: #1a1a1a; --bg: #ffffff; --muted: #6b7280; --line: #e5e7eb;
    --ok: #16a34a; --bad: #dc2626; --warn: #d97706; --accent: #4f46e5;
    --panel: #fafafa; }
  @media (prefers-color-scheme: dark) { :root {
    --fg: #e5e7eb; --bg: #111318; --muted: #9ca3af; --line: #2a2e37;
    --panel: #171a21; } }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); height: 100vh;
    display: flex; flex-direction: column;
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, sans-serif; }
  header { padding: .8rem 1rem; border-bottom: 1px solid var(--line);
    display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; }
  header h1 { font-size: 1rem; margin: 0 .6rem 0 0; font-weight: 600; }
  header h1 a { color: var(--fg); text-decoration: none; }
  input, select, button { font: inherit; color: var(--fg); background: var(--bg);
    border: 1px solid var(--line); border-radius: 6px; padding: .3rem .5rem; }
  button { cursor: pointer; }
  button.on { border-color: var(--accent); color: var(--accent); }
  .spacer { flex: 1; }
  .drops { color: var(--warn); font-size: .8rem; }
  main { flex: 1; display: grid; grid-template-columns: minmax(280px, 40%) 1fr;
    min-height: 0; }
  #list { overflow-y: auto; border-right: 1px solid var(--line); }
  #detail { overflow-y: auto; padding: 1rem; background: var(--panel); }
  table { width: 100%; border-collapse: collapse; }
  tr.row { cursor: pointer; border-bottom: 1px solid var(--line); }
  tr.row:hover { background: var(--panel); }
  tr.row.sel { background: color-mix(in srgb, var(--accent) 12%, transparent); }
  td { padding: .35rem .5rem; white-space: nowrap; overflow: hidden;
    text-overflow: ellipsis; }
  td.path { max-width: 1px; width: 100%; font-family: ui-monospace, monospace;
    font-size: .85em; }
  .m { color: var(--muted); font-size: .8rem; }
  .s2 { color: var(--ok); } .s3 { color: var(--accent); }
  .s4, .s5 { color: var(--bad); }
  h2 { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em;
    color: var(--muted); margin: 1.2rem 0 .4rem; font-weight: 500; }
  h2:first-child { margin-top: 0; }
  pre { background: var(--bg); border: 1px solid var(--line); border-radius: 6px;
    padding: .6rem; overflow-x: auto; font-size: .8rem; margin: 0; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .1rem .8rem;
    margin: 0; font-size: .85rem; }
  dt { color: var(--muted); }
  dd { margin: 0; font-family: ui-monospace, monospace; word-break: break-all; }
  .empty { color: var(--muted); padding: 2rem 1rem; }
  #more { margin: .8rem; width: calc(100% - 1.6rem); }
  @media (max-width: 700px) { main { grid-template-columns: 1fr; }
    #list { border-right: 0; border-bottom: 1px solid var(--line); max-height: 45vh; } }
</style>
</head>
<body>
<header>
  <h1><a href="/">Switchboard</a> inspector</h1>
  <input id="q" type="search" placeholder="filter path" size="14">
  <input id="domain" type="search" placeholder="domain" size="12">
  <select id="method">
    <option value="">any method</option>
    <option>GET</option><option>POST</option><option>PUT</option>
    <option>PATCH</option><option>DELETE</option>
  </select>
  <select id="status">
    <option value="">any status</option>
    <option value="2xx">2xx</option><option value="3xx">3xx</option>
    <option value="4xx">4xx</option><option value="5xx">5xx</option>
  </select>
  <button id="pause" class="on">live</button>
  <span class="spacer"></span>
  <span id="drops" class="drops"></span>
  <button id="clear">clear</button>
</header>
<main>
  <div id="list"><p class="empty">Waiting for traffic.</p></div>
  <div id="detail"><p class="empty">Pick a request.</p></div>
</main>
<script>
(function () {
  const $ = (id) => document.getElementById(id);
  const list = $("list"), detail = $("detail");
  const filters = { q: $("q"), domain: $("domain"), method: $("method"), status: $("status") };

  let rows = [];        // newest first
  let live = true;
  let selected = null;
  let source = null;
  const MAX_DOM = 500;

  const statusClass = (s) => "s" + String(s).charAt(0);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

  function matches(r) {
    const f = filters;
    if (f.domain.value && r.domain !== f.domain.value) return false;
    if (f.method.value && r.method !== f.method.value) return false;
    if (f.q.value && !r.path.toLowerCase().includes(f.q.value.toLowerCase())) return false;
    const s = f.status.value;
    if (s && String(r.status).charAt(0) !== s.charAt(0)) return false;
    return true;
  }

  function render() {
    const shown = rows.filter(matches).slice(0, MAX_DOM);
    if (!shown.length) {
      list.innerHTML = '<p class="empty">Nothing matches yet.</p>';
      return;
    }
    const body = shown.map((r) => `
      <tr class="row ${r.id === selected ? "sel" : ""}" data-id="${r.id}">
        <td class="m">${esc(r.started_at.slice(11, 23))}</td>
        <td class="m">${esc(r.method)}</td>
        <td class="path">${esc(r.path)}</td>
        <td class="${statusClass(r.status)}">${r.upgraded ? "101 ws" : r.status}</td>
        <td class="m">${r.duration_ms.toFixed(1)}ms</td>
      </tr>`).join("");
    list.innerHTML = "<table>" + body + "</table>";
  }

  function headerList(h) {
    if (!h) return '<p class="m">none</p>';
    const names = Object.keys(h).sort();
    if (!names.length) return '<p class="m">none</p>';
    return "<dl>" + names.map((k) =>
      `<dt>${esc(k)}</dt><dd>${esc(h[k].join(", "))}</dd>`).join("") + "</dl>";
  }

  async function show(id) {
    selected = id;
    render();
    const resp = await fetch("/api/inspect/requests/" + id);
    if (!resp.ok) { detail.innerHTML = '<p class="empty">Gone. The buffer may have trimmed it.</p>'; return; }
    const r = await resp.json();
    detail.innerHTML = `
      <h2>request</h2>
      <dl>
        <dt>when</dt><dd>${esc(r.started_at)}</dd>
        <dt>host</dt><dd>${esc(r.domain)}</dd>
        <dt>method</dt><dd>${esc(r.method)}</dd>
        <dt>path</dt><dd>${esc(r.path)}</dd>
        <dt>proto</dt><dd>${esc(r.proto)}${r.upgraded ? " (upgraded)" : ""}</dd>
        <dt>status</dt><dd>${r.status}</dd>
        <dt>took</dt><dd>${r.duration_ms.toFixed(1)} ms</dd>
        <dt>sent</dt><dd>${r.req_bytes} bytes</dd>
        <dt>received</dt><dd>${r.resp_bytes} bytes</dd>
        ${r.error ? `<dt>error</dt><dd>${esc(r.error)}</dd>` : ""}
      </dl>
      <h2>request headers</h2>${headerList(r.req_headers)}
      ${r.req_body ? `<h2>request body</h2><pre>${esc(r.req_body)}</pre>` : ""}
      <h2>response headers</h2>${headerList(r.resp_headers)}
      ${r.resp_body ? `<h2>response body</h2><pre>${esc(r.resp_body)}</pre>` : ""}`;
  }

  list.addEventListener("click", (e) => {
    const tr = e.target.closest("tr.row");
    if (tr) show(Number(tr.dataset.id));
  });

  Object.values(filters).forEach((el) => el.addEventListener("input", render));

  $("pause").addEventListener("click", () => {
    live = !live;
    $("pause").textContent = live ? "live" : "paused";
    $("pause").classList.toggle("on", live);
    if (live) connect(); else if (source) { source.close(); source = null; }
  });

  $("clear").addEventListener("click", async () => {
    const resp = await fetch("/api/inspect/clear", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    if (resp.ok) { rows = []; selected = null; detail.innerHTML = '<p class="empty">Pick a request.</p>'; render(); }
  });

  function add(r) {
    rows.unshift(r);
    if (rows.length > 2000) rows.length = 2000;
  }

  function connect() {
    if (source) source.close();
    // EventSource reconnects on its own, including after the server drops a
    // subscriber for falling behind. Each connection replays the last 200,
    // so a reconnect fills the gap.
    source = new EventSource("/api/inspect/stream");
    source.onmessage = (e) => {
      const r = JSON.parse(e.data);
      if (rows.some((x) => x.id === r.id)) return;
      add(r);
      render();
    };
  }

  async function drops() {
    const resp = await fetch("/api/inspect/requests?limit=1");
    if (!resp.ok) return;
    const { dropped } = await resp.json();
    $("drops").textContent = dropped ? dropped + " dropped" : "";
  }

  connect();
  drops();
  setInterval(drops, 10000);
})();
</script>
</body>
</html>
```

- [ ] **Step 4: Replace the page stub**

In `internal/dashboard/inspect.go`, delete the `handleInspectPage` stub and add:

```go
func (s *Server) handleInspectPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.ExecuteTemplate(w, "inspect.html", nil) //nolint:errcheck
}
```

The `//go:embed templates/*.html` in `dashboard.go` already picks the new file up.

- [ ] **Step 5: Link it from the route table**

In `internal/dashboard/templates/dashboard.html`, change the footer line to:

```html
  <footer>switchboard {{.Version}} · <a href="/inspect">inspector</a> · <a href="/api/routes">api</a></footer>
```

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/dashboard/ -v`
Expected: PASS.

- [ ] **Step 7: Look at it**

```bash
make build
./switchboard daemon &
open https://switchboard.test/inspect
```
Then load one of your routed domains and confirm rows appear live, filters narrow the list, clicking shows detail, pause stops the feed and clear empties it. Kill the daemon when done.

If you are not set up locally, `go test ./internal/daemon/ -run TestEndToEnd` in Task 11 covers the same ground without a browser.

- [ ] **Step 8: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/dashboard/inspect.go internal/dashboard/templates/
git commit -m "feat: add the inspector page

Split pane, live tail with pause, filters by domain, method and status,
path search, and clear. Vanilla JS and the existing CSS variables, so it
inherits dark mode and adds no build step.

At most 500 rows in the DOM. Filtering is client side over the last
2000, which is what the live feed can hold anyway."
```

---

### Task 11: End-to-end capture test

**Files:**
- Modify: `internal/daemon/daemon_test.go`

**Interfaces:**
- Consumes: everything.
- Produces: nothing.

- [ ] **Step 1: Record the data dir on testEnv**

In `internal/daemon/daemon_test.go`, add a field to `testEnv` (line 37):

```go
type testEnv struct {
	cfgPath string
	dataDir string
	cfg     *config.Config
	rootCAs *x509.CertPool
	cancel  context.CancelFunc
	done    chan error
}
```

and set it in `startEnv` where `dataDir` is already computed:

```go
	env.dataDir = dataDir
```

Place that line next to the other `env` field assignments in `startEnv`.

- [ ] **Step 2: Write the failing test**

Add to `internal/daemon/daemon_test.go`:

```go
func TestInspectorCapturesProxiedTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		io.WriteString(w, "captured me") //nolint:errcheck
	}))
	defer upstream.Close()

	env := startEnv(t, []config.Route{{
		Domain:   "app.test",
		Upstream: strings.TrimPrefix(upstream.URL, "http://"),
	}})
	client := env.client()

	resp, err := client.Get(fmt.Sprintf("https://app.test:%d/inspected?x=1", tHTTPSPort))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck

	// The dashboard's own loopback port, the same door the browser uses when
	// TLS or DNS is broken.
	api := fmt.Sprintf("http://127.0.0.1:%d/api/inspect/requests", tDashPort)

	type row struct {
		Domain string `json:"domain"`
		Method string `json:"method"`
		Path   string `json:"path"`
		Status int    `json:"status"`
	}
	var got []row
	waitFor(t, func() bool {
		r, err := http.Get(api) //nolint:noctx
		if err != nil {
			return false
		}
		defer r.Body.Close() //nolint:errcheck
		var out struct {
			Requests []row `json:"requests"`
		}
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			return false
		}
		got = out.Requests
		return len(out.Requests) > 0
	}, 15*time.Second, "the proxied request to be captured")

	if got[0].Path != "/inspected?x=1" {
		t.Errorf("path = %q, want the full request URI", got[0].Path)
	}
	if got[0].Status != 201 {
		t.Errorf("status = %d, want 201 from the upstream", got[0].Status)
	}
	if got[0].Domain != "app.test" {
		t.Errorf("domain = %q", got[0].Domain)
	}

	t.Run("dashboard traffic is not captured", func(t *testing.T) {
		before := len(got)

		// Load the dashboard itself several times through the proxy.
		for i := 0; i < 3; i++ {
			r, err := client.Get(fmt.Sprintf("https://%s:%d/", env.cfg.DashboardDomain(), tHTTPSPort))
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close() //nolint:errcheck
		}
		time.Sleep(500 * time.Millisecond)

		r, err := http.Get(api) //nolint:noctx
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close() //nolint:errcheck
		var out struct {
			Requests []row `json:"requests"`
		}
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		if len(out.Requests) != before {
			t.Fatalf("row count went %d -> %d; the inspector is recording itself",
				before, len(out.Requests))
		}
	})

	t.Run("the database lands in the data dir", func(t *testing.T) {
		if _, err := os.Stat(filepath.Join(env.dataDir, "inspect.db")); err != nil {
			t.Errorf("inspect.db: %v", err)
		}
	})
}
```

Add `"io"` to the test file's imports if it is not already there.

- [ ] **Step 3: Run it**

Run: `go test ./internal/daemon/ -run TestInspectorCapturesProxiedTraffic -v`
Expected: PASS.

If it fails on the very first run with a TLS error, that is issue #25 territory. Run it alone in a fresh process before investigating.

- [ ] **Step 4: Run the whole suite**

Run: `go test ./... -timeout 300s`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/daemon/daemon_test.go
git commit -m "test: prove the inspector captures real proxied traffic

Boots the daemon, makes a request through the proxy with real TLS, and
reads it back off the dashboard's loopback API.

Also asserts the row count does not move when the dashboard itself is
loaded. That is the regression that would otherwise be invisible until
somebody opened the inspector and found it full of itself."
```

---

### Task 12: Documentation

**Files:**
- Modify: `DESIGN.md:227,357`, `README.md`, `docs/ARCHITECTURE.md`, `CHANGELOG.md`

- [ ] **Step 1: Correct DESIGN.md**

Line 227 currently reads:

```
| (v0.2) live feed | WebSocket (`nhooyr.io/websocket`) from the dashboard handler | |
```

Replace with:

```
| (v0.3) live feed | Server-sent events from the dashboard handler | The feed only goes one way, so a websocket would add a dependency and buy nothing. SSE also reconnects on its own, which is what makes dropping a slow subscriber safe |
```

In the §6 roadmap table, line 357, strike route add and remove from the v0.3 row. Replace "Dashboard matured (inspector split-pane, route add/remove)." with:

```
Dashboard matured (inspector split-pane). Route add/remove moved out: it turns the dashboard into a write surface and needs its own origin and auth design.
```

- [ ] **Step 2: Add the README section**

In `README.md`, after the dashboard bullet near line 98, add:

```markdown
### Inspector

Every request through a route is recorded and shown live at
`https://switchboard.test/inspect`. Method, URL, status, timing and headers.
No setup. It is on as soon as you upgrade.

Bodies are not recorded unless you ask for them:

```toml
[inspect]
bodies = true
```

Two things worth knowing before you turn that on. Bodies are written to
`inspect.db` in the data directory. And turning bodies on also stops header
redaction, so `Authorization` and `Cookie` values are stored as sent.

With bodies off, the values of `Authorization`, `Proxy-Authorization`,
`Cookie`, `Set-Cookie`, `X-Api-Key` and `X-Auth-Token` are replaced before
anything is written. That list is fixed, so it reduces what ends up on disk
but does not promise to catch a custom token header of your own.

The buffer is bounded three ways and trims itself: 5,000 requests, 64 MiB,
and 7 days. All of it is configurable.

```toml
[inspect]
enabled        = true
bodies         = false
max_requests   = 5000
max_bytes      = 67108864
max_body_bytes = 65536
max_age        = "168h"
```
```

Also update the roadmap line near 164 to strike the inspector from what is upcoming.

- [ ] **Step 3: Update ARCHITECTURE.md**

Add the inspector to the component diagram section and add a new bullet to §7 ("What this does not claim"):

```markdown
- **The inspector records your own traffic to disk.** Metadata for every
  proxied request goes into `inspect.db` in the data directory, bounded by
  count, size and age. Header redaction is a fixed deny-list, so it reduces
  exposure rather than preventing it. Bodies are off unless you turn them
  on, and turning them on also turns redaction off.
```

Amend the existing loopback bullet to say the boundary now also protects captured traffic:

```markdown
- **Loopback is the security boundary for the dashboard.** It is unauthenticated
  and bound to `127.0.0.1`. Anything already running on your machine as you can
  reach it, and that now includes everything the inspector has captured. The
  one endpoint that changes state, clearing the buffer, additionally requires
  a matching `Origin`.
```

- [ ] **Step 4: Write the changelog entry**

At the top of `CHANGELOG.md`, replace the "Nothing yet." under Unreleased with:

```markdown
### Added

- **Request inspector.** Every request through a route now shows up live at
  `https://switchboard.test/inspect`. Method, URL, status, timing, headers.
  Filter by domain, method or status, search the path, click a row for the
  detail. Nothing to turn on.

  Bodies are not recorded by default. Set `bodies = true` under `[inspect]`
  if you want them. That also stops header redaction, so `Authorization` and
  `Cookie` get stored as sent.

  With bodies off, the values of the usual credential headers are replaced
  before anything hits disk. The list is fixed, so it cuts down what is
  stored without promising to catch a token header you invented.

  History lives in `inspect.db` in the data directory and trims itself at
  5,000 requests, 64 MiB, or 7 days, whichever comes first. All configurable.
```

- [ ] **Step 5: Check the notices file is current**

Run: `./scripts/gen-notices.sh /tmp/notices.check && diff -q /tmp/notices.check THIRD_PARTY_NOTICES`
Expected: no output. If it differs, run `make notices` and include the result.

- [ ] **Step 6: Commit**

```bash
git add DESIGN.md README.md docs/ARCHITECTURE.md CHANGELOG.md
git commit -m "docs: document the request inspector

Also corrects two things in DESIGN.md. The live feed is SSE, not a
websocket, because it only goes one way. And route add/remove is out of
v0.3: it makes the dashboard a write surface and needs its own design."
```

- [ ] **Step 7: Final check before the PR**

```bash
gofmt -l . && test -z "$(gofmt -l .)"
go vet ./...
CGO_ENABLED=0 go build ./...
go test ./... -timeout 300s
```
All four must pass. The third is the one that catches a CGo dependency sneaking in, which would break the release build and not the test run.

---

## Self-Review

**Spec coverage.** Every section maps to a task: packages and ownership (2 to 5), handler placement (6), capture path and the two emit points (5), bodies (2 and 5), redaction (2), schema (3), trim including open and tick (3 and 4), feed transport (9), config (1), HTTP surface (8 and 9), the clear endpoint's rule (8), dashboard UI (10), failure isolation (7), testing (every task plus 11), dependencies (3), docs to update (12).

**Two deliberate deviations from the spec, both narrower than they look:**

1. The spec says to wrap the writer in `caddyhttp.NewResponseRecorder`. Task 5 uses `caddyhttp.ResponseWriterWrapper` instead. The recorder has no hook at `WriteHeader`, and the 101 case needs one. The wrapper still supplies the `Hijack`, `Flush` and `Unwrap` behavior that was the reason to use Caddy's own type rather than hand-rolling one.

2. The spec's HTTP surface table implies `handleRoot` grew new paths. Task 8 extracts a `mux()` method and a `guard` wrapper instead, because the host check needed to apply to five handlers and copying it five times is how one of them ends up wrong.

**Known gap, deliberate.** Flipping `enabled` from true to false at reload stops capture, because `proxy.Generate` drops the handler, but it leaves `inspect.db` on disk and the recorder open. Deleting a user's captured history because they toggled a setting would be worse. `switchboard` has no command that removes the file; the user deletes it or uses clear.
