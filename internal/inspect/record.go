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
