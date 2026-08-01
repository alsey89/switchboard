# Switchboard v0.3 — Request Inspector Design

**Status:** approved design, ready for an implementation plan.
**Date:** 2026-08-02.
**Roadmap slot:** v0.3 in [DESIGN.md](../../../DESIGN.md) §6.

## Goal

Show the developer what just went through the proxy. Method, URL, status,
timing, and headers for every proxied request, live in the dashboard, with
history that survives a daemon restart.

## Scope

In scope:

- A Caddy handler module that captures each proxied request.
- A SQLite ring buffer, bounded by row count and by total bytes.
- A live feed to the dashboard.
- A split-pane inspector page. List on the left, detail on the right.
  Live tail with pause, filters, URL search, clear.

Not in scope for v0.3:

- Replay or resend of a captured request.
- Route add and remove from the dashboard.
- Per-route capture toggles.
- HAR or any other export format.

Route mutation gets its own spec. It turns the dashboard into a write
surface, which needs an origin and auth model. That is a different problem
from capture and it should not ride along inside this one. See
[dashboard.go](../../../internal/dashboard/dashboard.go) lines 80 to 88 for
the existing note on why.

## Decisions

Settled in DESIGN.md before this spec:

- Capture is a custom Caddy handler module compiled into the binary, not a
  proxy we write ourselves.
- Storage is `modernc.org/sqlite`, which needs no CGo.
- Bodies are captured only when explicitly enabled. Never by default.

Settled while writing this spec:

- **Metadata capture is on for every route by default, and it persists.**
  Open the dashboard and traffic is already there. No setup step, no empty
  page to explain.
- **Header values are redacted against a known list by default.** Full
  values need the same switch that turns on bodies.
- **The ring buffer is bounded three ways.** Rows, bytes, and age. A row
  cap alone is honest for metadata and a lie once bodies are on. Both
  volume caps miss the low-traffic case, where a few old rows sit on disk
  forever because nothing ever pushed them out.
- **The live feed is Server-Sent Events, not WebSocket.** See "Feed
  transport" below. DESIGN.md named WebSocket. That choice predates
  noticing the feed only ever goes one way.

## Architecture

### Packages

New package `internal/inspect`:

| File | Job |
|---|---|
| `record.go` | The `Record` type, header redaction, body tee. No I/O. |
| `store.go` | SQLite. Schema, batch insert, trim, queries. Knows nothing about Caddy or HTTP. |
| `recorder.go` | The bus. Buffered channel, drain goroutine, writes, subscriber fan-out. |
| `handler.go` | The Caddy middleware module. |

The dashboard gains `internal/dashboard/inspect.go` for the HTTP endpoints
and the feed. It depends on `internal/inspect`. Never the reverse.

`handler.go` registers the module in `init()`, the same shape as
[permission.go](../../../internal/proxy/permission.go):

```go
func init() { caddy.RegisterModule(Handler{}) }

func (Handler) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "http.handlers.switchboard_inspect",
        New: func() caddy.Module { return new(Handler) },
    }
}
```

### How the handler reaches the recorder

A package-level `atomic.Pointer[Recorder]` in `internal/inspect`, set once
by the daemon before it calls `proxy.Load`.

Caddy cannot hand a Go pointer through JSON config. The stronger reason is
lifecycle. Every `switchboard add` reloads the Caddy config and
re-provisions every handler instance. The recorder owns a SQLite handle, an
in-flight batch, and a set of live subscribers. All of that has to outlive
a config reload, so it cannot be owned by a Caddy module.

A nil pointer means pass through. A broken inspector is a no-op, not an
outage.

### Where the handler is inserted

In `proxy.Generate`, ahead of `reverse_proxy` in each user route.
See [proxy.go](../../../internal/proxy/proxy.go) lines 79 to 85.

The dashboard catch-all route on line 86 is **not** instrumented. If it
were, the inspector would record itself, including its own feed, and the
buffer would fill with its own traffic.

When `enabled` is false the handler is left out of the generated config
entirely. Not inserted and told to do nothing. Turning it off costs zero on
the request path, and because config generation already reruns on reload,
flipping the setting takes effect the same way a route change does.

### Capture path

1. The handler stamps a start time.
2. It wraps the writer in `caddyhttp.NewResponseRecorder`. Caddy's own
   recorder already passes `Hijacker` and `Flusher` through correctly.
   Do not write a new one.
3. It calls `next`.
4. It builds a `Record` and does a **non-blocking** send on the recorder's
   channel.

A full channel drops the record and bumps a counter. The dashboard shows
the count. Loss is visible, and it never becomes backpressure on somebody's
dev request.

Two emit points, one row each:

- **Normal requests** emit when the handler returns. Full duration, real
  response byte count.
- **Upgraded connections** emit the moment a 101 status is seen, not on
  close. A WebSocket handler blocks until the socket dies. Emitting on
  return would mean an HMR connection shows up in the inspector an hour
  later. Duration is time to upgrade, `upgraded` is 1, no bodies, no
  frames.

### Bodies

Off by default.

When enabled, capture is a write-through tee capped at `max_body_bytes`.
The first N bytes are copied aside while every byte still goes to the
client immediately. Do not buffer the response. Buffering breaks SSE and
large downloads, and a debugging feature does not get to do that.

Request side is a `TeeReader` around `r.Body` with the same cap. Response
side is a small `io.Writer` wrapper that copies until the cap and then
stops copying but keeps writing.

Bodies are never captured for upgraded connections.

### Redaction

Applied at capture time, in `record.go`, before anything reaches disk.
Header names are kept. Values for these become the literal string
`[redacted]`:

```
Authorization
Proxy-Authorization
Cookie
Set-Cookie
X-Api-Key
X-Auth-Token
```

Matching is case-insensitive.

The `bodies` switch also turns redaction off. One switch, both effects.
Someone who turned on body capture has already asked for the credentials in
the payload, and a redacted `Cookie` next to a full session body is a
confusing half measure. This coupling is easy to miss, so the config
comment says it out loud.

Documentation says this reduces exposure. It does not say it prevents it.
A deny-list will miss a custom token header. Claiming otherwise would be
worse than the leak.

### Schema

```sql
CREATE TABLE requests (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at   INTEGER NOT NULL,  -- unix microseconds
  duration_us  INTEGER NOT NULL,
  domain       TEXT    NOT NULL,
  method       TEXT    NOT NULL,
  path         TEXT    NOT NULL,  -- path plus query
  status       INTEGER NOT NULL,
  proto        TEXT    NOT NULL,
  upgraded     INTEGER NOT NULL DEFAULT 0,
  req_bytes    INTEGER NOT NULL DEFAULT 0,
  resp_bytes   INTEGER NOT NULL DEFAULT 0,
  error        TEXT,
  req_headers  TEXT    NOT NULL,  -- JSON object, redacted
  resp_headers TEXT    NOT NULL,  -- JSON object, redacted
  req_body     BLOB,
  resp_body    BLOB,
  size_bytes   INTEGER NOT NULL   -- approximate row cost, for the byte cap
);

CREATE INDEX idx_requests_started ON requests(started_at);
```

At 5,000 rows a scan for the other filters is fine. One index is enough.

`size_bytes` is the row's approximate cost. Header JSON length, plus body
lengths, plus a fixed overhead for the scalar columns. The store keeps a
running total in memory so the trim never runs `SUM()` over the table.

File is `DataDir()/inspect.db`, mode 0600, journal mode WAL.

### Trim

Runs after each batch insert. Three conditions, all enforced:

1. Delete rows older than `max_age`.
2. Delete oldest by `id` until row count is at or under `max_requests`.
3. Delete oldest by `id` until the byte total is at or under `max_bytes`.

Recompute the running byte total from the deleted rows. On open, compute it
once with a single `SUM(size_bytes)`, and run a full trim right then. That
open-time trim is what actually enforces `max_age`, because a daemon that
sat idle overnight has stale rows and no writes coming to trigger a trim.

The drain goroutine also runs a trim on a one hour ticker. Trim on write
plus trim on open still leaves a hole: a daemon that stays up for a week
with three quiet days in the middle holds rows past `max_age` because
nothing triggers the check. Age should be enforced by the clock, not by
whether someone happened to load a page.

Age alone would not be a sufficient bound, which is why it is third and not
first. A load test or an HMR-heavy frontend can write a lot inside one age
window. The volume caps are the real limit. Age is the floor under the
quiet case.

### Feed transport

Server-Sent Events over the dashboard's existing HTTP server. No new
dependency.

The feed only ever goes one way. Server to browser. Filters are query
params or client-side. Pause is client-side. Clear is a POST. There is no
client-to-server message, so a bidirectional protocol buys nothing and
costs a module.

SSE also reconnects on its own, which a WebSocket does not.

DESIGN.md line 227 names `nhooyr.io/websocket` for this. Two things about
that. The package moved to `github.com/coder/websocket`, same library. And
the reason to pick it was never examined once the feed turned out to be
one-way. Update that row in DESIGN.md when this lands.

Note the connection limit. SSE over HTTP/1.1 shares the six-per-origin cap.
The dashboard is served over h2 through Caddy so this does not bite. Direct
loopback access at `http://127.0.0.1:8484` is HTTP/1.1 and uses one stream.
Fine either way.

## Config

```toml
[inspect]
enabled        = true      # metadata capture
bodies         = false     # request and response bodies. also stops
                           # header redaction. both, not one.
max_requests   = 5000
max_bytes      = 67108864  # 64 MiB
max_body_bytes = 65536     # 64 KiB per body
max_age        = "168h"    # 7 days
```

`max_age` is a Go duration string. It is the only knob here that is not a
number, because "168h" is checkable at a glance and 604800 is not.

`enabled` is a `*bool`. The struct tags use `omitzero` and this default is
true, so a plain `bool` cannot tell "unset" from "off". The integers follow
the existing `orDefault` accessor pattern in
[config.go](../../../internal/config/config.go) lines 352 to 355.

Everything here hot-reloads through the watcher already in
[daemon.go](../../../internal/daemon/daemon.go) lines 122 to 179. Turning
`bodies` on takes effect without a restart. Lowering a cap trims on the
next write.

## HTTP surface

All on the dashboard server, loopback only.

| Route | Purpose |
|---|---|
| `GET /inspect` | The split-pane page. |
| `GET /api/inspect/requests` | History. See params below. |
| `GET /api/inspect/requests/{id}` | One record, with bodies. |
| `GET /api/inspect/stream` | SSE. Last 200 records, then live. |
| `POST /api/inspect/clear` | Empty the buffer. |

History params:

| Param | Meaning |
|---|---|
| `domain` | Exact match. |
| `method` | Exact match, upper case. |
| `status` | Exact code (`404`) or a class (`4xx`). |
| `q` | Substring of the path, case-insensitive. |
| `before` | Cursor. Return rows with `id` below this. Omit for newest. |
| `limit` | Default 200, max 500. |

Newest first, always.

`handleRoot` currently 404s any path other than `/`. It needs to route
`/inspect` and the API prefix.

A slow SSE subscriber is dropped with a counter. It never blocks the
recorder.

### The clear endpoint

This is the dashboard's first mutation, and route mutation was deferred out
of this spec. So it gets a stated rule rather than an accident.

- `POST` only.
- `Origin` must be present and must match the dashboard origin. An absent
  `Origin` is rejected, not trusted. Browsers always send it on `fetch`, so
  rejecting absence closes the simple-request CSRF hole.

What it destroys is inspector data. No route, no trust setting, no config.
It is the smallest real version of the model the route-mutation spec will
need, and building it here means that spec starts from something working.

## Dashboard UI

Extend the existing templates. No framework, consistent with DESIGN.md.
Plain JS, the existing CSS variables, the existing dark and light handling.

- Split pane. Request list left, detail right.
- Live tail with pause and resume.
- Filters: domain, method, status class.
- URL substring search.
- Clear.
- Dropped-record count when it is above zero.

Render at most 500 rows in the DOM with a "load more" control. Do not
virtualize.

The route table at `/` stays as it is.

## Failure isolation

The proxy is the product. The inspector is never the reason it fails to
start.

- SQLite will not open: log a warning, leave the recorder pointer nil, run
  with capture off.
- The drain goroutine recovers from panics and keeps draining.
- A write error is logged once per interval, not per row.

## Testing

Unit:

- Redaction. Cased variants, unknown headers pass through.
- Trim. Row cap alone, byte cap alone, age alone, all three at once.
- Trim on open. Stale rows go when the daemon starts, with no writes.
- Trim on tick. Inject the clock so this does not need a real hour.
- Tee cap. Client still receives every byte when the cap truncates.
- Schema round trip through the store.

Handler, with `httptest` and a stub `next`:

- Field correctness on a normal request.
- The 101 path emits at upgrade, not at return.
- A deliberately full channel drops without blocking.

Integration, extending the daemon end-to-end test:

- A real proxied request lands a row and reaches a subscriber.
- Dashboard traffic produces no rows.

Known going in: `TestEndToEnd` is already flaky on repeat runs in one
process. See issue #25. Do not read a failure there as caused by this work
without checking that first.

## Dependencies

New to `go.mod`:

- `modernc.org/sqlite`

That is all. SSE needs nothing.

The v0.2 plan forbade new modules. That constraint was about that plan, and
it does not carry. SQLite was always the roadmap's answer for this, and it
is the only addition.

## Docs to update when this lands

- **DESIGN.md line 227.** It names `nhooyr.io/websocket` for the live feed.
  The feed is SSE. Replace the row and say why in one line.
- **DESIGN.md §6, v0.3 row.** Strike route add and remove. That moved to
  its own spec.
- **README.md.** The inspector is a headline feature. It needs a mention
  and the default-capture and redaction behavior stated plainly.
- **docs/ARCHITECTURE.md.** New subsystem, new file on disk at
  `DataDir()/inspect.db`, and the loopback boundary note in §7 now covers
  captured traffic too.
- **CHANGELOG.md.** Under a new version heading.

## Open risks

- **Binary size.** The binary is already about 64 MB. `modernc.org/sqlite`
  is a large pure-Go package. Measure after it lands. DESIGN.md §7 already
  flags size as a revisit-if-it-hurts item.
- **Redaction is best effort.** Stated above, repeated here because it is
  the one claim in this feature that could mislead someone.
- **Write volume.** An HMR-heavy frontend can generate a lot of requests.
  The batch and the caps should hold, but the drop counter exists so the
  failure is visible if they do not.
