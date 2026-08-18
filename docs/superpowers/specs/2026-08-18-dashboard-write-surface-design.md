# Switchboard — Dashboard Write Surface

**Status:** approved design, ready for an implementation plan.
**Date:** 2026-08-18.
**Roadmap slot:** proposed as a new v0.5. Windows and Linux each shift one.

## Goal

Make the dashboard a GUI over the CLI. Anything the CLI can do without sudo,
you can do by clicking.

Today the dashboard is read only. You watch traffic and you read a route
table. To change anything you go back to a terminal. That is fine while the
only thing worth changing is a route. It stops being fine when tunnels land
and the config grows a relay address, an auth token and a share list.

## Scope

In scope:

- Route add, remove and edit from the dashboard.
- `dashboard_port` and every `inspect` setting from the dashboard.
- Doctor output as a page.
- Service status, and whether a saved change is actually running yet.
- The frontend becomes a built SPA. Vite, React, TypeScript, Tailwind,
  shadcn/ui.
- The inspector gets ported to that SPA. Same endpoints, same behavior.
- An origin model for writes.

Not in scope:

- Anything needing sudo. `setup`, `uninstall`, `suffix`, `dns_port`, and
  `http_port` / `https_port` under a launch daemon. See "The sudo tier".
- Auth. There is none and there does not need to be. See "Threat model".
- Remote access. The listener stays bound to 127.0.0.1.
- Tunnels. This is the surface they will land on. It is not the tunnels.
- A raw TOML editor in the browser. Maybe later.

## Threat model

DESIGN.md deferred this twice, both times saying a write surface "needs its
own origin and auth design". The auth half turns out to be a non-problem, and
it is worth writing down why so nobody re-opens it.

A local process running as you can already rewrite `config.toml`. The file is
0644 in your home directory and the header says it is safe to edit by hand.
So a write API hands a local process nothing it did not already have. Auth
would be theatre.

What a write API does change is what a *web page* can reach. That is plain
CSRF, and CSRF is what this design defends against.

The hole today is real. `sameOrigin` in `inspect.go` accepts any loopback
origin at any port. That is deliberate and correct for the inspector, but it
means `http://localhost:3000` passes. Your own Vite dev server, one bad npm
dependency deep, is inside the trust boundary. Its blast radius right now is
"can clear captured traffic". With config writes it becomes "can repoint
app.test at my server". The comment on `sameOrigin` predicted exactly this.

Three layers on every mutating endpoint:

1. **Host guard.** The existing `guard`. Unchanged.
2. **Strict origin.** New. `Origin` must be present, and must be either
   `https://switchboard.<suffix>` or loopback at the dashboard port. Not any
   loopback port. This is the real gate.
3. **CSRF token.** 32 random bytes, hex, minted once per process. Injected
   into `index.html`. Sent back as `X-Switchboard-CSRF`. Compared with
   `subtle.ConstantTimeCompare`.

The token cannot leak to a foreign page. Reading `index.html` cross origin
needs CORS, and the dashboard grants none. A foreign page can fire a request
it cannot read. It can never learn the token.

Reads keep the permissive `sameOrigin`. When the resolver file or the CA
trust is broken, `http://127.0.0.1:8484` is the only way in, and that is
exactly when you need doctor. Loosening reads is the point of that allowance.
Tightening writes does not touch it.

**Enforced by construction.** `routeEntry` gains a `mutating bool`. A test
walks `routes()` and asserts every mutating entry rejects a foreign Host, a
missing Origin, a loopback Origin on the wrong port, and a bad token. This is
the same idiom as `TestEveryGuardedRouteRejectsAForeignHost`, which exists
because `/api/routes` escaped the host guard by living only in a hand written
list. Same trap, one level up.

## API

Reads. Permissive origin, existing guard.

| Endpoint | Returns |
|---|---|
| `GET /api/routes` | Unchanged. |
| `GET /api/config` | Config as written, effective values, `version`, `applied`, `applyError`, `restartRequired`. |
| `GET /api/doctor` | `doctor.Run` output. |
| `GET /api/service` | `service.Status()`, mode, and the plist path. |
| `GET /api/inspect/*` | Unchanged. |

Writes. Strict origin plus token.

| Endpoint | Body | Codes |
|---|---|---|
| `POST /api/routes` | `{domain, port \| upstream, version}` | 201, 409, 422 |
| `PATCH /api/routes/{domain}` | `{domain?, port?, upstream?, version}` | 200, 404, 409, 422 |
| `DELETE /api/routes/{domain}` | `?version=` | 204, 404, 409 |
| `PATCH /api/config` | `{dashboard_port?, inspect?, version}` | 200, 409, 422 |
| `POST /api/inspect/clear` | Existing. Upgraded to strict origin. | 204 |

`version` is the first 16 hex characters of the sha256 of the config file
bytes. `config.LoadWithVersion(path)` returns it alongside the config, so the
hash is computed in one place and both the daemon and the dashboard use it.

422 carries the `Validate` error text straight through. The messages are
already written for humans and already name the offending route.

One thing to keep in mind for later. The config holds no secrets today, so
`GET /api/config` returning it whole is fine. Tunnels will add a relay token.
When that lands, that endpoint needs a redaction pass, the same way the
inspector already redacts headers. Better to remember it now than to find it
in a bug report.

## Applying a change

Every write handler does the same five things.

1. Take the package write mutex.
2. Re-read the file and recompute the version. If it does not match what the
   client sent, return 409 **with the current config in the body**, so the
   client re-renders without a second round trip.
3. Mutate the in-memory config.
4. `cfg.Save(path)`. Save already calls `Validate` and already writes through
   a temp file and a rename.
5. Return the new version.

Then it stops. The fsnotify watcher in `daemon.go` sees the rename and calls
`proxy.Load`, exactly as it does for a hand edit. **There is no new apply
path.** The GUI and a text editor behave identically. That equivalence is the
property worth protecting, and it is why the write API goes through the file
rather than poking the running proxy.

The mutex serializes GUI writes against each other. It cannot serialize
against the CLI. A CLI write between the client's GET and its POST is caught
by the version compare. A CLI write inside step 2 to step 4 is not. That
window is microseconds and the CLI is human paced. Named here so nobody
mistakes it for an oversight.

### Saved is not running

`Validate` passing is not the same as `proxy.Load` succeeding. A write can
return 200 and the reload can still fail, leaving the file ahead of the
running proxy.

Do not fix this by making writes synchronous. Make the reload observable
instead. The daemon already calls `dash.SetConfig(next)` after a good reload.
Add `dash.SetApplied(version, err)`, called on both outcomes. `GET
/api/config` then reports:

- `applied: false` when the file version differs from the last applied one.
- `applyError` when the last reload failed, with the reason.

The SPA shows a banner. This is strictly better than a synchronous write,
because it also catches a hand edit that fails to load. Today that only shows
up in the log, where nobody is looking.

`restartRequired` works the same way. `dashboard_port` saves like anything
else, but the dashboard cannot rebind mid flight without killing the request
it is answering. So it is a banner and a button. In agent mode the button
shells `launchctl kickstart -k gui/<uid>/<label>`, which needs no sudo. Under
a launch daemon it shows the command instead.

## The sudo tier

`suffix`, `dns_port`, and the privileged ports are read only in the GUI. But
visibly read only, not silently.

Each one shows its current value, one line saying why it cannot change here,
and a command you can copy:

```
switchboard suffix dev.example.com
```

`GET /api/doctor` already detects the resulting state. Resolver file present,
CA trusted, ports bound. So once you run the command in a terminal, the GUI
reflects it on the next poll. That is the entire integration. No helper, no
privileged channel, no new IPC.

This is the honest reading of "GUI over the CLI". Most of the surface becomes
clickable. The rest becomes discoverable and one paste away, instead of
something you have to already know exists.

Why the ports cannot move: the privileged parent hardcodes :443 and :80 by
design. `config.go` spells out the reason. Root must never learn a port
number from a file any local process can rewrite. A browser page asking for a
port change is precisely the case that rule exists to stop.

## Frontend

Source in `web/` at the repo root. Build output committed to
`internal/dashboard/webui/`. Root `/dist/` is goreleaser's and is gitignored,
hence the different name.

**The build output is committed. This is load bearing.**

- `go install github.com/alsey89/switchboard/cmd/switchboard@latest` has to
  keep working. The module proxy serves the repo as it is and runs no build
  hooks. Uncommitted output means `go:embed` finds nothing and that install
  path dies.
- `go build ./...` and `go test ./...` keep working for a Go contributor with
  no Node installed.
- goreleaser stays pure Go.
- The repo already does this. `THIRD_PARTY_NOTICES` is a committed generated
  artifact with a CI gate that fails when it is stale. Same idiom, no new
  concept to learn.

`index.html` stays a Go template, but only to inject the CSRF token and the
version string. Everything else is API driven.

`noroute.html` stays a server rendered Go template and does not move into the
SPA. It answers arbitrary foreign hosts and has to work when the bundle is
beside the point.

Static serving falls back to `index.html` for unknown paths under the
dashboard host, so client side routing works. `/api/*` never falls through.

Screens: Routes, Inspector, Doctor, Settings.

### Why a framework now

DESIGN.md decision 7 justified the web dashboard on "zero framework cost".
That was right for a read only page. Two things changed.

Writes mean forms, field level validation, optimistic updates and error
states. That is where hand rolled DOM code stops paying for itself.

Tunnels are the real trigger. Connection state, relay config, auth against a
hosted service, share links. That is not six screens.

Decision 7 gets rewritten rather than quietly contradicted, and the ADR says
tunnels are the trigger, so the reversal reads as a decision and not as
drift.

## Build and CI

- `make web` runs `npm ci && npm run build` in `web/`, output to
  `internal/dashboard/webui/`.
- Plain `go build` still works from a clean checkout, because the output is
  committed.
- CI gains a job: `setup-node`, `make web`, then
  `git diff --exit-code internal/dashboard/webui`. Mirrors the existing
  notices staleness gate.
- `gen-notices.sh` grows npm coverage, runtime dependencies only. Vite and
  Tailwind are build time and never ship in the bundle.
- goreleaser unchanged.

## Testing

Add on the Go side:

- The guard table test, extended. Every mutating route rejects a foreign
  Host, a missing Origin, a loopback Origin on the wrong port, and a bad
  CSRF token.
- Per write endpoint: happy path, 409 on a stale version, 422 on a validation
  failure, 404 on an unknown domain.
- Write, then reload, then `applied: true`.
- A failed reload surfaces as `applyError`.
- Two concurrent writes at the same version. Exactly one wins.
- SPA fallback serves `index.html` for an unknown path and never for
  `/api/*`.

Add on the frontend side:

- Vitest over the API client and form validation.
- This is the first automated coverage the console JavaScript has ever had,
  which closes issue #35.
- No end to end tests yet.

Keep passing: every existing inspector API test. The Go handler tests do not
change, which is most of what de-risks the port.

## What must not regress

The v0.3 and v0.4 console has hard won behavior in it. The React port is
where that gets quietly dropped. Carry all of it:

- Rows keyed by record id, never a full table rebuild. Rebuilding reset
  `scrollTop` on every live event.
- The scroll anchor, so rows arriving above you do not move you.
- Cursor paging with `before`, and the rule that the live stream only
  delivers newer rows, so the two paths cannot fetch the same record.
- Filters applied by the store, not by filtering the last 200 rows client
  side.
- The `matches()` mirror of the store's SQL semantics for live records.
- The generation counter on refresh, and the pending queue.
- **Nothing goes near `innerHTML`.** In React that means
  `dangerouslySetInnerHTML` never appears in this codebase. Every record
  field is attacker influenced.
- The SSE handler keeps watching `s.done`. A handler that only watches the
  client blocks daemon shutdown for as long as a background tab stays open.
- `/inspect` still redirects to `/`. The README, the CHANGELOG and the 0.3.0
  release notes all name that URL.
- The two empty states. Inspector off, naming the config key that turns it
  on. No routes, naming the add command.
- `go install ...@latest` still works.

## Files

| File | Change |
|---|---|
| `web/` | New. Vite, React, TypeScript, Tailwind, shadcn/ui. |
| `internal/dashboard/webui/` | New. Committed build output. The `go:embed` target. |
| `internal/dashboard/templates/index.html` | New. Shell. Injects the CSRF token and version. |
| `internal/dashboard/templates/console.html` | Deleted. Ported to React. |
| `internal/dashboard/templates/noroute.html` | Unchanged. |
| `internal/dashboard/dashboard.go` | `New` takes an options struct carrying the config path and data dir. `routeEntry` gains `mutating`. Static serving with SPA fallback. |
| `internal/dashboard/origin.go` | New. `sameOriginStrict` and the CSRF token. |
| `internal/dashboard/write.go` | New. Route and config writes, the version guard, the write mutex. |
| `internal/dashboard/status.go` | New. `GET /api/doctor` and `GET /api/service`. |
| `internal/dashboard/inspect.go` | `handleInspectClear` moves to strict origin. |
| `internal/config/config.go` | `LoadWithVersion`. |
| `internal/daemon/daemon.go` | Passes the config path and data dir to the dashboard. Reports the reload outcome via `SetApplied`. |
| `Makefile` | `web` target. `build` depends on it. |
| `.github/workflows/ci.yml` | Node job and the staleness check. |
| `scripts/gen-notices.sh` | npm runtime dependency licenses. |
| `DESIGN.md` | Decision 7 rewritten. New decision row for the write surface. Roadmap row. |
| `docs/adr/0004-the-dashboard-write-surface.md` | New. The threat model, and why there is no auth. |

## Sequencing

One frontend, ported in one go. But the Go side can land first, behind the
existing console, which keeps the diff reviewable:

1. Read endpoints. `GET /api/config`, `/api/doctor`, `/api/service`.
   `LoadWithVersion`. Dashboard options struct.
2. The origin model. `sameOriginStrict`, the token, `mutating` on
   `routeEntry`, the extended guard test. `handleInspectClear` already exists
   and already mutates, so it is the one route this step tightens. That gives
   the new test table a real entry to prove itself against instead of passing
   vacuously on an empty set.
3. Write endpoints, the version guard, and `SetApplied`.
4. The SPA. Build pipeline, CI gate, all four screens, the inspector port,
   console deleted.
5. Docs. DESIGN.md, the ADR, README.
