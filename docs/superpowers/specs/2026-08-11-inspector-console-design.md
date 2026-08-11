# Switchboard — Inspector Console Design

**Status:** approved design, ready for an implementation plan.
**Date:** 2026-08-11.
**Roadmap slot:** none. This is polish on v0.3, taken before v0.4 (Windows).

## Goal

Make the inspector the thing you see when you open the dashboard.

v0.3 shipped the capture engine and a good inspector page. Almost nobody
will find it. The dashboard links to it from a 0.8rem grey footer, next to a
link that dumps raw JSON. The headline feature of the release is styled like
a debug affordance.

## Scope

In scope:

- `/` becomes the console. Routes, live request list, and request detail on
  one page.
- The routes view becomes live instead of a render-time snapshot.
- Upstream probing goes concurrent, because the live view now runs it every
  ten seconds.
- The two page templates merge into one.
- Presentation polish inside the panes. Listed below.
- `/api/routes` leaves the primary chrome.

Not in scope:

- Route add and remove from the dashboard. Still needs its own origin and
  auth model. Same reasoning as v0.3, see
  [dashboard.go](../../../internal/dashboard/dashboard.go) lines 80 to 88.
- Issue #29, bare name suffixing.
- Binary notarization.
- Replay, resend, or HAR export.

## Decisions

- **The console is inspector first.** Routes become a left rail. The rail
  doubles as the domain filter. Traffic is the page. Routes are navigation.
- **The rail folds to a horizontal chip strip below 1100px, not a
  dropdown.** A dropdown scales to more routes and costs no vertical space.
  It also drops the up and down dots at the exact width you use most, which
  is half the reason to put routes on the traffic page at all.
- **`/inspect` redirects to `/`. It does not stay a separate page.** The
  README, the CHANGELOG and the 0.3.0 release notes all name that URL.
  Bookmarks exist. It cannot 404.
- **The routes table survives, but only in the inspector-off state.** See
  below.

## Layout

Three regions under one header.

| Width | Layout |
|---|---|
| 1100px and up | Routes rail, request list, detail. Three columns. |
| 700px to 1100px | Rail folds to a chip strip under the header. List and detail stay side by side. |
| Below 700px | Detail leaves the column flow and becomes a sheet over the list. |

The 700px breakpoint already exists in `inspect.html`. Today it stacks the
detail under a list capped at 45vh, so reading a request scrolls the list off
screen. A sheet fixes that.

The middle band is the one to get right. A half screen window next to an
editor is the normal way to watch an inspector. Mobile is not a target. The
resolver only answers on this machine until LAN sharing lands in v1.x.

## The rail is live

Today `/` is server rendered once. A route coming up does not show until you
reload.

The rail fetches `/api/routes` on the same ten second `poll()` tick the
inspector page already runs. Clicking a route sets the domain filter, which
is already a text input on the page. The rail just drives it.

This exposes a cost that does not matter today and does after the change.
`probe()` in
[dashboard.go](../../../internal/dashboard/dashboard.go) dials each upstream
one after another with a 300ms timeout. Five down routes is a 1.5 second
render. That was once per page load. It becomes every ten seconds.

So: probe concurrently, one goroutine per route, and cache the result for 5
seconds so the page render and the API call do not each pay for it. 5 is
half the poll interval, so a route coming up shows within one tick and never
two.

Without this the console is slower than what it replaces.

## Two states the merge must not fumble

**Inspector disabled.** `InspectEnabled()` can be false. A traffic first
page with no traffic source is not a page. The rail expands to a full width
routes table, which is roughly today's dashboard, with a line saying capture
is off and the config key that turns it back on. Today the inspector page
says "The inspector is off" and offers nothing to do about it.

**No routes.** The `switchboard add app 3000` empty state is the first thing
a new user sees. It lives only in `dashboard.html` right now. It has to
survive the merge.

## The api link

`/api/routes` comes out of the footer. The endpoint stays. The guard table
and its test depend on it, and the rail now consumes it. The footer carries
the version and a docs link.

## Polish inside the panes

Ranked. Everything here is presentation, none of it touches the store.

1. **Column headers on the list.** There are none. Five unlabeled columns.
2. **Copy as cURL, and copy URL, in the detail pane.** Best value per line
   in the list.
3. **Keyboard.** Up and down move the selection. Esc dismisses the sheet.
   `/` focuses the filter.
4. **Redacted headers.** They render as a bare replacement string with no
   explanation. Mark them as redacted and say what turns it off.
5. **Status as a pill.** `101 ws` stops being a special cased string in the
   status column.
6. **Relative time on recent rows.** "2s ago", absolute on hover.

## What must not regress

The v0.3 inspector page is well built and the merge is where that gets lost.
Carry all of it over:

- The reconciling render. It keys rows by record id and never rebuilds the
  table. Rebuilding reset `scrollTop` on every live event.
- The scroll anchor, so rows arriving above you do not move you.
- Cursor paging with `before`, and the rule that the live stream only
  delivers newer rows so the two paths cannot fetch the same record.
- Filters applied by the store, not by filtering an array of the last 200.
- The `matches()` mirror of the store's SQL semantics for live records.
- The generation counter on refresh, and the pending queue.
- Every value lands as `textContent`, a `data-*` value, or a class name
  built from literals. Nothing goes near `innerHTML`. Every record field is
  attacker influenced.

## Testing

Keep passing:

- The guard table test. Route entries change, `/inspect` becomes a redirect.
- The host guard on the new page.
- The existing inspector API tests.

Add:

- `/inspect` redirects to `/`.
- The console renders with the inspector off, and names the config key.
- The console renders with no routes, and names the add command.
- Probing is concurrent. A slow upstream does not serialize the rest.

## Files

| File | Change |
|---|---|
| `internal/dashboard/templates/console.html` | New. Merges `dashboard.html` and `inspect.html`. |
| `internal/dashboard/templates/dashboard.html` | Deleted. |
| `internal/dashboard/templates/inspect.html` | Deleted. |
| `internal/dashboard/templates/noroute.html` | Unchanged. |
| `internal/dashboard/dashboard.go` | `handleRoot` renders the console. `probe` goes concurrent and caches. |
| `internal/dashboard/inspect.go` | `/inspect` becomes a redirect. |
| `internal/dashboard/*_test.go` | New cases above. |

`console.html` will be large, since it carries the merged page and its
script. If it gets unwieldy the script splits into an embedded `.js` served
as its own asset. Not doing that up front.
