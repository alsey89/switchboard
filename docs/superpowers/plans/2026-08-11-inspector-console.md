# Inspector Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `/` the inspector console, so the v0.3 capture engine is the first thing a developer sees instead of a grey footer link.

**Architecture:** The two dashboard templates merge into one page. `inspect.html` is the base, because it carries all the hard-won client logic, and the routes table folds into it as a left rail that doubles as the domain filter. `/inspect` becomes a redirect. Upstream probing goes concurrent and cached, because the rail now refreshes every ten seconds instead of once per page load.

**Tech Stack:** Go 1.25, `html/template`, `embed`. No frontend framework, no build step. The page is one HTML file with an inline `<script>`, served from `embed.FS`.

**Spec:** [docs/superpowers/specs/2026-08-11-inspector-console-design.md](../specs/2026-08-11-inspector-console-design.md)

**Branch:** `feat/console`, already created off `main`.

## Global Constraints

These apply to every task. They are not repeated per task.

- **Commits use Conventional Commits** (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`). No AI attribution or co-author trailers.
- **Prose is spartan.** Short sentences. No em dashes. Applies to comments, docs, commit bodies, and any copy that renders on the page.
- **Nothing in the page script goes near `innerHTML`.** Every record field is attacker influenced. Values land as `textContent`, a `data-*` value, or a class name built from string literals. This is not negotiable and there is a comment in the file saying so.
- **The template is served from `embed.FS`** via the package-level `tmpl`. New template files must match the `templates/*.html` glob in `dashboard.go`.
- **Run `make test` and `make vet` before every commit.** Both must pass.
- **Do not touch `internal/inspect/`.** This is a presentation change. The store, the recorder, and the Caddy handler stay as they are.
- **Do not add route add or remove.** Out of scope. It needs its own origin and auth model.

## What must not regress

`inspect.html` has real engineering in it and a template merge is exactly where that gets lost. After every task that touches the page, these must still be true:

- The render reconciles by record id. It never clears `#list` and rebuilds.
- The scroll anchor runs, so rows arriving above the viewport do not move it.
- Paging uses the `before` cursor, and only the live stream delivers newer rows.
- Filters are sent to the store as query parameters. They are never applied by filtering a local array.
- `matches()` still mirrors the store's SQL semantics for live records.
- `refresh()` still uses the generation counter and the pending queue.

`TestInspectPageRenders` (renamed in Task 3) asserts several of these by substring. Do not weaken it.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/dashboard/probe.go` | New. Concurrent, TTL-cached upstream probing. Knows nothing about HTTP. |
| `internal/dashboard/probe_test.go` | New. Tests for the above, with an injected dial function so no sockets are opened. |
| `internal/dashboard/templates/console.html` | New, from `git mv` of `inspect.html`. The whole page. |
| `internal/dashboard/templates/dashboard.html` | Deleted in Task 2. |
| `internal/dashboard/templates/noroute.html` | Unchanged. |
| `internal/dashboard/dashboard.go` | `handleRoot` renders the console. `probe` moves to `probe.go`. |
| `internal/dashboard/inspect.go` | `handleInspectPage` becomes `handleInspectRedirect`. |
| `internal/dashboard/dashboard_test.go` | Console render cases. |
| `internal/dashboard/inspect_test.go` | Redirect case, renamed page-render test. |

---

### Task 1: Concurrent, cached upstream probing

No user-visible change. This lands first because the console makes the current
implementation a performance bug: `probe` dials each upstream one after
another with a 300ms timeout, and the rail will call it every ten seconds
instead of once per page load.

**Files:**
- Create: `internal/dashboard/probe.go`
- Create: `internal/dashboard/probe_test.go`
- Modify: `internal/dashboard/dashboard.go` (delete `probe`, add the `probes` field, rewire both callers)

**Interfaces:**
- Consumes: nothing.
- Produces: `func newProber(ttl time.Duration) *prober` and `func (p *prober) statuses(addrs []string) map[string]bool`. `Server` gains a `probes *prober` field. Task 2 uses `s.probes.statuses`.

- [ ] **Step 1: Write the failing tests**

Create `internal/dashboard/probe_test.go`:

```go
package dashboard

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestProberDialsConcurrently(t *testing.T) {
	p := newProber(time.Minute)
	p.dial = func(string) bool {
		time.Sleep(100 * time.Millisecond)
		return true
	}

	addrs := []string{"a:1", "b:2", "c:3", "d:4", "e:5"}
	start := time.Now()
	got := p.statuses(addrs)
	elapsed := time.Since(start)

	// Serially this is 500ms. Overlapped it is a little over 100ms.
	if elapsed > 300*time.Millisecond {
		t.Errorf("took %v, want the dials to overlap", elapsed)
	}
	if len(got) != len(addrs) {
		t.Fatalf("got %d results, want %d", len(got), len(addrs))
	}
	for _, a := range addrs {
		if !got[a] {
			t.Errorf("%s: got down, want up", a)
		}
	}
}

func TestProberCachesWithinTTL(t *testing.T) {
	p := newProber(time.Minute)
	var calls int32
	p.dial = func(string) bool {
		atomic.AddInt32(&calls, 1)
		return true
	}

	p.statuses([]string{"a:1"})
	p.statuses([]string{"a:1"})

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("dialed %d times, want 1", n)
	}
}

func TestProberRedialsAfterTTL(t *testing.T) {
	p := newProber(5 * time.Second)
	clock := time.Now()
	p.now = func() time.Time { return clock }
	var calls int32
	p.dial = func(string) bool {
		atomic.AddInt32(&calls, 1)
		return true
	}

	p.statuses([]string{"a:1"})
	clock = clock.Add(6 * time.Second)
	p.statuses([]string{"a:1"})

	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("dialed %d times, want 2", n)
	}
}

func TestProberDialsADuplicateUpstreamOnce(t *testing.T) {
	// Two routes may point at the same dev server.
	p := newProber(time.Minute)
	var calls int32
	p.dial = func(string) bool {
		atomic.AddInt32(&calls, 1)
		return true
	}

	got := p.statuses([]string{"a:1", "a:1"})

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("dialed %d times, want 1", n)
	}
	if !got["a:1"] {
		t.Error("a:1 should be up")
	}
}

func TestProberForgetsRemovedUpstreams(t *testing.T) {
	// A daemon that runs for weeks must not keep an entry per address it
	// has ever seen.
	p := newProber(time.Minute)
	p.dial = func(string) bool { return true }

	p.statuses([]string{"a:1", "b:2"})
	p.statuses([]string{"a:1"})

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen["b:2"]; ok {
		t.Error("b:2 is gone from the config and should be gone from the cache")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dashboard/ -run TestProber -v`
Expected: FAIL to build, with `undefined: newProber`.

- [ ] **Step 3: Write the implementation**

Create `internal/dashboard/probe.go`:

```go
package dashboard

import (
	"net"
	"sync"
	"time"
)

const (
	probeTimeout = 300 * time.Millisecond

	// probeTTL is half the console's ten second poll interval, so a route
	// that comes up shows within one tick and never two.
	probeTTL = 5 * time.Second
)

type probeResult struct {
	up bool
	at time.Time
}

// prober answers "is anything listening at this address" for a set of
// upstreams at once, and remembers each answer for ttl.
//
// Both halves matter now that the console refreshes routes on a timer. The
// old code dialed serially, so five down routes cost 1.5 seconds, and the
// page render and its /api/routes call each paid for it separately.
//
// now and dial are fields rather than direct calls so tests can drive the
// clock and count dials without opening a socket.
type prober struct {
	ttl  time.Duration
	now  func() time.Time
	dial func(addr string) bool

	mu   sync.Mutex
	seen map[string]probeResult
}

func newProber(ttl time.Duration) *prober {
	return &prober{
		ttl:  ttl,
		now:  time.Now,
		dial: dialTCP,
		seen: map[string]probeResult{},
	}
}

func dialTCP(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return false
	}
	c.Close() //nolint:errcheck
	return true
}

// statuses reports up or down for every address in addrs. It dials only the
// ones with no fresh cached answer, dials those in parallel, and dials a
// repeated address once.
func (p *prober) statuses(addrs []string) map[string]bool {
	now := p.now()
	out := make(map[string]bool, len(addrs))
	todo := make(map[string]struct{})

	p.mu.Lock()
	for _, a := range addrs {
		if r, ok := p.seen[a]; ok && now.Sub(r.at) < p.ttl {
			out[a] = r.up
			continue
		}
		todo[a] = struct{}{}
	}
	p.mu.Unlock()

	if len(todo) == 0 {
		return out
	}

	var (
		wg    sync.WaitGroup
		fmu   sync.Mutex
		fresh = make(map[string]bool, len(todo))
	)
	for a := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			up := p.dial(a)
			fmu.Lock()
			fresh[a] = up
			fmu.Unlock()
		}()
	}
	wg.Wait()

	stamp := p.now()
	p.mu.Lock()
	for a, up := range fresh {
		out[a] = up
		p.seen[a] = probeResult{up: up, at: stamp}
	}
	// Anything cached that is not in this call's address list is a route
	// that has since been removed.
	for a := range p.seen {
		if _, ok := out[a]; !ok {
			delete(p.seen, a)
		}
	}
	p.mu.Unlock()

	return out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dashboard/ -run TestProber -v`
Expected: PASS, five tests.

- [ ] **Step 5: Delete the old `probe` and rewire both callers**

In `internal/dashboard/dashboard.go`, delete this function entirely:

```go
// probe reports whether something is listening at addr.
func probe(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
```

Add the field to `Server`, next to `version`:

```go
	probes  *prober
```

Set it in `New`:

```go
func New(cfg *config.Config, version string) *Server {
	s := &Server{version: version, done: make(chan struct{}), probes: newProber(probeTTL)}
	s.cfg.Store(cfg)
	return s
}
```

Replace the loop body in `handleRoot`:

```go
	addrs := make([]string, 0, len(cfg.Routes))
	for _, rt := range cfg.Routes {
		addrs = append(addrs, rt.UpstreamAddr())
	}
	up := s.probes.statuses(addrs)
	for _, rt := range cfg.Routes {
		data.Routes = append(data.Routes, routeView{
			Domain:   rt.Domain,
			Upstream: rt.UpstreamAddr(),
			Up:       up[rt.UpstreamAddr()],
		})
	}
```

And the same shape in `handleAPIRoutes`:

```go
	addrs := make([]string, 0, len(cfg.Routes))
	for _, rt := range cfg.Routes {
		addrs = append(addrs, rt.UpstreamAddr())
	}
	up := s.probes.statuses(addrs)
	for _, rt := range cfg.Routes {
		out.Routes = append(out.Routes, routeJSON{
			Domain:   rt.Domain,
			Upstream: rt.UpstreamAddr(),
			Up:       up[rt.UpstreamAddr()],
		})
	}
```

`net` may now be unused in `dashboard.go`. It is not: `hostOnly` and
`isLoopbackHost` still use it. Leave the import.

- [ ] **Step 6: Run the full suite**

Run: `make test && make vet`
Expected: PASS. Existing dashboard tests still pass because the rendered
output is unchanged.

- [ ] **Step 7: Commit**

```bash
git add internal/dashboard/probe.go internal/dashboard/probe_test.go internal/dashboard/dashboard.go
git commit -m "perf: probe upstreams concurrently and cache the answer

The console refreshes routes every ten seconds instead of once per page
load. Dialing serially with a 300ms timeout made five down routes a 1.5
second render, and the page and its API call each paid separately.

Answers are cached for 5 seconds, half the poll interval, so a route that
comes up shows within one tick and never two."
```

---

### Task 2: Merge the two templates into the console at `/`

The big one. `inspect.html` becomes `console.html` and grows a routes rail.
`handleRoot` serves it. `dashboard.html` is deleted.

**Files:**
- Rename: `internal/dashboard/templates/inspect.html` to `internal/dashboard/templates/console.html`
- Delete: `internal/dashboard/templates/dashboard.html`
- Modify: `internal/dashboard/dashboard.go` (`handleRoot`)
- Modify: `internal/dashboard/inspect.go` (`handleInspectPage` renders `console.html`)
- Modify: `internal/dashboard/dashboard_test.go`

**Interfaces:**
- Consumes: `s.probes.statuses` from Task 1.
- Produces: `console.html` with template fields `.Version`, `.Suffix`, `.Routes` (each `{Domain, Upstream string; Up bool}`). Client-side globals used by later tasks: `rows`, `selected`, `show(id)`, `render()`, `refresh()`, `refreshRoutes()`, and the `filters` object whose `domain` member is now a hidden input.

- [ ] **Step 1: Rename the template, keeping history**

```bash
git mv internal/dashboard/templates/inspect.html internal/dashboard/templates/console.html
```

Point both current callers at the new name so the tree still builds. In
`inspect.go`, `handleInspectPage`:

```go
	tmpl.ExecuteTemplate(w, "console.html", nil) //nolint:errcheck
```

Run `make test`. The dashboard tests pass, the inspect page test passes.
Nothing has changed behaviourally yet.

- [ ] **Step 2: Write the failing tests**

In `internal/dashboard/dashboard_test.go`, replace `TestDashboardServedOnItsOwnDomain` with:

```go
func TestConsoleServedOnItsOwnDomain(t *testing.T) {
	rec := get(t, newBasicServer(), "switchboard.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// The rail is server rendered so the first paint already has routes.
	// The client refreshes it, but a flash of "no routes" on every load
	// would be worse than the reload it replaces.
	if !strings.Contains(body, "app.test") {
		t.Error("console should list the configured route in the rail")
	}
	// And it is the console, not the old routes-only dashboard.
	for _, want := range []string{`id="list"`, `id="detail"`, `id="rail"`, "EventSource"} {
		if !strings.Contains(body, want) {
			t.Errorf("console is missing %q", want)
		}
	}
}

func TestConsoleWithNoRoutesNamesTheAddCommand(t *testing.T) {
	s := New(&config.Config{Suffix: "test"}, "test-version")
	rec := get(t, s, "switchboard.test")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	// A first run has no routes. This is the new user's first screen and it
	// has to say what to type.
	if !strings.Contains(rec.Body.String(), "switchboard add") {
		t.Error("empty rail should name the add command")
	}
}
```

Leave `TestDashboardServedOnLoopback`, `TestUnroutedHostGetsNoRoutePage` and
`TestNonLoopbackHostIsNotTreatedAsDashboard` as they are. They assert host
handling, which is unchanged. `TestDashboardServedOnLoopback` also asserts
`app.test` is in the body, which the rail satisfies.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/dashboard/ -run TestConsole -v`
Expected: FAIL. `id="rail"` and `EventSource` are missing, because `/` still
renders `dashboard.html`.

- [ ] **Step 4: Add the rail markup to `console.html`**

Add these CSS rules inside the existing `<style>` block, after the
`#detail` rule:

```css
  main { grid-template-columns: 190px minmax(240px, 34%) 1fr; }
  #rail { overflow-y: auto; border-right: 1px solid var(--line); padding: .6rem 0; }
  #rail h2 { margin: 0 .7rem .3rem; }
  #rail ul { list-style: none; margin: 0; padding: 0; }
  #rail li { padding: .3rem .7rem; cursor: pointer; display: flex;
    align-items: baseline; gap: .35rem; }
  #rail li:hover { background: var(--panel); }
  #rail li.sel { background: color-mix(in srgb, var(--accent) 12%, transparent);
    font-weight: 600; }
  #rail .addr { color: var(--muted); font-size: .75rem;
    font-family: ui-monospace, monospace; margin-left: auto; }
  .dot { width: .5rem; height: .5rem; border-radius: 50%; flex: none;
    background: var(--bad); }
  .dot.up { background: var(--ok); }
```

Note the `main` rule overrides the existing two-column
`grid-template-columns` on `main`. Put it after that rule, not before.

Replace the `<main>` element with:

```html
<main>
  <aside id="rail">
    <h2>Routes</h2>
    <ul id="routes">
      <li data-domain="" class="sel">All traffic</li>
      {{range .Routes}}
      <li data-domain="{{.Domain}}">
        <span class="dot{{if .Up}} up{{end}}"></span>{{.Domain}}<span class="addr">{{.Upstream}}</span>
      </li>
      {{end}}
    </ul>
    {{if not .Routes}}
    <p class="empty">No routes yet. Add one:<br><code>switchboard add app 3000</code></p>
    {{end}}
  </aside>
  <div id="list"><p class="empty">Waiting for traffic.</p></div>
  <div id="detail"><p class="empty">Pick a request.</p></div>
</main>
```

Add the `code` rule the empty state needs, next to the existing `.empty` rule:

```css
  #rail code { background: color-mix(in srgb, var(--line) 50%, transparent);
    padding: .1rem .35rem; border-radius: 4px; font-size: .85em; }
  #rail .empty { padding: .8rem .7rem; font-size: .8rem; }
```

Update the footer of the header bar to carry the version, replacing the
`<span id="drops" class="drops"></span>` line with:

```html
  <span id="drops" class="drops"></span>
  <span class="m">{{.Version}}</span>
```

The `.Suffix` field is used by the title. Change the `<h1>`:

```html
  <h1><a href="/">Switchboard</a><span class="m">.{{.Suffix}}</span></h1>
```

- [ ] **Step 5: Turn the domain filter into the rail**

The rail replaces the free-text domain input. Keeping the input as a hidden
field means `query()`, `matches()` and `anyFilterSet()` keep working
untouched, which is the point: none of the query logic needs to know the
control changed.

Replace this line in the header:

```html
  <input id="domain" type="search" placeholder="domain" size="12">
```

with:

```html
  <input id="domain" type="hidden">
```

Add the rail click handler and the refresh, in the script, just above the
`$("pause")` handler:

```js
  // The rail is the domain filter. #domain is a hidden input rather than a
  // variable so query(), matches() and anyFilterSet() keep reading their
  // filter from the same place they always did.
  $("routes").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-domain]");
    if (!li) return;
    filters.domain.value = li.dataset.domain;
    for (const other of $("routes").children) {
      other.classList.toggle("sel", other === li);
    }
    refresh();
  });

  // refreshRoutes keeps the rail live. The dashboard this page replaced was
  // rendered once, so a route coming up did not show until a reload.
  async function refreshRoutes() {
    let data;
    try {
      const resp = await fetch("/api/routes");
      if (!resp.ok) return;
      data = await resp.json();
    } catch {
      return; // daemon restarting; the next tick retries
    }
    const ul = $("routes");
    const active = filters.domain.value;
    ul.textContent = "";

    const all = document.createElement("li");
    all.dataset.domain = "";
    all.textContent = "All traffic";
    all.className = active === "" ? "sel" : "";
    ul.appendChild(all);

    for (const rt of data.routes) {
      const li = document.createElement("li");
      li.dataset.domain = rt.domain;
      li.className = rt.domain === active ? "sel" : "";
      const dot = document.createElement("span");
      dot.className = rt.up ? "dot up" : "dot";
      const addr = document.createElement("span");
      addr.className = "addr";
      addr.textContent = rt.upstream;
      li.append(dot, document.createTextNode(rt.domain), addr);
      ul.appendChild(li);
    }
  }
```

Every value above is `textContent`, a `data-*` value, or a class name from a
literal. `rt.domain` and `rt.upstream` come from the user's own config, but
the rule in this file is unconditional.

Call it on the existing poll tick. Replace the bottom of the script:

```js
  poll()
    .then(() => { if (!inspectorOff) return refresh(); })
    .finally(() => { if (!inspectorOff && live) connect(); });
  setInterval(poll, 10000);
```

with:

```js
  poll()
    .then(() => { if (!inspectorOff) return refresh(); })
    .finally(() => { if (!inspectorOff && live) connect(); });
  setInterval(() => { poll(); refreshRoutes(); }, 10000);
```

The first rail render is server side, so `refreshRoutes` is not called on
load.

- [ ] **Step 6: Serve the console from `handleRoot`**

In `dashboard.go`, change the last line of `handleRoot`:

```go
	tmpl.ExecuteTemplate(w, "console.html", data) //nolint:errcheck
```

`data` already carries `Version`, `Suffix` and `Routes`. No change to its
shape.

- [ ] **Step 7: Delete the old template**

```bash
git rm internal/dashboard/templates/dashboard.html
```

This is also how the `/api/routes` link leaves the primary chrome. It lived
only in `dashboard.html`'s footer, as a peer of the inspector link. The
endpoint stays and the rail now consumes it, but it is no longer presented
to the user as a feature. The version string it also carried moved into the
header bar in Step 4.

- [ ] **Step 8: Run the tests**

Run: `make test && make vet`
Expected: PASS.

`TestInspectPageRenders` still passes at this point: `/inspect` renders
`console.html` with nil data, so the `{{range .Routes}}` block renders empty
and every substring it asserts is still there. Task 3 replaces that handler.

- [ ] **Step 9: Look at it**

```bash
make build && ./switchboard start
```

Open `https://switchboard.test`. Send some traffic through a route. Confirm:
routes in the rail with correct dots, clicking one filters the list,
clicking "All traffic" clears it, live rows still arrive, "load older" still
works and does not jump the scroll.

Stop the daemon with Ctrl-C.

- [ ] **Step 10: Commit**

```bash
git add -A internal/dashboard
git commit -m "feat: make the console the dashboard

The v0.3 inspector was reachable from a 0.8rem grey footer link, next to a
link that dumps raw JSON. It is the best thing in the release and almost
nobody would find it.

/ is now the console. The routes table becomes a left rail that doubles as
the domain filter, and the rail refreshes on the poll tick instead of only
at page load."
```

---

### Task 3: Redirect `/inspect`

**Files:**
- Modify: `internal/dashboard/inspect.go`
- Modify: `internal/dashboard/dashboard.go` (the `routes()` table entry)
- Modify: `internal/dashboard/inspect_test.go`

**Interfaces:**
- Consumes: `console.html` at `/` from Task 2.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing tests**

In `internal/dashboard/inspect_test.go`, rename `TestInspectPageRenders` to
`TestConsolePageRenders` and change its target from `/inspect` to `/`. Keep
every substring assertion. Add the redirect test next to it:

```go
func TestConsolePageRenders(t *testing.T) {
	s, _ := testServer(t)
	w := do(s, "GET", "/", nil)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	// The history API the page must actually use. Its only data source used
	// to be the stream, whose backfill is 200 rows, so the filters ran over
	// an in-memory array and the other ~96% of a default buffer was
	// unreachable. A filter that matched nothing on screen looked identical
	// to no matching traffic at all.
	//
	// The last two are the render path. render() used to clear #list and
	// rebuild every row, which reset scrollTop to 0 on every live event and
	// so made load older unusable on a proxy with any traffic through it.
	// It now reconciles by record id and restores the scroll anchor.
	for _, want := range []string{
		"EventSource", "/api/inspect/stream", "id=\"list\"",
		"/api/inspect/requests?", "p.set(\"domain\"", "{ before:", "load older",
		"tbody.insertBefore", "list.scrollTop +=",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

// TestInspectRedirectsToTheConsole keeps the v0.3 URL working. The README,
// the CHANGELOG and the 0.3.0 release notes all name it, and people have
// bookmarked it.
func TestInspectRedirectsToTheConsole(t *testing.T) {
	s, _ := testServer(t)
	w := do(s, "GET", "/inspect", nil)
	if w.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Errorf("Location %q, want /", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dashboard/ -run 'TestConsolePageRenders|TestInspectRedirects' -v`
Expected: `TestInspectRedirectsToTheConsole` FAILs with `status 200, want 302`.

- [ ] **Step 3: Write the implementation**

In `internal/dashboard/inspect.go`, replace `handleInspectPage` entirely:

```go
// handleInspectRedirect keeps the v0.3 inspector URL working. The page moved
// to /, which is now the console.
//
// 302 and not 301: a permanent redirect is cached by the browser more or
// less forever, so if /inspect ever needs to mean something again there is
// no way to take it back from the people who visited it once.
//
// It stays wrapped in guardPage in the routes table, so the host check runs
// before the redirect does. A foreign Host still gets the no-route page
// rather than a redirect telling it where the dashboard lives.
func (s *Server) handleInspectRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}
```

In `dashboard.go`, update the routes table entry:

```go
		{"/inspect", s.guardPage(s.handleInspectRedirect), true},
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `make test && make vet`
Expected: PASS. In particular `TestEveryGuardedRouteRejectsAForeignHost` and
`TestInspectPageForeignHostGetsTheNoRoutePage` still pass, because
`guardPage` runs before the redirect.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard
git commit -m "feat: redirect /inspect to the console

The inspector page moved to /. The README, the CHANGELOG and the 0.3.0
release notes all name the old URL, so it redirects rather than 404s.

302, not 301. A permanent redirect is cached forever and there would be no
way to take /inspect back later."
```

---

### Task 4: The inspector-off state expands the rail

Today the page says "The inspector is off" and offers nothing to do about
it. With routes in the rail, the off state has something better to be: the
routes list, full width, plus the config key.

One code path, not two. `setOff` already handles a config reload flipping
capture off or on while the page stays open, so the initial load uses it too
rather than a server-rendered branch that could drift from it.

**Files:**
- Modify: `internal/dashboard/templates/console.html`
- Modify: `internal/dashboard/dashboard_test.go`

**Interfaces:**
- Consumes: `setOff(off)` and the `#rail` markup from Task 2.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing test**

In `internal/dashboard/dashboard_test.go`:

```go
// TestConsoleNamesTheConfigKeyForCaptureOff checks the page ships the copy
// that the inspector-off state renders. The state itself is set client side
// by setOff, so this asserts the string is present to be rendered.
func TestConsoleNamesTheConfigKeyForCaptureOff(t *testing.T) {
	rec := get(t, newBasicServer(), "switchboard.test")
	body := rec.Body.String()
	for _, want := range []string{"inspector-off", "[inspect]", "enabled = true"} {
		if !strings.Contains(body, want) {
			t.Errorf("console is missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/dashboard/ -run TestConsoleNamesTheConfigKey -v`
Expected: FAIL, missing `"inspector-off"`.

- [ ] **Step 3: Add the CSS**

In `console.html`, after the `#rail` rules:

```css
  /* Capture off. The traffic columns have nothing to show, so the rail
     stops being a rail and the routes become the page. */
  body.inspector-off #list, body.inspector-off #detail { display: none; }
  body.inspector-off main { grid-template-columns: 1fr; }
  body.inspector-off #rail { border-right: 0; }
  body.inspector-off #rail li { cursor: default; }
  body.inspector-off #rail li:hover { background: none; }
  #offnote { display: none; padding: .8rem .7rem; font-size: .85rem;
    color: var(--warn); }
  body.inspector-off #offnote { display: block; }
```

- [ ] **Step 4: Add the markup**

Inside `<aside id="rail">`, after the `{{if not .Routes}}` block:

```html
    <p id="offnote">
      Capture is off, so there is no traffic to show. Set
      <code>enabled = true</code> under <code>[inspect]</code> in your config
      to turn it back on.
    </p>
```

- [ ] **Step 5: Rewrite `setOff`**

Replace the body of `setOff` in the script:

```js
  // setOff flips the page between the console and the capture-off state, in
  // either direction: a config reload can turn the inspector off or back on
  // while this page stays open, and poll() below is what notices which way
  // it went.
  //
  // Off is not an error state. The routes are still worth showing, so the
  // rail becomes the page and the note says which key turns capture back on.
  function setOff(off) {
    if (inspectorOff === off) return;
    inspectorOff = off;
    document.body.classList.toggle("inspector-off", off);
    $("pause").disabled = off;
    $("clear").disabled = off;
    if (off) {
      if (source) { source.close(); source = null; }
      $("drops").textContent = "";
    } else {
      selected = null;
      rows = [];
      more = false;
      render();
      empty(detail, "Pick a request.");
      refresh();
      if (live) connect();
    }
    refreshRoutes();
  }
```

The `empty(list, ...)` and `empty(detail, ...)` calls in the off branch are
gone. Both columns are hidden by CSS, so writing copy into them was writing
into nothing.

- [ ] **Step 6: Run the tests**

Run: `make test && make vet`
Expected: PASS.

- [ ] **Step 7: Look at it**

```bash
make build
```

Add `enabled = false` under `[inspect]` in `~/.config/switchboard/config.toml`,
then `./switchboard start`. Open the console. Expect the routes list full
width and the note naming the key. Set `enabled = true` and save while the
page is open. Within ten seconds the console should come back without a
reload. Revert the config.

- [ ] **Step 8: Commit**

```bash
git add internal/dashboard
git commit -m "feat: make capture-off show routes instead of nothing

The inspector page said 'The inspector is off' and offered nothing to do
about it. With routes on the page there is something better to fall back to:
the rail goes full width and the note names the config key.

One code path. setOff already handled a reload flipping capture while the
page stayed open, so the initial load goes through it too."
```

---

### Task 5: The responsive fold

Three widths. The middle one matters most: a half screen window next to an
editor is the normal way to watch an inspector.

**Files:**
- Modify: `internal/dashboard/templates/console.html`

**Interfaces:**
- Consumes: the rail and console markup from Task 2.
- Produces: nothing later tasks depend on, except that Task 8's Esc key
  closes the sheet this task adds.

- [ ] **Step 1: Add the chip strip breakpoint**

Below 1100px the rail folds above the list as a horizontal strip. Replace
the existing single media query at the bottom of the `<style>` block with:

```css
  /* Below 1100px the rail folds above the list. A dropdown would scale to
     more routes and cost no height, but it drops the up and down dots at
     the width you actually use, which is most of the reason routes are on
     the traffic page at all. */
  @media (max-width: 1100px) {
    main { grid-template-columns: minmax(240px, 40%) 1fr;
      grid-template-rows: auto 1fr; }
    #rail { grid-column: 1 / -1; overflow: visible; border-right: 0;
      border-bottom: 1px solid var(--line); padding: .4rem .6rem;
      display: flex; gap: .35rem; flex-wrap: wrap; align-items: center; }
    #rail h2 { display: none; }
    #rail ul { display: flex; gap: .35rem; flex-wrap: wrap; }
    #rail li { border: 1px solid var(--line); border-radius: 999px;
      padding: .12rem .55rem; font-size: .8rem; }
    #rail li.sel { border-color: var(--accent); color: var(--accent); }
    #rail .addr { display: none; }
    #rail .empty, #offnote { padding: .2rem 0; }
    body.inspector-off #rail { flex-direction: column; align-items: stretch; }
    body.inspector-off #rail ul { flex-direction: column; }
    body.inspector-off #rail li { border: 0; border-radius: 0;
      font-size: .9rem; padding: .3rem 0; }
    body.inspector-off #rail .addr { display: inline; }
  }

  /* Below 700px the detail stops being a column. It used to stack under a
     list capped at 45vh, so reading a request scrolled the list off screen.
     A sheet keeps the list where it was. */
  @media (max-width: 700px) {
    main { grid-template-columns: 1fr; grid-template-rows: auto 1fr; }
    #list { border-right: 0; }
    #detail { position: fixed; inset: 35% 0 0 0; z-index: 10;
      border-top: 2px solid var(--accent);
      box-shadow: 0 -8px 24px rgb(0 0 0 / .18); display: none; }
    body.sheet-open #detail { display: block; }
    #sheetclose { display: none; position: fixed; right: .6rem; top: 35%;
      margin-top: .4rem; z-index: 11; }
    body.sheet-open #sheetclose { display: block; }
  }
```

- [ ] **Step 2: Add the close control**

The sheet needs a way out. Add it just before `</main>`:

```html
  <button id="sheetclose" aria-label="Close request detail">✕</button>
```

- [ ] **Step 3: Open and close the sheet**

`show(id)` is what opens it. Add this as the first line of `show`, right
after `selected = id;`:

```js
    document.body.classList.add("sheet-open");
```

And add the close handler, next to the rail click handler:

```js
  // The sheet only exists below 700px. Clearing the class at any width is
  // harmless, since nothing above 700px reads it.
  function closeSheet() {
    document.body.classList.remove("sheet-open");
  }
  $("sheetclose").addEventListener("click", closeSheet);
```

- [ ] **Step 4: Verify by looking at it**

There is no Go test for CSS. Run it and resize.

```bash
make build && ./switchboard start
```

Open the console and drag the window through all three widths. Confirm:

- Above 1100px: three columns.
- Around 800px: routes are pills above the list, list and detail side by
  side, status dots still visible.
- Below 700px: clicking a row opens the sheet over the list, the ✕ closes
  it, the list has not scrolled.
- With capture off at 800px, routes stack as a list and show their
  upstreams again.

- [ ] **Step 5: Commit**

```bash
git add internal/dashboard/templates/console.html
git commit -m "feat: fold the console for narrow windows

Three columns do not fit a half screen window, which is the normal way to
watch an inspector.

Below 1100px the rail folds to a chip strip above the list. Below 700px the
detail becomes a sheet over the list, instead of stacking under a list
capped at 45vh where reading a request scrolled the list away."
```

---

### Task 6: Column headers, status pill, relative time

Three presentation fixes to the list, in one task because they are all the
same five columns.

**Files:**
- Modify: `internal/dashboard/templates/console.html`
- Modify: `internal/dashboard/inspect_test.go`

**Interfaces:**
- Consumes: `rowNode(r)` and `render()` from Task 2.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing test**

In `internal/dashboard/inspect_test.go`, add:

```go
func TestConsoleListHasColumnHeaders(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	// Five unlabeled columns is a puzzle, not a table. The header row is
	// built client side, so this asserts the code that builds it. Asserting
	// "<thead>" would never match: it is never in the served source.
	for _, want := range []string{
		`createElement("thead")`,
		`["time", "method", "path", "status", "took"]`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list is missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/dashboard/ -run TestConsoleListHasColumnHeaders -v`
Expected: FAIL, missing `createElement("thead")`.

- [ ] **Step 3: Add the header row**

The table is built in `render()`. Give it a `<thead>` when it is created.
Replace the table creation block inside `render()`:

```js
      if (!tbody) {
        list.textContent = "";
        table = document.createElement("table");
        const thead = document.createElement("thead");
        const hr = document.createElement("tr");
        for (const label of ["time", "method", "path", "status", "took"]) {
          const th = document.createElement("th");
          th.textContent = label;
          hr.appendChild(th);
        }
        thead.appendChild(hr);
        tbody = document.createElement("tbody");
        table.append(thead, tbody);
        list.appendChild(table);
        nodes.clear();
      }
```

Keep the label array on one line and spelled exactly as written. The test
greps the page source for it, since the header row itself only exists once
the script has run.

Add the sticky header CSS next to the existing `td` rule:

```css
  thead th { position: sticky; top: 0; z-index: 1; background: var(--bg);
    text-align: left; padding: .3rem .5rem; font-size: .7rem; font-weight: 500;
    color: var(--muted); text-transform: uppercase; letter-spacing: .05em;
    border-bottom: 1px solid var(--line); }
```

- [ ] **Step 4: Status pill and relative time**

Replace `rowNode` and add two helpers above it:

```js
  // rel renders a recent timestamp as an age, because "4s ago" answers the
  // question the clock time is standing in for. Anything older than an hour
  // is back to a clock time, where the age stops being the useful part.
  function rel(iso) {
    const then = Date.parse(iso);
    if (Number.isNaN(then)) return iso.slice(11, 23);
    const secs = Math.max(0, (Date.now() - then) / 1000);
    if (secs < 60) return Math.floor(secs) + "s ago";
    if (secs < 3600) return Math.floor(secs / 60) + "m ago";
    return iso.slice(11, 19);
  }

  function statusCell(r) {
    const td = document.createElement("td");
    const pill = document.createElement("span");
    // An upgraded connection has no meaningful final status. It said 101 and
    // then stopped being HTTP.
    pill.className = "pill " + (r.upgraded ? "s1" : statusClass(r.status));
    pill.textContent = r.upgraded ? "101 ws" : String(r.status);
    td.appendChild(pill);
    return td;
  }

  function rowNode(r) {
    const tr = document.createElement("tr");
    tr.dataset.id = String(r.id);
    const when = cell(rel(r.started_at), "m");
    when.title = r.started_at;
    tr.append(
      when,
      cell(r.method, "m"),
      cell(r.path, "path"),
      statusCell(r),
      cell(r.duration_ms.toFixed(1) + "ms", "m"),
    );
    return tr;
  }
```

Add the pill CSS next to the existing `.s2` rules, and a class for the
upgrade case:

```css
  .pill { display: inline-block; padding: .02rem .35rem; border-radius: 4px;
    font-size: .78rem; font-variant-numeric: tabular-nums;
    background: color-mix(in srgb, currentColor 12%, transparent); }
  .s1 { color: var(--accent); }
```

- [ ] **Step 5: Keep the ages moving**

A row rendered as "4s ago" must not still say that a minute later. Ages are
re-stamped on the poll tick, which already runs every ten seconds. Add to
the interval callback:

```js
  setInterval(() => {
    poll();
    refreshRoutes();
    // Walk rows and look the node up, not the other way around. rows can
    // hold 5000 records, and scanning rows once per node would be 25
    // million comparisons every ten seconds.
    for (const r of rows) {
      const tr = nodes.get(r.id);
      if (tr) tr.firstElementChild.textContent = rel(r.started_at);
    }
  }, 10000);
```

- [ ] **Step 6: Run the tests**

Run: `make test && make vet`
Expected: PASS.

- [ ] **Step 7: Look at it**

`make build && ./switchboard start`, send traffic, confirm: headers stay put
while the list scrolls, the newest rows read as "2s ago" and age as you
watch, hovering a time shows the full timestamp, and a websocket route shows
a `101 ws` pill.

- [ ] **Step 8: Commit**

```bash
git add internal/dashboard
git commit -m "feat: label the list columns, pill the status, age the times

Five unlabeled columns is a puzzle. The headers stick to the top of the
list.

Recent rows now read as an age, which is the question the clock time was
standing in for, with the full timestamp on hover. Older than an hour goes
back to a clock time."
```

---

### Task 7: Copy as cURL and copy URL

**Files:**
- Modify: `internal/dashboard/templates/console.html`
- Modify: `internal/dashboard/inspect_test.go`

**Interfaces:**
- Consumes: `show(id)` from Task 2, which is where the detail pane is built.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing test**

```go
func TestConsoleOffersCopyAsCurl(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	for _, want := range []string{"copy as curl", "navigator.clipboard"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail pane is missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/dashboard/ -run TestConsoleOffersCopyAsCurl -v`
Expected: FAIL, missing `"copy as curl"`.

- [ ] **Step 3: Write the implementation**

Add above `show`:

```js
  // shellQuote wraps a value for a POSIX shell in single quotes, which quote
  // everything except a single quote itself. There is no escape for one
  // inside single quotes, so the string is closed, an escaped quote is
  // added, and the string is reopened.
  function shellQuote(s) {
    return "'" + String(s).replaceAll("'", `'\\''`) + "'";
  }

  // asCurl rebuilds the request as a command. Redacted header values are
  // dropped rather than emitted: pasting `-H 'authorization: [redacted]'`
  // produces a command that looks right and fails, which is worse than one
  // that is visibly missing its credentials.
  function asCurl(r) {
    const parts = ["curl", "-i", "-X", r.method];
    const headers = r.req_headers || {};
    for (const k of Object.keys(headers).sort()) {
      for (const v of headers[k]) {
        if (v === "[redacted]") continue;
        parts.push("-H", shellQuote(k + ": " + v));
      }
    }
    if (r.req_body) parts.push("--data-raw", shellQuote(r.req_body));
    parts.push(shellQuote("https://" + r.domain + r.path));
    return parts.join(" ");
  }

  // copyButton is a button whose label reports what happened. The clipboard
  // API can reject (no permission, an insecure context) and a button that
  // silently did nothing is the worst version of this.
  function copyButton(label, text) {
    const b = document.createElement("button");
    b.className = "copy";
    b.textContent = label;
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        b.textContent = "copied";
      } catch {
        b.textContent = "copy failed";
      }
      setTimeout(() => { b.textContent = label; }, 1500);
    });
    return b;
  }
```

In `show`, after `detail.textContent = "";` and before
`detail.append(heading("request"));`:

```js
    const actions = document.createElement("div");
    actions.className = "actions";
    actions.append(
      copyButton("copy as curl", asCurl(r)),
      copyButton("copy url", "https://" + r.domain + r.path),
    );
    detail.append(actions);
```

CSS, next to the existing `h2` rule:

```css
  .actions { display: flex; gap: .4rem; margin-bottom: .8rem; }
  .actions .copy { font-size: .78rem; padding: .18rem .45rem; }
```

- [ ] **Step 4: Run the tests**

Run: `make test && make vet`
Expected: PASS.

- [ ] **Step 5: Look at it**

`make build && ./switchboard start`. Click a request, click copy as curl,
paste it in a terminal, run it. It should reproduce the request. With
`bodies = true` set, a POST should carry its `--data-raw`. With bodies off,
confirm no `[redacted]` header made it into the command.

- [ ] **Step 6: Commit**

```bash
git add internal/dashboard
git commit -m "feat: copy a captured request as curl

Seeing the request and reproducing it were separate jobs. Now the detail
pane hands you the command.

Redacted headers are dropped from the command rather than pasted in. A
command that looks right and fails on a [redacted] credential is worse than
one that is visibly missing it."
```

---

### Task 8: Keyboard

**Files:**
- Modify: `internal/dashboard/templates/console.html`
- Modify: `internal/dashboard/inspect_test.go`

**Interfaces:**
- Consumes: `rows`, `selected`, `show(id)` from Task 2; `closeSheet()` from Task 5.
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

```go
func TestConsoleHandlesKeys(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	for _, want := range []string{"ArrowDown", "ArrowUp", "Escape", "keydown"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not handle %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/dashboard/ -run TestConsoleHandlesKeys -v`
Expected: FAIL, missing `"ArrowDown"`.

- [ ] **Step 3: Write the implementation**

Add near the other listeners:

```js
  // step moves the selection by n rows and opens what it lands on. rows is
  // newest first, so down is older, which is the direction the eye travels.
  function step(n) {
    if (!rows.length) return;
    let i = rows.findIndex((r) => r.id === selected);
    if (i < 0) i = n > 0 ? -1 : rows.length;
    const next = rows[Math.min(rows.length - 1, Math.max(0, i + n))];
    if (!next) return;
    show(next.id);
    nodes.get(next.id)?.scrollIntoView({ block: "nearest" });
  }

  // typing is true when the key belongs to a field the user is filling in.
  // Arrow keys inside a search box move the caret, and stealing that would
  // be worse than not having the shortcut.
  function typing(el) {
    return el instanceof HTMLInputElement || el instanceof HTMLSelectElement;
  }

  document.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "Escape") {
      closeSheet();
      if (typing(e.target)) e.target.blur();
      return;
    }
    if (typing(e.target)) return;
    if (e.key === "ArrowDown" || e.key === "j") { e.preventDefault(); step(1); }
    else if (e.key === "ArrowUp" || e.key === "k") { e.preventDefault(); step(-1); }
    else if (e.key === "/") { e.preventDefault(); $("q").focus(); }
  });
```

- [ ] **Step 4: Run the tests**

Run: `make test && make vet`
Expected: PASS.

- [ ] **Step 5: Look at it**

`make build && ./switchboard start`. Arrow up and down move the selection
and scroll it into view. `/` jumps to the filter box. Arrows inside the
filter box still move the caret. Esc leaves the box, and below 700px Esc
closes the sheet.

- [ ] **Step 6: Commit**

```bash
git add internal/dashboard
git commit -m "feat: drive the console from the keyboard

Arrows move the selection, / focuses the filter, Esc leaves a field and
closes the detail sheet. j and k work too.

Keys are ignored while a field has focus, so arrows still move the caret in
the filter box."
```

---

### Task 9: Mark redacted headers

A header value rendering as the bare string `[redacted]` says nothing about
why, or what to do if you need the real thing.

**Files:**
- Modify: `internal/dashboard/templates/console.html`
- Modify: `internal/dashboard/inspect_test.go`

**Interfaces:**
- Consumes: `headerList(h)` from Task 2.
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

```go
func TestConsoleMarksRedactedHeaders(t *testing.T) {
	s, _ := testServer(t)
	body := do(s, "GET", "/", nil).Body.String()
	// inspect.Redacted is the exact value the store writes.
	if !strings.Contains(body, inspect.Redacted) {
		t.Errorf("page should know the %q sentinel to mark it", inspect.Redacted)
	}
	if !strings.Contains(body, "bodies = true") {
		t.Error("the redaction note should name the key that turns it off")
	}
}
```

`inspect` is already imported in this test file.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/dashboard/ -run TestConsoleMarksRedactedHeaders -v`
Expected: FAIL, missing `"[redacted]"`.

- [ ] **Step 3: Write the implementation**

Replace the loop body in `headerList`:

```js
  // REDACTED is the sentinel internal/inspect writes in place of a
  // credential header's value. Matching on it is a little blunt, and a real
  // header whose value happens to be this string would be marked too. That
  // is a better failure than the alternative, which is the value rendering
  // as unexplained literal text.
  const REDACTED = "[redacted]";

  function headerList(h) {
    const names = h ? Object.keys(h).sort() : [];
    if (!names.length) {
      const p = document.createElement("p");
      p.className = "m";
      p.textContent = "none";
      return p;
    }
    const dl = document.createElement("dl");
    for (const k of names) {
      const dt = document.createElement("dt");
      dt.textContent = k;
      const dd = document.createElement("dd");
      const value = h[k].join(", ");
      if (value === REDACTED) {
        dd.className = "redacted";
        dd.textContent = "redacted";
        dd.title = "Set bodies = true under [inspect] to store this value as sent.";
      } else {
        dd.textContent = value;
      }
      dl.append(dt, dd);
    }
    return dl;
  }
```

CSS, next to the `dd` rule:

```css
  .redacted { color: var(--warn); font-family: inherit; font-style: italic;
    cursor: help; }
```

- [ ] **Step 4: Run the tests**

Run: `make test && make vet`
Expected: PASS.

- [ ] **Step 5: Look at it**

`make build && ./switchboard start`. Send a request carrying a `Cookie` or
`Authorization` header. The value should read as an italic "redacted" and
the tooltip should name `bodies = true`.

- [ ] **Step 6: Commit**

```bash
git add internal/dashboard
git commit -m "fix: say that a header was redacted, and what turns it off

A value rendering as the literal string [redacted] reads like the header was
sent that way. It is now marked as redacted, with the config key that stores
values as sent on hover."
```

---

### Task 10: Docs

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/ARCHITECTURE.md` if it names `/inspect` or the two templates

**Interfaces:**
- Consumes: everything above.
- Produces: nothing.

- [ ] **Step 1: Find every mention of the old URL and the old shape**

```bash
grep -rn "/inspect\b" README.md CHANGELOG.md docs/ --include="*.md"
grep -rn "dashboard.html\|inspect.html" docs/ README.md
```

- [ ] **Step 2: Update the README inspector section**

Replace these three lines under `### Inspector`:

```markdown
Every request through a route is recorded and shown live at
`https://switchboard.test/inspect`. Method, URL, status, timing and headers.
No setup. It is on as soon as you upgrade.
```

with:

```markdown
Every request through a route is recorded and shown live at
`https://switchboard.test`. Method, URL, status, timing and headers. No
setup. Routes sit in a rail on the left. Click one to see only its traffic.

The old `/inspect` URL still works. It redirects.
```

Keep the bodies and redaction paragraphs below it exactly as they are.
Nothing about capture changed.

The "How it works" bullet that says the dashboard lives at
`https://switchboard.test` is still true. Leave it.

- [ ] **Step 3: Add the changelog entry**

Add above the `## 0.3.0` heading. Follow the existing voice: what changed,
then what you need to do about it.

```markdown
## Unreleased

### Changed

- **The inspector is the dashboard.** `https://switchboard.test` now opens
  the request console instead of a routes table. Routes moved to a rail on
  the left that doubles as the domain filter. Click one to see only its
  traffic.

  `https://switchboard.test/inspect` still works. It redirects.

  Nothing about capture changed. Same storage, same defaults, same config.

### Added

- Copy a captured request as a `curl` command from the detail pane.
  Redacted headers are left out rather than pasted in as `[redacted]`.
- Keyboard control. Arrows move the selection, `/` focuses the filter, Esc
  closes the detail sheet.
- The routes list is live. A dev server coming up shows within ten seconds
  with no reload.
```

- [ ] **Step 4: Verify nothing stale is left**

Run: `grep -rn "footer.*inspector\|inspector.*footer" README.md docs/`
Expected: no hits.

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md docs/
git commit -m "docs: record the console"
```

Note: `.goreleaser.yaml` filters `^docs:` out of generated release notes, so
this commit will not appear there. The CHANGELOG entry it adds is the
release-facing record.

---

### Task 11: Open the PR

- [ ] **Step 1: Run the whole suite one more time**

```bash
make test && make vet && make build
```

Expected: PASS, and a binary.

- [ ] **Step 2: Walk the regression list**

Open the console with real traffic flowing and confirm each item from the
"What must not regress" section at the top of this plan. In particular: let
traffic run while you scroll back through "load older" and confirm the view
does not jump.

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin feat/console
gh pr create --base main --title "feat: make the inspector the dashboard" --body "$(cat <<'EOF'
The v0.3 inspector was reachable from a 0.8rem grey footer link, next to a
link that dumps raw JSON. It is the best thing in the release and almost
nobody would find it.

`/` is now the console. The routes table becomes a rail on the left that
doubles as the domain filter, and it refreshes on a timer instead of only at
page load. `/inspect` redirects.

Also in here:

- Upstream probing runs concurrently and caches for 5 seconds. It used to
  dial serially with a 300ms timeout, which the new refresh interval would
  have made a real cost.
- Capture-off shows the routes full width and names the config key, instead
  of an empty page saying "The inspector is off".
- Copy a request as curl. Redacted headers are dropped, not pasted in.
- Column headers, status pills, relative times, keyboard control.

Nothing about capture changed. Same storage, same defaults, same config.

Design: `docs/superpowers/specs/2026-08-11-inspector-console-design.md`
EOF
)"
```
