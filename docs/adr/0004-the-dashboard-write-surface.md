# ADR 0004 — The dashboard write surface

- **Status:** Accepted
- **Date:** 2026-08-18
- **Affects:** `internal/dashboard`, and every write endpoint the GUI adds
- **Relates to:** [ADR 0001](0001-binding-privileged-ports-on-macos.md), whose
  rule about what root may learn from a user-writable file decides what this
  API is never allowed to change.

---

## Summary

The dashboard is growing endpoints that edit the config file. A write must
pass three checks: the existing Host guard, a strict Origin check, and a
per-process CSRF token the page carries in a meta tag.

There is no login, no password and no API key. That is deliberate. The Origin
check is the gate. The token is defence in depth behind it.

---

## Context

### The adversary is a web page, not a process

The config is a TOML file the user owns. Any process running as that user can
open it, rewrite it, and let the file watcher reload it. The daemon will then
proxy `app.test` wherever the file now says.

So a write API hands a local process nothing it did not already have. A
password guarding the API would be a password that same process can read out
of the same directory. Authentication here is a lock on a door in a wall that
does not exist.

What a write API does add is a path for something with no filesystem access
at all: a page in the user's browser. `https://evil.example` cannot open
`config.toml`. It can run `fetch("http://127.0.0.1:8484/...", {method:
"POST"})`, and the browser sends it, because the browser is on the same
machine as the listener.

That is CSRF. It is the entire threat model. Every layer below exists for it.

### Why the old check was not enough

The dashboard already had `sameOrigin`. It accepted any loopback origin at
any port, so `http://localhost:3000` passed exactly as well as
`https://switchboard.test`.

That was a considered choice, and it was written down as one. Pinning to a
single port fights the premise of the product, which is to sit in front of
whatever is already listening on loopback.

It also means everything listening on loopback is inside the trust boundary.
That set is not abstract. It is every dev server this proxy serves. A page
from your own Vite server on `http://localhost:3000` is a trusted caller
under that rule, and getting code onto that page takes one compromised npm
dependency.

While the only mutating endpoint was "clear the captured traffic", the blast
radius was small enough to accept, and `sameOrigin`'s own comment said the
trust needed revisiting before anything larger arrived. This is larger. A
hostile dependency inside your own project could repoint `app.test` at a host
it controls, and your next request to your own app would go there under a
padlock, because the certificate is genuinely trusted.

---

## Decision

Three layers, all required for a write.

**1. `guard`.** The Host header names this dashboard. Unchanged, and shared
with reads. Necessary, never sufficient: a Host header is something the
attacker's page also gets to send.

**2. `sameOriginStrict`.** The Origin header names this dashboard
specifically. This is the gate.

**3. A per-process token.** 32 bytes from `crypto/rand`, hex encoded, minted
in `New` and rendered into the page as `<meta name="switchboard-csrf">`.
Writes echo it in `X-Switchboard-CSRF`. Compared with
`crypto/subtle.ConstantTimeCompare`.

`mutate` applies layers 2 and 3 in one wrapper. `routes()` marks the entry
`mutating`, and a test walks that table.

`handleInspectClear` is the only write that exists today, so it is what the
machinery was proved against. Landing the boundary before the endpoints that
need it means the config writes arrive into a protection that already has
tests, rather than the other way round.

### What the Origin check accepts

- The dashboard's own domain. Nothing else answers on that name, and it
  resolves to loopback only because we put it in the resolver file.
- Loopback at the port the dashboard listener actually bound, 8484 unless
  `dashboard_port` says otherwise.
- Nothing else.

Two rejections are worth stating, because both look like edge cases and
neither is.

**An absent Origin is refused, not treated as neutral.** Browsers set Origin
on every request that is not a GET or a HEAD, cross-origin form posts
included. That is the fact an origin check is built on. It follows that a
write arriving with no Origin did not come from a page acting for the user,
and whatever it did come from has the config file anyway. Treating absence
as neutral would hand the gate to anything that just leaves the header off.

**Loopback with no explicit port is refused.** No port means port 80. The
dashboard does not run on 80, so an origin that claims it is not the
dashboard. `net.SplitHostPort` returns an error for a bare host, and that
error is the rejection.

The dashboard's own domain is matched by name, so it is accepted at any port
and over either scheme. That is looser than it first looks, because the resolver file sends every
`*.test` name to loopback, and `http://switchboard.test:3000` therefore
reaches whatever dev server is on 3000. Getting script to run at that origin
is the hard part: a hostile page cannot make a local server serve its code,
and nobody browses to their dev server by the dashboard's name. If it
happened anyway, the token is what stops the write, which is the clearest
example of why the token is worth having.

Narrowing it to the dashboard's real scheme and port is not as easy as the
loopback branch makes it look, and the asymmetry is worth stating. The
loopback branch compares against the port the listener accepted, which is
true by construction. There is no equivalent number for the domain branch:
the daemon does not serve that name, Caddy does, on a socket it may have
inherited. `https_port` is inert whenever the socket came from the privileged
parent, and the daemon already logs a warning saying so. A check against that
number would refuse the real dashboard, which is a worse failure than the one
it prevents.

**The port compared against is the one the listener took, not the one the
config names.** `Start` binds once. A `dashboard_port` edit hot-reloads into
the server's config and rebinds nothing, so from that moment the configured
value names a port nothing is serving. Keying the check on the config would
403 `http://127.0.0.1:<old>`, the URL that is still working and the
break-glass path this ADR argues must keep working, and would begin accepting
writes from `http://127.0.0.1:<new>`, which is whatever process happens to be
listening there. So the server records the port off its own listener and the
check reads that.

### Why the token exists, given the Origin check

A page cannot learn the token unless it can read the dashboard's HTML, and
reading a cross-origin response needs CORS, which this server never grants.

So the token adds nothing against the attack the Origin check already stops.
It is there for the mistake nobody has made yet: a handler registered without
`guard`, a CORS header added for a reasonable-looking purpose, a proxy that
rewrites Origin. Each of those switches the gate off quietly. The token does
not switch off quietly, because a caller either holds 64 hex characters from
a page this process rendered or it does not.

`ConstantTimeCompare` reports 0 for inputs of different length, so an absent
header needs no special case.

### Reads keep the permissive check

`hostAllowed` still accepts any loopback host, and a read still needs only
that.

This is the asymmetry, and it is the decision rather than an oversight in it.
When `/etc/resolver/test` is missing or the CA is not trusted,
`https://switchboard.test` will not resolve or will not load, and
`http://127.0.0.1:8484` is the only way to reach the dashboard at all. That is
exactly the moment a user needs `doctor` to tell them what broke. Tightening
reads to the write rule would make the diagnostic unreachable precisely when
it is the thing being reached for.

It is also safe in a way a write is not. A hostile page can fire a read at
the loopback port, but the browser will not let it read the answer, because
there is no `Access-Control-Allow-Origin` on the response. A read's damage
needs the response. A write's damage is done by the request.

### The privileged ports stay out

The write surface covers routes, the suffix, and the inspector settings. It
does not cover `https_port` or `http_port`.

ADR 0001 settled why. The privileged parent binds 80 and 443, hardcoded, and
reads the user's config never. "Root will bind whatever port you name" is a
capability-granting primitive however few lines implement it, and the danger
is the unclaimed privileged ports, 88, 548, 631, not the busy ones. Those two
settings are already inert when the sockets were inherited, and the daemon
logs a warning naming each one.

An endpoint that edited them would be a friendlier interface to a value that
does nothing at best, and to a request root must never take at worst. They
stay where they are, edited by hand in a file, which is the form ADR 0001
already reasoned about.

### Options that lost

**Keep `sameOrigin`.** Loopback at any port puts every proxied dev server
inside the boundary. That is a strange boundary for a proxy whose whole job is
sitting in front of dev servers.

**Add authentication.** A secret the daemon can read is a secret every local
process can read. It stops the adversary we do not face and not the one we
do, and it puts a login screen on a tool whose pitch is that it just works.

**Serve writes on a Unix socket.** File permissions would keep browsers out
completely, since a browser cannot speak to a Unix socket. That is also why it
fails: the dashboard is a browser page, and it is the client.

**Rely on the custom header alone.** A request carrying `X-Switchboard-CSRF`
is not a simple request, so a cross-origin caller needs a preflight this
server never answers. That is a real defence, and it is part of why the token
is worth having. It is not the gate, because it is a property of browser
behaviour we would be leaning on rather than a check we are making.

**Tighten reads to match writes.** It closes the break-glass path, which is
the only reason loopback access exists.

---

## Consequences

### Anyone who can run code as this user can still do all of this

Said plainly, because it would be dishonest to imply otherwise: this design
stops a web page. It does not stop a process. A process running as the user
can edit `config.toml` directly and the daemon will reload it.

That is not a gap being deferred to a later version. It is the boundary the
product sits inside. Switchboard is a developer tool the user installs and
runs as themselves. Defending the config from that user's own processes would
mean a privileged daemon owning the config, and ADR 0001 spent its entire
argument on keeping root's job as small as it can possibly be.

### The write API is not usable from curl

A write needs the token, and the token exists only inside a page this process
rendered. `curl -X POST` cannot get one without scraping the dashboard HTML
first.

That is acceptable, because the scripting interface for this is not HTTP. It
is the file, or the CLI. The API is for the GUI. If a scripted write is ever
wanted it should be a second door with its own decision, not a hole left open
in this one.

### A daemon restart invalidates an open tab

The token is per process. Restart the daemon and a tab opened before the
restart holds a token nothing will accept, so its next write gets a 403.

The page treats a failed clear as a message rather than a silent no-op, which
is the right shape for this too. Persisting the token to disk would fix the
tab and give up the only property the token has, since every local process
could then read it.

### A new write route cannot skip the wrapper by accident

`TestEveryMutatingRouteRejectsABadWrite` walks `routes()` and fires six
hostile requests at every entry marked `mutating`. A route added without
`mutate` fails by construction, not because somebody remembered to add a
case.

The test also fails outright when it finds no mutating routes. A guard test
that passes because it checked nothing is worse than no test at all, and this
codebase has had one: in an earlier version `/api/routes` escaped the Host
guard, because `mux()`'s route list and the test's route list were two
hand-maintained things and only one of them got updated.
