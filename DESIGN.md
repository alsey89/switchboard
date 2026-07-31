# Switchboard — Design Document

> Status: revision 3 — v0.1 (§3, §6) is implemented in this repo. Supersedes
> the pure-Rust plan (preserved in git history at fe3533d if ever needed).

**Switchboard** is an open-source tool for local web development with real
domains: `app.test` → `localhost:3000`, with automatic locally-trusted HTTPS,
no `/etc/hosts` editing, no root daemon. Later: traffic inspection and public
tunnels.

The telephone-operator metaphor is the mental model: you tell the operator
which line a name connects to, and every call gets patched through.

---

## 1. Positioning

### The wedge

This space is crowded. The differentiation is **fully open source +
self-hostable**, not any single feature:

| Tool | What it is | Why we're different |
|---|---|---|
| **LocalCan** | Closest competitor — local domains, HTTPS, tunnels, inspector, desktop app | Closed source, paid |
| **ngrok** | Owns "tunnel" mindshare | Proprietary service; local-domain story weak |
| **Cloudflare Tunnel / Tailscale Funnel** | Free public exposure of local ports | Not dev-domain-native; no local `.test` + HTTPS + inspector loop |
| **Caddy / mkcert / dnsmasq** | The raw ingredients | Assembly required; Switchboard is the assembled product |
| **puma-dev / Valet** | `.test` local domains | Language-ecosystem-specific, no inspector, no tunnels |

Pitch: *"The open-source LocalCan. Everything local is free forever; tunnels
are self-hostable."*

Being "a Caddy wrapper" is not a weakness: Laravel Valet wraps nginx+dnsmasq
and is beloved; LocalCan charges money for what is largely this assembly.
The product is the UX and integration, not the proxy.

### Monetization stance (decided early so incentives stay honest)

- **Everything that runs on the user's machine is OSS and free forever**:
  DNS, proxy, HTTPS, inspector, GUI. This is the adoption engine; there is
  no infra cost to us, so there is nothing honest to charge for.
- **The tunnel is the only honest monetization point** — it is the only
  component where we pay for infrastructure (VPS, bandwidth, wildcard
  domain, TLS at edge, abuse/DMCA handling). Model: open-core.
  - OSS, self-hostable tunnel server (BYO VPS) — free.
  - Hosted relay with nice subdomains — paid, **only if traction warrants**.
- Eyes open: a public relay makes you quasi-an-ISP (phishing served from
  your subdomains, DMCA, DDoS), and free Cloudflare Tunnel / Tailscale
  Funnel undercut it. Strongest argument for building tunnels **last**.

---

## 2. Decisions log

| # | Decision | Choice | Rationale |
|---|---|---|---|
| 1 | MVP scope | **Local domains + HTTPS only** (v0.1) | Smallest genuinely-useful slice; proves the hard part (DNS + certs + privilege UX) |
| 2 | Stack | **Go, with Caddy embedded as a library** | See below. Ships in days, not weeks; borrows a decade of proxy/TLS hardening |
| 3 | OS order | **macOS → Windows → Linux** | macOS has the cleanest story (see §5); Windows has NRPT; Linux DNS is the messiest and lands last |
| 4 | Default suffix | **`.test`** (configurable — see row 10 for the full permitted set: `test`, `internal`, `localhost`, or any multi-label domain the user owns) | RFC 6761 reserves `.test` for exactly this, so nothing can ever be delegated under it. `.local` collides with mDNS (RFC 6762). `.dev` and `.app` are real gTLDs Google sells — the objection is **namespace collision**, not HSTS: Switchboard serves genuinely trusted HTTPS, so HSTS preloading is satisfied. Hijacking `.dev` in the OS resolver would send `go.dev`, `web.dev` and `*.workers.dev` to 127.0.0.1 machine-wide |
| 5 | Proxy & TLS | **Caddy's** — reverse proxy, internal PKI, trust-store install | The parts we shouldn't hand-roll; Caddy erases WS/h2/streaming edge cases and cross-platform CA install |
| 6 | Inspector (v0.2) | **Custom Caddy handler module**, compiled into our binary | Caddy modules are plain Go registered at build time; ~300 lines to tee traffic into SQLite |
| 7 | GUI | **Web dashboard served by the daemon** (at `https://switchboard.<suffix>`); a native *tray* item, not a native dashboard, if/when we want glanceability | Zero framework cost, and once the daemon runs under launchd there is no terminal for a TUI to draw in. The only thing the web dashboard genuinely can't do is be glanceable — that's a menu-bar item, not a Wails port |
| 8 | Business model | **Open-core; tunnel relay is the only paid surface** | See §1 |
| 9 | License | **Apache-2.0** | Matches Caddy (no compatibility analysis needed) and carries an explicit patent grant, which matters more for infrastructure than for a library |
| 10 | Domain suffix policy | **Reserved single-label TLDs (`test`, `internal`, `localhost`) or any multi-label domain the user owns** | A bare non-reserved TLD is or could become real; hijacking it in the OS resolver breaks real sites machine-wide. A multi-label suffix is the user *asserting* they own it — the rule shifts the collision risk onto them, it does not remove it. `co.uk`, `com.au` and `github.io` all pass validation, and `/etc/resolver/co.uk` would hijack that namespace machine-wide. Telling those apart needs a public-suffix list; that means a new dependency, which the no-new-modules constraint rules out, so the policy stands as-is with the risk named honestly |
| 11 | Distribution | **GoReleaser → GitHub releases + a Homebrew cask** (`alsey89/homebrew-tap`) | `brew install` is table stakes for a dev CLI; a cask is the right shape for a prebuilt binary (a formula would imply building from source). Notarization is deferred: it needs a paid Apple Developer account. Note casks **do** quarantine their payload, unlike formulae — hence the `xattr -dr com.apple.quarantine` post-install hook in `.goreleaser.yaml`. Without it Gatekeeper blocks the binary outright, so this is not a browser-download-only concern |

### Why Go + Caddy (and the road not taken)

A pure-Rust build (hickory-dns + hyper/rustls/rcgen) was seriously
considered and fully designed — see fe3533d. What decided it:

- **Caddy erases the long tail**: WebSocket upgrades (Vite HMR), h2,
  streaming/buffering, HTTP→HTTPS redirects, hot config reload — plus an
  internal PKI with **trust-store installation across macOS Keychain,
  Windows cert store, and NSS/Firefox** (Smallstep truststore). That last
  one is the biggest win for the mac→win→linux roadmap.
- **Rebuilding those in Rust ≈ weeks + a permanent maintenance tail**;
  wrapping Caddy ≈ days. For a solo OSS project, shipping risk dominates.
- **Trust story**: "we use Caddy's PKI, the same code running on millions
  of servers" reads better in a README than "install my hand-rolled CA."
- The inspector argument for owning the proxy dissolved: a custom Caddy
  handler module (plain Go, compiled in) captures traffic cleanly.
- Embedding as a **library** (not a subprocess) keeps it one binary, one
  process, one language — config is built programmatically and reloaded
  with `caddy.Load()`, no admin-API socket management.

---

## 3. Architecture (v0.1, macOS)

One unprivileged user-space Go binary. No root daemon — DNS needs no
privilege thanks to `/etc/resolver`'s `port` directive (§5). The `:80`/`:443`
listeners in the diagram below are the unresolved part of that goal: they
*do* need privilege on macOS, and how to get it is an open problem (§5).

```
                      ┌─────────────────────────────────────────────┐
                      │      switchboard daemon (one Go binary)     │
                      │                                             │
  OS resolver ──DNS──▶│  DNS responder (miekg/dns)  127.0.0.1:53535 │
  (via /etc/resolver/ │   *.test → A 127.0.0.1                      │
   test, port 53535)  │   (AAAA → NODATA, see gotcha below)         │
                      │                                             │
  Browser ── :443 ───▶│  Embedded Caddy                             │
  Browser ── :80  ───▶│   TLS: internal PKI, per-host certs minted  │
                      │        on demand, auto-rotated              │
                      │   :80 → automatic redirect to https         │
                      │        │                                    │
                      │        ▼                                    │
                      │   reverse_proxy routes (generated config)   │
                      │    app.test  → 127.0.0.1:3000               │
                      │    api.test  → 127.0.0.1:8080               │
                      │    switchboard.test → built-in dashboard    │
                      │    unknown host → branded "no route" page   │
                      └─────────────────────────────────────────────┘

  One-time `switchboard setup` (two admin prompts; ADR 0001 may add a third):
    1. write /etc/resolver/test  (nameserver 127.0.0.1, port 53535)
    2. install Caddy's root CA into the System Keychain (Smallstep truststore)
```

### How the Caddy embedding works

- Import `caddy/v2` + the standard modules; build a `caddy.Config` in
  memory from our own user config and call `caddy.Run()` / `caddy.Load()`.
  Caddy's admin endpoint stays disabled — reloads are in-process calls.
- TLS automation: **internal issuer**. Explicit route hostnames are listed
  as subjects; arbitrary unconfigured `*.test` hosts (needed for the
  branded "no route" page) use **on-demand issuance**, permission-gated to
  our managed TLDs only.
- `reverse_proxy` defaults are already right for dev: `Host` preserved to
  upstream, `X-Forwarded-For/Proto` added, websockets and streaming just
  work.
- Our own code is: config schema + Caddy-config generation, the DNS
  responder, setup/trust automation, CLI, doctor.

### Repo structure

```
switchboard/
├── cmd/switchboard/     # main: CLI (cobra)
├── internal/
│   ├── dnsd/            # miekg/dns responder
│   ├── proxy/           # caddy config generation + lifecycle
│   ├── ca/              # trust install/uninstall (smallstep truststore)
│   ├── config/          # TOML schema, load/watch/validate
│   ├── setup/           # /etc/resolver, NRPT, resolved — per-OS
│   └── doctor/          # diagnostics
└── (v0.2) internal/inspect/   # caddy handler module + sqlite + ws
```

### Config

Hand-editable file, hot-reloaded via file-watch (`fsnotify`). The CLI
(`switchboard add app.test 3000`) just edits this file and the daemon
regenerates + reloads Caddy config in-process.

```toml
# ~/.config/switchboard/config.toml
suffix = "test"

[[routes]]
domain = "app.test"
port   = 3000

[[routes]]
domain   = "api.app.test"
upstream = "127.0.0.1:8080"
```

### CLI surface (v0.1)

```
switchboard setup              # one-time: resolver file + trust CA (admin prompts)
switchboard start              # run daemon in foreground (launchd agent later)
switchboard add app.test 3000
switchboard rm  app.test
switchboard ls                 # routes + live status
switchboard doctor             # port conflicts, resolver state, CA trust state
```

---

## 4. Component choices (Go)

| Concern | Library | Notes |
|---|---|---|
| Proxy, TLS, PKI, trust install | `github.com/caddyserver/caddy/v2` (embedded) | The core borrow; Apache-2.0, attribution in README |
| DNS server | `github.com/miekg/dns` | Tiny authoritative responder; ~100 lines |
| CLI | `spf13/cobra` | |
| Config | TOML (`BurntSushi/toml`), `fsnotify` for hot reload | |
| (v0.2) storage | `modernc.org/sqlite` (CGo-free) | Inspector log, ring-buffer semantics |
| (v0.2) live feed | WebSocket (`nhooyr.io/websocket`) from the dashboard handler | |
| (v0.3?) native shell | Wails | Only if the web dashboard proves insufficient |

### Certificate handling (all Caddy)

- Root/intermediate/leaf lifecycle fully managed by Caddy's internal PKI;
  leaves are minted per-host on demand and auto-rotated in-process.
- Trust install via Smallstep truststore: macOS Keychain, Windows root
  store, Linux system anchors, **and Firefox/NSS where `certutil` exists**.
- Known gap vs the Rust plan: Caddy's PKI does not expose X.509 **name
  constraints** on its root. Acceptable for v0.1; a potential upstream
  contribution to Caddy later (constrain root to `.test`/`.localhost` so a
  leaked key can't mint browser-accepted certs for real domains).

### Proxy behavior we still assert (via generated config + tests)

- Unknown `Host` on :443 → branded page: *"no route for `foo.test` — run
  `switchboard add foo.test <port>`"*. Cheap, great UX.
- Port 443/80 conflict (Docker, another Caddy/nginx) → detect
  `EADDRINUSE`, name the offending PID in `doctor`; escape hatch:
  alternate ports in config (URLs grow `:port`, acceptable).
- Vite/Next HMR (websocket upgrade) is covered by an integration test
  (`internal/proxy/websocket_test.go`) that drives a real upgrade through
  embedded Caddy — it's the #1 breakage users notice.

### DNS gotchas (learned from prior art; ours in every architecture)

- Answer `A → 127.0.0.1` for **any** name under the TLD, even unrouted
  ones (the proxy serves the friendly error).
- **AAAA queries must return NOERROR/NODATA, not NXDOMAIN** — NXDOMAIN
  negative-caches the whole name and kills the A record too.
- `/etc/resolver` only affects the system resolver (`getaddrinfo`):
  browsers/curl work, but `dig`/`nslookup` bypass it and will "fail".
  FAQ entry; puma-dev has the same one. `scutil --dns` shows the truth.
- Setup should `killall -HUP mDNSResponder` after writing the resolver file.

---

## 5. Platform strategy

With Caddy handling TLS + trust stores everywhere, per-OS work reduces to
**DNS routing + service packaging**.

### macOS (v0.1) — the easy one, one lucky break and one open problem

1. **`/etc/resolver/<suffix>` files support a `port` directive** — DNS listens
   on 53535, no fight over :53. (puma-dev ships exactly this pattern.) This
   is the lucky break: it is what removes any need for a privileged DNS
   listener.

2. **:80/:443 are still root-only — OPEN PROBLEM.** Earlier revisions of this
   document claimed macOS had lifted the <1024 restriction since Mojave.
   That is false, and it was never true: macOS enforces the classic Unix
   boundary like every other Unix. Verified on macOS 15 (Darwin 25.5.0) as
   uid 501 — binding `127.0.0.1:80`, `:443` and `:1023` all fail with
   `permission denied`; `:1024` succeeds.

   So an unprivileged daemon on the default ports cannot start. Today the
   only working answer is the escape hatch already contemplated above in §4:
   set `http_port`/`https_port` to high ports and accept `:8443` in URLs.
   The real options — pf redirect from 443, a root LaunchDaemon or helper,
   launchd socket activation (which binds privileged sockets and passes them
   to an unprivileged job), or simply defaulting to high ports — trade off
   differently on privilege, install friction, and URL aesthetics. They are
   weighed in full, with the measurements and the rejected alternatives, in
   [ADR 0001](docs/adr/0001-binding-privileged-ports-on-macos.md).

   **Decided there:** a small privileged parent binds :80/:443, drops
   privileges, and spawns the daemon as the user with the listeners inherited
   as file descriptors. That is a separate piece of work, gated on the open
   questions the ADR records; none of it is implemented yet.

   Until it is: `switchboard daemon install` refuses when a configured port
   below 1024 is genuinely unbindable, rather than installing a launch agent
   that crash-loops (`KeepAlive{SuccessfulExit: false}` relaunches a failing
   daemon forever, throttled to roughly every 10s, into an unrotated log).

Privileged surface *today*: two one-shot admin prompts in `setup` (write
resolver file, install CA trust). Everything else runs as the user — but
that holds only on high ports; whatever resolves the open problem above may
add a third privileged step or a one-time helper install.

### Windows (v0.4) — NRPT is the /etc/resolver equivalent

- `Add-DnsClientNrptRule -Namespace ".test" -NameServers 127.0.0.1`
  (admin, one-time). Caveat: NRPT has no port field → we must bind
  `127.0.0.1:53`, which is usually free but can collide with ICS/WSL/Docker.
  **Fallback**: managed block in the `hosts` file — we know every configured
  domain, so we can materialize exact entries (loses true wildcard, keeps
  UX, since routes are explicit anyway). Verify NRPT behavior on Home
  edition.
- No low-port restriction on Windows; trust install covered by Caddy.

### Linux (v0.5) — the messy one, deliberately last

- No `/etc/resolver`. Options, in preference order: `systemd-resolved`
  split-DNS (per-link DNS + `~test` routing domain), `dnsmasq` drop-in
  (`server=/test/127.0.0.1#53535`), NetworkManager integration.
- Low ports need `CAP_NET_BIND_SERVICE` (`setcap` on the binary, or
  systemd socket activation).
- Trust: system anchors + Firefox/Chromium NSS — covered by Caddy's
  truststore where `certutil` is installed; `doctor` should detect and
  advise otherwise.

---

## 6. Roadmap

| Version | Contents |
|---|---|
| **v0.1** | macOS. CLI + daemon: DNS, embedded Caddy (proxy + HTTPS + trust), `setup`/`add`/`rm`/`ls`/`doctor`, hot-reload config. **The whole point, shippable alone.** |
| **v0.2** | Apache-2.0 license; `.internal` and user-owned domain suffixes; dashboard reachable on loopback; websocket/HMR integration test; **launchd agent (`switchboard daemon install`)**; Homebrew distribution. |
| **v0.3** | Inspector: custom Caddy handler module captures method/URL/headers/bodies → SQLite ring buffer → live WS feed. Dashboard matured (inspector split-pane, route add/remove). Best demo material. |
| **v0.4** | Windows (NRPT + hosts-block fallback). |
| **v0.5** | Linux (resolved/dnsmasq + setcap). |
| **v1.x** | Tunnels: OSS self-hostable relay first (candidates to embed or crib: `frp`, `chisel` — embeddable Go lib — or custom on `yamux`); hosted paid tier only on traction. mDNS/Bonjour LAN sharing (`myapp.local` to your phone) as a separate opt-in feature — note mDNS can't do wildcards and only `.local`. |

Failure mode being avoided: building tunnels (hardest, costs money, weakest
moat) before anyone loves the local loop.

---

## 7. Open questions

- **Config location**: `~/.config/switchboard/` everywhere vs platform dirs.
  Leaning `~/.config` — dev-tool convention.
- **Multiple TLDs** at once (`.test` + `.localhost`)? Cheap to support.
- **Binary size**: embedding Caddy means a ~64MB binary (measured, already
  importing only the Caddy modules we use rather than `modules/standard` —
  the weight is Caddy's core dependency tree: quic-go, smallstep, etc.).
  Fine for a dev tool; revisit only if it starts to hurt.
- **Name-constraints upstream**: propose to Caddy's PKI? (See §4.)
- Upstream health indication in `ls` (connect-probe the port?) — nice
  `doctor` candidate.
