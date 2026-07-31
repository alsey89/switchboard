# Switchboard

Local domains with real HTTPS for web development:

```
https://app.test  →  localhost:3000
```

No `/etc/hosts` editing. No root proxy. No self-signed-certificate warnings.
You tell the operator which line a name connects to; every call gets patched
through.

```console
$ switchboard setup            # once, ever — resolver, trusted CA, background service
$ switchboard add app 3000
https://app.test → 127.0.0.1:3000
$ open https://app.test        # green padlock
```

`setup` does everything needed to make it work, and `switchboard uninstall`
undoes all of it. `switchboard start` runs the daemon in your terminal
instead, for when you want to watch it.

> **Where the password prompts go.** `:80` and `:443` are reserved for root on
> macOS, so something has to be privileged. That something is a ~150-line
> parent process that binds the two sockets, drops to your user, and starts
> the daemon with them already open. The proxy, the TLS stack, Caddy and its
> whole dependency tree, and the certificate authority all run as you — the
> root part reads no configuration, parses no traffic, and listens on no IPC.
> The full reasoning, including the three options that lost, is in
> [ADR 0001](docs/adr/0001-binding-privileged-ports-on-macos.md).
>
> Prefer nothing privileged at all? Set `https_port = 8443` and `http_port =
> 8080` in the config and `daemon install` will set up a plain user agent
> instead. Everything works identically; URLs carry the port.

## Install

**macOS:**

```console
$ brew install alsey89/tap/switchboard
```

**Linux:** grab the archive for your architecture from
[releases](https://github.com/alsey89/switchboard/releases) — Homebrew
casks are macOS-only, so there's no tap path here yet.

> Release binaries are not yet notarized by Apple. The Homebrew cask
> strips the quarantine attribute on install, so `brew install` works
> fine — but a binary downloaded directly through a browser will still
> be quarantined and needs `xattr -d com.apple.quarantine ./switchboard`
> before it runs.

## What it puts on your machine

Yours, no privilege, safe to delete: `~/.config/switchboard/` holds your
config, the local CA and its key, and the per-host certificates Caddy issues.
`rm -rf` on that directory is a complete reset.

System-wide, each installed with a `sudo` command printed before it runs:
`/etc/resolver/<suffix>`, and — only if you serve `:443`/`:80` — a
LaunchDaemon plus a root-owned copy of the binary in
`/Library/PrivilegedHelperTools`. The local CA is trusted in your **login**
keychain, which needs no root and grants trust to your user rather than the
whole machine. `switchboard uninstall` removes
all of it. Everything binds to `127.0.0.1`; nothing is reachable from the
network.

The full inventory, the process model, and what each command actually does
are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Why

- **Real subdomains locally** — cookies, CORS, OAuth redirects, and
  multi-tenant `*.app.test` setups behave like production.
- **Real HTTPS locally** — Secure cookies, `SameSite=None`, service workers,
  and everything else that demands a secure context just works.
- **Open source, local-first** — everything on this machine is free forever.
  (The eventual tunnel relay is the only planned paid surface, and it will be
  self-hostable. See [DESIGN.md](DESIGN.md).)

## How it works

One unprivileged process does all the work (a single Go binary):

- A tiny **DNS responder** answers `*.test → 127.0.0.1`. macOS is pointed at
  it via a file in `/etc/resolver/` — with a custom port, so nothing fights
  over `:53`.
- **Embedded [Caddy](https://caddyserver.com)** terminates TLS on
  `127.0.0.1:443` and reverse-proxies by hostname to your dev servers.
  WebSockets (Vite HMR etc.), HTTP/2, and streaming all just work.
- A **local root CA**, minted once and trusted in your login keychain by
  `switchboard setup`. It carries X.509 **name constraints** pinning it to
  your suffix, so even with the private key in hand nobody can use it to
  forge a certificate for `google.com` — your browser rejects the chain.
  Caddy's PKI issues the per-host certificates beneath it and rotates them.
- The **dashboard** lives at `https://switchboard.test`; unrouted `*.test`
  hosts get a friendly page telling you the exact command to route them.

Privilege is confined to three things, each a visible `sudo` command you can
read before it runs: the two one-time steps in `setup` (write the resolver
file, trust the CA), and installing the launch daemon. That daemon is a small
parent that binds `:443` and `:80` and immediately drops to your user — see
[ADR 0001](docs/adr/0001-binding-privileged-ports-on-macos.md). Everything in
the list above runs as you.

## Choosing a domain suffix

The default is `.test` — RFC 6761 reserves it for exactly this, and nothing
else can ever claim it. Set `suffix` in `~/.config/switchboard/config.toml`
to change it:

| Suffix | Notes |
|---|---|
| `test` | **Default.** RFC 6761. Always safe. |
| `internal` | Reserved by ICANN in 2024 for private use. Reads nicer, but check that your employer's VPN doesn't already hand out `*.internal` names. |
| `localhost` | RFC 6761. Safe, but some libraries special-case it. |
| `dev.example.com` | A subdomain of a domain **you own**. Zero collision risk and the URLs look real. |

Changing it later is one command — `switchboard suffix internal` — which
rewrites your routes, re-issues the CA, and swaps the resolver file in one
step. Editing `suffix` by hand needs all three done together.

Switchboard refuses anything else, and the error says why. `.dev` and `.app`
are the common mistakes: they are real gTLDs that Google sells, so pointing
your OS resolver at them would send `go.dev`, `web.dev` and `*.workers.dev`
to `127.0.0.1` machine-wide. (HSTS preloading is *not* the problem —
Switchboard serves real, trusted HTTPS. The namespace collision is.)

## Commands

```
switchboard setup            make it work: CA, resolver, CA trust, service
                             (--no-service to run the daemon yourself)
switchboard uninstall        undo all of that (keeps your config)

switchboard add <name> <port>   route a domain (bare names get .test appended)
switchboard add api --upstream 192.168.1.5:8080
switchboard rm <name>        remove a route
switchboard ls               list routes and status
switchboard suffix <s>       switch domain suffix: routes, CA, resolver, restart
switchboard doctor           diagnose setup/port/upstream problems
switchboard version          print the version

switchboard start            run the daemon in this terminal instead
switchboard daemon install   (re)install the background service, or restart it
switchboard daemon status    is it installed and running?
switchboard daemon logs      show the service log (-f to follow, --path for it)
switchboard daemon uninstall stop and remove the background service
```

Config lives at `~/.config/switchboard/config.toml`, is safe to edit by
hand, and hot-reloads while the daemon runs.

## Status

Early. **v0.1 targets macOS** (it has the cleanest OS story — see
[DESIGN.md](DESIGN.md) for the platform matrix). Windows (NRPT) and Linux
(systemd-resolved/dnsmasq) automation are next; on those platforms `setup`
currently prints exact manual steps instead.

Roadmap (details in [DESIGN.md](DESIGN.md)): traffic inspector →
dashboard/GUI → Windows → Linux → self-hostable tunnels.

### FAQ: `dig app.test` doesn't resolve!

Expected. `/etc/resolver` configures the *system* resolver; `dig` and
`nslookup` bypass it. Browsers and `curl` use it. Check with
`scutil --dns` instead.

## Building from source

```console
$ go build ./cmd/switchboard
$ go test ./...
```

## License

[Apache-2.0](LICENSE). Switchboard embeds
[Caddy](https://github.com/caddyserver/caddy) (Apache-2.0) — see [NOTICE](NOTICE).

The binary statically links its dependencies, so every linked third-party
module's license text is reproduced in
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) (regenerate with `make notices`).
The Go standard library is also statically compiled in; it is covered
separately by the Go project's own BSD-3-Clause license.
