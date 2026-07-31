# Switchboard

Local domains with real HTTPS for web development:

```
https://app.test  →  localhost:3000
```

No `/etc/hosts` editing. No root daemon. No self-signed-certificate warnings.
You tell the operator which line a name connects to; every call gets patched
through.

```console
$ switchboard setup          # once, ever — two password prompts
$ switchboard add app 3000
https://app.test → 127.0.0.1:3000
$ switchboard start
$ open https://app.test      # green padlock
```

## Why

- **Real subdomains locally** — cookies, CORS, OAuth redirects, and
  multi-tenant `*.app.test` setups behave like production.
- **Real HTTPS locally** — Secure cookies, `SameSite=None`, service workers,
  and everything else that demands a secure context just works.
- **Open source, local-first** — everything on this machine is free forever.
  (The eventual tunnel relay is the only planned paid surface, and it will be
  self-hostable. See [DESIGN.md](DESIGN.md).)

## How it works

One unprivileged process (a single Go binary):

- A tiny **DNS responder** answers `*.test → 127.0.0.1`. macOS is pointed at
  it via a file in `/etc/resolver/` — with a custom port, so nothing fights
  over `:53`.
- **Embedded [Caddy](https://caddyserver.com)** terminates TLS on
  `127.0.0.1:443` and reverse-proxies by hostname to your dev servers.
  WebSockets (Vite HMR etc.), HTTP/2, and streaming all just work.
- Caddy's **internal PKI** mints a local root CA once; `switchboard setup`
  installs it into the system trust store. Per-host certificates are issued
  on demand and rotated automatically. Issuance is hard-limited to the
  managed TLD — the CA will refuse to mint a certificate for `google.com`.
- The **dashboard** lives at `https://switchboard.test`; unrouted `*.test`
  hosts get a friendly page telling you the exact command to route them.

The only privileged actions are the two one-time steps in `setup` (write the
resolver file, trust the CA), each run as a visible `sudo` command.

## Commands

```
switchboard setup            one-time system setup (resolver + CA trust)
switchboard start            run the daemon in the foreground
switchboard add <name> <port>   route a domain (bare names get .test appended)
switchboard add api --upstream 192.168.1.5:8080
switchboard rm <name>        remove a route
switchboard ls               list routes and status
switchboard doctor           diagnose setup/port/upstream problems
switchboard uninstall        undo system setup (keeps your config)
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

[Apache-2.0](LICENSE) — the same license as
[Caddy](https://github.com/caddyserver/caddy), which Switchboard embeds.
