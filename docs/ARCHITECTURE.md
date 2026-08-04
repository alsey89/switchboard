# Switchboard: architecture and user flow

What actually runs, as whom, and what ends up on your machine.

This describes the system as built and verified on macOS. For *why* it is
shaped this way, see the ADRs — [0001](adr/0001-binding-privileged-ports-on-macos.md)
(privileged ports), [0002](adr/0002-the-listener-seam.md) (listener seam),
[0003](adr/0003-name-constrained-local-ca.md) (the local CA). For roadmap and
positioning, see [DESIGN.md](../DESIGN.md).

---

## 1. The shape

Two processes, and the asymmetry between them is the whole design:

```
launchd
  └── switchboard __supervise --uid 501 --gid 20 --home /Users/you      [root]
        │   binds 127.0.0.1:443 and 127.0.0.1:80
        │   setgroups → setgid → setuid                                  ← privilege ends here
        └── switchboard __serve                                          [you]
              DNS responder      127.0.0.1:53535/udp
              reverse proxy      the two inherited sockets
              TLS termination    + certificate authority
              dashboard          127.0.0.1:8484
              inspector          records to inspect.db, served via the dashboard
              config watcher     hot-reloads on change
```

The parent exists to do the one thing an unprivileged process cannot: bind a
port below 1024. It binds two sockets, drops to your user, and execs the
child with those descriptors already open. Then it supervises.

It reads no configuration file, parses no network traffic, listens on no IPC
socket, and holds no keys. It is a few dozen lines you can read in one
sitting. Everything with attack surface — Caddy and its ~140 linked modules,
the TLS stack, the reverse proxy, the certificate authority — is in the
child, as you.

**Verify it yourself, on a running system:**

```console
$ lsof -nP -iTCP:443 -sTCP:LISTEN
switchboa 87288 you  8u  IPv4 ...  TCP 127.0.0.1:443 (LISTEN)
```

An unprivileged process is holding `:443`. `switchboard doctor` reports the
same fact as a `privilege` check.

---

## 2. Where privilege is, and where it is not

| Action | Runs as | When |
|---|---|---|
| Write `/etc/resolver/<suffix>` | root | once, in `setup` |
| Trust the root CA | **you** | once, in `setup` |
| Install the launch daemon | root | once, in `daemon install` |
| Bind `:443` and `:80` | root | at every start, then drops immediately |
| **Everything else** | **you** | always |

Each step that needs elevation is a separate `sudo` command, printed before
it runs, so you can read what you are agreeing to rather than hand root to
one opaque installer. `sudo` caches its timestamp, so consecutive elevated
steps ask once.

Trusting the CA is deliberately *not* one of them. It goes into your login
keychain, which needs no root and grants trust to your user rather than to
every account and system service on the machine. macOS still shows its own
authorization dialog — that is the Security framework, a different mechanism
from `sudo`, insisting that "trust a new certificate authority" be a
deliberate human act. It is un-scriptable by design, which is the property
you want here.

That dialog can open behind whatever is in front. Click it to focus before
authorizing: Touch ID is only armed while it is the frontmost window, and
unfocused it silently offers password entry alone.

**Nothing user-writable steers a root process.** The parent's ports are
hardcoded, never read from the config file. This is deliberate and is the
security crux: a config-driven parent would be a "root will bind whatever
port you name" primitive, and a hostile config could make root take an
unclaimed privileged port (631/CUPS, 88, 548) and hand the descriptor to the
attacker's process. See ADR 0001.

For the same reason, the launch daemon runs a **root-owned copy** of the
binary from `/Library/PrivilegedHelperTools`, not the one on your `PATH`.
launchd validates the plist's ownership but never the program's, and
Homebrew's prefix is user-writable by design — a plist pointing there would
let anything running as you replace the binary and get root at the next boot.

---

## 3. What lands on your machine

### Yours (no privilege, safe to delete)

| Path | What | Notes |
|---|---|---|
| `~/.config/switchboard/config.toml` | Your routes and settings | Hand-editable; the CLI also rewrites it |
| `~/.config/switchboard/data/pki/root.crt` | The local root CA | Name-constrained to your suffix |
| `~/.config/switchboard/data/pki/root.key` | Its private key | `0600`. The most sensitive file here |
| `~/.config/switchboard/data/caddy/pki/…` | Intermediate cert + key | Managed and rotated by Caddy |
| `~/.config/switchboard/data/caddy/certificates/…` | Per-host leaf certs | Issued on demand, auto-renewed |
| `~/.config/switchboard/data/inspect.db` | Captured request history | Bounded by count, size and age; survives `bodies`/`enabled` toggles, gone only if you delete it (plus `inspect.db-wal` and `inspect.db-shm`, which WAL mode creates; both are normally present while the daemon runs and can survive an unclean exit — delete all three together) |

`rm -rf ~/.config/switchboard` is a complete reset of everything unprivileged.

### Outside your home directory (each authorized explicitly)

| Path | Owner | Installed by | Removed by |
|---|---|---|---|
| `/etc/resolver/<suffix>` | `root:wheel 0644` | `setup` | `uninstall` |
| Login keychain trust entry | **you, no root** | `setup` | `uninstall` |
| `/Library/LaunchDaemons/io.github.alsey89.switchboard.plist` | `root:wheel 0644` | `daemon install` | `uninstall` |
| `/Library/PrivilegedHelperTools/io.github.alsey89.switchboard` | `root:wheel 0755` | `daemon install` | `uninstall` |
| `/Library/Logs/switchboard.log` | root | the daemon | `uninstall` |

The log is deliberately not under your home: launchd creates it as root, and
a root-owned file inside `~/.config/switchboard` would make the documented
`rm -rf` reset fail halfway. Being root-owned is also why `uninstall` removes
it rather than leaving it — you could not delete it yourself without
working out that you needed `sudo`, in a directory you have no reason to
look in.

Because the two service shapes log to different places, `switchboard daemon
logs` reads the path out of the installed plist rather than computing one. It
used to print the *agent's* path unconditionally, which on the default
install — a launch daemon — named a file nothing writes to.

It shows the log rather than pointing at it: the last 50 lines by default,
`-f` to follow, `--path` for the location alone. Printing the path was one
step short of the reason anyone runs the command, and `/Library/Logs` is not
a location people have memorized. It is a tail rather than a `cat` because
nothing rotates this file — a service that crash-loops appends to it
indefinitely, so the day you need it most is the day it is largest.

`-f` is the practical way to watch a reboot: launchd starts the parent before
FileVault has decrypted the home directory, and the child's non-zero exit and
the parent's retry both land here (§5).

### Ports

| Port | Protocol | Bound by | Reachable from |
|---|---|---|---|
| 443 | tcp | the privileged parent | loopback only |
| 80 | tcp | the privileged parent | loopback only |
| 53535 | udp | the daemon (you) | loopback only |
| 8484 | tcp | the daemon (you) | loopback only |

Everything is bound to `127.0.0.1`. Nothing is reachable from the network.

DNS never needs `:53`, because `/etc/resolver` files carry a `port`
directive — which is why the privileged parent holds exactly two descriptors
and knows nothing about UDP.

---

## 4. The user flow

### `switchboard setup` — once, ever

Does everything needed to make Switchboard work, and is the exact inverse of
`switchboard uninstall`. That symmetry is deliberate: `setup` used to install
two of the three things `uninstall` removed, and the missing one — the
background service — was the difference between "setup complete ✓" and
anything actually working. It was discoverable only by running `start`,
failing to bind :443, and reading the remedy out of the error.

`--no-service` skips the last step for anyone who would rather run the daemon
themselves.

1. Mints the root CA if absent (unprivileged, pure `crypto/x509`), with name
   constraints pinning it to your suffix.
2. **sudo:** creates `/etc/resolver` if needed and writes
   `/etc/resolver/<suffix>` → `nameserver 127.0.0.1`, `port 53535`, then
   HUPs `mDNSResponder`.
3. **keychain authorization (not sudo, no root):** adds the root CA to your
   login keychain as a trusted root. macOS shows its own dialog for this —
   that is the Security framework insisting a human authorize "trust a new
   certificate authority", which is un-scriptable by design.
4. **sudo:** installs the background service — everything under `switchboard
   daemon install` below. Skipped by `--no-service`.

Run it *without* `sudo`. It elevates only steps 2 and 4. Running the whole
command as root would create the CA under `/var/root`, where nothing else
would look for it — and would put the trust in root's keychain rather than
yours.

If step 4 fails, `setup` exits non-zero and says so: the resolver and the CA
are installed, but nothing is serving, and a script that treated that as
success would be wrong about the only thing it was checking. On a platform
with no service automation yet (Linux, Windows) it is not a failure — setup
finishes and points at `switchboard start`.

### `switchboard add app 3000`

Writes a route to your config. If the daemon is running it hot-reloads within
about 200ms; if not, it tells you. Nothing privileged.

### `switchboard daemon install`

Run by `setup`; also available on its own to restart the service or to pick up
a new binary after an upgrade.

**sudo:** stages a root-owned copy of the binary, writes the LaunchDaemon
plist, and bootstraps it into the system domain. Re-run it any time to
restart the service, or to pick up a new binary after an upgrade.

Run it *without* `sudo` — same reason as `setup`. It records your uid, gid
and home directory in the plist, and under `sudo` those would all resolve to
root's.

### Day to day

```console
$ switchboard add app 3000        # https://app.test → localhost:3000
                                  # a name, not 127.0.0.1: see below
$ switchboard add app 3001        # same name again: changes the port
$ switchboard ls                  # routes and whether each upstream is up
$ switchboard doctor              # every assumption above, checked
$ switchboard daemon status       # installed, and actually serving?
$ switchboard daemon logs         # last 50 lines; -f to follow, --path for the path
```

The `<port>` shorthand becomes `localhost:<port>`, not `127.0.0.1:<port>`.
Those are different addresses, and a dev server listening on IPv6 loopback
only — the default for a lot of Node tooling — never answers on the IPv4 one.
Hardcoding `127.0.0.1` produced routes that were dead the moment they were
added and reported as `down`, which is the same word `ls` uses for a server
that is not running, so it pointed away from the cause. A name lets the
dialer try both families and take whichever answers, which is exactly what
the browser does when someone checks `localhost:3000` and concludes their app
is fine. `--upstream` is passed through untouched: naming an address is how
you say you meant that one.

This is only about the outbound connection to your dev server. Everything
Switchboard *listens* on stays pinned to `127.0.0.1` (§1).

`daemon status` asks launchd whether the job is up *and* dials the HTTPS port,
because those are different questions. Under the privileged parent the
supervisor stays alive across every child restart, so a daemon crash-looping
on an unreadable config leaves the job `running` for as long as it keeps
failing. Reporting only what launchd thinks meant the one command whose job is
to say whether Switchboard works answered yes while nothing was served.

The everyday commands also print one line when the background service is
running a different build from the binary you just ran. `brew upgrade`
replaces the binary on your PATH and cannot touch the root-owned staged copy
(§2), so the two drift on every upgrade, and the person who upgraded to get a
fix is the last one who would think to run a diagnostic.

Editing `~/.config/switchboard/config.toml` by hand works identically — the
daemon watches the file.

**Changing the suffix is the exception**, and has its own command:

```console
$ switchboard suffix internal
```

It is an operation, not a setting. It rewrites every route domain, re-issues
the CA under the new name constraint, invalidates every certificate issued so
far, and replaces `/etc/resolver/<old>` with `/etc/resolver/<new>` — the old
file left behind would keep sending that whole namespace to a responder that
no longer answers for it. Doing it by hand means knowing all four steps, and
getting the routes wrong makes the config unloadable, which takes `add`, `ls`
and `doctor` down with it.

The command shows what will change and asks before touching anything, then
restarts the background service itself. That last part is not a convenience:
between the config change and the restart, DNS sends the new suffix to a
daemon still serving the old zone and holding certificates that no longer
exist, so the machine works less well than before the command ran. A
foreground `switchboard start` cannot be restarted for you, and the command
says so instead.

### `switchboard uninstall`

Boots out and removes the launch daemon and its staged binary, and removes
the resolver file (**sudo**); removes CA trust *and* deletes the certificate
from your keychain (no root). Leaves `~/.config/switchboard` alone, so your
routes survive; delete that directory for a full reset.

---

## 5. Boot

launchd starts the parent at boot, before anyone logs in. On a FileVault Mac
your home directory is not decrypted at that moment, so the child cannot read
its config.

Rather than come up "healthy" serving zero routes — which is what a missing
config file would otherwise mean — a supervised daemon treats it as fatal and
exits non-zero. The parent backs off (1s, doubling to 30s) and retries, so
the service comes up properly within about half a minute of the home
directory becoming available. The backoff resets once the child has been up
for a minute, so a crash hours later is not punished for one at boot.

A clean exit is different from a crash: the child exiting zero is a
deliberate stop, so the parent exits zero too and
`KeepAlive{SuccessfulExit: false}` leaves the whole tree down.

---

## 6. The unprivileged mode

Set high ports in your config and nothing privileged runs at all:

```toml
http_port  = 8080
https_port = 8443
```

`daemon install` then installs a plain launch *agent* in
`~/Library/LaunchAgents` — no password, no root, no staged binary. Everything
works identically; URLs carry the port (`https://app.test:8443`).

The mode is not a preference you set, it is implied by the ports. Anything
below 1024 needs the parent; anything above it does not.

This mode is not a fallback that will be removed. It is the right answer for
MDM-managed machines, for anyone who declines a persistent root job, and — on
Windows, which has no privileged-port range at all — it is simply how the
tool works.

**One asymmetry worth knowing:** under the privileged parent, `http_port` and
`https_port` do nothing. The daemon was handed sockets already bound to 443
and 80; it did not choose them and cannot change them. It logs a warning
naming each setting that is inert rather than letting you watch a config edit
take effect on nothing.

---

## 7. What this does not claim

- **The proxy does not run as root. Switchboard does put a root process on
  your machine.** In the default configuration a small root parent runs at
  boot and supervises the daemon. That is a real thing to be aware of, and
  the honest sentence is the specific one, not "no root daemon".

- **Name constraints bound the damage from a leaked CA key; they do not
  eliminate it.** Within your suffix the key is still absolute — whoever has
  it can impersonate `app.test` to you. What they cannot do is impersonate
  your bank. See ADR 0003.

- **Loopback is the security boundary for the dashboard.** It is unauthenticated
  and bound to `127.0.0.1`. Anything already running on your machine as you can
  reach it, and that now includes everything the inspector has captured. The
  one endpoint that changes state, clearing the buffer, additionally requires
  a matching `Origin`.

- **The inspector records your own traffic to disk.** Metadata for every
  proxied request goes into `inspect.db` in the data directory, bounded by
  count, size and age. Header redaction is a fixed deny-list, so it reduces
  exposure rather than preventing it. Bodies are off unless you turn them
  on, and turning them on also turns redaction off.

- **Release binaries are not notarized.** The Homebrew cask strips the
  quarantine attribute on install. A binary downloaded through a browser needs
  `xattr -d com.apple.quarantine` before it will run.

---

## 8. Verification

Every claim above was exercised on macOS 15 (Darwin 25.5.0), not just tested
in isolation:

| Claim | How it was checked |
|---|---|
| User-domain trust works for real clients | `curl`, Go's verifier and a live TLS handshake all accept it |
| Root binds, unprivileged process serves | `lsof -iTCP:443` shows uid 501 |
| Only the socket binder is root | `ps` — root parent, user child |
| The CA cannot sign outside the suffix | `openssl` on the live root; chain verifies, `google.com` leaf rejected in test |
| Config reload survives inherited sockets | same pid and descriptor after `add`/`rm` |
| No user-writable path to root | writing the staged binary as the user is denied |
| Uninstall leaves nothing trusted | `security find-certificate` after uninstall |

The one path not yet exercised on hardware is a **reboot** — the FileVault
boot-order case in §5.
