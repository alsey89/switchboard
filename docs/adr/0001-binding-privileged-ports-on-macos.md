# ADR 0001 — Binding privileged ports on macOS

- **Status:** Accepted
- **Date:** 2026-07-30
- **Supersedes:** the "lucky break #1" premise in `DESIGN.md` §5
- **Affects:** `internal/daemon`, `internal/setup`, `internal/service`, `internal/proxy`, the install story, and the project's core positioning
- **Revised before merge:** the chosen option changed from a privileged *peer*
  passing descriptors over a Unix socket to a privileged *parent* passing them
  by inheritance. Both forms are documented; the reasoning for the change is in
  "Considered and rejected". Three secondary corrections are marked inline where
  an earlier draft was wrong.

---

## Summary

Switchboard v0.1 was designed around the claim that macOS lets unprivileged
processes bind ports below 1024. **That claim is false.** The daemon cannot
bind `:80` or `:443` as an ordinary user, so the headline UX — `https://app.test`
with no port suffix — is unreachable without privilege somewhere.

After weighing four options we chose **a small privileged parent that binds the
sockets, drops privileges, and spawns the daemon as the user — passing the
listeners by fd inheritance**. This keeps "the proxy does not run as root" true,
at the cost of one tiny root component.

An earlier revision of this ADR chose a variant of the same idea in which the
privileged component was a *peer* rather than a *parent*, handing descriptors
over a Unix socket with `SCM_RIGHTS`. That variant is recorded below because the
reasoning that killed it is the most useful thing in this document: making the
helper the parent turns fd transfer from a negotiation into an inheritance, and
an entire class of authorization problem simply ceases to exist.

---

## Context: how we got here

### The original premise

`DESIGN.md` §5 listed two "lucky breaks" that justified the whole architecture:

> 1. **Since Mojave (10.14), unprivileged processes may bind ports < 1024** —
>    the daemon binds :80/:443 as the user. No root, no helper daemon.

Everything followed from this. The README's second line is *"No `/etc/hosts`
editing. No root daemon."* `DESIGN.md` §1 positions against competitors partly
on it. §5 concludes: *"Total privileged surface: two one-shot admin prompts in
`setup`, ever."*

### The premise is wrong

Measured on Darwin 25.5.0 as uid 501:

| Bind target | Result |
|---|---|
| `127.0.0.1:443` | `bind: permission denied` |
| `127.0.0.1:80` | `bind: permission denied` |
| `127.0.0.1:1023` | `bind: permission denied` |
| `127.0.0.1:1024` | OK |
| `127.0.0.1:8443` | OK |

macOS enforces the classic privileged-port boundary exactly like every other
Unix. There is no Mojave-era exemption.

Running the daemon confirms it end to end:

```
$ switchboard start          # default ports
INFO msg="dns responder up" addr=127.0.0.1:53535 suffix=.test
error: proxy cannot bind 127.0.0.1:443: permission denied.

$ switchboard start          # http_port = 8080, https_port = 8443
INFO msg="dns responder up" addr=127.0.0.1:53535 suffix=.test
INFO msg="proxy up" https=127.0.0.1:8443 routes=0 dashboard=https://switchboard.test
```

Two observations that shaped the decision:

1. **It is not a daemon problem.** `switchboard start` in a plain terminal
   fails identically. Binding is what needs privilege, not the thing that
   launches it. Dropping the background service would not have helped.
2. **Everything else already works.** On high ports the daemon comes up
   cleanly: DNS, proxy, TLS, dashboard. The defect is narrowly about which
   port number the listener may claim.

### Why this surfaced now

The bug is pre-existing v0.1, but the v0.2 branch made it a shipping problem:

- **The launchd agent amplifies it.** `KeepAlive{SuccessfulExit: false}` means a
  daemon that exits non-zero on a bind failure is relaunched forever, throttled
  to roughly every 10 seconds, appending to a log with no rotation. What used to
  be one visible terminal error became a silent crash-loop.
- **The Homebrew cask advertises it.** The cask's `caveats` tell every new user
  to run `switchboard daemon install` as step 2 of 2.
- **The error message argued with reality.** `internal/daemon/daemon.go` printed
  *"(macOS 10.14+ allows this without privileges.)"* directly beneath the
  permission-denied error it was explaining.

It was found by the final whole-branch code review of the v0.2 branch — no
per-task review could see it, because no single task was responsible for the
premise.

---

## Constraints that shaped the decision

These are the things any option had to survive:

1. **A trusted root CA is already installed.** `switchboard setup` puts a CA
   into the System keychain, and per `DESIGN.md` §4 Caddy's PKI cannot express
   X.509 name constraints — so that CA is *not* scoped to `.test`. Users are
   already extending significant trust.
2. **The config is user-writable by design.** `~/.config/switchboard/config.toml`
   is meant to be hand-edited, and `upstream` accepts an arbitrary `host:port`.
3. **The CA private key currently lives under `~/.config/switchboard/data`.**
4. **`CGO_ENABLED=0`.** Release binaries cross-compile from Linux; anything
   requiring cgo is disqualified. **This constraint was challenged and
   re-examined** — see "launchd socket activation" below. It is self-imposed and
   relaxable, so it is not allowed to settle any argument by itself.
5. **No new modules in the build graph.**
6. **macOS first.** Windows lands in v0.4, Linux in v0.5 — but whatever we
   choose should not be gratuitously unportable.

---

## Options weighed

### Option 1 — High ports only

Default `https_port = 8443`, `http_port = 8080`. Nothing privileged anywhere.

- **For:** Zero privilege at any point. Works today with no code changes. No
  new components, no new failure modes.
- **Against:** Every URL becomes `https://app.test:8443`. This attacks the
  product's core promise — `DESIGN.md` §1 sells "local domains" against
  competitors, and a port suffix is the visible mark of a dev server.

  The cost is **not** purely cosmetic, and an earlier draft of this ADR was
  wrong to say so. `https://app.test:8443` and `https://app.test` are
  **different origins**, which changes real behaviour: CORS allow-lists,
  `postMessage` target origins, `localStorage`/IndexedDB partitioning, and
  service-worker scope all key on the port. Cookies are the exception that
  makes this *feel* cosmetic — cookies are not port-scoped, so they survive.
  And OAuth providers commonly reject redirect URIs on non-standard ports
  outright, which is exactly the workflow a local-domain tool exists to make
  pleasant.
- **Verdict:** Rejected as the default. Retained as the documented workaround,
  as the current v0.2 behaviour, and as the supported zero-privilege mode for
  CI and sandboxes.

### Option 2 — Full root daemon

A `/Library/LaunchDaemons` entry running the whole daemon as root.

- **For:** Simplest and most robust. It is what puma-dev and Valet effectively
  do; nobody would call it negligent for a single-user dev machine.
- **Against:**
  - **Privilege escalation surface.** A root process reading a *user-writable*
    config, where `upstream` is an arbitrary `host:port`, lets anything that can
    write that file steer root's network connections. A root process reading and
    writing a user-owned storage directory is also a symlink-attack surface.
    Taking root therefore *requires* migrating both the config and the CA
    storage to root-owned paths, and making `switchboard add` either privileged
    or mediated by validated IPC. That is substantial work.
  - **Blast radius.** Embedded Caddy plus 139 linked modules — quic-go,
    smallstep, and the rest — all running as root, listening on `:80`/`:443`.
    Any RCE in that tree is immediate root.
  - **Caddy's own project does not do this.** The standard Caddy install runs
    as a dedicated user with `CAP_NET_BIND_SERVICE`. Running embedded Caddy as
    root does something upstream deliberately avoids.
  - **Positioning.** "Trust my root CA" is already a large ask. "Trust my root
    CA *and* let my proxy run as root permanently" is qualitatively larger.
  - **Practical friction.** Managed corporate Macs frequently block or audit
    `/Library/LaunchDaemons` while permitting user agents. A cask installing a
    LaunchDaemon needs elevation at both install and uninstall. **In fairness,
    this objection does not distinguish Option 2 from Option 4** — both need a
    LaunchDaemon plist, so both face the identical install surface. Option 4
    differs only in what that plist launches. Keeping the comparison honest:
    this is an argument against persistent-root-anything, not against Option 2
    specifically.
- **Verdict:** Rejected. The blast radius and the escalation surface are the
  deciding factors, not the install mechanics. Since it demands the config and
  CA-storage migration anyway, it is not meaningfully cheaper than Option 4.

### Option 3 — `pf` redirect

During `setup` (which already elevates), install a `pf` anchor redirecting
`443 → 8443` and `80 → 8080` on loopback. The daemon binds high ports and stays
fully unprivileged.

- **For:** **Best security profile of all options** — zero privileged processes
  at runtime, root only during `setup`, which already happens. Clean URLs
  preserved. Nothing long-lived to attack.
- **Against:** Persistence is genuinely fiddly. macOS loads `/etc/pf.conf` at
  boot, so surviving a reboot means editing a system file and adding an anchor,
  then reloading with `pfctl`. Editing `/etc/pf.conf` is invasive and collides
  with other tools that do the same (VPNs, Docker, corporate agents). Debugging
  a silently-dropped anchor is unpleasant, and `uninstall` must reliably undo a
  system file edit.
- **Verdict:** Rejected reluctantly. It is the most secure option and remains
  the best fallback if Option 4 proves unworkable. The deciding factor was
  operational fragility, not security. Note that the gap narrowed once Option 4
  was found to need a LaunchDaemon of its own: `pf` needs root at `setup` time
  and never again, which is still strictly less persistent privilege than any
  helper design.

### Option 4 — Privileged parent, unprivileged child **(chosen)**

A small root process binds `:80` and `:443`, then spawns the daemon as the
invoking user, passing the bound listeners as inherited file descriptors. The
daemon never binds a privileged port; it starts life already holding them.

In Go this is `(*net.TCPListener).File()` into `exec.Cmd.ExtraFiles`, with
`SysProcAttr.Credential{Uid, Gid}` to set the child's identity. The parent then
supervises: it waits on the child and, if the child dies unexpectedly, respawns
it with the same descriptors.

- **For:**
  - Clean URLs preserved.
  - The privileged component's entire job is "bind two sockets, drop, exec,
    supervise" — small enough to audit in one sitting, and its security
    argument fits in a paragraph.
  - Caddy and all 139 modules stay unprivileged. "The proxy does not run as
    root" remains true and honest.
  - No config or CA-storage migration required, because root never reads the
    user's config.
  - **No IPC surface at all.** There is no socket for a hostile process to
    connect to, no peer-credential check to get right, no one-shot-versus-
    reconnect dilemma, and no ordering problem between two independently
    supervised services. This is the decisive advantage over the socket variant.
  - Respawning the child with the *same* listeners means `:443` is never
    unbound during a restart.
  - It is the classic bind-then-drop-privileges pattern — nginx, sshd, and
    every inetd descendant.
  - It is portable in shape. The same parent/child split works on Linux, and
    the Windows story in v0.4 does not need a macOS-specific mechanism carved
    out of it.
- **Against:**
  - A new long-lived root process, however small.
  - Requires a `/Library/LaunchDaemons` entry, so `setup` gains a privileged
    install step and `uninstall` gains a privileged removal step. The "two
    admin prompts, ever" claim in `DESIGN.md` §5 must be restated.
  - **Two supervisors.** launchd's `KeepAlive` watches the parent, not the
    child. If the child dies and the parent does not notice, launchd sees a
    healthy job and does nothing. The parent must therefore be a real
    supervisor, with backoff — this is code that has to be correct.
  - The child cannot be restarted by launchd directly (`launchctl kickstart`
    knows only about the parent). In practice this is fine: killing the child
    makes the parent re-exec it from the binary path, which is also how a
    `brew upgrade` takes effect without a second sudo prompt.
  - Privilege still has to come from *somewhere* at install time.
- **Verdict:** **Accepted.**

#### Modes

The same parent/child architecture supports two persistence models, and both
should ship:

| Mode | Supervisor | Privilege | For |
|---|---|---|---|
| `sudo switchboard run` | the user's terminal | one sudo prompt per run, nothing persistent | machines that forbid LaunchDaemons, debugging, and anyone who refuses persistent root |
| LaunchDaemon | launchd, `KeepAlive` | one privileged install, then always-on | the default: survives reboots, matches the "set it up once" pitch |

The insight worth keeping is that these are the *same program*. Whether the
privileged parent is started by a terminal or by launchd is a persistence
choice, not an architectural one.

**Manual mode is not the default**, and shipping it as the only mode was
considered and rejected. It would mean a sudo prompt every session, a manual
start after every reboot, an occupied terminal, and nothing bringing the proxy
back when it dies at 11pm — making "it's down because I forgot to start it" the
most common failure mode of a tool whose entire pitch is that `app.test` just
works. It also makes the user's shell session the supervisor, dragging sudo
timeouts, closed laptops, and terminated SSH sessions into the reliability
story. The sharpest version of the problem: the DNS responder lives in the same
process, so manual-only makes `.test` resolution itself intermittent — and
browsers cache negative DNS answers and HSTS state, so the failures are sticky
and present as "Switchboard is broken" rather than "Switchboard isn't running."

### Considered and rejected

- **Privileged *peer* + `SCM_RIGHTS` over a Unix socket.** The original choice
  in this ADR, superseded by Option 4 above. A root helper binds the ports and
  hands descriptors to a separately-launched daemon over a Unix socket. It
  works — it was validated end to end (see below) — but it introduces an
  authorization problem that the parent/child form does not have: *anyone* who
  can connect to that socket can receive `:443`, and with a trusted CA already
  in the keychain, a hostile receiver could MITM every local domain with no
  browser warning. Defending it needs socket mode and ownership, root-owned
  parent directories, `LOCAL_PEERCRED` peer checks, and a policy for repeat
  handovers after a daemon restart — all of which the inheritance form deletes
  outright. It also has a genuine startup-ordering failure mode between two
  services that launchd supervises independently.

  Retained here because it remains the fallback if the parent/child form hits
  something unforeseen, and because its one real advantage is worth recording:
  the daemon can restart entirely independently of the privileged component.

- **launchd socket activation.** Conceptually the best fit for the platform:
  launchd binds the privileged socket and hands it to a job running under an
  unprivileged `UserName`, so Apple's code is the privileged helper and the
  authorization question largely dissolves.

  The original dismissal — "needs cgo, disqualified by constraint 4" — was too
  quick, and the constraint was doing more work than it had earned.
  Re-examined properly, it is still rejected, for three better reasons:

  1. **It removes no privileged surface.** Binding `:443` still requires a
     `/Library/LaunchDaemons` plist, so the privileged install and uninstall
     steps remain exactly as they are under Option 4. The thing it saves is the
     helper *process*, not the elevation.
  2. **It is macOS-only.** v0.4 is Windows and v0.5 is Linux. Option 4's shape
     ports; `launch_activate_socket` does not.
  3. **The cgo escape is real but expensive.** Retrieving the socket needs
     `launch_activate_socket` from libSystem, which means either cgo — and
     therefore building darwin artifacts on a macOS runner, since GoReleaser's
     split-build-and-merge across runners is a Pro feature — or a pure-Go
     dlopen shim like `purego`, which violates constraint 5. Neither is
     impossible; both cost more than Option 4 saves.

  Recorded as *re-examined and held*, not as *ruled out by fiat*.

- **setuid binary.** A setuid-root Go binary is a well-known bad idea; the Go
  runtime starts threads before `main`, and the attack surface is the entire
  program rather than a bind call.
- **Granting the binary an entitlement / codesign capability.** macOS has no
  `CAP_NET_BIND_SERVICE` equivalent available to third-party developers.
- **Asking users to `sudo switchboard start`** — that is, running the *whole*
  daemon as root in the foreground. Rejected for the same reason as Option 2,
  plus a path bug: `os.UserHomeDir` resolves to `/var/root` under sudo, so
  `setup` and `start` would disagree about where the CA lives. Note that
  `sudo switchboard run` (above) is a *different* thing — there, root binds and
  immediately drops before anything touches the CA.

---

## Decision

**Adopt Option 4: a privileged parent binds `:80`/`:443`, drops privileges, and
spawns the unprivileged daemon with the listeners inherited as file
descriptors.** Ship it in both modes — foreground `sudo switchboard run` and a
LaunchDaemon-supervised persistent form.

Retain high ports (Option 1) as the supported, documented fallback for anyone
who prefers zero privileged components — including CI and sandboxed
environments.

Keep Option 3 (`pf`) on file as the fallback if the parent/child form hits
something unforeseen. Keep the `SCM_RIGHTS` peer variant on file as the fallback
if the daemon ever genuinely needs to restart independently of the privileged
component.

---

## Validation performed before accepting

Two load-bearing mechanism assumptions, both checked rather than assumed.

### 1. Pure-Go descriptor passing works on macOS without cgo

Validated when the `SCM_RIGHTS` peer variant was the leading candidate. A
two-process harness where a "helper" binds a TCP listener, passes the descriptor
with `syscall.UnixRights` and `(*net.UnixConn).WriteMsgUnix`, then closes its own
copy; a separate process reads it with `ReadMsgUnix`,
`ParseSocketControlMessage`, and `ParseUnixRights`, reconstructs a listener via
`os.NewFile` + `net.FileListener`, and serves HTTP on it.

```
HELPER bound 127.0.0.1:49520
HELPER passed fd, dropping the listener
DAEMON received listener for 127.0.0.1:49520
RESULT: HTTP 200 "served-by-unprivileged-daemon"
```

Pure Go, no cgo, on Darwin 25.5.0. This result carries over: it proves a bound
listener survives transfer to another process and serves correctly, which is
equally the premise of the inheritance form.

### 2. Go drops privileges correctly on darwin, in pure Go

The inheritance form needs `SysProcAttr.Credential` to actually take effect on
darwin without cgo. Confirmed by reading the runtime's fork/exec path
(`$GOROOT/src/syscall/exec_libc2.go`): the child calls `setgroups`, then
`setgid`, then `setuid` — the correct order, since `setuid` first would forfeit
the privilege needed for the other two — and this happens *before* the
descriptor shuffle and the `exec`. `ExtraFiles` are installed into the child
after the credential drop, which is harmless because the sockets are already
bound. The mechanism is sound.

### Note on what fd passing does *not* affect

Descriptor transfer, by either mechanism, is invisible above the socket layer.
The kernel does not record which process called `bind()`; once the daemon holds
the descriptor, `accept()`, TLS, and HTTP behave identically to a
directly-bound listener. The browser sees `https://app.test` on port 443 either
way, so origin, cookies, CORS, `postMessage`, and OAuth redirect URIs are all
unchanged. This matters because it is precisely the property Option 1 lacks.

---

## Open questions (must be settled before implementation)

The parent/child form dissolved the original open question — "who may receive
the descriptors" — by removing the socket entirely. Three smaller ones remain,
and the first is the one that actually matters.

### 1. Which ports may the privileged parent bind?

**The parent must not learn its ports from the user-writable config.** If it
does, Option 2's escalation is rebuilt in miniature: a hostile config sets
`https_port = 631` and root binds CUPS's port, then hands it to a process the
attacker controls. "Root will bind whatever port you name" is a
capability-granting primitive no matter how few lines implement it, and the
danger is the *unclaimed* privileged ports — 88, 548, 631 — not the ones
already in use.

Resolution: the parent hardcodes 80 and 443, or validates against an allowlist
in a root-owned file written at install time. It reads the user's config never.
This applies identically to the `SCM_RIGHTS` variant; the earlier draft asked
who may *receive* a descriptor and failed to ask what they may receive.

### 2. Where does the target uid come from?

Under `sudo switchboard run`, `SUDO_UID` and `SUDO_USER` are present but must be
read deliberately — `os.UserHomeDir` resolves to `/var/root` and would put the
CA somewhere `setup` will never look. Under launchd there is **no** `SUDO_UID`
at all, because no sudo happened.

Resolution: both modes take the target uid and home directory as explicit
arguments, and `daemon install` writes them into the root-owned plist. Nothing
is inferred from the ambient environment at runtime.

### 3. Supervision and lifecycle

The parent must supervise the child with backoff rather than relying on
launchd, which only sees the parent. Exit semantics need to be pinned down:
child exits zero (a deliberate `switchboard stop`) → parent exits zero →
`KeepAlive{SuccessfulExit: false}` leaves it down. Child dies unexpectedly →
parent respawns with the same descriptors. `uninstall` must remove the plist and
stop the tree.

---

## Consequences

### Positive

- `https://app.test` works with no port suffix, on the real origin.
- The proxy, TLS stack, and all 139 linked modules remain unprivileged.
- No config or CA-storage migration needed — root never reads the user's config.
- The claim "Switchboard's proxy does not run as root" stays truthful.
- **No IPC attack surface.** There is no socket, no peer authentication, and
  nothing for a hostile local process to connect to.
- Users who refuse persistent root get a first-class mode rather than a
  degraded one, and it is the same code path.
- Restarts do not leave `:443` unbound, since the child is respawned with the
  descriptors already held.

### Negative

- A new root component and a new privileged install/uninstall step.
- `DESIGN.md` §5's "two admin prompts, ever" is no longer accurate and must be
  restated.
- The parent is a supervisor, which is real code with real failure modes
  (backoff, exit-code semantics, not hot-looping on a child that cannot start).
- The daemon can no longer be restarted independently of the privileged parent
  by launchd. Killing the child is the supported path; it re-execs from the
  binary path, which incidentally makes `brew upgrade` take effect without a
  second sudo prompt.
- Anything requiring the parent to change its ports requires a privileged
  reinstall, by design (see Open Question 1).

### Immediate changes shipped in v0.2 (the minimum, ahead of the parent)

The privileged parent is its own piece of work, gated on the open questions
above. v0.2 ships the honest interim state:

1. `DESIGN.md` §5's "lucky break #1" corrected from a solved property to an
   open problem.
2. `internal/daemon/daemon.go`'s bind-failure message rewritten to name the
   real cause and point at the `http_port` / `https_port` escape hatch, instead
   of asserting that macOS permits the bind.
3. `switchboard daemon install` refuses, with an actionable message, when the
   configured ports are below 1024 and cannot be bound — so it can no longer
   install an agent that crash-loops.

---

## Appendix — other decisions made during the v0.2 cycle

Recorded here because they were weighed deliberately and would otherwise be
invisible in the diff.

| # | Decision | Chosen | Why |
|---|---|---|---|
| A | Domain suffix policy | Reserved single-label TLDs (`test`, `internal`, `localhost`) **or** any multi-label domain the user owns | A bare non-reserved TLD is, or could become, real. `/etc/resolver/dev` would send `go.dev`, `web.dev` and `*.workers.dev` to 127.0.0.1 machine-wide. HSTS is *not* the reason `.dev` is unsafe — Switchboard serves genuinely trusted HTTPS, so HSTS is satisfied; the namespace collision is the harm. |
| B | Default suffix | Stays `test`, not `internal` | Corporate VPNs hand out real `*.internal` names; a `/etc/resolver/internal` file would hijack them. `.test` (RFC 6761) carries no such risk. |
| C | Dashboard hostname | Stays `switchboard.<suffix>` | The reserved label cannot be used for a user route, so squatting a generic word like `dashboard` would take a plausible project name away from every user. |
| D | WebSocket test dependency | `golang.org/x/net/websocket` over a hand-rolled handshake | `x/net` was already an indirect dependency, so this adds no module. Decisive reason: hand-rolling `Sec-WebSocket-Accept` on both the fake upstream *and* the client assertion fails **self-consistently** — a wrong computation passes the test while a real browser breaks. |
| E | launchd `ProcessType` | Key omitted entirely (launchd default `Standard`) | `Background` places the job in a throttled I/O and CPU band, wrong for a proxy the browser hits constantly. `Adaptive` transitions based on **XPC** activity and Switchboard uses no XPC, so it would likely stay throttled. `Interactive` over-claims. |
| F | Third-party attribution | Generate `THIRD_PARTY_NOTICES` from the build graph with a toolchain-only script | The binary statically links ~139 modules; MIT and BSD both require their full text accompany binary redistribution, and `NOTICE` named two. Using `go list` avoids installing any license-scanning tool. |
| G | Homebrew distribution | `homebrew_casks:`, not `brews:` | GoReleaser escalated the `brews` deprecation to a hard error in v2.17, and the workflow floats to latest v2 — the first real tag push would have failed CI. Casks quarantine their payload (formulae do not), hence the `xattr -dr com.apple.quarantine` post-install hook, and `uninstall.launchctl` so `brew uninstall` does not orphan the launch agent. |
| H | Attribution scope | `go list -deps ./cmd/switchboard`, GOOS-union across darwin and linux | Test-only dependencies are not redistributed and carry no obligation. The dependency **set** is GOOS-dependent even when the **count** is identical (139 on both) — `howett.net/plist` on darwin, `github.com/prometheus/procfs` on linux — so a count-based check silently passes while Linux archives ship the wrong list. |
