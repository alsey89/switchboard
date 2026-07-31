# ADR 0002 — Where the daemon's listening sockets come from

- **Status:** Accepted
- **Date:** 2026-07-31
- **Affects:** `internal/listen`, `internal/daemon`, `internal/proxy`, and the
  shape of the Windows (v0.4) and Linux (v0.5) ports
- **Relates to:** [ADR 0001](0001-binding-privileged-ports-on-macos.md), which
  chose the privileged parent. This decides the interface it hands sockets across.

---

## Summary

The daemon does not bind its own listening sockets. It asks a `listen.Set`
for a socket by name and receives either one inherited from a privileged
parent or one freshly bound. Callers do not branch on which.

This is a separate decision from ADR 0001 because it is the part that
outlives the mechanism. ADR 0001 picked *how* macOS gets a privileged socket.
This picks *what the daemon knows about it*, and the answer — as little as
possible — is what stops the Windows and Linux ports from each needing their
own carve-out in startup.

---

## Context

ADR 0001 constraint 6 said: "macOS first. Windows lands in v0.4, Linux in
v0.5 — but whatever we choose shouldn't need a macOS-specific mechanism
carved out later." It then chose a mechanism without saying what the seam
was, which is how that constraint gets quietly violated: the first
implementation reaches into `daemon.Run`, and by v0.5 there are three
platform branches through the startup path.

The three platforms genuinely differ, and not in degree:

| Platform | Privileged ports? | Mechanisms available |
|---|---|---|
| macOS | Yes, `<1024` | Privileged parent (ADR 0001), launchd socket activation (needs cgo) |
| Linux | Yes, `<1024` | The same parent, `setcap cap_net_bind_service`, systemd socket activation |
| Windows | **No** | None needed — any user can bind `:443` |

Windows is the important row. It is not a platform with a harder version of
the problem; it is a platform with *no* problem. A design that assumes
privilege must be acquired somehow would have Windows implementing a no-op
version of a ceremony that exists for someone else's operating system.

---

## Decision

`internal/listen` defines a `Set`:

```go
set.Listen(name, addr)  // the inherited socket, or a fresh bind of addr
set.Inherited(name)     // did this come from a parent?
set.Addr(name)          // what address is it really on?
```

The zero value is valid and means "inherited nothing", so the unprivileged
path is not a special case — it is the empty case.

**The daemon's contract is: I need a socket called `https`. I do not care
where it came from.** On Windows the Set is always empty and every call binds
normally, with no platform branch anywhere in startup. On macOS today, and
Linux tomorrow, a parent may have filled it.

Descriptors arrive by inheritance across `exec`, described by
`SWITCHBOARD_LISTEN_FDS=https:3,http:4`. Names travel with numbers
deliberately: a positional contract does not fail when someone reorders the
parent's bind calls, it silently serves HTTPS on the plaintext port.

### What is deliberately not in the Set

**DNS.** The resolver file names a port — `/etc/resolver/test` says
`53535` — so the DNS responder never needs `:53` and therefore never needs
privilege. Keeping it out means the privileged parent holds exactly two
descriptors and knows nothing about UDP.

**The dashboard.** Loopback, high port, no reason to be privileged.

`listen.Names()` is therefore two entries long, and
`TestNamesAreTheCompleteParentContract` pins it. Every name added there is
another socket root opens on the user's behalf, so growing the list should be
a decision, not a diff.

---

## Consequences

### The Caddy problem, and the bug it would have caused

Caddy binds from the addresses in its own config, so an inherited socket
needs `caddy.RegisterNetwork`: addresses appear as
`sbinherit/127.0.0.1:443` and resolve to the descriptor we already hold.

More important, and not obvious until you look for it: **Caddy closes its
listeners on every config reload.** For a socket Caddy bound itself, that is
correct. For an inherited one it is unrecoverable — the descriptor came from
a parent that is no longer root, so once closed nothing in the process can
ever bind `:443` again. The first time a user edited their config, the site
would go down and stay down, with no error that pointed anywhere near the
cause.

Inherited listeners are therefore wrapped so `Close` is a no-op
(`listen.KeepOpen`). The lifetime of a descriptor belongs to the process that
bound it, not to the library serving on it.

### HTTP/3 is off

Enabling h3 makes Caddy bind a UDP socket on the same port. For `:443` that
is a second privileged bind the parent would have to hold and pass. Local
browsers negotiate h2 over TLS; h3 buys nothing here and costs an extra
descriptor in the root-owned path.

### The config's port settings become conditional

Under a privileged parent, `https_port` and `http_port` describe sockets the
daemon did not choose and cannot change. The daemon logs a warning naming
each setting that is inert rather than letting it appear to work. See ADR
0001's "Which ports may the privileged parent bind?" — the parent never reads
these values at all, which is the point.

### For v0.4 and v0.5

Windows implements nothing. Linux gets to choose between the parent (already
written, since `Credential` and `ExtraFiles` are POSIX), `setcap`, or
systemd socket activation — and that choice becomes a `Set` constructor
rather than a change to how the daemon starts.
