# ADR 0003 — The local CA is name-constrained

- **Status:** Accepted
- **Date:** 2026-07-31
- **Supersedes:** the "known gap vs the Rust plan" note in `DESIGN.md` §4,
  which recorded this as acceptable for v0.1
- **Affects:** `internal/proxy`, `internal/setup`, `internal/doctor`

---

## Summary

Switchboard mints its own root CA with X.509 name constraints pinning it to
the managed suffix, and hands it to Caddy's PKI rather than letting Caddy
generate one. A stolen root key can now forge certificates for `*.test` and
nothing else.

---

## Context

`switchboard setup` installs a root certificate into the system trust store.
That is the entire product — it is why the padlock is green and why there are
no warnings — and it is also the most dangerous thing the tool does.

An unconstrained root in the system trust store is a **sign-anything
capability sitting on the user's disk**. Whoever obtains the private key can
mint a certificate for their bank, their employer's SSO, or any site at all,
and that user's browser will accept it silently. The key is protected by
nothing but file permissions on a laptop that also runs `npm install`.

`DESIGN.md` §4 recorded this honestly and then set it aside:

> Known gap vs the Rust plan: Caddy's PKI does not expose X.509 **name
> constraints** on its root. Acceptable for v0.1; a potential upstream
> contribution to Caddy later.

Two things make that the wrong place to leave it.

First, the exposure is not proportionate to the feature. Everything else
Switchboard does is confined to loopback and a reserved TLD. This one artifact
reaches every HTTPS connection the machine makes, forever, to any host.

Second — and this is what forced the decision now rather than later — **the
root certificate is the one artifact that cannot be fixed after release.**
Fixing it means getting the *old* root back out of every user's trust store.
A user who ignores the upgrade keeps an unconstrained, still-trusted root.
Every other mistake in this codebase can be corrected by shipping a new
binary; this one cannot.

---

## Decision

Generate the root in `internal/proxy/ca.go` with:

```go
PermittedDNSDomains:         []string{suffix},
PermittedDNSDomainsCritical: true,
ExcludedIPRanges:            []*net.IPNet{allIPv4, allIPv6},
```

and hand it to Caddy via `caddypki.CA.Root`, which accepts a supplied PEM
keypair. Caddy still creates, signs and rotates the intermediate and every
leaf beneath it; only the root's origin changes.

`ExcludedIPRanges` is not decoration. **Name constraints are per-type**: a
`dNSName` constraint says nothing about a certificate whose SAN is an IP
address. Without those two lines a leaked key could still mint a
browser-trusted certificate for `https://<any-address>`, and the dNSName
constraint would be silently irrelevant.

### Why not upstream it to Caddy

That was the first instinct and it is the wrong sequencing. It makes the fix
depend on someone else's review cycle and release schedule, for a change that
is ~150 lines locally and that Caddy already accommodates through a supported
extension point. Contributing name-constraint support upstream remains
worthwhile; it is no longer on the critical path.

---

## Validation

The claim "the root is constrained" is worth nothing on its own. What matters
is whether verification actually *fails* for a domain outside the suffix,
through the root → intermediate → leaf chain Caddy really builds.

`TestRootConstraintIsEnforced` constructs that chain and asserts:

| Name | Result |
|---|---|
| `app.test`, `test`, `api.staging.app.test` | verifies |
| `www.google.com` | **rejected** |
| `evil.notatest` (ends in the label, not a subdomain) | **rejected** |
| `app.internal` (a reserved TLD we do not manage) | **rejected** |

`TestRootExcludesIPAddresses` covers the per-type gap above.

The Caddy integration is proved by the pre-existing
`TestWebSocketUpgradeThroughProxy`, which performs a real TLS handshake
through the embedded proxy and verifies the chain against this root. If Caddy
rejected a supplied root, or built a chain that did not lead to it, that test
would fail.

Enforcement of constraints on a locally-installed root is implemented by
macOS's Security framework, NSS/Firefox, Chrome's verifier, and Go's
`crypto/x509`. The Go verifier is what the tests above exercise directly.

---

## Consequences

### Positive

- A stolen root key is bounded to the user's own dev namespace. The
  difference between "can impersonate your bank" and "can impersonate your
  own dev machine" is the difference between a system-wide compromise and a
  local one.
- `setup` no longer starts Caddy at all. Minting the root became our own few
  lines, so the CA step is now pure `crypto/x509` — faster, and one fewer
  place where a partially-started Caddy can leave state behind.
- `doctor` can report on it. An unconstrained root is not a broken install —
  everything works perfectly — which is exactly why it needs a check rather
  than a hope.

### Negative

- **Changing `suffix` now invalidates the root.** The constraint names one
  suffix, so switching from `.test` to `.internal` requires re-issuing and
  re-trusting. `EnsureRoot` refuses rather than proceeding, and says to run
  `switchboard uninstall && switchboard setup`.

  This is a real cost, accepted because the alternative — permitting every
  suffix the tool allows, so the constraint covers whatever the user might
  later choose — grants standing authority over three reserved TLDs to
  protect against an infrequent operation. Trust-store surgery is also not
  something to perform implicitly on a config edit.

- It is a bound on damage, not a fix for a leaked key. Within the suffix, the
  key is still absolute: someone holding it can impersonate `app.test` to
  that user. The threat model this addresses is escape from the sandbox, not
  compromise within it.

- One more thing that must be true for the padlock to be green. A verifier
  that mishandles name constraints would break Switchboard where an
  unconstrained root would have worked. The four listed above all implement
  them; this is noted as the risk it is.
