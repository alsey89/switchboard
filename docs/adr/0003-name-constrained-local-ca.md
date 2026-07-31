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

`switchboard setup` installs a root certificate into a trust store the
browser consults. That is the entire product — it is why the padlock is green
and why there are no warnings — and it is also the most dangerous thing the
tool does. (*Which* store was decided separately and later; see "Where the
root is trusted" below. The argument here holds either way.)

An unconstrained root in that store is a **sign-anything
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

## Where the root is trusted

Separate from *what* the root is, and decided later, after measurement:
Switchboard installs it into the **user's login keychain**, not
`/Library/Keychains/System.keychain`.

The system store requires root and grants trust to every account and every
system service on the machine. The login keychain requires no root at all and
grants trust to the one user who asked for it — which is the only one who
needs it, since both the daemon and the browser run as that user.

For a project whose entire argument is that only a socket binder is
privileged, asking for root to install a certificate authority was an
inconsistency. Removing it costs nothing that anyone has been shown to need.

**This was settled empirically, not by preference.** A throwaway
name-constrained CA was trusted in the user domain on macOS 15 and probed:

| Client | Result |
|---|---|
| `curl` | trusted |
| Go's `crypto/x509` verifier (what `doctor` uses) | trusted |
| Live TLS handshake against a leaf it signed | trusted |
| Python (`certifi`) | rejected — **and equally rejected via the system store** |
| Node (bundled CA list) | rejected — **same, needs `NODE_EXTRA_CA_CERTS` either way** |

The two rejections are not regressions: neither runtime consults the macOS
keychain in any domain. Everything that did work before still works.

One prediction did not survive contact, and the first explanation for why was
also wrong.

The user-domain dialog was expected to offer Touch ID consistently. It offered
it on one run and not the next, with an identical command, and that was
recorded here as macOS rationing Touch ID on a schedule of its own. It is not.
**Touch ID is only armed while the authorization dialog is the frontmost
window.** The dialog shows the fingerprint prompt either way; unfocused, the
sensor simply does not respond. The two runs differed in which window had
focus, not in anything macOS decided.

Corrected twice, in fact: the second attempt said the prompt "will not be
offered", which described something the user had not seen — the icon is
displayed, it just does nothing.

Worth keeping as a lesson about evidence rather than about Touch ID: given two
observations and no mechanism, the plausible-sounding story ("macOS decides")
got written down as a finding. It explained the data and was wrong, and being
wrong in a way that closed the question is the expensive part — nobody looks
for a cause they believe they already have.

Touch ID is therefore reliably available, provided the window has focus, and
`setup` now says so. It still is not the reason to prefer this design; the
privilege reduction is.

Known costs, accepted:

- `sudo switchboard doctor` cannot see the user's trust domain. It reports a
  warning explaining exactly that rather than a confident "not trusted",
  which would be a wrong answer given to someone who reached for `sudo`
  because something already looked broken.
- Anything run *as root* that needs the CA will not trust it.
- Trust does not extend to a second human account on the machine.
- It diverges from mkcert, `caddy trust` and Valet, which all use the system
  store. The divergence is deliberate and is in the direction of asking for
  less.

---

## Consequences

### Positive

- A stolen root key is bounded to the user's own dev namespace. The
  difference between "can impersonate your bank" and "can impersonate your
  own dev machine" is the difference between a system-wide compromise and a
  local one.
- Installing the CA needs no root at all — see "Where the root is trusted".
- `setup` no longer starts Caddy at all. Minting the root became our own few
  lines, so the CA step is now pure `crypto/x509` — faster, and one fewer
  place where a partially-started Caddy can leave state behind.
- `doctor` can report on it. An unconstrained root is not a broken install —
  everything works perfectly — which is exactly why it needs a check rather
  than a hope.

### Negative

- **Changing `suffix` now invalidates the root.** The constraint names one
  suffix, so switching from `.test` to `.internal` requires re-issuing and
  re-trusting. `EnsureRoot` refuses rather than proceeding, returning
  `ErrRootSuffixMismatch`; `switchboard suffix <s>` and `switchboard setup`
  catch it and rotate (untrust → delete the old root and everything issued
  under it → re-issue → re-trust), in that order.

  The first version of this shipped a dead end. `EnsureRoot` said to run
  `switchboard uninstall && switchboard setup`, but `uninstall` deliberately
  keeps the CA files — so the setup that followed hit the identical error,
  with the identical advice. Refusing an operation obliges you to check that
  the remedy you name actually reaches a working state.

  The refusal is still a real cost, accepted because the alternative — permitting every
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
