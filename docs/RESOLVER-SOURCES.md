# Resolver source interfaces

This document exists so a second implementer can write a source for AVA Pay's
verifier without reading the verifier. It describes two interfaces:

- **`FederatedSource`** answers "which key belongs to this identifier?" It runs
  inside the trust decision.
- **`OperatorSource`** answers "who is accountable for this origin?" It runs
  after the trust decision and only annotates it.

They are separate on purpose, and the reason is in
[Why operator lookup is a second interface](#why-operator-lookup-is-a-second-interface).

Everything below is taken from the code. File references:
`src/verifier/federated-directory.ts`, `src/verifier/agent-directory.ts`,
`src/verifier/operator-source.ts`.

---

## 1. `FederatedSource`

A source is a named lookup from a wire key identifier to a key record. That is
the whole surface: a name for provenance, and one method.

```ts
export interface FederatedSource {
  /** Short provenance label, e.g. "visa-jwks", "wba:https://chatgpt.com". */
  name: string;
  resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null>;
}
```

`agentId` is the identifier the wire carried. For Web Bot Auth and for any
Ed25519 key resolved through a key directory that is the RFC 7638 JWK
thumbprint, base64url, 43 characters. For Visa's JWKS it is the `kid`.

`name` is provenance, not identity. It is copied onto the record the chain
returns (`AgentRecord.source`) and into the observation log, so a merchant
looking at an event can see which root of trust answered.

AVA's own sources today, as a guide to what a source looks like in practice:

| Source | `name` | Answers for | Binding |
| --- | --- | --- | --- |
| `VisaJwksKeySource` | `visa-jwks` | RSA algorithm hints only | `domain` |
| `WbaPublishedKeySource` | `wba-directory` (records `wba:<origin>`) | 43-char thumbprints, Ed25519 hints | `domain` |
| `JwksUriKeySource` | `jwks_uri` or `cimd` | 43-char thumbprints, Ed25519 hints | `url-only` |
| `asSource(name, directory)` | caller's choice | whatever the wrapped directory knows | as recorded |

---

## 2. `AgentRecord`

What a source returns on a hit.

```ts
export interface AgentRecord {
  agentId: string;
  publicKey: KeyObject;
  revoked: boolean;
  /** Which root of trust produced this record (federated resolution provenance). */
  source?: string;
  /**
   * The domain or URL the key was observed at. Reputation and events key on the
   * (key, domain) pair, not the key alone (D1): the same key seen at two
   * origins is two observations. For a well-known directory this is the origin;
   * for a jwks_uri/cimd source it is the URL.
   */
  domain?: string;
  /**
   * Binding strength of the source that resolved this key (§5.5 / D3).
   * `domain` = discovered through an origin-bound path (well-known directory,
   * Visa root); `url-only` = key continuity at an arbitrary URL with no origin
   * association (jwks_uri/cimd).
   */
  binding?: 'domain' | 'url-only';
}
```

Field by field, for an implementer:

- **`agentId`**: echo back the identifier you were asked for. The chain uses it
  as the observation-log key.
- **`publicKey`**: a Node `KeyObject`, not a JWK. Build it with
  `createPublicKey({ key: jwk, format: 'jwk' })` and return `null` if that
  throws; a key you cannot construct is a key you do not have.
- **`revoked`**: `true` is a real answer, not a miss. See the chain rules: a
  revoked record from a higher-priority source stops the chain, which is the
  point. If your source has no revocation concept, return `false`.
- **`source`**: optional. Leave it unset and the chain fills in your `name`.
  Set it when one source speaks for several roots and you want the specific one
  recorded (`WbaPublishedKeySource` sets `wba:<origin>` for exactly this
  reason).
- **`domain`**: the origin or URL you observed the key at. Reputation keys on
  the `(key, domain)` pair, so a source that resolves from several places must
  say which one answered.
- **`binding`**: `domain` if discovery was tied to an origin (a reserved
  well-known path under that origin, or a root that is itself origin-bound).
  `url-only` if you fetched from an arbitrary URL, which proves key continuity
  at that URL and nothing about any origin. If you are unsure, it is
  `url-only`; the merchant-facing policy can price the difference, and
  overstating it is the one field where a wrong answer is a security claim.

---

## 3. `ResolveHints`

Optional context from the verifier, so a multi-key root resolves the right key
instead of the first one.

```ts
export interface ResolveHints {
  /** Protocol family of the incoming request (directory keys are scoped to these). */
  protocol?: 'visa' | 'ap2';
  /** Wire algorithm, e.g. "ed25519", "rsa-pss-sha256", "ES256". */
  alg?: string;
  /** Explicit key id, when the wire distinguishes it from the agent id. */
  kid?: string;
}
```

Hints are advisory input, never a reason to widen an answer. The useful pattern
is the one our sources use: treat a hint that your source cannot satisfy as a
reason to return `null` early.

```ts
if (hints?.alg && !isEd25519Alg(hints.alg)) return null;
```

An Ed25519-hinted request whose `keyid` happens to collide with an RSA `kid` in
another root must fall through, not stop the chain with a key that can never
verify. Hints are also part of the cache identity in `CachingAgentDirectory`, so
a `visa`-hinted hit never answers an `ap2`-hinted call.

---

## 4. Chain rules

These are the rules the header of `src/verifier/federated-directory.ts` states,
and `FederatedAgentDirectory.resolve` implements them in about fifteen lines.

**The first source that KNOWS the identifier wins, including a revoked record.**
Revocation in a higher-priority root is definitive and is never shadowed by a
lower source still listing the key. A source that returns a record with
`revoked: true` ends the chain there.

**A source that ERRORS is skipped.** Each source is an independently trusted
root, so a hit in any remaining root stands on its own. The residual risk, a
revocation unreadable during an outage while a lower source still lists the key,
is accepted and documented; the alternative, failing the whole chain on any
outage, couples every protocol's availability to every root's uptime.

**A source answers `null` for identifiers that are not its shape** (wrong
format, wrong algorithm family) so an accidental `kid` collision in one root
cannot shadow the right key in another.

The consequence for an implementer is a distinction you have to get right, and
it is the only genuinely subtle thing in this interface:

| You want to say | Return | Chain behavior |
| --- | --- | --- |
| "I do not have this key" | `null` | moves to the next source |
| "Not my kind of identifier" | `null` | moves to the next source |
| "I have it, and it is revoked" | record with `revoked: true` | **stops here**, definitively |
| "I could not check" | **throw** | skipped, next source may answer |

Returning `null` when you meant "I could not check" is the dangerous mistake: it
converts an outage into a definitive miss and lets a lower-priority root answer
where a higher one might have said "revoked". Our own sources go out of their
way to avoid it. `WbaPublishedKeySource` tracks whether any origin was
unreachable and throws at the end rather than reporting a miss:

```ts
// If every origin that could have answered was down, surface it as an
// outage (skipped by the chain) rather than a definitive miss.
if (sawOutage) throw new Error('all WBA key directories unavailable');
return null;
```

A redirected key directory counts as an outage for this purpose, not a miss: per
`draft-ietf-webbotauth-httpsig-protocol-00` Section 5.5 discovery must be served
with 200 (OK) and a verifier must not follow the redirect, so there is no key
material either way.

### Provenance is recorded for you

Every hit is written to the optional append-only `KeyObservationLog`
(`keyId`, `domain`, `source`, `binding`, `revoked`, `observedAt`). A source does
not call it; the chain does. The log is only ever appended to, so a future
key-continuity check is a pass over history rather than a rebuild.

### Fetch discipline expected of a network source

Not enforced by the interface, enforced by review. Our fetching sources all do
this, and a new one should:

- https only, and only to an explicitly allowlisted origin or URL. The allowlist
  doubles as the SSRF guard.
- Never follow a redirect into a non-allowlisted origin. `JwksUriKeySource` uses
  `redirect: 'error'`; the Web Bot Auth fetcher handles hops manually and
  refuses any non-https or off-allowlist hop, capped at 3.
- Bounded response reads (64 KiB default) and a per-fetch timeout (5s default).
- Honor the published key window (`nbf`/`exp`) with a small skew.
- Cache both hits and misses, so a flood of unknown identifiers cannot turn the
  verifier into a fetch cannon.

---

## 5. `OperatorSource`

The second interface. It does not resolve keys.

```ts
export interface OperatorSource {
  /** Short provenance label, e.g. "rdap". Mirrors FederatedSource.name. */
  name: string;
  /**
   * Describe who operates `origin` (an https origin, e.g.
   * "https://www.shopify.com"). Return null when the source has no record for
   * this origin, including when the origin is not its shape.
   */
  describe(origin: string): Promise<OperatorRecord | null>;
}
```

```ts
export interface OperatorRecord {
  /** The https origin this record describes, e.g. "https://www.shopify.com". */
  origin: string;
  /** Operator name as the registry reports it. Not a trust claim on its own. */
  operator: string;
  /** Abuse contact published for the origin, when the registry publishes one. */
  abuseContact?: string;
  /** Which registry answered, e.g. an RDAP service name. Provenance, not authority. */
  registry: string;
  /**
   * DNSSEC validation state of the key-to-name binding the source checked.
   * `unchecked` means the source did not attempt validation; it is NOT a pass.
   */
  dnssec: 'valid' | 'invalid' | 'absent' | 'unchecked';
  /** ISO 8601 timestamp of when the source made this observation. */
  observedAt: string;
}
```

`OperatorRecord` is declared in the SDK
(`packages/agent-sdk/src/types.ts`) because it travels to merchants on
`VerificationResult`, and re-exported from `src/verifier/operator-source.ts` so
an implementer imports the record and the interface from one place.

### Contract

- `describe()` is called **only** for a `trusted: true` result.
- Its answer is attached at `result.operator` and changes nothing else.
  `trusted`, `conclusive`, `reason`, `discount` and `ttlSeconds` stay exactly
  what the verifier produced.
- `null` means "no record" and leaves the result untouched.
- A throw is swallowed and leaves the result untouched. An operator lookup is
  never on the critical path, so its outage is not a merchant's outage.

That last point is not a weakened fail-closed default. The fail-closed decision
was already made upstream, by the verifier, and is not revisited here: a
swallowed operator error cannot turn an unverified request into a verified one
because an unverified request never reaches `describe()` at all.

All of it lives in one function so no caller can get it subtly wrong:

```ts
export async function annotateWithOperator<T extends { trusted: boolean }>(
  result: T,
  source: OperatorSource | undefined,
  origin: string | undefined,
): Promise<T> {
  if (!source || !origin) return result;
  if (result.trusted !== true) return result;
  let record: OperatorRecord | null;
  try {
    record = await source.describe(origin);
  } catch {
    return result; // a registry outage is provenance we lack, not a trust change
  }
  if (!record) return result;
  return { ...result, operator: record };
}
```

### Wiring

An `OperatorSource` is an optional constructor argument on
`MultiProtocolVerifier`, default none:

```ts
new MultiProtocolVerifier({ visa, visaTap, ap2, webBotAuth, operator: myOperatorSource });
```

Dispatch is the right seam precisely because accountability is
protocol-agnostic: who is accountable for an origin does not depend on which
protocol proved the request came from there. With no `operator` configured,
results are byte-for-byte what the verifiers returned.

The origin passed to `describe()` is the verified agent identity
(`result.agent.id`) when that identity is an https origin, which it is for Web
Bot Auth. Protocols that identify an agent by an opaque id yield no origin and
no lookup: an opaque id is not a name a registry can be asked about, and we do
not guess one.

### Why operator lookup is a second interface

Keys and accountability are different questions, and one must never shadow the
other.

A `FederatedSource` decides whether a request verifies at all. Its answer is
load-bearing, so a wrong answer is a security failure, and the chain is built to
make outages and misses distinguishable.

An `OperatorSource` describes who stands behind an origin. Nothing about that
answer should be able to move a trust decision in either direction:

- A registry that is down, wrong, or silent must never turn a verified request
  into an unverified one. Hence: skipped, swallowed, untouched.
- A registry naming a reputable operator must never rescue a request whose
  signature did not verify. Hence: verified results only, and the record is
  attached beside the verdict rather than folded into it.

Collapsing the two, by making the registry one more link in the resolution
chain, would break both directions at once: an RDAP outage would become a
verification outage, and a well-known operator name would become an input to a
decision that only cryptography should make. Keeping them apart also keeps the
`binding` distinction honest. `domain` binding is a claim about key discovery,
not about who owns the domain; an operator record is a claim about who owns the
domain, not about any key. A merchant reading an event deserves both, labelled
separately.

---

## 6. What a real operator source owes its caller

The first planned implementation is registry-anchored: an RDAP lookup plus a
DNSSEC-validated key-to-name binding. `examples/operator-composition.ts` runs a
clearly labelled `StubOperatorSource` in its place, whose every field says
"example" where a registry value belongs and whose `dnssec` is `unchecked`,
because it checked nothing.

An adapter replacing it should hold to these:

- **`dnssec: 'unchecked'` is not a pass.** Report `valid` only for a binding the
  source actually validated. `absent` means the zone published nothing to
  validate. `invalid` means validation ran and failed, and it is a fact worth
  recording, not a reason to return `null`.
- **`registry` names who answered**, so a record is traceable to a source. It is
  provenance, not authority.
- **`operator` is the registry's string**, reproduced, not normalized into a
  judgement. The policy layer decides what a name is worth.
- **`observedAt` is when the lookup happened**, ISO 8601. Registry data is
  cached and goes stale; a merchant reading an event needs to know how old the
  claim is.
- **Return `null`, do not invent.** No record is a fine answer, and it is a much
  better one than a plausible guess.
- **Cache and bound it** the same way a network `FederatedSource` does. The same
  fetch discipline applies, minus the trust consequences.

### Run the worked example

```bash
npx tsx examples/operator-composition.ts   # network required
```

It fetches the live Shopify Web Bot Auth directory, shows the apex redirect the
draft forbids following, resolves the published key through the real chain, and
composes the stub operator record onto a verified result, then shows the same
source declining to touch one that did not verify.
