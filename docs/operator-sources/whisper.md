# WhisperOperatorSource

The `OperatorSource` implementation backed by the [Whisper](https://whisper.security) graph. It answers
*who is accountable for this origin*, separately from and without ever influencing *which agent signed
this*. See the [README](../../README.md#operator-provenance-optional) for how to switch it on, and
[`RESOLVER-SOURCES.md`](../RESOLVER-SOURCES.md) for the contract an operator source owes its caller.

## What it sends, and where

Each origin you pass to `describe()` is sent to
`https://graph.whisper.online/api/query`, an endpoint operated by Whisper Security, as a hostname and its
registrable parent. No request content, no buyer data and no signing-key material goes with it. The only
credential that ever leaves your process is your own Whisper API key, and only if you choose to supply
one: it is sent as `x-api-key` to that same endpoint, and it changes no answer; a key the endpoint rejects is
treated as an outage, so provenance is withheld rather than wrong. Nothing is sent at all until you call
`describe()`. That call returns `null` when there is nothing yet and throws when it could
not check; the verifier treats both as no-ops, so an unreachable graph never blocks verification and is
never reported as "no operator".

## The record

A verified result carries, for example:

```json
{
  "origin": "https://www.shopify.com",
  "operator": "Shopify Inc.",
  "registry": "whisper-graph",
  "dnssec": "unchecked",
  "observedAt": "2025-03-19T15:44:35.000Z",
  "retrievedAt": "2026-09-28T14:11:27.382Z",
  "operatorSource": "registrant-corroborated",
  "registrar": "MarkMonitor, Inc.",
  "nameservers": [
    "gold.foundationdns.com",
    "gold.foundationdns.net",
    "gold.foundationdns.org"
  ],
  "firstRegistered": "2005-03-11",
  "queriedName": "www.shopify.com",
  "resolvedName": "shopify.com",
  "network": {
    "organization": "Cloudflare, Inc.",
    "abuseContact": "abuse@cloudflare.com",
    "asns": [
      "AS13335"
    ],
    "asNames": [
      "CLOUDFLARENET-AS"
    ],
    "prefixes": [
      "104.18.42.0/24",
      "172.64.145.0/24"
    ],
    "rirs": [
      "ARIN"
    ],
    "rpki": {
      "status": "valid",
      "roaOrigin": 13335,
      "maxLength": 24
    },
    "anycast": false,
    "moas": false,
    "retrievedAt": "2026-09-28T14:11:27.238Z"
  }
}
```

Five things in that record are worth reading carefully, because they are what stops it from being a
guess dressed as a fact:

- **`operator` is the registry's registrant, published only when corroborated.** A registrant string is
  accepted as the operator only when something outside WHOIS independently agrees it names this
  business. Most WHOIS is redacted or proxied, and a privacy service is a commercial product that can
  be named anything, so a source that published whatever the field contained would report
  "Identity Protection Service" as the operator of real merchants. When nothing corroborates, the
  answer is **no record**, which is the honest one.
- **`network.organization` is the CDN or host, not the merchant.** It describes the address the name
  resolves through. Most legitimate commerce is proxied, so this field is advisory context and is never
  promoted into `operator`.
- **`resolvedName` means the answer is about a different name.** Registries publish WHOIS for the
  registrable parent, so a record for `www.shopify.com` is really about `shopify.com`. Where that
  happens both names are reported rather than one being quietly substituted.
- **`observedAt` is the registry snapshot's own time; `retrievedAt` is ours.** They can be a year
  apart, and only the first one tells you how old the claim is.
- **`registrar`, `nameservers` and `firstRegistered` come from the same snapshot as `operator`**, so
  the four cannot disagree about which observation they describe. They accompany an operator rather than
  standing in for one: a record exists only when an operator was corroborated, so these deepen a record
  you already have rather than filling in for one you do not. Who a name was registered through
  separates a brand-protection registrar from a bulk reseller; the nameservers say whether the name is
  served from its own infrastructure or sits on a registrar's parking set; and `firstRegistered` is the
  creation date the registry publishes for the registration in that snapshot. All three are reproduced,
  never scored, and none of them is the merchant's age: a name is often much older than whoever holds it
  now, and a name that dropped and was re-registered carries the later registration's date.

  Registry facts therefore appear only alongside a corroborated operator, because `operator` is a
  required `string` on `OperatorRecord`.

## Absent means "not established"

Every field above except `origin`, `operator`, `registry`, `dnssec` and `observedAt` is optional, and
each one is **omitted rather than guessed**. A scalar appears only when the underlying data holds
exactly one distinct value: two ASNs is a fact about a multi-homed or anycast origin, so collapsing it
to one would assert something the data does not say, and the field is left out instead. Read an absent
field as "not established", never as "none".

## Timing and bounds

`describe()` never awaits the network. The first call for an unseen origin returns `null` and queues
the lookup in the background, so provenance appears on a later request rather than adding latency to
this one. Everything is bounded and configurable: `maxEntries`, `maxQueue`, `maxCallsPerMinute`, the
per-state TTLs, and injectable `fetchImpl` / `nowMs` / `random` / `onWarning` seams. `stats()` returns
raw counters, including each reason a record was withheld.

## Run it against the live graph

```bash
npx tsx examples/whisper-operator.ts                      # keyless
npx tsx examples/whisper-operator.ts https://your-shop.com
```
