# AVA Pay

The neutral verification + payment layer for AI shopping agents.

One install on the merchant side. One registration on the agent-issuer side. **Three protocols** supported out of the box — Visa Trusted Agent Protocol (RFC 9421 + Ed25519), Google Agent Payments Protocol (AP2 mandate-chain JWS), and IETF Web Bot Auth (the signature scheme real ChatGPT agent traffic carries today). One protocol-agnostic `VerificationResult` shape downstream.

Web Bot Auth results are **agent identity only** — they prove which agent operator sent the request (e.g. `https://chatgpt.com`), not that a buyer authorized a purchase. Payment authority comes from the mandate-carrying protocols (Visa TAP, AP2).

If you're an AI agent issuer, the on-ramp is [`AGENT_ISSUERS.md`](./AGENT_ISSUERS.md) — register your public key once, every AVA Pay merchant trusts you on either protocol.

## 60-second quickstart

```bash
npm install
npm run demo            # Visa Trusted Agent Protocol (RFC 9421 + Ed25519)
npm run demo:ap2        # Google Agent Payments Protocol (JWS mandate chain)
npm run demo:wba        # IETF Web Bot Auth (identity-only, key-directory discovery)
```

You'll see a signed request and a `✓ trusted` response in well under a millisecond, on either protocol. The same primitives the demo uses (`src/sdk/index.ts` — soon `@ava-pay/agent` on npm) are what production agents would import.

## Repo layout

```
AVA Pay/
├── packages/
│   └── agent-sdk/                  # @ava-pay/agent — publishable npm package
│       ├── src/agent/{visa,ap2}.ts # signWithVisa, buildAp2Headers, signIntent/CartMandate
│       ├── src/protocol/visa/      # RFC 9421 primitives (parser, base, Ed25519 verify)
│       ├── src/protocol/ap2/       # JWS sign/verify, AP2 type aliases
│       ├── src/types.ts            # canonical shared types
│       └── src/index.ts            # public exports
├── src/                            # API server (depends on @ava-pay/agent)
│   ├── routes/verify.ts            # POST /verify, schema-validated, structured logs
│   ├── verifier/
│   │   ├── interface.ts            # AgentVerifier — the swap point
│   │   ├── multi.ts                # MultiProtocolVerifier — header-sniffs and dispatches
│   │   ├── visa.ts                 # Visa TAP verifier
│   │   ├── ap2.ts                  # AP2 verifier
│   │   ├── web-bot-auth.ts         # Web Bot Auth verifier + key-directory resolvers
│   │   ├── agent-directory.ts      # Static/Remote + 5-min CachingAgentDirectory
│   │   ├── mandate.ts              # shared mandate scope check
│   │   └── mock.ts                 # non-crypto mock for plumbing tests
│   ├── directory/
│   │   ├── types.ts                # DirectoryAgentRecord, DirectoryAgentKey
│   │   ├── storage.ts              # InMemory + File backed stores
│   │   ├── routes.ts               # /.well-known + /directory/agents (register, lookup, revoke)
│   │   └── storage-directory.ts    # adapter — verifier resolves through hosted storage
│   └── server.ts                   # buildServer — composes verifier, directory, static landing
├── public/                         # static landing page (live in-browser demo using Web Crypto)
├── examples/agent-demo.ts          # runnable Node demo (TAP + AP2 + Web Bot Auth)
├── tests/                          # 87 Vitest cases — real cryptography, no fakes
├── scripts/check-type-sync.ts      # CI guardrail against API↔plugin type drift
├── shopify-app/                    # Shopify Remix plugin (settings + traffic dashboard + theme extension)
├── AGENT_ISSUERS.md                # how AI agent issuers register with the directory
└── Dockerfile + docker-compose.yml + .github/workflows/ci.yml
```

## Status

| | |
|---|---|
| API `POST /verify` | ✅ Fastify + TypeScript + structured pino logs |
| **Multi-protocol verifier** | ✅ `MultiProtocolVerifier` sniffs the request and dispatches |
| Visa Trusted Agent Protocol | ✅ RFC 9421 + Ed25519, content-digest, mandatory alg/created/nonce, server-side max signature age |
| Google AP2 | ✅ Intent + cart mandate JWS chain, spend-limit enforcement, merchant scoping, single-use cart jti |
| **IETF Web Bot Auth** | ✅ draft-meunier-webbotauth-httpsig-protocol/-directory: `tag="web-bot-auth"`, Signature-Agent (both wire forms), RFC 7638 thumbprint keyids, allowlisted `/.well-known/http-message-signatures-directory` resolution, identity-only result (no mandate) |
| **Replay protection** | ✅ nonce + cart-jti dedup via `ReplayGuard` (in-memory now, Redis-ready interface) |
| Rate limiting | ✅ `@fastify/rate-limit`, `RATE_LIMIT_MAX`/min (default 300) |
| Fail-closed directory writes | ✅ no `DIRECTORY_REGISTRATION_TOKEN` → writes disabled (opt-in dev flag `AVA_ALLOW_OPEN_DIRECTORY_WRITES=1`); constant-time token compare |
| Agent Directory + caching | ✅ 5-min TTL, caches misses, `Remote`/`Static`/`StorageBacked` impls |
| **Hosted Agent Directory** | ✅ `/.well-known/ava-agent-directory`, register/lookup/revoke, file-backed storage |
| Public agent SDK | ✅ `packages/agent-sdk/` — `@ava-pay/agent`, ready-to-publish (17.4 kB tarball) |
| Public landing page + live demo | ✅ `public/` — Web Crypto Ed25519 in the browser, signs and verifies against a pre-seeded public demo agent |
| Agent issuer onboarding | ✅ [`AGENT_ISSUERS.md`](./AGENT_ISSUERS.md) |
| Runnable demos | ✅ `npm run demo`, `npm run demo:ap2`, `npm run demo:wba` |
| API tests | ✅ 87 with real cryptography (TAP + AP2 + Web Bot Auth + directory + caching + replay/hardening) |
| Shopify plugin | ✅ OAuth, Polaris settings, traffic dashboard, App Proxy pass-through |
| Plugin tests | ✅ 10 |
| Dockerfile + compose with Redis | ✅ |
| CI (typecheck + tests + drift + docker build) | ✅ |
| Real Visa Agent Directory wiring | ⏳ partner-gated — `VISA_AGENT_DIRECTORY_URL` swaps in zero-code |
| Real Google AP2 attestation roots | ⏳ awaiting public spec finalization |
| Redis-backed `CachingAgentDirectory` | ⏳ Redis service provisioned, swap pending |
| Published `@ava-pay/agent` npm package | ⏳ tarball builds clean, awaiting `npm publish` |
| Self-serve directory auth (DPoP) | ⏳ V1 uses bearer token; DPoP next |

## Run the API

```bash
npm install
npm run dev          # http://localhost:3000  (logs JSON to stdout)
```

Or in Docker:

```bash
docker compose up --build    # API on :3000, Redis on :6379 (ready for the cache swap)
```

## Test it

```bash
npm test                  # 87 real-cryptography tests across all three protocols + directory
npm run typecheck         # full TS strict check
npm run check:type-sync   # API ↔ plugin VerificationFailureReason drift guard
npm run demo              # in-process Visa TAP demo
npm run demo:ap2          # in-process AP2 demo
npm run demo:wba          # in-process Web Bot Auth demo
```

Web Bot Auth key discovery is allowlist-gated: the verifier only fetches
`/.well-known/http-message-signatures-directory` from origins in
`WBA_ALLOWED_SIGNATURE_AGENTS` (comma-separated https origins; defaults to
`https://chatgpt.com`, the only major agent operator publishing a live
directory as of July 2026).

## Hosted Agent Directory

When the API runs, it also exposes:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/ava-agent-directory` | Discovery — `{ service, version, count, generatedAt }` |
| `GET /directory/agents` | Public list (revoked agents hidden) |
| `GET /directory/agents/:id` | Lookup |
| `POST /directory/agents` | Register / update — bearer-token auth (`DIRECTORY_REGISTRATION_TOKEN`) |
| `POST /directory/agents/:id/revoke` | Revoke — bearer-token auth |

Storage path is `AVA_DIRECTORY_DATA` (file-backed JSON, persists across restarts). Defaults to in-memory when unset.

When `VISA_AGENT_DIRECTORY_URL` is set, the verifier resolves through Visa's hosted directory instead. When it's not, the verifier resolves through the hosted-locally `StorageBackedAgentDirectory` — meaning agents you register here are immediately resolvable by `/verify`.

See [`AGENT_ISSUERS.md`](./AGENT_ISSUERS.md) for the agent-side onboarding flow.

## Architecture

```
src/
├── index.ts                    # entry point — listens on $PORT (default 3000)
├── server.ts                   # buildServer(opts) — wires VisaAgentVerifier by default
├── routes/verify.ts            # POST /verify — schema-validates and delegates
├── types.ts                    # IncomingRequest, VerificationResult, Mandate, BuyerInfo
├── verifier/
│   ├── interface.ts            # AgentVerifier — the swap point
│   ├── visa.ts                 # VisaAgentVerifier — REAL Visa TAP verification
│   ├── http-signatures.ts      # RFC 9421 base + Ed25519 verify (Node crypto, no deps)
│   ├── agent-directory.ts      # AgentDirectory + Static + Remote + 5-min CachingDir
│   ├── mandate.ts              # decode + scope-check (shared with mock)
│   └── mock.ts                 # MockAgentVerifier — header-driven, for non-crypto tests
└── store/keystore.ts           # legacy in-memory keystore (still used by mock)
```

`VisaAgentVerifier` is the default. The route is unchanged from the mock days — only the verifier behind the `AgentVerifier` interface swapped.

## Real Visa Protocol — getting your Visa API credentials

The Trusted Agent Protocol (TAP) is published by Visa. The on-the-wire format — RFC 9421 HTTP Message Signatures + Ed25519 + a JWKS-style Agent Directory — is what `VisaAgentVerifier` already implements. What's *partner-gated* is access to Visa's hosted Agent Directory (their authoritative source of agent public keys + revocation status).

To wire that in:

1. **Apply for Visa Partners access** at https://developer.visa.com (look for "Trusted Agent Protocol" / "AI Commerce"). Anthropic, OpenAI, and the other major agent issuers are already in the directory; you'll receive `VISA_API_KEY` and the `VISA_AGENT_DIRECTORY_URL` for your environment (sandbox vs prod).
2. **Set environment variables** before starting the API:

   ```bash
   export VISA_AGENT_DIRECTORY_URL=https://agent-directory.visa.com    # provisioned per-tenant
   export VISA_API_KEY=...                                              # your bearer token
   npm run dev
   ```

   On boot, `buildServer` detects `VISA_AGENT_DIRECTORY_URL` and switches the directory from `StaticAgentDirectory` (dev) to `CachingAgentDirectory(RemoteAgentDirectory(...), 5min)` automatically.
3. **No code changes needed.** Verification, mandate scoping, content-digest enforcement, and revocation handling all flow through the same `AgentVerifier` interface.

While you wait for partner access, dev mode pre-loads an empty `StaticAgentDirectory`. The test suite uses the same primitive, generating fresh Ed25519 keypairs at test boot — that's how every assertion in `tests/verify.test.ts` exercises real cryptography end-to-end.

## Performance

The route emits an `x-ava-verify-ms` response header so we can monitor the <50 ms target end-to-end. The full Visa pipeline (parse + signature window + content-digest + cached directory hit + Ed25519 verify + mandate decode + scope check) runs in single-digit milliseconds locally; the only sub-50ms risk is a cold directory miss on first agent contact (Visa Agent Directory round-trip).

## Shopify plugin

Lives in [`shopify-app/`](./shopify-app/README.md). Two-minute install:

1. `cd shopify-app && cp .env.example .env` — fill in Partners API keys + `AVA_PAY_API_URL`.
2. `npm install && npm run setup && npm run dev` — Shopify CLI tunnels and opens the install on your dev store.
3. In your dev store theme editor: **Online Store → Customize → App embeds → AVA Pay → ON**.

Or, instead of step 3, paste this single line into `theme.liquid`:

```liquid
<script async src="{{ shop.url }}/apps/ava-pay/embed.js"></script>
```

Storefront pages now ping the App Proxy → AVA Pay `/verify` → mint a one-time discount code → redirect verified agents through `/discount/AVA-XXXXXXXX`. Merchant policy (toggle + max-cap) is configured in the embedded admin UI; full architecture diagram and dev walkthrough live in [`shopify-app/README.md`](./shopify-app/README.md).
