# Agent issuer onboarding

If you ship an AI shopping agent — Anthropic, OpenAI, indie agent dev, anyone — this is how you make every AVA Pay merchant trust you.

## How it works

AVA Pay merchants accept *verified* agent traffic and skip *unverified* traffic into their normal bot-detection lane. "Verified" means the merchant's plugin can resolve your agent's public key in an Agent Directory and confirm your signature on the request.

You register **once**, with **one** public key, and you appear at every AVA Pay merchant — across both protocols (Visa Trusted Agent Protocol and Google Agent Payments Protocol).

## 1. Generate an Ed25519 keypair

Use any tool that produces a JWK. With Node:

```js
import { generateKeyPairSync } from 'node:crypto';
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const publicJwk = publicKey.export({ format: 'jwk' });
console.log(publicJwk);
// { kty: 'OKP', crv: 'Ed25519', x: '...' }
```

Keep `privateKey` in your wallet/secrets. Only the public JWK gets registered.

## 2. Register with the AVA Agent Directory

```bash
curl -X POST https://api.avapay.example.com/directory/agents \
  -H "Authorization: Bearer $AVA_DIRECTORY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "agent_acme_shopping",
    "issuer": "Acme Shopping Bots",
    "url": "https://acme.example.com",
    "keys": [{
      "alg": "ed25519",
      "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "<your public x>" },
      "protocols": ["visa", "ap2"]
    }]
  }'
```

You'll get back a `DirectoryAgentRecord`. Anyone can now resolve you:

```bash
curl https://api.avapay.example.com/directory/agents/agent_acme_shopping
```

> **Getting a registration token.** Email nick@lifelightlabs.com. We're not gating early issuers; the bearer token only exists to keep drive-by spam off the registry. Long term we'll move to DPoP-style proof-of-key-possession authentication so registration is fully self-serve.

## 3. Sign requests using `@ava-pay/agent`

```bash
npm install @ava-pay/agent
```

```ts
import {
  generateAgentKeyPair,
  signWithVisa,               // AVA TAP-style profile (RFC 9421 + Ed25519)
  buildCheckoutMandateChain,  // Google AP2 v0.2 (dSD-JWT mandate chains)
} from '@ava-pay/agent';

// Visa TAP path
const signed = signWithVisa({
  method: 'POST',
  url: 'https://shop.example.com/cart',
  body: JSON.stringify({ items: [...] }),
  agentId: 'agent_acme_shopping',
  privateKey,
  mandate: {
    id: 'mandate_xyz',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 600,
    maxAmountMinor: 50_000,
    currency: 'USD',
    allowedMerchants: ['shop.example.com'],
    buyer: { buyerId: 'user_abc' },
  },
});

await fetch(signed.url, {
  method: signed.method,
  headers: signed.headers,
  body: signed.body,
});

// AP2 v0.2 path — a delegated SD-JWT chain: user-signed open mandate
// (constraints + the agent's key as cnf) followed by an agent-signed
// closed mandate committing to a merchant-signed checkout.
const user = generateAgentKeyPair();   // the wallet/root key, registered in a directory
const agent = generateAgentKeyPair();  // the agent's key, delegated via cnf

const checkoutChain = buildCheckoutMandateChain({
  user: { privateKey: user.privateKey, kid: 'user_wallet_1' },
  agentPrivateKey: agent.privateKey,
  agentPublicKey: agent.publicKey,
  constraints: [
    { type: 'checkout.allowed_merchants', allowed: [{ name: 'Shop', url: 'https://shop.example.com' }] },
  ],
  checkoutJwt,                          // merchant-signed UCP Checkout JWT
  aud: 'https://shop.example.com',      // the merchant origin
  nonce: crypto.randomUUID(),           // single-use; verifiers deduplicate
});

await fetch('https://shop.example.com/cart', {
  method: 'POST',
  headers: { 'Ap2-Checkout-Mandate': checkoutChain },
  body,
});
```

## 4. Both your halves are now trusted

Every merchant who installs the AVA Pay Shopify plugin (or, soon, any other AVA Pay merchant integration) can now verify your agent. They don't need to know about you bilaterally; the directory does the introduction.

### Note: SDK publication

The SDK is live on npm as [`@ava-pay/agent`](https://www.npmjs.com/package/@ava-pay/agent) (0.2.0+), MIT-licensed, with signers for all four protocols. Source lives at `packages/agent-sdk/` in this monorepo; see its README for the full per-protocol reference.

## Field reference

### Mandate (Visa TAP)

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique mandate identifier; opaque |
| `iat` | number | Issued-at, seconds since epoch |
| `exp` | number | Expiry, seconds since epoch |
| `maxAmountMinor` | number | Spend ceiling in minor currency units (cents for USD) |
| `currency` | string | ISO 4217 |
| `allowedMerchants` | string[] | Allowlist of merchant hosts; `"*"` for any |
| `buyer` (optional) | BuyerInfo | Embed buyer identity directly in the signed mandate |

### IntentMandate / CartMandate (AP2)

Two JWS-encoded mandates, both signed with your agent key:

- **Intent**: "user authorizes me to spend up to X at merchant Y." Long-lived.
- **Cart**: "right now, I'm buying these items totaling Z." Short-lived, references the intent by `jti`.

Both ride on the request as `Ap2-Attestation` and `Ap2-Cart-Mandate` headers.

## Failure modes

If verification fails at the merchant, your agent gets back a `403` with one of:

- `unknown_agent` — you're not registered (or the directory hasn't caught up; cache TTL is 5min)
- `revoked_agent` — your registration was revoked
- `invalid_signature` / `jws_signature_invalid` — signature didn't verify
- `signature_expired` / `mandate_expired` — time window violated
- `mandate_merchant_mismatch` — your mandate didn't authorize this merchant
- `cart_exceeds_intent_limit` (AP2) — cart total exceeds intent's spend cap
- `cart_intent_mismatch` (AP2) — cart's `intent_ref` doesn't match the intent's `jti`
- `mandate_chain_mismatch` (AP2) — intent and cart signed by different agents

## Questions?

- nick@lifelightlabs.com (registration tokens, integration help)
- File an issue on the AVA Pay repo
