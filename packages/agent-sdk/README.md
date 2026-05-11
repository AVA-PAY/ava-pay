# @ava-pay/agent

> **Status: developer preview (0.1.x).** The API surface and signing
> behaviour are usable for early integration and testing, but they may
> change before 1.0. The Visa mandate path in this version is
> **agent-signed**: the mandate JWS is signed with the agent's key,
> treating the agent as the authority over its own spending limits.
> A **buyer-signed / wallet-signed** authorization path (production
> grade payment authorization, where the human or the human's wallet
> signs the mandate, and the agent only relays it) is on the roadmap.
> If you're integrating against this preview, treat the verdict as
> "this signed request really came from this registered agent," not
> "this transaction is authorized by an end user."

Sign Visa Trusted Agent Protocol (RFC 9421 + Ed25519) and Google Agent Payments Protocol (AP2 mandate chain JWS) requests, from Node.js. The agent side SDK for [AVA Pay](https://github.com/AVA-PAY/ava-pay), the merchant installable verification and payment layer for AI shopping agents.

Use it from any AI agent (Claude, ChatGPT, custom) that needs to make purchases on behalf of a verified user.

## Install

```bash
npm install @ava-pay/agent
```

## Use

### Visa Trusted Agent Protocol

```ts
import { generateAgentKeyPair, signWithVisa } from '@ava-pay/agent';

const { publicKey, privateKey } = generateAgentKeyPair();

// (Register publicKey with the AVA Agent Directory once — see AGENT_ISSUERS.md
//  in the main repo. The merchant's verifier resolves your `agentId` via the
//  directory. Cache the keys.)

const signed = signWithVisa({
  method: 'POST',
  url: 'https://shop.example.com/cart',
  body: JSON.stringify({ items: [{ sku: 'TOOL-1234', qty: 1, price: 4999 }] }),
  agentId: 'agent_acme_shopping',
  privateKey,
  mandate: {
    id: `mandate_${Date.now()}`,
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
```

### Google AP2

```ts
import { generateAgentKeyPair, buildAp2Headers } from '@ava-pay/agent';

const { privateKey } = generateAgentKeyPair();

const { headers } = buildAp2Headers({
  intent: {
    agentId: 'agent_acme_shopping',
    privateKey,
    buyerId: 'user_abc',
    spendLimitMinor: 50_000,
    currency: 'USD',
    allowedMerchants: ['shop.example.com'],
  },
  cart: {
    agentId: 'agent_acme_shopping',
    privateKey,
    merchant: 'shop.example.com',
    items: [{ sku: 'TOOL-1234', qty: 1, price: 4999 }],
    totalMinor: 4999,
    currency: 'USD',
  },
});

await fetch('https://shop.example.com/cart', {
  method: 'POST',
  headers,
  body: JSON.stringify({ /* ... */ }),
});
```

### Build your own verifier

The SDK also exports the parsing primitives so you can verify on the merchant side without depending on AVA Pay:

```ts
import { parseSignatureInput, parseSignature, buildSignatureBase, verifyEd25519 } from '@ava-pay/agent/protocol/visa';
import { parseJws, verifyJws } from '@ava-pay/agent/protocol/ap2';
```

## API surface

### Top-level
- `generateAgentKeyPair(): AgentKeyPair` — fresh Ed25519 keypair
- `signWithVisa(input: VisaSignInput): SignedRequest` — RFC 9421 signer
- `buildAp2Headers(opts): Ap2Attestations` — AP2 intent + cart in one call
- `signIntentMandate(input: BuildIntentInput): string` — long-lived AP2 intent JWS
- `signCartMandate(input: BuildCartInput): string` — short-lived AP2 cart JWS
- `encodeMandate(m: Mandate): string` — base64-encode a mandate

### Types
- `Mandate`, `BuyerInfo`, `IncomingRequest`, `VerificationResult`, `VerificationFailureReason`
- `IntentMandateClaims`, `CartMandateClaims`, `JwsHeader`, `Ap2FailureReason`

### Subpath imports for low-level work
- `@ava-pay/agent/protocol/visa` — RFC 9421 parser, signature base, Ed25519 verify, content-digest
- `@ava-pay/agent/protocol/ap2` — JWS sign/parse/verify, AP2 type aliases

## Onboarding

To get an `agentId` recognized by AVA Pay merchants, register your public key with the AVA Agent Directory. See [AGENT_ISSUERS.md](https://github.com/ava-pay/ava-pay/blob/main/AGENT_ISSUERS.md) in the main repo.

## License

MIT
