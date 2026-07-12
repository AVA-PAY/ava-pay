# @ava-pay/agent

> **Status: developer preview (0.2.x).** The API surface may change before
> 1.0. **0.2.0 is a breaking release**: the AP2 v0.1 Intent/Cart API
> (`buildAp2Headers`, `signIntentMandate`, `signCartMandate`) was removed in
> favor of AP2 v0.2 dSD-JWT mandate chains — see the AP2 section below.
>
> Be clear about what each protocol's verdict means. Web Bot Auth and
> browse-intent Visa TAP prove **agent identity** ("this request really came
> from this agent operator") — not that an end user authorized a purchase.
> The AVA TAP-style profile's mandate is **agent-signed** in this preview.
> AP2 v0.2 chains carry a **user-rooted delegation** (the root mandate is
> signed by the user/wallet key and delegates to the agent's key), which is
> the closest thing here to end-user payment authorization.

Sign AI-agent requests for all four protocols the [AVA Pay](https://github.com/AVA-PAY/ava-pay) merchant-side verifier accepts, from Node.js (≥20, zero dependencies):

- **Visa Trusted Agent Protocol** (real wire format: `agent-browser-auth` / `agent-payer-auth` tags)
- **IETF Web Bot Auth** (the scheme real ChatGPT agent traffic uses)
- **Google Agent Payments Protocol v0.2** (dSD-JWT Checkout / Payment mandate chains)
- **AVA's TAP-style profile** (RFC 9421 + Ed25519 + `x-ava-mandate`)

Plus the parsing/verification primitives to build your own merchant-side verifier.

## Install

```bash
npm install @ava-pay/agent
```

## Use

### Visa Trusted Agent Protocol (real wire format)

```ts
import { generateAgentKeyPair, signWithVisaTap } from '@ava-pay/agent';

const { privateKey } = generateAgentKeyPair(); // Ed25519; RSA keys work too (rsa-pss-sha256)

const signed = signWithVisaTap({
  url: 'https://shop.example.com/products/tool-1234',
  privateKey,
  keyid: 'agent_acme_shopping',        // resolvable via the merchant's directory
  tag: 'agent-browser-auth',           // or 'agent-payer-auth' at checkout
});

await fetch(signed.url, { method: signed.method, headers: signed.headers });
```

Checkout requests can attach the signed body objects (`agenticConsumer` /
`agenticPaymentContainer`) via `signTapObject` — kid/alg/nonce must match the
message signature.

### Web Bot Auth (IETF)

```ts
import { generateAgentKeyPair, signWithWebBotAuth, webBotAuthKeyId } from '@ava-pay/agent';

const { publicKey, privateKey } = generateAgentKeyPair();
// Publish publicKey (as a JWK) at
//   https://YOUR-ORIGIN/.well-known/http-message-signatures-directory
// Verifiers resolve it by RFC 7638 thumbprint: webBotAuthKeyId(publicKey).

const signed = signWithWebBotAuth({
  method: 'GET',
  url: 'https://shop.example.com/products/tool-1234',
  signatureAgent: 'https://your-agent.example',
  privateKey,
});
```

### Google AP2 v0.2 (mandate chains)

An AP2 v0.2 presentation is a delegated SD-JWT chain: a **user-signed open
mandate** (constraints + the agent's key as `cnf`) followed by an
**agent-signed closed mandate** committing to a merchant-signed checkout.

```ts
import {
  generateAgentKeyPair,
  buildCheckoutMandateChain,
  buildPaymentMandateChain,
  computeCheckoutHash,
} from '@ava-pay/agent';

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
  headers: {
    'ap2-checkout-mandate': checkoutChain,
    // optional: 'ap2-payment-mandate': buildPaymentMandateChain({ ... transaction_id: computeCheckoutHash(checkoutJwt) ... }),
  },
});
```

(The `Ap2-Checkout-Mandate` / `Ap2-Payment-Mandate` headers are AVA Pay's
HTTP binding of AP2 v0.2; AP2 itself specifies A2A message transport.)

### AVA TAP-style profile

```ts
import { generateAgentKeyPair, signWithVisa } from '@ava-pay/agent';

const { privateKey } = generateAgentKeyPair();
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
```

### Build your own verifier

```ts
import { parseSignatureInput, buildSignatureBase, verifyEd25519 } from '@ava-pay/agent/protocol/visa';
import { parseSignatureAgent, parseKeyDirectory, ed25519JwkThumbprint } from '@ava-pay/agent/protocol/web-bot-auth';
import { verifyTapSignature, parseVisaJwks, parseIdToken } from '@ava-pay/agent/protocol/visa-tap';
import { verifyChain, checkCheckoutConstraints } from '@ava-pay/agent/protocol/ap2';
```

## API surface

### Signers
- `generateAgentKeyPair(): AgentKeyPair` — fresh Ed25519 keypair
- `signWithVisaTap(input): SignedRequest` / `signTapObject(fields, key)` — real Visa TAP
- `signWithWebBotAuth(input): SignedRequest` / `webBotAuthKeyId(key): string` — Web Bot Auth
- `createRootMandate` / `presentMandate` / `buildCheckoutMandateChain` / `buildPaymentMandateChain` / `makeCheckoutJwt` / `computeCheckoutHash` — AP2 v0.2 chains
- `signWithVisa(input): SignedRequest` / `encodeMandate(m)` — AVA TAP-style profile

### Types
- `Mandate`, `BuyerInfo`, `IncomingRequest`, `VerificationResult`, `VerificationFailureReason`
- `VerifiedProtocol`, `VerifiedAgentIdentity`, `TapVerificationDetail`
- `CheckoutMandate`, `OpenCheckoutMandate`, `PaymentMandate`, `OpenPaymentMandate`, `Checkout`
- `CheckoutConstraintEvaluator`, `PaymentConstraintEvaluator` (pluggable validator registries)

### Subpath imports for low-level work
- `@ava-pay/agent/protocol/visa` — RFC 9421 parser, signature base, Ed25519 verify, content-digest
- `@ava-pay/agent/protocol/visa-tap` — TAP tags/algorithms, Visa JWKS + PS256 IdToken parsing, signed body objects
- `@ava-pay/agent/protocol/web-bot-auth` — Signature-Agent parsing (both wire forms), RFC 7638 thumbprints, key-directory parsing
- `@ava-pay/agent/protocol/ap2` — dSD-JWT chain verify, v0.2 mandate shapes, constraint evaluators, compact-JWS helpers

## Onboarding

To get a key recognized by AVA Pay merchants, either register it with the AVA Agent Directory (see [AGENT_ISSUERS.md](https://github.com/ava-pay/ava-pay/blob/main/AGENT_ISSUERS.md)) or publish it at your origin's Web Bot Auth key directory — AVA Pay merchants resolve keys through a federated chain (Visa's directories → Web Bot Auth agent cards → the AVA directory), so a key published once works across protocols.

## License

MIT
