/**
 * @ava-pay/agent — public SDK for AI shopping agents.
 *
 * Two protocols supported out of the box:
 *
 *   import { generateAgentKeyPair, signWithVisa } from '@ava-pay/agent';
 *
 *   const keys = generateAgentKeyPair();
 *   const signed = signWithVisa({
 *     method: 'POST', url: 'https://shop.example.com/cart',
 *     body: JSON.stringify({ items: [...] }),
 *     agentId: 'my_agent', privateKey: keys.privateKey,
 *     mandate,
 *   });
 *   await fetch(signed.url, { method: signed.method, headers: signed.headers, body: signed.body });
 *
 *   // — or AP2 —
 *
 *   import { buildAp2Headers } from '@ava-pay/agent';
 *
 *   const { headers } = buildAp2Headers({
 *     intent: { agentId, privateKey, buyerId, spendLimitMinor: 50000, currency: 'USD',
 *               allowedMerchants: ['shop.example.com'] },
 *     cart:   { agentId, privateKey, merchant: 'shop.example.com', items, totalMinor: 4999,
 *               currency: 'USD' },
 *   });
 *   await fetch('https://shop.example.com/cart', { method: 'POST', headers, body });
 *
 * The package also exports the parsing primitives so you can build your own
 * verifier:
 *
 *   import { parseSignatureInput, verifyEd25519 } from '@ava-pay/agent/protocol/visa';
 *   import { parseJws, verifyJws } from '@ava-pay/agent/protocol/ap2';
 */

import { generateKeyPairSync, type KeyObject } from 'node:crypto';

export interface AgentKeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

/** Generate a fresh Ed25519 keypair. The public key is what gets registered with an Agent Directory. */
export function generateAgentKeyPair(): AgentKeyPair {
  return generateKeyPairSync('ed25519');
}

// Visa Trusted Agent Protocol
export {
  signWithVisa,
  encodeMandate,
  type VisaSignInput,
  type SignedRequest,
} from './agent/visa.js';

// AP2 (Google Agent Payments Protocol) — v0.2 dSD-JWT mandate chains
export {
  createRootMandate,
  presentMandate,
  buildCheckoutMandateChain,
  buildPaymentMandateChain,
  makeCheckoutJwt,
  type Ap2KeyRef,
  type CheckoutChainInput,
  type PaymentChainInput,
  type PresentMandateInput,
} from './agent/ap2.js';

// Web Bot Auth (IETF draft-meunier-webbotauth-httpsig-protocol)
export {
  signWithWebBotAuth,
  webBotAuthKeyId,
  type WebBotAuthSignInput,
} from './agent/web-bot-auth.js';

// Visa Trusted Agent Protocol — real wire format
export {
  signWithVisaTap,
  signTapObject,
  type VisaTapSignInput,
} from './agent/visa-tap.js';

// Shared protocol-agnostic types
export type {
  IncomingRequest,
  Mandate,
  BuyerInfo,
  VerificationResult,
  VerificationFailureReason,
  VerifiedProtocol,
  VerifiedAgentIdentity,
  TapVerificationDetail,
} from './types.js';

// AP2 protocol re-exports for users implementing custom AP2 logic
export { computeCheckoutHash } from './protocol/ap2/mandates.js';
export type { JwsHeader, Ap2FailureReason } from './protocol/ap2/types.js';
export type {
  CheckoutMandate,
  OpenCheckoutMandate,
  OpenPaymentMandate,
  PaymentMandate,
  Checkout,
  CheckoutConstraintEvaluator,
  PaymentConstraintEvaluator,
} from './protocol/ap2/mandates.js';
