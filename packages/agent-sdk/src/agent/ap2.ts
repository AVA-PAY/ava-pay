import type { KeyObject } from 'node:crypto';
import { signJws } from '../protocol/ap2/jws.js';
import type { CartMandateClaims, IntentMandateClaims } from '../protocol/ap2/types.js';

/**
 * AP2 (Google Agent Payments Protocol) — agent-side signing.
 *
 * Symmetric to `signWithVisa`. Produces the AP2 attestation header pair an
 * agent attaches to a merchant request:
 *
 *   Ap2-Attestation:  <intent-mandate JWS>
 *   Ap2-Cart-Mandate: <cart-mandate JWS>
 *
 * Both are signed with the agent's Ed25519 key. (FIDO/WebAuthn attestation of
 * the user's wallet is a separate signal supplied as a payload field, which
 * we don't yet validate.)
 *
 * Use `buildAp2Headers(...)` if you want a ready-to-go header map, or call
 * `signIntentMandate` and `signCartMandate` separately if you want to cache
 * an intent across multiple cart attempts (which is the real-world flow).
 */

export interface BuildIntentInput {
  agentId: string;
  privateKey: KeyObject;
  buyerId: string;
  spendLimitMinor: number;
  currency: string;
  allowedMerchants: string[];
  jti?: string;
  iat?: number;
  exp?: number;
}

export interface BuildCartInput {
  agentId: string;
  privateKey: KeyObject;
  intentJti: string;
  merchant: string;
  items: ReadonlyArray<{ sku: string; qty: number; price: number }>;
  totalMinor: number;
  currency: string;
  jti?: string;
  iat?: number;
  exp?: number;
}

export interface Ap2Attestations {
  intent: string;
  cart: string;
  /** Header map ready to spread into a fetch() init. */
  headers: { 'ap2-attestation': string; 'ap2-cart-mandate': string };
}

export function signIntentMandate(input: BuildIntentInput): string {
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const exp = input.exp ?? iat + 600;
  const claims: IntentMandateClaims = {
    iss: input.agentId,
    iat,
    exp,
    jti: input.jti ?? randomId('intent'),
    ap2: {
      type: 'intent',
      sub: input.buyerId,
      spend_limit: { value: input.spendLimitMinor, currency: input.currency },
      allowed_merchants: input.allowedMerchants,
    },
  };
  return signJws(
    { alg: 'EdDSA', typ: 'JWT', kid: input.agentId },
    claims,
    input.privateKey,
  );
}

export function signCartMandate(input: BuildCartInput): string {
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const exp = input.exp ?? iat + 60;
  const claims: CartMandateClaims = {
    iss: input.agentId,
    iat,
    exp,
    jti: input.jti ?? randomId('cart'),
    ap2: {
      type: 'cart',
      intent_ref: input.intentJti,
      merchant: input.merchant,
      items: input.items,
      total: { value: input.totalMinor, currency: input.currency },
    },
  };
  return signJws(
    { alg: 'EdDSA', typ: 'JWT', kid: input.agentId },
    claims,
    input.privateKey,
  );
}

export function buildAp2Headers(opts: {
  intent: BuildIntentInput;
  cart: Omit<BuildCartInput, 'intentJti'> & { intentJti?: string };
}): Ap2Attestations {
  const intentJti = opts.intent.jti ?? randomId('intent');
  const intent = signIntentMandate({ ...opts.intent, jti: intentJti });
  const cart = signCartMandate({ ...opts.cart, intentJti });
  return {
    intent,
    cart,
    headers: { 'ap2-attestation': intent, 'ap2-cart-mandate': cart },
  };
}

function randomId(prefix: string): string {
  const ts = Date.now();
  const noise = Math.floor(Math.random() * 1e9).toString(36);
  return `${prefix}_${ts}_${noise}`;
}
