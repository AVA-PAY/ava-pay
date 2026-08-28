/**
 * Signing the test agent visit. See test-visit.ts for what the feature is and
 * why it behaves the way it does.
 *
 * This half is server only: it reaches for node:crypto through the SDK. Keeping
 * it out of test-visit.ts is what lets the Settings component import the
 * verdict wording without dragging node builtins into the browser bundle, which
 * fails the client build outright. Only test-visit.server.ts imports this.
 *
 * Signing comes from @ava-pay/agent, the same SDK a real agent would use. The
 * standalone scripts/simulate-verified-agent.mjs hand-rolls its own copy of
 * this signing because that script has to run from a bare `node` with nothing
 * installed; that constraint does not apply here, so this module imports.
 */

import { createPrivateKey } from 'node:crypto';
import { signWithVisa, type Mandate } from '@ava-pay/agent';
import type { IncomingRequest } from './ava-types.js';

/**
 * AVA Pay's public demo agent, seeded into the hosted directory as
 * `agent_demo_public` (src/directory/seed-demo.ts in the API repo).
 *
 * The private key is public on purpose and carries no authority beyond being
 * verifiable, which is what makes a self-contained demo possible. Real agents
 * hold keys nobody else has. The same pair is in public/app.js (the landing
 * page demo) and scripts/simulate-verified-agent.mjs; rotating it means
 * changing all of them together, and test-visit.test.ts checks that this
 * private half still derives the seeded public half.
 */
export const DEMO_AGENT_ID = 'agent_demo_public';
export const DEMO_AGENT_PUBLIC_X = 'yKCkvxtkVtmYT1xK0FFuvQPFAQqQ_z6Zg9q6VKsJTU4';
export const DEMO_AGENT_PRIVATE_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  d: 'RfgxZQvu3WXbskCO0QZlhSOjguLIuTz8ANz0x3uCvRo',
  x: DEMO_AGENT_PUBLIC_X,
} as const;

/** How long the test mandate authorises for. Matches the simulator. */
const MANDATE_TTL_SECONDS = 600;
const MANDATE_MAX_AMOUNT_MINOR = 50_000;
const MANDATE_CURRENCY = 'USD';

/**
 * The buyer mandate the demo credential carries: what a shopper would have
 * authorised this agent to spend, scoped to this store and expiring shortly.
 *
 * Shared with the storefront test visit (storefront-visit.server.ts) so the two
 * merchant-initiated paths cannot drift into authorising different things.
 */
export function demoAgentMandate(shop: string, created: number): Mandate {
  return {
    id: `mandate_test_visit_${created}`,
    iat: created - 5,
    exp: created + MANDATE_TTL_SECONDS,
    maxAmountMinor: MANDATE_MAX_AMOUNT_MINOR,
    currency: MANDATE_CURRENCY,
    allowedMerchants: [shop],
    buyer: { buyerId: 'buyer_demo_001', country: 'US', displayName: 'Demo Shopper' },
  };
}

export interface BuildTestVisitOptions {
  /** Unix seconds. Defaults to now. Tests pin it. */
  created?: number;
  /** Single-use replay nonce. Defaults to a fresh UUID inside the SDK. */
  nonce?: string;
}

/**
 * The signed request a demo agent would send to this store's App Proxy.
 *
 * The URL is the one the App Proxy endpoint lives at, because that is what a
 * real agent signs against and what the verifier recomputes the signature base
 * from. We hand the envelope straight to `/verify` rather than send it over the
 * wire to the storefront, so the signature covers the same target either way.
 */
export function buildTestVisitRequest(
  shop: string,
  options: BuildTestVisitOptions = {},
): IncomingRequest {
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const url = `https://${shop}/apps/ava-pay/verify`;
  const body = JSON.stringify({
    cart: [{ sku: 'DEMO-1234', qty: 1, price_minor: 4999 }],
  });

  const signed = signWithVisa({
    method: 'POST',
    url,
    body,
    agentId: DEMO_AGENT_ID,
    privateKey: createPrivateKey({ key: DEMO_AGENT_PRIVATE_JWK, format: 'jwk' }),
    mandate: demoAgentMandate(shop, created),
    created,
    ...(options.nonce !== undefined ? { nonce: options.nonce } : {}),
    extraHeaders: { 'content-type': 'application/json' },
  });

  return {
    method: signed.method,
    url: signed.url,
    headers: signed.headers,
    ...(signed.body !== undefined ? { body: signed.body } : {}),
  };
}
