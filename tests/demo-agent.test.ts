import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrivateKey } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { VisaTapVerifier } from '../src/verifier/visa-tap.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import { demoteDemoResult, MultiProtocolVerifier } from '../src/verifier/multi.js';
import { InMemoryDirectoryStorage } from '../src/directory/storage.js';
import { StorageBackedAgentDirectory } from '../src/directory/storage-directory.js';
import { DEMO_AGENT_ID, seedDemoAgent } from '../src/directory/seed-demo.js';
import {
  buildCheckoutMandateChain,
  generateAgentKeyPair,
  makeCheckoutJwt,
  type AgentKeyPair,
} from '../src/sdk/index.js';
import type { Checkout } from '@ava-pay/agent/protocol/ap2';
import { generateAgentKeyPair as generatePair, signRequest, type KeyPair } from './sign-helper.js';
import type { Mandate, VerificationResult } from '../src/types.js';

/**
 * The demo-agent gate, end to end against the seeded production record.
 *
 * agent_demo_public's PRIVATE key is published in public/app.js by design, so
 * anyone can sign as it, including a self-made mandate with any spend cap and
 * allowedMerchants they like. These tests pin the fix: whatever a demo-signed
 * request carries, the result that leaves the engine is trusted (the demo
 * still demos) but identity-only, flagged demo: true, with the mandate, buyer
 * info and discount hint stripped at the dispatcher.
 *
 * The directory is the real StorageBackedAgentDirectory over the real
 * seedDemoAgent() record, and the signatures use the real published private
 * key, so a drift between the seed and the landing page keypair fails here.
 */

const FIXED_NOW = 1_750_000_000;
const MERCHANT = 'shop.example.com';
const AUD = `https://${MERCHANT}`;

/** The published demo private key, verbatim from public/app.js. */
const DEMO_PRIVATE_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  d: 'RfgxZQvu3WXbskCO0QZlhSOjguLIuTz8ANz0x3uCvRo',
  x: 'yKCkvxtkVtmYT1xK0FFuvQPFAQqQ_z6Zg9q6VKsJTU4',
} as const;

const DEFAULT_BODY = JSON.stringify({ items: [{ sku: 'SKU-1', qty: 1 }] });

function selfMadeMandate(overrides: Partial<Mandate> = {}): Mandate {
  return {
    id: 'mandate_self_made',
    iat: FIXED_NOW - 60,
    exp: FIXED_NOW + 600,
    maxAmountMinor: 9_999_999,
    currency: 'USD',
    allowedMerchants: ['*'],
    buyer: { buyerId: 'buyer_self_made', country: 'US', displayName: 'Mallory' },
    ...overrides,
  };
}

function checkout(): Checkout {
  return {
    id: 'checkout_demo',
    merchant: { name: 'Demo Shop', url: AUD },
    line_items: [{ item: { id: 'SKU-1', title: 'Widget' }, quantity: 1 }],
    status: 'ready_for_complete',
    currency: 'USD',
    totals: [
      { type: 'subtotal', amount: 4999 },
      { type: 'total', amount: 4999 },
    ],
  };
}

let nonceCounter = 0;
function freshNonce(): string {
  return `demo_nonce_${++nonceCounter}`;
}

describe('demo agent results are demoted to identity-only (demo: true)', () => {
  let app: FastifyInstance;
  let demoPrivateKey: ReturnType<typeof createPrivateKey>;
  let realKeys: KeyPair;
  let ap2AgentKeys: AgentKeyPair;
  let merchantKeys: AgentKeyPair;

  beforeAll(async () => {
    demoPrivateKey = createPrivateKey({ key: DEMO_PRIVATE_JWK, format: 'jwk' });
    realKeys = generatePair();
    ap2AgentKeys = generateAgentKeyPair();
    merchantKeys = generateAgentKeyPair();

    // The REAL seed over the real storage adapter: what production resolves.
    const storage = new InMemoryDirectoryStorage();
    await seedDemoAgent(storage);
    await storage.put({
      agentId: 'agent_real',
      issuer: 'A registered non-demo agent',
      keys: [
        {
          alg: 'ed25519',
          jwk: realKeys.publicKey.export({ format: 'jwk' }) as { kty: string },
          protocols: ['visa', 'ap2'],
        },
      ],
      revoked: false,
      registeredAt: new Date(FIXED_NOW * 1000).toISOString(),
      updatedAt: new Date(FIXED_NOW * 1000).toISOString(),
    });
    const directory = new StorageBackedAgentDirectory(storage);

    const visa = new VisaAgentVerifier({ directory, now: () => FIXED_NOW });
    const visaTap = new VisaTapVerifier({ directory, now: () => FIXED_NOW });
    const ap2 = new Ap2AgentVerifier({ directory, now: () => FIXED_NOW });
    const webBotAuth = new WebBotAuthVerifier({
      resolver: new StaticSignatureAgentKeys(),
      now: () => FIXED_NOW,
    });
    const verifier = new MultiProtocolVerifier({
      visa,
      visaTap,
      ap2,
      webBotAuth,
      demoAgentId: DEMO_AGENT_ID,
    });
    app = await buildServer({ verifier, logger: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  async function verifyVia(payload: unknown): Promise<{ status: number; body: VerificationResult }> {
    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      payload: payload as Record<string, unknown>,
      headers: { 'content-type': 'application/json' },
    });
    return { status: res.statusCode, body: res.json() as VerificationResult };
  }

  it('ava-tap: a demo-signed request with a self-made mandate verifies with NO mandate and demo: true', async () => {
    const signed = signRequest({
      method: 'POST',
      url: `${AUD}/cart`,
      body: DEFAULT_BODY,
      agentId: DEMO_AGENT_ID,
      privateKey: demoPrivateKey,
      mandate: selfMadeMandate(),
      created: FIXED_NOW - 5,
      expires: FIXED_NOW + 30,
    });
    // The verifier reads this header without requiring signature coverage
    // (known, reported in PR #41), so the strip must cover it too.
    signed.headers['x-ava-discount-hint'] = '0.5';

    const { status, body } = await verifyVia(signed);
    expect(status).toBe(200);
    if (!body.trusted) throw new Error(`expected trusted, got ${JSON.stringify(body)}`);
    expect(body.demo).toBe(true);
    expect(body.conclusive).toBe(true);
    expect(body.protocol).toBe('ava-tap');
    expect(body.agent?.id).toBe(DEMO_AGENT_ID);
    expect(body.mandate).toBeUndefined();
    expect(body.buyerInfo).toBeUndefined();
    expect(body.discount).toBeUndefined();
  });

  it('ap2: the published demo key CAN produce a valid v0.2 chain, and it comes back mandate-less with demo: true', async () => {
    // The demo record is registered for ap2, so the demo key resolves as a
    // chain root. Everything else in the chain (agent key, "merchant-signed"
    // checkout JWT) can be fabricated by whoever holds the published key,
    // which is exactly why the result must not keep its mandate.
    const chain = buildCheckoutMandateChain({
      user: { privateKey: demoPrivateKey, kid: DEMO_AGENT_ID },
      agentPrivateKey: ap2AgentKeys.privateKey,
      agentPublicKey: ap2AgentKeys.publicKey,
      constraints: [
        { type: 'checkout.allowed_merchants', allowed: [{ name: 'Demo Shop', url: AUD }] },
      ],
      checkoutJwt: makeCheckoutJwt(checkout(), merchantKeys.privateKey),
      aud: AUD,
      nonce: freshNonce(),
      iat: FIXED_NOW - 5,
    });

    const { status, body } = await verifyVia({
      method: 'POST',
      url: `${AUD}/cart`,
      headers: { host: MERCHANT, 'ap2-checkout-mandate': chain },
      body: '',
    });
    expect(status).toBe(200);
    if (!body.trusted) throw new Error(`expected trusted, got ${JSON.stringify(body)}`);
    expect(body.demo).toBe(true);
    expect(body.protocol).toBe('ap2');
    expect(body.agent?.id).toBe(DEMO_AGENT_ID);
    expect(body.mandate).toBeUndefined();
    expect(body.buyerInfo).toBeUndefined();
  });

  it('a registered non-demo agent with a mandate is unchanged: mandate kept, no demo flag', async () => {
    const mandate = selfMadeMandate({ id: 'mandate_real', allowedMerchants: [MERCHANT] });
    const signed = signRequest({
      method: 'POST',
      url: `${AUD}/cart`,
      body: DEFAULT_BODY,
      agentId: 'agent_real',
      privateKey: realKeys.privateKey,
      mandate,
      created: FIXED_NOW - 5,
      expires: FIXED_NOW + 30,
    });

    const { status, body } = await verifyVia(signed);
    expect(status).toBe(200);
    if (!body.trusted) throw new Error(`expected trusted, got ${JSON.stringify(body)}`);
    expect(body.demo).toBeUndefined();
    expect(body.agent?.id).toBe('agent_real');
    expect(body.mandate?.id).toBe('mandate_real');
    expect(body.buyerInfo?.buyerId).toBe('buyer_self_made');
  });
});

describe('demoteDemoResult (unit)', () => {
  const verifiedDemo: VerificationResult = {
    trusted: true,
    conclusive: true,
    protocol: 'ava-tap',
    agent: { id: 'agent_demo_public', protocol: 'ava-tap' },
    buyerInfo: { buyerId: 'buyer_x' },
    mandate: {
      id: 'm1',
      iat: 1,
      exp: 2,
      maxAmountMinor: 100,
      currency: 'USD',
      allowedMerchants: ['*'],
    },
    discount: 0.1,
    ttlSeconds: 60,
  };

  it('strips mandate, buyerInfo and discount, keeps trusted/protocol/agent/ttl, sets demo', () => {
    const out = demoteDemoResult(verifiedDemo, 'agent_demo_public');
    expect(out).toEqual({
      trusted: true,
      conclusive: true,
      protocol: 'ava-tap',
      agent: { id: 'agent_demo_public', protocol: 'ava-tap' },
      demo: true,
      ttlSeconds: 60,
    });
  });

  it('leaves other identities untouched', () => {
    expect(demoteDemoResult(verifiedDemo, 'someone_else')).toBe(verifiedDemo);
  });

  it('does nothing when no demo agent id is configured', () => {
    expect(demoteDemoResult(verifiedDemo, undefined)).toBe(verifiedDemo);
  });

  it('never touches an untrusted result', () => {
    const failed: VerificationResult = {
      trusted: false,
      reason: 'invalid_signature',
      message: 'nope',
      conclusive: true,
    };
    expect(demoteDemoResult(failed, 'agent_demo_public')).toBe(failed);
  });
});
