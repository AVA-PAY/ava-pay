import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import {
  buildAp2Headers,
  generateAgentKeyPair,
  signCartMandate,
  signIntentMandate,
  type AgentKeyPair,
} from '../src/sdk/index.js';
import type { VerificationResult } from '../src/types.js';

const FIXED_NOW = 1_750_000_000;
const MERCHANT = 'shop.example.com';

function buildPayload(headers: Record<string, string>) {
  return {
    method: 'POST',
    url: `https://${MERCHANT}/cart`,
    headers: { ...headers, host: MERCHANT },
    body: '',
  };
}

describe('Ap2AgentVerifier — real JWS chains', () => {
  let app: FastifyInstance;
  let demoKeys: AgentKeyPair;
  let strangerKeys: AgentKeyPair;
  let directory: StaticAgentDirectory;

  beforeAll(async () => {
    demoKeys = generateAgentKeyPair();
    strangerKeys = generateAgentKeyPair();

    directory = new StaticAgentDirectory();
    directory.add('agent_demo', demoKeys.publicKey);
    directory.add('agent_revoked', strangerKeys.publicKey, true);

    const visa = new VisaAgentVerifier({ directory, now: () => FIXED_NOW });
    const ap2 = new Ap2AgentVerifier({ directory, now: () => FIXED_NOW });
    const verifier = new MultiProtocolVerifier({ visa, ap2 });

    app = await buildServer({ verifier, logger: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('returns trusted=true for a valid intent + cart chain', async () => {
    const { headers } = buildAp2Headers({
      intent: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        buyerId: 'buyer_alex',
        spendLimitMinor: 50_000,
        currency: 'USD',
        allowedMerchants: [MERCHANT],
        iat: FIXED_NOW - 5,
        exp: FIXED_NOW + 600,
      },
      cart: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        merchant: MERCHANT,
        items: [{ sku: 'A', qty: 1, price: 4999 }],
        totalMinor: 4999,
        currency: 'USD',
        iat: FIXED_NOW - 1,
        exp: FIXED_NOW + 60,
      },
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: buildPayload(headers) });
    expect(res.statusCode).toBe(200);
    const body = res.json() as VerificationResult;
    if (!body.trusted) throw new Error(`expected trusted, got ${JSON.stringify(body)}`);
    expect(body.buyerInfo.buyerId).toBe('buyer_alex');
  });

  it('rejects when the cart is signed by a different agent than the intent → mandate_chain_mismatch', async () => {
    const intent = signIntentMandate({
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      buyerId: 'buyer_alex',
      spendLimitMinor: 50_000,
      currency: 'USD',
      allowedMerchants: [MERCHANT],
      iat: FIXED_NOW - 5,
      exp: FIXED_NOW + 600,
    });
    // Cart signed by a different agent — header.kid will differ.
    const cart = signCartMandate({
      agentId: 'agent_revoked',
      privateKey: strangerKeys.privateKey,
      intentJti: 'whatever', // intent_ref check happens later, but kid mismatch catches first
      merchant: MERCHANT,
      items: [{ sku: 'A', qty: 1, price: 100 }],
      totalMinor: 100,
      currency: 'USD',
      iat: FIXED_NOW - 1,
      exp: FIXED_NOW + 60,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      payload: buildPayload({ 'ap2-attestation': intent, 'ap2-cart-mandate': cart }),
    });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('mandate_chain_mismatch');
  });

  it('rejects a cart whose total exceeds the intent spend limit → cart_exceeds_intent_limit', async () => {
    const { headers } = buildAp2Headers({
      intent: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        buyerId: 'buyer_alex',
        spendLimitMinor: 1_000, // $10
        currency: 'USD',
        allowedMerchants: [MERCHANT],
        iat: FIXED_NOW - 5,
        exp: FIXED_NOW + 600,
      },
      cart: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        merchant: MERCHANT,
        items: [{ sku: 'BIG', qty: 1, price: 9999 }],
        totalMinor: 9999, // way over the $10 cap
        currency: 'USD',
        iat: FIXED_NOW - 1,
        exp: FIXED_NOW + 60,
      },
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: buildPayload(headers) });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('cart_exceeds_intent_limit');
  });

  it('rejects when intent_ref doesn\'t match the intent jti → cart_intent_mismatch', async () => {
    const intent = signIntentMandate({
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      buyerId: 'buyer_alex',
      spendLimitMinor: 50_000,
      currency: 'USD',
      allowedMerchants: [MERCHANT],
      jti: 'intent_real',
      iat: FIXED_NOW - 5,
      exp: FIXED_NOW + 600,
    });
    const cart = signCartMandate({
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      intentJti: 'intent_wrong', // doesn't match
      merchant: MERCHANT,
      items: [{ sku: 'A', qty: 1, price: 100 }],
      totalMinor: 100,
      currency: 'USD',
      iat: FIXED_NOW - 1,
      exp: FIXED_NOW + 60,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      payload: buildPayload({ 'ap2-attestation': intent, 'ap2-cart-mandate': cart }),
    });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('cart_intent_mismatch');
  });

  it('rejects an expired intent mandate → mandate_expired', async () => {
    const { headers } = buildAp2Headers({
      intent: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        buyerId: 'buyer_alex',
        spendLimitMinor: 50_000,
        currency: 'USD',
        allowedMerchants: [MERCHANT],
        iat: FIXED_NOW - 600,
        exp: FIXED_NOW - 60, // already expired
      },
      cart: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        merchant: MERCHANT,
        items: [{ sku: 'A', qty: 1, price: 100 }],
        totalMinor: 100,
        currency: 'USD',
        iat: FIXED_NOW - 1,
        exp: FIXED_NOW + 60,
      },
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: buildPayload(headers) });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('mandate_expired');
  });

  it('rejects when the cart merchant doesn\'t match the request host → mandate_merchant_mismatch', async () => {
    const { headers } = buildAp2Headers({
      intent: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        buyerId: 'buyer_alex',
        spendLimitMinor: 50_000,
        currency: 'USD',
        allowedMerchants: ['*'],
        iat: FIXED_NOW - 5,
        exp: FIXED_NOW + 600,
      },
      cart: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        merchant: 'other-shop.com', // cart says other shop
        items: [{ sku: 'A', qty: 1, price: 100 }],
        totalMinor: 100,
        currency: 'USD',
        iat: FIXED_NOW - 1,
        exp: FIXED_NOW + 60,
      },
    });

    // Request is to MERCHANT, but cart claims to be for other-shop.com.
    const res = await app.inject({ method: 'POST', url: '/verify', payload: buildPayload(headers) });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('mandate_merchant_mismatch');
  });

  it('rejects a tampered JWS (signature flipped) → jws_signature_invalid', async () => {
    const { headers } = buildAp2Headers({
      intent: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        buyerId: 'buyer_alex',
        spendLimitMinor: 50_000,
        currency: 'USD',
        allowedMerchants: [MERCHANT],
        iat: FIXED_NOW - 5,
        exp: FIXED_NOW + 600,
      },
      cart: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        merchant: MERCHANT,
        items: [{ sku: 'A', qty: 1, price: 100 }],
        totalMinor: 100,
        currency: 'USD',
        iat: FIXED_NOW - 1,
        exp: FIXED_NOW + 60,
      },
    });

    // Mutate the cart JWS signature segment.
    const parts = headers['ap2-cart-mandate'].split('.');
    const sigBuf = Buffer.from(parts[2]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    sigBuf[0] = sigBuf[0]! ^ 0xff;
    const mutated = sigBuf
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    headers['ap2-cart-mandate'] = `${parts[0]}.${parts[1]}.${mutated}`;

    const res = await app.inject({ method: 'POST', url: '/verify', payload: buildPayload(headers) });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('jws_signature_invalid');
  });

  it('rejects requests with both Visa and AP2 credentials → ambiguous_protocol', async () => {
    const { headers: ap2Headers } = buildAp2Headers({
      intent: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        buyerId: 'buyer_alex',
        spendLimitMinor: 50_000,
        currency: 'USD',
        allowedMerchants: [MERCHANT],
        iat: FIXED_NOW - 5,
        exp: FIXED_NOW + 600,
      },
      cart: {
        agentId: 'agent_demo',
        privateKey: demoKeys.privateKey,
        merchant: MERCHANT,
        items: [{ sku: 'A', qty: 1, price: 100 }],
        totalMinor: 100,
        currency: 'USD',
        iat: FIXED_NOW - 1,
        exp: FIXED_NOW + 60,
      },
    });
    // Spuriously include Visa headers too.
    const headers: Record<string, string> = {
      ...ap2Headers,
      signature: 'sig1=:abc:',
      'signature-input': 'sig1=("@method")',
    };

    const res = await app.inject({ method: 'POST', url: '/verify', payload: buildPayload(headers) });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('ambiguous_protocol');
  });
});
