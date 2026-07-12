import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { VisaTapVerifier } from '../src/verifier/visa-tap.js';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import {
  buildCheckoutMandateChain,
  buildPaymentMandateChain,
  computeCheckoutHash,
  createRootMandate,
  generateAgentKeyPair,
  makeCheckoutJwt,
  presentMandate,
  type AgentKeyPair,
} from '../src/sdk/index.js';
import type { Checkout } from '@ava-pay/agent/protocol/ap2';
import type { VerificationResult } from '../src/types.js';

/**
 * AP2 v0.2 tests — dSD-JWT mandate chains, real Ed25519/ES256 crypto.
 *
 * The wire format is a CLEAN BREAK from v0.1: Ap2-Checkout-Mandate /
 * Ap2-Payment-Mandate presentation chains replace the Intent/Cart JWS pair,
 * and v0.1 headers get a typed unsupported_protocol_version.
 */

const FIXED_NOW = 1_750_000_000;
const MERCHANT = 'shop.example.com';
const AUD = `https://${MERCHANT}`;
const USER_KID = 'user_wallet_1';

let nonceCounter = 0;
function freshNonce(prefix = 'n'): string {
  return `${prefix}_${++nonceCounter}`;
}

function demoCheckout(overrides: Partial<Checkout> = {}): Checkout {
  return {
    id: 'checkout_1',
    merchant: { name: 'Demo Shop', url: AUD },
    line_items: [{ item: { id: 'SKU-1', title: 'Widget' }, quantity: 1 }],
    status: 'ready_for_complete',
    currency: 'USD',
    totals: [
      { type: 'subtotal', amount: 4999 },
      { type: 'total', amount: 4999 },
    ],
    ...overrides,
  };
}

describe('POST /verify (AP2 v0.2 mandate chains)', () => {
  let app: FastifyInstance;
  let userKeys: AgentKeyPair;
  let agentKeys: AgentKeyPair;
  let strangerKeys: AgentKeyPair;
  let merchantKeys: AgentKeyPair;
  let checkoutJwt: string;

  function chain(overrides: Partial<Parameters<typeof buildCheckoutMandateChain>[0]> = {}): string {
    return buildCheckoutMandateChain({
      user: { privateKey: userKeys.privateKey, kid: USER_KID },
      agentPrivateKey: agentKeys.privateKey,
      agentPublicKey: agentKeys.publicKey,
      constraints: [
        { type: 'checkout.allowed_merchants', allowed: [{ name: 'Demo Shop', url: AUD }] },
      ],
      checkoutJwt,
      aud: AUD,
      nonce: freshNonce(),
      iat: FIXED_NOW - 5,
      ...overrides,
    });
  }

  function payload(headers: Record<string, string>) {
    return {
      method: 'POST',
      url: `${AUD}/cart`,
      headers: { host: MERCHANT, ...headers },
      body: '',
    };
  }

  async function verifyVia(headers: Record<string, string>): Promise<VerificationResult> {
    const res = await app.inject({ method: 'POST', url: '/verify', payload: payload(headers) });
    return res.json() as VerificationResult;
  }

  beforeAll(async () => {
    userKeys = generateAgentKeyPair();
    agentKeys = generateAgentKeyPair();
    strangerKeys = generateAgentKeyPair();
    merchantKeys = generateAgentKeyPair();
    checkoutJwt = makeCheckoutJwt(demoCheckout(), merchantKeys.privateKey);

    const directory = new StaticAgentDirectory();
    directory.add(USER_KID, userKeys.publicKey);
    directory.add('user_revoked', strangerKeys.publicKey, true);

    const visa = new VisaAgentVerifier({ directory, now: () => FIXED_NOW });
    const visaTap = new VisaTapVerifier({ directory, now: () => FIXED_NOW });
    const ap2 = new Ap2AgentVerifier({ directory, now: () => FIXED_NOW });
    const webBotAuth = new WebBotAuthVerifier({
      resolver: new StaticSignatureAgentKeys(),
      now: () => FIXED_NOW,
    });
    const verifier = new MultiProtocolVerifier({ visa, visaTap, ap2, webBotAuth });
    app = await buildServer({ verifier, logger: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('verifies a checkout mandate chain (open user mandate ~~ closed agent mandate)', async () => {
    const result = await verifyVia({ 'ap2-checkout-mandate': chain() });
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.protocol).toBe('ap2');
    expect(result.agent?.id).toBe(USER_KID);
    expect(result.mandate?.id).toBe(computeCheckoutHash(checkoutJwt));
    expect(result.mandate?.maxAmountMinor).toBe(4999);
    expect(result.mandate?.allowedMerchants).toEqual([MERCHANT]);
  });

  it('verifies checkout + payment mandate chains together', async () => {
    const paymentChain = buildPaymentMandateChain({
      user: { privateKey: userKeys.privateKey, kid: USER_KID },
      agentPrivateKey: agentKeys.privateKey,
      agentPublicKey: agentKeys.publicKey,
      constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 50_000 }],
      payment: {
        transaction_id: computeCheckoutHash(checkoutJwt),
        payee: { name: 'Demo Shop', url: AUD },
        payment_amount: { currency: 'USD', amount: 4999 },
        payment_instrument: { type: 'card', last_four: '4242' },
      },
      aud: AUD,
      nonce: freshNonce('p'),
      iat: FIXED_NOW - 5,
    });
    const result = await verifyVia({
      'ap2-checkout-mandate': chain(),
      'ap2-payment-mandate': paymentChain,
    });
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.mandate?.maxAmountMinor).toBe(4999);
    expect(result.mandate?.currency).toBe('USD');
  });

  it('answers v0.1 headers with unsupported_protocol_version (clean break)', async () => {
    const result = await verifyVia({ 'ap2-attestation': 'x.y.z', 'ap2-cart-mandate': 'x.y.z' });
    expect(result).toMatchObject({ trusted: false, reason: 'unsupported_protocol_version' });
  });

  it('rejects an unknown root kid → unknown_agent and a revoked one → revoked_agent', async () => {
    const unknown = chain({ user: { privateKey: userKeys.privateKey, kid: 'nobody' } });
    expect(await verifyVia({ 'ap2-checkout-mandate': unknown })).toMatchObject({
      trusted: false,
      reason: 'unknown_agent',
    });

    const revoked = chain({ user: { privateKey: strangerKeys.privateKey, kid: 'user_revoked' } });
    expect(await verifyVia({ 'ap2-checkout-mandate': revoked })).toMatchObject({
      trusted: false,
      reason: 'revoked_agent',
    });
  });

  it('rejects a closed hop signed by a key other than the delegated cnf key', async () => {
    const forged = chain({ agentPrivateKey: strangerKeys.privateKey });
    expect(await verifyVia({ 'ap2-checkout-mandate': forged })).toMatchObject({
      trusted: false,
      reason: 'jws_signature_invalid',
    });
  });

  it('rejects a tampered disclosure (mandate content swapped after signing)', async () => {
    const good = chain();
    const segments = good.split('~~');
    const closedParts = segments[1]!.split('~');
    // Replace the closed mandate's disclosure with a different (validly
    // encoded) one — its digest no longer matches the signed payload.
    closedParts[1] = Buffer.from(JSON.stringify(['salt', { vct: 'mandate.checkout.1', checkout_jwt: 'a.b.c', checkout_hash: 'x' }])).toString('base64url');
    const tampered = `${segments[0]}~~${closedParts.join('~')}`;
    expect(await verifyVia({ 'ap2-checkout-mandate': tampered })).toMatchObject({
      trusted: false,
      reason: 'malformed_jws',
    });
  });

  it('rejects a checkout_hash that does not match the embedded checkout_jwt', async () => {
    const open = createRootMandate(
      {
        vct: 'mandate.checkout.open.1',
        constraints: [
          { type: 'checkout.allowed_merchants', allowed: [{ name: 'Demo Shop', url: AUD }] },
        ],
        cnf: { jwk: agentKeys.publicKey.export({ format: 'jwk' }) },
        iat: FIXED_NOW - 5,
        exp: FIXED_NOW + 3600,
      },
      { privateKey: userKeys.privateKey, kid: USER_KID },
    );
    const lying = presentMandate({
      prevToken: open,
      holderKey: agentKeys.privateKey,
      mandate: {
        vct: 'mandate.checkout.1',
        checkout_jwt: checkoutJwt,
        checkout_hash: 'not-the-real-hash',
        iat: FIXED_NOW - 5,
        exp: FIXED_NOW + 600,
      },
      aud: AUD,
      nonce: freshNonce(),
      iat: FIXED_NOW - 5,
    });
    expect(await verifyVia({ 'ap2-checkout-mandate': lying })).toMatchObject({
      trusted: false,
      reason: 'checkout_hash_mismatch',
    });
  });

  it('enforces open-mandate merchant constraints → mandate_constraint_violation', async () => {
    const wrongMerchant = chain({
      constraints: [
        { type: 'checkout.allowed_merchants', allowed: [{ name: 'Other Shop', url: 'https://other.example' }] },
      ],
    });
    expect(await verifyVia({ 'ap2-checkout-mandate': wrongMerchant })).toMatchObject({
      trusted: false,
      reason: 'mandate_constraint_violation',
    });
  });

  it('enforces line_items constraints (matching item passes, missing item fails)', async () => {
    const pass = chain({
      constraints: [
        {
          type: 'checkout.line_items',
          items: [{ id: 'req1', acceptable_items: [{ id: 'SKU-1', title: 'Widget' }], quantity: 1 }],
        },
      ],
    });
    expect((await verifyVia({ 'ap2-checkout-mandate': pass })).trusted).toBe(true);

    const failCase = chain({
      constraints: [
        {
          type: 'checkout.line_items',
          items: [{ id: 'req1', acceptable_items: [{ id: 'SKU-OTHER', title: 'Other' }], quantity: 1 }],
        },
      ],
    });
    expect(await verifyVia({ 'ap2-checkout-mandate': failCase })).toMatchObject({
      trusted: false,
      reason: 'mandate_constraint_violation',
    });
  });

  it('fails closed on constraint types with no registered evaluator', async () => {
    const exotic = chain({ constraints: [{ type: 'checkout.custom_geo_fence', region: 'EU' }] });
    expect(await verifyVia({ 'ap2-checkout-mandate': exotic })).toMatchObject({
      trusted: false,
      reason: 'mandate_constraint_violation',
    });
  });

  it('rejects an aud minted for a different merchant → mandate_merchant_mismatch', async () => {
    const elsewhere = chain({ aud: 'https://other-shop.example' });
    expect(await verifyVia({ 'ap2-checkout-mandate': elsewhere })).toMatchObject({
      trusted: false,
      reason: 'mandate_merchant_mismatch',
    });
  });

  it('rejects a checkout that names a different merchant', async () => {
    const foreignCheckout = makeCheckoutJwt(
      demoCheckout({ merchant: { name: 'Other', url: 'https://other-shop.example' } }),
      merchantKeys.privateKey,
    );
    const c = chain({ checkoutJwt: foreignCheckout });
    expect(await verifyVia({ 'ap2-checkout-mandate': c })).toMatchObject({
      trusted: false,
      reason: 'mandate_merchant_mismatch',
    });
  });

  it('rejects a replayed presentation (same nonce) → replay_detected', async () => {
    const c = chain();
    expect((await verifyVia({ 'ap2-checkout-mandate': c })).trusted).toBe(true);
    expect(await verifyVia({ 'ap2-checkout-mandate': c })).toMatchObject({
      trusted: false,
      reason: 'replay_detected',
    });
  });

  it('rejects expired mandates → mandate_expired', async () => {
    const expired = chain({ iat: FIXED_NOW - 7200, exp: FIXED_NOW - 3600 });
    expect(await verifyVia({ 'ap2-checkout-mandate': expired })).toMatchObject({
      trusted: false,
      reason: 'mandate_expired',
    });
  });

  it('rejects a bare root token (no delegation hop) → mandate_chain_mismatch', async () => {
    const root = createRootMandate(
      {
        vct: 'mandate.checkout.open.1',
        constraints: [],
        cnf: { jwk: agentKeys.publicKey.export({ format: 'jwk' }) },
      },
      { privateKey: userKeys.privateKey, kid: USER_KID },
    );
    expect(await verifyVia({ 'ap2-checkout-mandate': root })).toMatchObject({
      trusted: false,
      reason: 'mandate_chain_mismatch',
    });
  });

  it('rejects a payment mandate for a different checkout → checkout_hash_mismatch', async () => {
    const paymentChain = buildPaymentMandateChain({
      user: { privateKey: userKeys.privateKey, kid: USER_KID },
      agentPrivateKey: agentKeys.privateKey,
      agentPublicKey: agentKeys.publicKey,
      constraints: [],
      payment: {
        transaction_id: 'some-other-checkout-hash',
        payee: { name: 'Demo Shop', url: AUD },
        payment_amount: { currency: 'USD', amount: 4999 },
        payment_instrument: { type: 'card' },
      },
      aud: AUD,
      nonce: freshNonce('p'),
      iat: FIXED_NOW - 5,
    });
    expect(
      await verifyVia({ 'ap2-checkout-mandate': chain(), 'ap2-payment-mandate': paymentChain }),
    ).toMatchObject({ trusted: false, reason: 'checkout_hash_mismatch' });
  });

  it('enforces payment amount_range constraints', async () => {
    const paymentChain = buildPaymentMandateChain({
      user: { privateKey: userKeys.privateKey, kid: USER_KID },
      agentPrivateKey: agentKeys.privateKey,
      agentPublicKey: agentKeys.publicKey,
      constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 1000 }],
      payment: {
        transaction_id: computeCheckoutHash(checkoutJwt),
        payee: { name: 'Demo Shop', url: AUD },
        payment_amount: { currency: 'USD', amount: 4999 }, // over the 1000 cap
        payment_instrument: { type: 'card' },
      },
      aud: AUD,
      nonce: freshNonce('p'),
      iat: FIXED_NOW - 5,
    });
    expect(
      await verifyVia({ 'ap2-checkout-mandate': chain(), 'ap2-payment-mandate': paymentChain }),
    ).toMatchObject({ trusted: false, reason: 'mandate_constraint_violation' });
  });
});

describe('AP2 v0.2 pluggable evaluators', () => {
  it('a deployment-registered evaluator makes an exotic constraint verifiable', async () => {
    const userKeys = generateAgentKeyPair();
    const agentKeys = generateAgentKeyPair();
    const merchantKeys = generateAgentKeyPair();
    const directory = new StaticAgentDirectory();
    directory.add(USER_KID, userKeys.publicKey);

    const { DEFAULT_CHECKOUT_EVALUATORS } = await import('@ava-pay/agent/protocol/ap2');
    const evaluators = new Map(DEFAULT_CHECKOUT_EVALUATORS);
    evaluators.set('checkout.custom_geo_fence', (constraint) =>
      constraint['region'] === 'EU' ? [] : ['region not allowed'],
    );

    const verifier = new Ap2AgentVerifier({
      directory,
      now: () => FIXED_NOW,
      checkoutEvaluators: evaluators,
    });

    const checkoutJwt = makeCheckoutJwt(demoCheckout(), merchantKeys.privateKey);
    const c = buildCheckoutMandateChain({
      user: { privateKey: userKeys.privateKey, kid: USER_KID },
      agentPrivateKey: agentKeys.privateKey,
      agentPublicKey: agentKeys.publicKey,
      constraints: [{ type: 'checkout.custom_geo_fence', region: 'EU' }],
      checkoutJwt,
      aud: AUD,
      nonce: freshNonce('x'),
      iat: FIXED_NOW - 5,
    });
    const result = await verifier.verify({
      method: 'POST',
      url: `${AUD}/cart`,
      headers: { host: MERCHANT, 'ap2-checkout-mandate': c },
    });
    expect(result.trusted).toBe(true);
  });
});
