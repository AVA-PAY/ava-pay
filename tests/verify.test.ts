import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import type { Mandate, VerificationResult } from '../src/types.js';
import { generateAgentKeyPair, signRequest, type KeyPair } from './sign-helper.js';

/**
 * End-to-end tests for /verify against the REAL VisaAgentVerifier.
 *
 * Each test produces a real Ed25519-signed RFC 9421 request via the helper,
 * pipes it through the Fastify route, and asserts the verifier's verdict.
 *
 * Time is fixed via `now: () => FIXED_NOW` on the verifier and the helper, so
 * mandate/signature expiry is deterministic.
 */

const FIXED_NOW = 1_750_000_000;

function defaultMandate(overrides: Partial<Mandate> = {}): Mandate {
  return {
    id: 'mandate_demo',
    iat: FIXED_NOW - 60,
    exp: FIXED_NOW + 600,
    maxAmountMinor: 50_000,
    currency: 'USD',
    allowedMerchants: ['shop.example.com'],
    buyer: { buyerId: 'buyer_alex_001', country: 'US', displayName: 'Alex' },
    ...overrides,
  };
}

const DEFAULT_BODY = JSON.stringify({ items: [{ sku: 'SKU-1', qty: 1 }] });

describe('POST /verify (VisaAgentVerifier, real signatures)', () => {
  let app: FastifyInstance;
  let directory: StaticAgentDirectory;
  let demoKeys: KeyPair;
  let revokedKeys: KeyPair;

  beforeAll(async () => {
    demoKeys = generateAgentKeyPair();
    revokedKeys = generateAgentKeyPair();

    directory = new StaticAgentDirectory();
    directory.add('agent_demo', demoKeys.publicKey);
    directory.add('agent_revoked', revokedKeys.publicKey, true);

    const verifier = new VisaAgentVerifier({
      directory,
      now: () => FIXED_NOW,
    });
    app = await buildServer({ verifier, logger: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('returns trusted=true for a valid signed request', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW - 5,
      expires: FIXED_NOW + 30,
    });

    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      payload: signed,
      headers: { 'content-type': 'application/json' },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as VerificationResult;
    if (!body.trusted) throw new Error(`expected trusted=true, got ${JSON.stringify(body)}`);
    expect(body.buyerInfo?.buyerId).toBe('buyer_alex_001');
    expect(body.mandate?.id).toBe('mandate_demo');
    expect(res.headers['x-ava-verify-ms']).toBeDefined();
  });

  it('echoes an x-ava-discount-hint when included in the cover set', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate(),
      extraHeaders: { 'x-ava-discount-hint': '0.15' },
      components: [
        '@method',
        '@target-uri',
        'host',
        'content-digest',
        'x-ava-mandate',
        'x-ava-discount-hint',
      ],
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(200);
    const body = res.json() as VerificationResult;
    if (!body.trusted) throw new Error('unreachable');
    expect(body.discount).toBe(0.15);
  });

  it('rejects an invalid signature (signed bytes mutated) → invalid_signature', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });
    // Flip one bit in the signature.
    const sigHeader = signed.headers['signature']!;
    const m = sigHeader.match(/^(.*?=:)([^:]+)(:)$/);
    if (!m) throw new Error('signature header pattern did not match');
    const [, prefix, b64, suffix] = m;
    const buf = Buffer.from(b64!, 'base64');
    buf[0] = buf[0]! ^ 0xff;
    signed.headers['signature'] = `${prefix}${buf.toString('base64')}${suffix}`;

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('invalid_signature');
  });

  it('rejects when the body changes after signing → content_digest_mismatch', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });
    signed.body = JSON.stringify({ items: [{ sku: 'SKU-1', qty: 999 }] });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('content_digest_mismatch');
  });

  it('rejects an expired signature → signature_expired', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW - 600,
      expires: FIXED_NOW - 60,
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('signature_expired');
  });

  it('rejects an expired mandate → mandate_expired', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate({ exp: FIXED_NOW - 1 }),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('mandate_expired');
  });

  it('rejects a request to a non-allowlisted merchant → mandate_merchant_mismatch', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://other-merchant.com/checkout',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('mandate_merchant_mismatch');
  });

  it('rejects a revoked agent → revoked_agent', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_revoked',
      privateKey: revokedKeys.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('revoked_agent');
  });

  it('rejects an unknown agent (keyid not in directory) → unknown_agent', async () => {
    const stranger = generateAgentKeyPair();
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_stranger',
      privateKey: stranger.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('unknown_agent');
  });

  it('rejects a wrong-key signature (signer ≠ directory key) → invalid_signature', async () => {
    const otherKeys = generateAgentKeyPair();
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: otherKeys.privateKey, // signed with wrong key
      mandate: defaultMandate(),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('invalid_signature');
  });

  it('rejects an unsupported algorithm → unsupported_algorithm', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });
    signed.headers['signature-input'] = signed.headers['signature-input']!.replace(
      'alg="ed25519"',
      'alg="rsa-pss-sha512"',
    );

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('unsupported_algorithm');
  });

  it('rejects malformed signature headers → malformed_signature_header', async () => {
    const signed = signRequest({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body: DEFAULT_BODY,
      agentId: 'agent_demo',
      privateKey: demoKeys.privateKey,
      mandate: defaultMandate(),
      created: FIXED_NOW,
      expires: FIXED_NOW + 30,
    });
    signed.headers['signature-input'] = 'this-is-not-a-valid-sig-input';

    const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('malformed_signature_header');
  });

  it('rejects requests missing signature headers → missing_agent_credentials', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      payload: {
        method: 'POST',
        url: 'https://shop.example.com/cart',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      },
    });
    expect(res.statusCode).toBe(403);
    const body = res.json() as VerificationResult;
    if (body.trusted) throw new Error('unreachable');
    expect(body.reason).toBe('missing_agent_credentials');
  });

  it('still 400s on schema-malformed payloads', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      payload: { method: 'POST' /* missing url + headers */ },
    });
    expect(res.statusCode).toBe(400);
  });
});
