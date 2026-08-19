import { createPublicKey, verify as edVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decideTestVisit, describeTestVisit } from './test-visit.js';
import {
  buildTestVisitRequest,
  DEMO_AGENT_ID,
  DEMO_AGENT_PRIVATE_JWK,
  DEMO_AGENT_PUBLIC_X,
} from './test-visit-request.js';
import type { AvaCallResult } from './ava.server.js';
import type { MerchantPolicyInput } from './policy.js';
import type { VerificationResult } from './ava-types.js';

const SHOP = 'ava-pay-test-store.myshopify.com';

/** Read a header the request must have, failing loudly rather than typing around it. */
function header(req: { headers: Record<string, string | undefined> }, name: string): string {
  const value = req.headers[name];
  expect(value, `expected a ${name} header`).toBeTypeOf('string');
  return value as string;
}

const settings: MerchantPolicyInput = {
  acceptVerifiedAgents: true,
  defaultDiscountPct: 10,
  maxDiscountPct: 20,
  identityOnlyDiscountPct: 0,
  policy: null,
};

function trustedResult(): VerificationResult {
  return {
    trusted: true,
    protocol: 'ava-tap',
    agent: { id: DEMO_AGENT_ID, protocol: 'ava-tap' },
    buyerInfo: { buyerId: 'buyer_demo_001' },
    mandate: {
      id: 'mandate_test_visit_1',
      iat: 0,
      exp: 9_999_999_999,
      maxAmountMinor: 50_000,
      currency: 'USD',
      allowedMerchants: [SHOP],
    },
  } as VerificationResult;
}

describe('the demo credential', () => {
  it('still derives the public key seeded in the hosted directory', () => {
    // The private half is public on purpose, but it is copied into three
    // places (here, public/app.js, scripts/simulate-verified-agent.mjs). If
    // anyone rotates one without the others, the signature stops verifying
    // against the directory and this fails first, with an explanation.
    const derived = createPublicKey({ key: DEMO_AGENT_PRIVATE_JWK, format: 'jwk' });
    const jwk = derived.export({ format: 'jwk' }) as { x?: string; crv?: string };
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.x).toBe(DEMO_AGENT_PUBLIC_X);
  });
});

describe('buildTestVisitRequest', () => {
  it('signs the App Proxy URL the agent would have signed', () => {
    const req = buildTestVisitRequest(SHOP);
    expect(req.method).toBe('POST');
    expect(req.url).toBe(`https://${SHOP}/apps/ava-pay/verify`);
    expect(req.headers.host).toBe(SHOP);
    expect(header(req, 'signature-input')).toContain(`keyid="${DEMO_AGENT_ID}"`);
    expect(header(req, 'signature-input')).toContain('alg="ed25519"');
  });

  it('produces a signature that actually verifies over the RFC 9421 base', () => {
    // Real crypto, no mocks: recompute the base from the headers exactly as a
    // verifier would and check the Ed25519 signature against the demo public
    // key. This is what keeps the button honest if the SDK's signing changes.
    const created = 1_760_000_000;
    const req = buildTestVisitRequest(SHOP, { created, nonce: 'nonce-under-test' });

    const match = /^sig1=\((.*)\)(.*)$/.exec(header(req, 'signature-input'));
    if (!match) throw new Error('signature-input did not parse');
    const [, componentList = '', params = ''] = match;
    const components = componentList.split(' ').map((c) => c.replace(/"/g, ''));
    const value = `(${componentList})${params}`;

    const lines = components.map((c) => {
      if (c === '@method') return `"${c}": POST`;
      if (c === '@target-uri') return `"${c}": ${req.url}`;
      return `"${c}": ${header(req, c)}`;
    });
    lines.push(`"@signature-params": ${value}`);

    const sigMatch = /^sig1=:(.*):$/.exec(header(req, 'signature'));
    if (!sigMatch) throw new Error('signature header did not parse');
    const signature = Buffer.from(sigMatch[1] ?? '', 'base64');
    const publicKey = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: DEMO_AGENT_PUBLIC_X },
      format: 'jwk',
    });

    expect(edVerify(null, Buffer.from(lines.join('\n')), publicKey, signature)).toBe(true);
  });

  it('scopes the mandate to this shop and gives every visit a fresh nonce', () => {
    const a = buildTestVisitRequest(SHOP);
    const b = buildTestVisitRequest(SHOP);

    const mandate = JSON.parse(
      Buffer.from(header(a, 'x-ava-mandate'), 'base64').toString('utf-8'),
    );
    expect(mandate.allowedMerchants).toEqual([SHOP]);
    expect(mandate.exp).toBeGreaterThan(mandate.iat);

    // A replayed nonce is rejected by the verifier's replay guard, so two
    // presses of the button must never collide.
    expect(header(a, 'signature-input')).not.toBe(header(b, 'signature-input'));
  });
});

describe('decideTestVisit', () => {
  it('records a verified visit marked as a test, with no discount code', () => {
    const req = buildTestVisitRequest(SHOP);
    const call: AvaCallResult = { ok: true, result: trustedResult() };

    const { event, result } = decideTestVisit(settings, call, req);

    expect(event.outcome).toBe('verified');
    expect(event.source).toBe('test');
    expect(event.protocol).toBe('ava-tap');
    expect(event).not.toHaveProperty('discountCode');
    expect(result.outcome).toBe('verified');
    expect(result.discountPct).toBe(10);
  });

  it('records a rejection as failed when the verifier reached a verdict', () => {
    const req = buildTestVisitRequest(SHOP);
    const call: AvaCallResult = {
      ok: true,
      result: { trusted: false, reason: 'invalid_signature' } as VerificationResult,
    };

    const { event, result } = decideTestVisit(settings, call, req);

    expect(event.outcome).toBe('failed');
    expect(event.source).toBe('test');
    expect(result.reason).toBe('invalid_signature');
    expect(result.discountPct).toBe(0);
  });

  it('records unverifiable, not failed, when a trust root was unreachable', () => {
    const req = buildTestVisitRequest(SHOP);
    const call: AvaCallResult = {
      ok: true,
      result: {
        trusted: false,
        reason: 'directory_unavailable',
        conclusive: false,
      } as VerificationResult,
    };

    const { event, result } = decideTestVisit(settings, call, req);

    expect(event.outcome).toBe('unverifiable');
    expect(result.outcome).toBe('unverifiable');
  });

  it('records an error when AVA Pay could not be reached at all', () => {
    const req = buildTestVisitRequest(SHOP);
    const call: AvaCallResult = { ok: false, error: 'network' };

    const { event, result } = decideTestVisit(settings, call, req);

    expect(event.outcome).toBe('error');
    expect(event.source).toBe('test');
    expect(result.reason).toBe('ava_network');
    expect(result.discountPct).toBe(0);
  });

  it('records policy_blocked when the merchant switched agents off', () => {
    const req = buildTestVisitRequest(SHOP);
    const call: AvaCallResult = { ok: true, result: trustedResult() };

    const { event } = decideTestVisit(
      { ...settings, acceptVerifiedAgents: false },
      call,
      req,
    );

    expect(event.outcome).toBe('policy_blocked');
    expect(event.source).toBe('test');
  });
});

describe('describeTestVisit', () => {
  it('never calls a could-not-check result a rejection', () => {
    const message = describeTestVisit({
      outcome: 'unverifiable',
      reason: 'directory_unavailable',
      protocol: null,
      platform: null,
      discountPct: 0,
    });
    expect(message.tone).toBe('warning');
    expect(message.body).toContain('not a rejection');
    expect(message.title).not.toMatch(/reject|blocked|fail/i);
  });

  it('says plainly that a verified test visit minted no code', () => {
    const message = describeTestVisit({
      outcome: 'verified',
      reason: null,
      protocol: 'ava-tap',
      platform: DEMO_AGENT_ID,
      discountPct: 10,
    });
    expect(message.tone).toBe('success');
    expect(message.body).toContain('10%');
    expect(message.body).toContain('No discount code was created');
  });

  it('reports an unreachable API as a check that did not happen', () => {
    const message = describeTestVisit({
      outcome: 'error',
      reason: 'ava_timeout',
      protocol: null,
      platform: null,
      discountPct: 0,
    });
    expect(message.title).toContain('Could not reach');
    expect(message.body).toContain('fail closed');
  });
});
