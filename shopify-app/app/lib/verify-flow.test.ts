import { describe, expect, it } from 'vitest';
import { decideVerification, isConclusive, REASON_UNVERIFIABLE } from './verify-flow.js';
import type { MerchantPolicyInput } from './policy.js';
import type { AvaCallResult } from './ava.server.js';
import type { VerificationFailureReason, VerificationResult } from './ava-types.js';

/** Headers as a Web Bot Auth request presents them. */
const WBA_HEADERS: Record<string, string> = {
  signature: 'sig1=:abc:',
  'signature-input': 'sig1=("@authority");keyid="k";tag="web-bot-auth"',
  'signature-agent': '"https://chatgpt.com"',
};

/** Headers as an AVA TAP request presents them: signed, no tag, no agent origin. */
const TAP_HEADERS: Record<string, string> = {
  signature: 'sig1=:abc:',
  'signature-input': 'sig1=("@authority");keyid="agent_123";alg="ed25519"',
};

function settings(overrides: Partial<MerchantPolicyInput> = {}): MerchantPolicyInput {
  return {
    acceptVerifiedAgents: true,
    defaultDiscountPct: 10,
    maxDiscountPct: 20,
    identityOnlyDiscountPct: 0,
    ...overrides,
  };
}

function verdict(result: VerificationResult): AvaCallResult {
  return { ok: true, result };
}

function rejected(
  reason: VerificationFailureReason,
  conclusive?: boolean,
): AvaCallResult {
  return {
    ok: true,
    result: {
      trusted: false,
      reason,
      message: 'no',
      ...(conclusive === undefined ? {} : { conclusive }),
    },
  };
}

const IDENTITY_ONLY: VerificationResult = {
  trusted: true,
  conclusive: true,
  protocol: 'web-bot-auth',
  agent: { id: 'https://chatgpt.com', protocol: 'web-bot-auth' },
  ttlSeconds: 60,
};

const MANDATE_BACKED: VerificationResult = {
  trusted: true,
  conclusive: true,
  protocol: 'ava-tap',
  buyerInfo: { buyerId: 'b1' },
  mandate: {
    id: 'm',
    iat: 0,
    exp: 9_999_999,
    maxAmountMinor: 50_000,
    currency: 'USD',
    allowedMerchants: ['*'],
  },
  ttlSeconds: 60,
};

describe('isConclusive', () => {
  it('reads a present boolean', () => {
    expect(isConclusive({ trusted: false, reason: 'unknown_agent', message: '', conclusive: false })).toBe(false);
    expect(isConclusive({ trusted: false, reason: 'unknown_agent', message: '', conclusive: true })).toBe(true);
  });

  it('reads an absent value as conclusive (the API forward-compat rule)', () => {
    // A verdict from an API build older than the field, or one cached before it
    // existed, means "we checked". Reading it the other way would relabel every
    // ordinary rejection as could-not-check.
    expect(isConclusive({ trusted: false, reason: 'unknown_agent', message: '' })).toBe(true);
  });

  it('reads a malformed value as conclusive', () => {
    const malformed = {
      trusted: false,
      reason: 'unknown_agent',
      message: '',
      conclusive: 'false',
    } as unknown as VerificationResult;
    expect(isConclusive(malformed)).toBe(true);
  });
});

describe('decideVerification', () => {
  it('fails closed with an error row when AVA Pay cannot be reached', () => {
    for (const error of ['timeout', 'network', 'bad_response'] as const) {
      const d = decideVerification(settings(), { ok: false, error }, WBA_HEADERS);
      expect(d.response).toEqual({ allow: false, reason: `ava_${error}` });
      expect(d.event.outcome).toBe('error');
      expect(d.event.reason).toBe(`ava_${error}`);
      expect(d.event.platform).toBe('https://chatgpt.com');
      expect(d.event.protocol).toBe('web-bot-auth');
      expect(d.mintDiscountPct).toBe(0);
    }
  });

  it('reports a checked-and-rejected agent as blocked', () => {
    const d = decideVerification(settings(), rejected('invalid_signature', true), WBA_HEADERS);
    expect(d.response).toEqual({ allow: false, reason: 'agent_blocked' });
    expect(d.event.outcome).toBe('failed');
    expect(d.event.reason).toBe('invalid_signature');
    expect(d.event.protocol).toBe('web-bot-auth');
    expect(d.mintDiscountPct).toBe(0);
  });

  /**
   * The one that matters. A verdict the verifier could not complete must fail
   * closed AND must not be reported as a blocked agent: we did not block this
   * agent, we never managed to check it.
   */
  it('fails closed on a could-not-check verdict without calling it blocked', () => {
    const d = decideVerification(settings(), rejected('directory_unavailable', false), TAP_HEADERS);

    expect(d.response.allow).toBe(false);
    expect(d.response.reason).not.toBe('agent_blocked');
    expect(d.response.reason).toBe(REASON_UNVERIFIABLE);

    expect(d.event.outcome).toBe('unverifiable');
    expect(d.event.outcome).not.toBe('failed');
    expect(d.event.reason).toBe('directory_unavailable');
    expect(d.event.protocol).toBe('ava-tap');
    expect(d.event.platform).toBe('agent_123');
    expect(d.mintDiscountPct).toBe(0);
  });

  it('keys the split on conclusive, never on the reason string', () => {
    // Web Bot Auth and the Visa JWKS path report the same could-not-check
    // condition under the older name key_directory_unavailable, and the
    // vocabulary will keep growing.
    const cases: Array<[VerificationFailureReason, boolean, string, string]> = [
      ['directory_unavailable', false, 'unverifiable', REASON_UNVERIFIABLE],
      ['key_directory_unavailable', false, 'unverifiable', REASON_UNVERIFIABLE],
      ['unknown_agent', true, 'failed', 'agent_blocked'],
      ['unsigned_key', true, 'failed', 'agent_blocked'],
      ['key_proof_invalid', true, 'failed', 'agent_blocked'],
    ];
    for (const [reason, conclusive, outcome, responseReason] of cases) {
      const d = decideVerification(settings(), rejected(reason, conclusive), WBA_HEADERS);
      expect(d.response.allow, reason).toBe(false);
      expect(d.event.outcome, reason).toBe(outcome);
      expect(d.response.reason, reason).toBe(responseReason);
      expect(d.event.reason, reason).toBe(reason);
    }
  });

  it('treats a verdict with no conclusive field as a real rejection', () => {
    const d = decideVerification(settings(), rejected('unknown_agent'), WBA_HEADERS);
    expect(d.event.outcome).toBe('failed');
    expect(d.response.reason).toBe('agent_blocked');
  });

  it('admits identity-only traffic with no discount by default', () => {
    const d = decideVerification(settings(), verdict(IDENTITY_ONLY), WBA_HEADERS);
    expect(d.response).toEqual({ allow: true, reason: 'verified' });
    expect(d.event.outcome).toBe('verified');
    expect(d.event.identityOnly).toBe(true);
    expect(d.event.platform).toBe('https://chatgpt.com');
    expect(d.event.protocol).toBe('web-bot-auth');
    expect(d.event.discountPct).toBe(0);
    expect(d.mintDiscountPct).toBe(0);
  });

  it('admits mandate-backed traffic with the merchant default discount', () => {
    const d = decideVerification(settings(), verdict(MANDATE_BACKED), TAP_HEADERS);
    expect(d.response.allow).toBe(true);
    expect(d.event.outcome).toBe('verified');
    expect(d.event.identityOnly).toBe(false);
    expect(d.event.discountPct).toBe(10);
    expect(d.mintDiscountPct).toBe(10);
  });

  it('records a policy rejection under its own outcome and reason', () => {
    const d = decideVerification(
      settings({ acceptVerifiedAgents: false }),
      verdict(IDENTITY_ONLY),
      WBA_HEADERS,
    );
    expect(d.response).toEqual({ allow: false, reason: 'merchant_disabled' });
    expect(d.event.outcome).toBe('policy_blocked');
    expect(d.event.identityOnly).toBe(true);
    expect(d.mintDiscountPct).toBe(0);
  });

  it('falls back to the sniffed protocol when a trusted verdict carries none', () => {
    const bare: VerificationResult = { trusted: true, ttlSeconds: 60 };
    const d = decideVerification(settings(), verdict(bare), TAP_HEADERS);
    expect(d.event.protocol).toBe('ava-tap');
    expect(d.event.platform).toBe('agent_123');
  });

  /**
   * The perk is decided here, minted by the route. A code that cannot be minted
   * (createOneTimeDiscount returns null on every failure) leaves this decision
   * untouched, which is what keeps a coupon problem from demoting a verified
   * agent to a failure.
   */
  it('keeps the verdict independent of whether a code can be minted', () => {
    const d = decideVerification(settings(), verdict(MANDATE_BACKED), TAP_HEADERS);
    // Replaying the route's compose step with minting having failed.
    const discount = null;
    const response = { ...d.response, ...(discount ? { discount } : {}) };
    const event = { ...d.event, ...(discount ? { discountCode: 'x' } : {}) };

    expect(response).toEqual({ allow: true, reason: 'verified' });
    expect(event.outcome).toBe('verified');
    expect(event).not.toHaveProperty('discountCode');
    expect(event.discountPct).toBe(10);
  });
});
