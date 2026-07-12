import { describe, expect, it } from 'vitest';
import { applyMerchantPolicy, type MerchantPolicyInput } from './policy.js';
import type { VerificationResult } from './ava-types.js';

const trusted: VerificationResult = {
  trusted: true,
  buyerInfo: { buyerId: 'b1' },
  mandate: {
    id: 'm',
    iat: 0,
    exp: 9_999_999,
    maxAmountMinor: 0,
    currency: 'USD',
    allowedMerchants: ['*'],
  },
  ttlSeconds: 60,
};

/** Identity-only trust: e.g. a Web Bot Auth result. No mandate, no buyer. */
const identityOnly: VerificationResult = {
  trusted: true,
  protocol: 'web-bot-auth',
  agent: { id: 'https://chatgpt.com', protocol: 'web-bot-auth' },
  ttlSeconds: 60,
};

const blocked: VerificationResult = {
  trusted: false,
  reason: 'invalid_signature',
  message: 'nope',
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

describe('applyMerchantPolicy', () => {
  it('blocks when the merchant has the toggle off', () => {
    const decision = applyMerchantPolicy(settings({ acceptVerifiedAgents: false }), trusted);
    expect(decision).toEqual({ allow: false, reason: 'merchant_disabled' });
  });

  it('blocks when AVA returns trusted=false', () => {
    const decision = applyMerchantPolicy(settings(), blocked);
    expect(decision).toEqual({ allow: false, reason: 'agent_blocked' });
  });

  it('uses the merchant default when AVA returns no discount', () => {
    const decision = applyMerchantPolicy(settings({ defaultDiscountPct: 7 }), trusted);
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 7 });
  });

  it("respects AVA's discount when present", () => {
    const decision = applyMerchantPolicy(settings({ defaultDiscountPct: 7 }), {
      ...trusted,
      discount: 0.15,
    });
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 15 });
  });

  it("caps AVA's discount at the merchant's max", () => {
    const decision = applyMerchantPolicy(
      settings({ defaultDiscountPct: 5, maxDiscountPct: 10 }),
      { ...trusted, discount: 0.5 },
    );
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 10 });
  });

  it('admits identity-only results with NO discount by default', () => {
    const decision = applyMerchantPolicy(settings(), identityOnly);
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 0 });
  });

  it('applies the identity-only tier when the merchant opted in', () => {
    const decision = applyMerchantPolicy(settings({ identityOnlyDiscountPct: 5 }), identityOnly);
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 5 });
  });

  it('caps the identity-only tier at the merchant max', () => {
    const decision = applyMerchantPolicy(
      settings({ identityOnlyDiscountPct: 50, maxDiscountPct: 10 }),
      identityOnly,
    );
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 10 });
  });

  it('ignores a verifier discount hint on a mandate-less result', () => {
    const decision = applyMerchantPolicy(settings(), { ...identityOnly, discount: 0.15 });
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 0 });
  });

  it('does not let the identity-only tier leak onto mandate-backed results', () => {
    const decision = applyMerchantPolicy(
      settings({ identityOnlyDiscountPct: 3, defaultDiscountPct: 12 }),
      trusted,
    );
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 12 });
  });
});
