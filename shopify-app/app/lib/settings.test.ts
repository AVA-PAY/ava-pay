import { describe, expect, it } from 'vitest';
import { applyMerchantPolicy } from './policy.js';
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

const blocked: VerificationResult = {
  trusted: false,
  reason: 'invalid_signature',
  message: 'nope',
};

describe('applyMerchantPolicy', () => {
  it('blocks when the merchant has the toggle off', () => {
    const decision = applyMerchantPolicy(
      { acceptVerifiedAgents: false, defaultDiscountPct: 10, maxDiscountPct: 20 },
      trusted,
    );
    expect(decision).toEqual({ allow: false, reason: 'merchant_disabled' });
  });

  it('blocks when AVA returns trusted=false', () => {
    const decision = applyMerchantPolicy(
      { acceptVerifiedAgents: true, defaultDiscountPct: 10, maxDiscountPct: 20 },
      blocked,
    );
    expect(decision).toEqual({ allow: false, reason: 'agent_blocked' });
  });

  it('uses the merchant default when AVA returns no discount', () => {
    const decision = applyMerchantPolicy(
      { acceptVerifiedAgents: true, defaultDiscountPct: 7, maxDiscountPct: 20 },
      trusted,
    );
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 7 });
  });

  it("respects AVA's discount when present", () => {
    const decision = applyMerchantPolicy(
      { acceptVerifiedAgents: true, defaultDiscountPct: 7, maxDiscountPct: 20 },
      { ...trusted, discount: 0.15 },
    );
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 15 });
  });

  it("caps AVA's discount at the merchant's max", () => {
    const decision = applyMerchantPolicy(
      { acceptVerifiedAgents: true, defaultDiscountPct: 5, maxDiscountPct: 10 },
      { ...trusted, discount: 0.5 },
    );
    expect(decision).toEqual({ allow: true, reason: 'verified', discountPct: 10 });
  });
});
