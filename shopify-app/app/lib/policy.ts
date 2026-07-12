import type { VerificationResult } from './ava-types.js';

/**
 * Pure decision logic combining merchant settings and a /verify result.
 * Lives in its own file so it can be unit-tested without spinning up Prisma.
 */

export interface MerchantPolicyInput {
  acceptVerifiedAgents: boolean;
  defaultDiscountPct: number;
  maxDiscountPct: number;
  /**
   * Discount tier for identity-only verified agents (trusted but carrying no
   * buyer mandate, e.g. Web Bot Auth). 0 — the default — admits them with no
   * discount; merchants opt in explicitly by raising it.
   */
  identityOnlyDiscountPct: number;
}

export type AppliedDecision =
  | { allow: true; discountPct: number; reason: 'verified' }
  | { allow: false; reason: 'merchant_disabled' | 'agent_blocked' };

export function applyMerchantPolicy(
  settings: MerchantPolicyInput,
  result: VerificationResult,
): AppliedDecision {
  if (!settings.acceptVerifiedAgents) {
    return { allow: false, reason: 'merchant_disabled' };
  }
  if (!result.trusted) {
    return { allow: false, reason: 'agent_blocked' };
  }

  // Identity-only trust proves who the agent is, not that a buyer authorized
  // spending. Admit it — that's the point of verification — but discounts
  // come from the merchant's explicit identity-only tier, and a verifier
  // discount hint is not honored without a mandate behind it.
  if (!result.mandate) {
    const pct = Math.max(0, Math.min(settings.identityOnlyDiscountPct, settings.maxDiscountPct));
    return { allow: true, discountPct: pct, reason: 'verified' };
  }

  const verifierPct =
    result.discount !== undefined ? Math.round(result.discount * 100) : settings.defaultDiscountPct;
  const finalPct = Math.max(0, Math.min(verifierPct, settings.maxDiscountPct));
  return { allow: true, discountPct: finalPct, reason: 'verified' };
}

export function clampPct(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}
