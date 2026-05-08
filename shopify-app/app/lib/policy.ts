import type { VerificationResult } from './ava-types.js';

/**
 * Pure decision logic combining merchant settings and a /verify result.
 * Lives in its own file so it can be unit-tested without spinning up Prisma.
 */

export interface MerchantPolicyInput {
  acceptVerifiedAgents: boolean;
  defaultDiscountPct: number;
  maxDiscountPct: number;
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

  const verifierPct =
    result.discount !== undefined ? Math.round(result.discount * 100) : settings.defaultDiscountPct;
  const finalPct = Math.max(0, Math.min(verifierPct, settings.maxDiscountPct));
  return { allow: true, discountPct: finalPct, reason: 'verified' };
}

export function clampPct(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}
