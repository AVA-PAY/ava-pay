import type { VerificationResult } from './ava-types.js';
import { resolveRule, type AgentPolicy } from './agent-policy.js';

/**
 * Pure decision logic combining merchant settings, the optional per-platform
 * policy document, and a /verify result. Lives in its own file so it can be
 * unit-tested without spinning up Prisma.
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
  /**
   * Per-agent-platform rules. Null/absent = no policy configured = the
   * pre-policy behavior, exactly.
   */
  policy?: AgentPolicy | null;
}

export type AppliedDecision =
  | { allow: true; discountPct: number; reason: 'verified' }
  | {
      allow: false;
      reason:
        | 'merchant_disabled'
        | 'agent_blocked'
        | 'blocked_by_policy'
        | 'challenge_required'
        | 'spend_limit_exceeded';
    };

export function applyMerchantPolicy(
  settings: MerchantPolicyInput,
  result: VerificationResult,
  platform: string | null = null,
): AppliedDecision {
  if (!settings.acceptVerifiedAgents) {
    return { allow: false, reason: 'merchant_disabled' };
  }
  if (!result.trusted) {
    return { allow: false, reason: 'agent_blocked' };
  }

  const rule = settings.policy ? resolveRule(settings.policy, platform) : null;

  if (rule) {
    if (rule.action === 'block') {
      return { allow: false, reason: 'blocked_by_policy' };
    }
    // Challenge = this platform must come back with buyer authorization.
    // Mandate-backed requests pass; identity-only ones get a typed retry hint.
    if (rule.action === 'challenge' && !result.mandate) {
      return { allow: false, reason: 'challenge_required' };
    }
    // Spend rule: refuse mandates authorizing more than the platform cap.
    if (
      rule.maxSpendMinor !== undefined &&
      result.mandate &&
      result.mandate.maxAmountMinor > rule.maxSpendMinor
    ) {
      return { allow: false, reason: 'spend_limit_exceeded' };
    }
  }

  // The effective cap is the intersection of the global cap and the rule cap.
  const capPct =
    rule?.maxDiscountPct !== undefined
      ? Math.min(settings.maxDiscountPct, rule.maxDiscountPct)
      : settings.maxDiscountPct;

  // Identity-only trust proves who the agent is, not that a buyer authorized
  // spending. Admit it — that's the point of verification — but discounts
  // come only from the merchant's explicit identity-only tier. Neither a
  // verifier discount hint nor a platform offer is honored without a mandate.
  if (!result.mandate) {
    const pct = Math.max(0, Math.min(settings.identityOnlyDiscountPct, capPct));
    return { allow: true, discountPct: pct, reason: 'verified' };
  }

  // Mandate-backed: platform offer > verifier hint > merchant default.
  const basePct =
    rule?.offerDiscountPct !== undefined
      ? rule.offerDiscountPct
      : result.discount !== undefined
        ? Math.round(result.discount * 100)
        : settings.defaultDiscountPct;
  const finalPct = Math.max(0, Math.min(basePct, capPct));
  return { allow: true, discountPct: finalPct, reason: 'verified' };
}

export function clampPct(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}
