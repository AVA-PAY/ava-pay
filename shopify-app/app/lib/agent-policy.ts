/**
 * Agent platform policy — the merchant's rules layer.
 *
 * A policy is a versioned, JSON-portable document: per-platform
 * allow/challenge/block, discount caps, spend rules, and agent-only offers.
 * Everything here is pure (no I/O) so enforcement is unit-testable.
 *
 * Fail-closed contract:
 *   - No policy configured (null)  → legacy behavior, unchanged.
 *   - Platform with no matching rule → the explicit defaultRule if present,
 *     otherwise the MOST RESTRICTIVE synthesis of the listed rules
 *     (harshest action, lowest caps). Unknown platforms never get a better
 *     deal than any known one.
 *   - A policy with no rules and no defaultRule is rejected at parse time —
 *     it has no defined behavior to fall back to.
 *
 * Identity-only invariant (non-negotiable, decided by Nick 2026-07-12):
 *   traffic verified without a buyer mandate is admitted but receives NO
 *   discount unless the merchant raised identityOnlyDiscountPct. Platform
 *   offers (offerDiscountPct) apply to mandate-backed traffic only and can
 *   never leak onto identity-only requests.
 */

export type PolicyAction = 'allow' | 'challenge' | 'block';

export interface PolicyRuleBody {
  action: PolicyAction;
  /** Cap on the discount % this rule's traffic can receive. Always intersected with the global max. */
  maxDiscountPct?: number;
  /** Spend rule: reject mandates authorizing more than this many minor units (cents). */
  maxSpendMinor?: number;
  /** Agent-only offer: preferred discount % for MANDATE-BACKED traffic under this rule. */
  offerDiscountPct?: number;
}

export interface PlatformRule extends PolicyRuleBody {
  /** Exact platform identity (e.g. "https://chatgpt.com"). Matched case-insensitively. */
  platform: string;
}

export interface AgentPolicy {
  version: 1;
  /** Fallback for platforms with no matching rule. Omitted → most-restrictive synthesis. */
  defaultRule?: PolicyRuleBody;
  rules: PlatformRule[];
}

export type ParsePolicyResult =
  | { ok: true; policy: AgentPolicy }
  | { ok: false; error: string };

const ACTIONS: readonly PolicyAction[] = ['allow', 'challenge', 'block'];
/** Restrictiveness order for the unknown-platform synthesis. */
const ACTION_RANK: Record<PolicyAction, number> = { allow: 0, challenge: 1, block: 2 };

function validateRuleBody(rule: unknown, label: string): PolicyRuleBody | string {
  if (typeof rule !== 'object' || rule === null || Array.isArray(rule)) {
    return `${label} must be an object`;
  }
  const r = rule as Record<string, unknown>;
  if (!ACTIONS.includes(r.action as PolicyAction)) {
    return `${label}: action must be one of ${ACTIONS.join(', ')}`;
  }
  for (const key of ['maxDiscountPct', 'offerDiscountPct'] as const) {
    const v = r[key];
    if (v === undefined) continue;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 100) {
      return `${label}: ${key} must be an integer 0–100`;
    }
  }
  if (r.maxSpendMinor !== undefined) {
    const v = r.maxSpendMinor;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) {
      return `${label}: maxSpendMinor must be a non-negative integer (minor units)`;
    }
  }
  const body: PolicyRuleBody = { action: r.action as PolicyAction };
  if (r.maxDiscountPct !== undefined) body.maxDiscountPct = r.maxDiscountPct as number;
  if (r.maxSpendMinor !== undefined) body.maxSpendMinor = r.maxSpendMinor as number;
  if (r.offerDiscountPct !== undefined) body.offerDiscountPct = r.offerDiscountPct as number;
  return body;
}

/** Strict validation — imports reject rather than silently repair. */
export function parseAgentPolicy(json: string): ParsePolicyResult {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return { ok: false, error: 'Not valid JSON.' };
  }
  return validateAgentPolicy(raw);
}

export function validateAgentPolicy(raw: unknown): ParsePolicyResult {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, error: 'Policy must be a JSON object.' };
  }
  const p = raw as Record<string, unknown>;
  if (p.version !== 1) {
    return { ok: false, error: 'Unsupported policy version (expected version: 1).' };
  }
  if (!Array.isArray(p.rules)) {
    return { ok: false, error: 'rules must be an array.' };
  }

  const rules: PlatformRule[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < p.rules.length; i++) {
    const entry = p.rules[i] as Record<string, unknown>;
    const label = `rules[${i}]`;
    if (typeof entry !== 'object' || entry === null) {
      return { ok: false, error: `${label} must be an object` };
    }
    if (typeof entry.platform !== 'string' || entry.platform.trim() === '') {
      return { ok: false, error: `${label}: platform must be a non-empty string` };
    }
    const platform = entry.platform.trim();
    const key = platform.toLowerCase();
    if (seen.has(key)) {
      return { ok: false, error: `${label}: duplicate platform "${platform}"` };
    }
    seen.add(key);
    const body = validateRuleBody(entry, label);
    if (typeof body === 'string') return { ok: false, error: body };
    rules.push({ platform, ...body });
  }

  let defaultRule: PolicyRuleBody | undefined;
  if (p.defaultRule !== undefined) {
    const body = validateRuleBody(p.defaultRule, 'defaultRule');
    if (typeof body === 'string') return { ok: false, error: body };
    defaultRule = body;
  }

  if (rules.length === 0 && !defaultRule) {
    return {
      ok: false,
      error: 'Policy must contain at least one rule or a defaultRule (an empty policy has no defined behavior).',
    };
  }

  const policy: AgentPolicy = { version: 1, rules };
  if (defaultRule) policy.defaultRule = defaultRule;
  return { ok: true, policy };
}

export function serializeAgentPolicy(policy: AgentPolicy): string {
  return JSON.stringify(policy, null, 2);
}

/**
 * Most-restrictive synthesis for platforms no rule names: harshest action of
 * any listed rule, lowest defined caps. Offers are per-platform grants and
 * are never inherited.
 */
export function mostRestrictiveRule(policy: AgentPolicy): PolicyRuleBody {
  const sources = policy.rules.length > 0 ? policy.rules : [policy.defaultRule!];
  const out: PolicyRuleBody = { action: 'allow' };
  for (const r of sources) {
    if (ACTION_RANK[r.action] > ACTION_RANK[out.action]) out.action = r.action;
    if (r.maxDiscountPct !== undefined) {
      out.maxDiscountPct = Math.min(out.maxDiscountPct ?? r.maxDiscountPct, r.maxDiscountPct);
    }
    if (r.maxSpendMinor !== undefined) {
      out.maxSpendMinor = Math.min(out.maxSpendMinor ?? r.maxSpendMinor, r.maxSpendMinor);
    }
  }
  return out;
}

/** Rule for a given platform: exact match → explicit default → most-restrictive synthesis. */
export function resolveRule(policy: AgentPolicy, platform: string | null): PolicyRuleBody {
  if (platform) {
    const key = platform.toLowerCase();
    const match = policy.rules.find((r) => r.platform.toLowerCase() === key);
    if (match) return match;
  }
  if (policy.defaultRule) return policy.defaultRule;
  return mostRestrictiveRule(policy);
}
