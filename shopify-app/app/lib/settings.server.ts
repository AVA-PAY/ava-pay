import prisma from '../db.server.js';
import { clampPct } from './policy.js';
import { validateAgentPolicy, type AgentPolicy } from './agent-policy.js';

export interface ShopSettings {
  shop: string;
  acceptVerifiedAgents: boolean;
  defaultDiscountPct: number;
  maxDiscountPct: number;
  /** Discount for identity-only verified agents (no mandate). 0 = admit, no discount. */
  identityOnlyDiscountPct: number;
  /** Per-agent-platform policy. Null = none configured (pre-policy behavior). */
  policy: AgentPolicy | null;
}

const DEFAULTS = {
  acceptVerifiedAgents: true,
  defaultDiscountPct: 10,
  maxDiscountPct: 20,
  identityOnlyDiscountPct: 0,
} as const;

/**
 * A stored policy that no longer validates (e.g. written by a newer app
 * version) is treated as ABSENT rather than partially applied: the verify
 * path falls back to the documented no-policy behavior instead of guessing.
 */
function parseStoredPolicy(policyJson: string | null): AgentPolicy | null {
  if (!policyJson) return null;
  try {
    const parsed = validateAgentPolicy(JSON.parse(policyJson));
    return parsed.ok ? parsed.policy : null;
  } catch {
    return null;
  }
}

export async function getShopSettings(shop: string): Promise<ShopSettings> {
  const row = await prisma.shopSettings.findUnique({ where: { shop } });
  if (!row) {
    return { shop, ...DEFAULTS, policy: null };
  }
  return {
    shop: row.shop,
    acceptVerifiedAgents: row.acceptVerifiedAgents,
    defaultDiscountPct: row.defaultDiscountPct,
    maxDiscountPct: row.maxDiscountPct,
    identityOnlyDiscountPct: row.identityOnlyDiscountPct,
    policy: parseStoredPolicy(row.policyJson),
  };
}

/**
 * Persist a validated policy document (or clear it with null). Callers must
 * pass an AgentPolicy that came out of validateAgentPolicy/parseAgentPolicy.
 */
export async function saveShopPolicy(shop: string, policy: AgentPolicy | null): Promise<void> {
  const policyJson = policy ? JSON.stringify(policy) : null;
  await prisma.shopSettings.upsert({
    where: { shop },
    update: { policyJson },
    create: { shop, ...DEFAULTS, policyJson },
  });
}

export async function saveShopSettings(
  shop: string,
  patch: Partial<Omit<ShopSettings, 'shop'>>,
): Promise<ShopSettings> {
  const data = {
    acceptVerifiedAgents: patch.acceptVerifiedAgents ?? DEFAULTS.acceptVerifiedAgents,
    defaultDiscountPct: clampPct(patch.defaultDiscountPct ?? DEFAULTS.defaultDiscountPct),
    maxDiscountPct: clampPct(patch.maxDiscountPct ?? DEFAULTS.maxDiscountPct),
    identityOnlyDiscountPct: clampPct(
      patch.identityOnlyDiscountPct ?? DEFAULTS.identityOnlyDiscountPct,
    ),
  };
  const saved = await prisma.shopSettings.upsert({
    where: { shop },
    update: data,
    create: { shop, ...data },
  });
  return {
    shop: saved.shop,
    acceptVerifiedAgents: saved.acceptVerifiedAgents,
    defaultDiscountPct: saved.defaultDiscountPct,
    maxDiscountPct: saved.maxDiscountPct,
    identityOnlyDiscountPct: saved.identityOnlyDiscountPct,
    policy: parseStoredPolicy(saved.policyJson),
  };
}

export { applyMerchantPolicy } from './policy.js';
export type { AppliedDecision } from './policy.js';
