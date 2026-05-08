import prisma from '../db.server.js';
import { clampPct } from './policy.js';

export interface ShopSettings {
  shop: string;
  acceptVerifiedAgents: boolean;
  defaultDiscountPct: number;
  maxDiscountPct: number;
}

const DEFAULTS = {
  acceptVerifiedAgents: true,
  defaultDiscountPct: 10,
  maxDiscountPct: 20,
} as const;

export async function getShopSettings(shop: string): Promise<ShopSettings> {
  const row = await prisma.shopSettings.findUnique({ where: { shop } });
  if (!row) {
    return { shop, ...DEFAULTS };
  }
  return {
    shop: row.shop,
    acceptVerifiedAgents: row.acceptVerifiedAgents,
    defaultDiscountPct: row.defaultDiscountPct,
    maxDiscountPct: row.maxDiscountPct,
  };
}

export async function saveShopSettings(
  shop: string,
  patch: Partial<Omit<ShopSettings, 'shop'>>,
): Promise<ShopSettings> {
  const data = {
    acceptVerifiedAgents: patch.acceptVerifiedAgents ?? DEFAULTS.acceptVerifiedAgents,
    defaultDiscountPct: clampPct(patch.defaultDiscountPct ?? DEFAULTS.defaultDiscountPct),
    maxDiscountPct: clampPct(patch.maxDiscountPct ?? DEFAULTS.maxDiscountPct),
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
  };
}

export { applyMerchantPolicy } from './policy.js';
export type { AppliedDecision } from './policy.js';
