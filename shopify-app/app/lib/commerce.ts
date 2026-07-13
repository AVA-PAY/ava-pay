/**
 * Pure helpers for attributing Shopify checkouts/orders back to verified
 * agent traffic. Webhook payload parsing lives here (no I/O) so it can be
 * unit-tested against real payload shapes.
 */

export const AVA_DISCOUNT_PREFIX = 'AVA-';

export interface WebhookDiscountCode {
  code?: string;
}

export interface WebhookNoteAttribute {
  name?: string;
  value?: string;
}

/** First AVA-minted discount code on a checkout/order payload, if any. */
export function findAvaDiscountCode(codes: WebhookDiscountCode[] | undefined): string | null {
  for (const c of codes ?? []) {
    if (typeof c.code === 'string' && c.code.startsWith(AVA_DISCOUNT_PREFIX)) return c.code;
  }
  return null;
}

/** True when the storefront embed marked this checkout/order as agent-verified. */
export function hasVerifiedNoteAttribute(attrs: WebhookNoteAttribute[] | undefined): boolean {
  return (attrs ?? []).some((a) => a.name === 'ava_pay_verified' && a.value === 'true');
}

/**
 * Shopify sends money as decimal strings ("123.45"). Convert to integer minor
 * units; null for absent/malformed values (never NaN into the database).
 */
export function toMinorUnits(amount: string | number | undefined | null): number | null {
  if (amount === undefined || amount === null || amount === '') return null;
  const n = typeof amount === 'number' ? amount : Number(amount);
  if (!Number.isFinite(n)) return null;
  return Math.round(n * 100);
}
