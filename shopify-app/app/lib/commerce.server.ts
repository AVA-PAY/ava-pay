import prisma from '../db.server.js';

/**
 * Record a checkout/order funnel event, attributing it to an agent platform
 * via the discount code the App Proxy minted at verification time.
 *
 * Upsert keyed on (shop, kind, sourceId): Shopify webhooks redeliver, and a
 * redelivered payload must not double-count revenue.
 */
export interface CommerceEventInput {
  shop: string;
  kind: 'checkout' | 'order';
  sourceId: string;
  orderName?: string | null;
  totalMinor?: number | null;
  currency?: string | null;
  discountCode?: string | null;
}

export async function recordCommerceEvent(input: CommerceEventInput): Promise<void> {
  let platform: string | null = null;
  let protocol: string | null = null;

  if (input.discountCode) {
    const source = await prisma.verificationEvent.findFirst({
      where: { shop: input.shop, discountCode: input.discountCode },
      orderBy: { createdAt: 'desc' },
      select: { platform: true, protocol: true },
    });
    platform = source?.platform ?? null;
    protocol = source?.protocol ?? null;
  }

  const data = {
    orderName: input.orderName ?? null,
    totalMinor: input.totalMinor ?? null,
    currency: input.currency ?? null,
    discountCode: input.discountCode ?? null,
    platform,
    protocol,
  };

  await prisma.agentCommerceEvent.upsert({
    where: {
      shop_kind_sourceId: { shop: input.shop, kind: input.kind, sourceId: input.sourceId },
    },
    update: data,
    create: { shop: input.shop, kind: input.kind, sourceId: input.sourceId, ...data },
  });
}
