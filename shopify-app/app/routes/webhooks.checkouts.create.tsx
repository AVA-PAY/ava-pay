import type { ActionFunctionArgs } from '@remix-run/node';
import { authenticate } from '../shopify.server.js';
import prisma from '../db.server.js';

/**
 * checkouts/create webhook — telemetry only.
 *
 * The actual verification + discount happens in the App Proxy before the
 * customer gets here. We use this hook to record what made it to checkout so
 * the merchant dashboard can show "X verified agent checkouts in the last 7
 * days, Y blocked" without needing to query Shopify.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, payload, topic } = await authenticate.webhook(request);

  const checkout = (payload ?? {}) as { note_attributes?: Array<{ name: string; value: string }> };
  const attrs = checkout.note_attributes ?? [];
  const verifiedAttr = attrs.find((a) => a.name === 'ava_pay_verified');
  const discountAttr = attrs.find((a) => a.name === 'ava_pay_discount_pct');

  await prisma.verificationLog.create({
    data: {
      shop,
      trusted: verifiedAttr?.value === 'true',
      reason: `webhook_${topic}`,
      discountPct: discountAttr ? Number(discountAttr.value) || null : null,
    },
  });

  return new Response();
}
