import type { ActionFunctionArgs } from '@remix-run/node';
import { authenticate } from '../shopify.server.js';
import prisma from '../db.server.js';

/**
 * orders/create webhook — record realized agent revenue.
 *
 * If a verified-agent order completed, we log the order id + applied discount
 * percent so the dashboard can compute "agent-driven GMV" and merchant-funded
 * discount spend. No mutating action here — discounts were applied at the
 * App Proxy step.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, payload } = await authenticate.webhook(request);

  const order = (payload ?? {}) as {
    id?: number;
    name?: string;
    note_attributes?: Array<{ name: string; value: string }>;
    discount_codes?: Array<{ code: string; amount: string; type: string }>;
  };

  const verified = order.note_attributes?.some(
    (a) => a.name === 'ava_pay_verified' && a.value === 'true',
  );
  const avaCode = order.discount_codes?.find((c) => c.code.startsWith('AVA-'));
  if (!verified && !avaCode) return new Response();

  await prisma.verificationLog.create({
    data: {
      shop,
      trusted: true,
      reason: 'order_completed',
      discountPct: avaCode ? Number(avaCode.amount) || null : null,
    },
  });

  return new Response();
}
