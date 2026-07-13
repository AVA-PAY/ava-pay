import type { ActionFunctionArgs } from 'react-router';
import { authenticate } from '../shopify.server.js';
import { recordCommerceEvent } from '../lib/commerce.server.js';
import {
  findAvaDiscountCode,
  hasVerifiedNoteAttribute,
  toMinorUnits,
  type WebhookDiscountCode,
  type WebhookNoteAttribute,
} from '../lib/commerce.js';

/**
 * orders/create webhook — record realized agent revenue.
 *
 * If a verified-agent order completed, we store its value and attribute it
 * back to the agent platform via the AVA-minted discount code, so the
 * dashboard can show conversion and revenue by agent source. No mutating
 * action here — discounts were applied at the App Proxy step.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, payload } = await authenticate.webhook(request);

  const order = (payload ?? {}) as {
    id?: number | string;
    name?: string;
    total_price?: string;
    currency?: string;
    note_attributes?: WebhookNoteAttribute[];
    discount_codes?: WebhookDiscountCode[];
  };

  const avaCode = findAvaDiscountCode(order.discount_codes);
  const verified = hasVerifiedNoteAttribute(order.note_attributes);
  if (!verified && !avaCode) return new Response();
  if (order.id === undefined || order.id === null) return new Response();

  await recordCommerceEvent({
    shop,
    kind: 'order',
    sourceId: String(order.id),
    orderName: order.name ?? null,
    totalMinor: toMinorUnits(order.total_price),
    currency: order.currency ?? null,
    discountCode: avaCode,
  });

  return new Response();
}
