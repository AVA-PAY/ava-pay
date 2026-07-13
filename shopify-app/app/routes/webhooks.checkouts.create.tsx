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
 * checkouts/create webhook — mid-funnel telemetry only.
 *
 * The actual verification + discount happens in the App Proxy before the
 * customer gets here. Recording checkout-reached lets the dashboard show the
 * verified→checkout→order funnel without querying Shopify.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, payload } = await authenticate.webhook(request);

  const checkout = (payload ?? {}) as {
    id?: number | string;
    token?: string;
    total_price?: string;
    currency?: string;
    note_attributes?: WebhookNoteAttribute[];
    discount_codes?: WebhookDiscountCode[];
  };

  const avaCode = findAvaDiscountCode(checkout.discount_codes);
  const verified = hasVerifiedNoteAttribute(checkout.note_attributes);
  if (!verified && !avaCode) return new Response();

  const sourceId = checkout.token ?? (checkout.id !== undefined ? String(checkout.id) : null);
  if (!sourceId) return new Response();

  await recordCommerceEvent({
    shop,
    kind: 'checkout',
    sourceId,
    totalMinor: toMinorUnits(checkout.total_price),
    currency: checkout.currency ?? null,
    discountCode: avaCode,
  });

  return new Response();
}
