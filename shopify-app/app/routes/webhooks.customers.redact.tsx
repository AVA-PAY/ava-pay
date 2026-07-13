import type { ActionFunctionArgs } from 'react-router';
import { authenticate } from '../shopify.server.js';

/**
 * customers/redact — Shopify mandatory compliance webhook.
 *
 * Shopify calls this when a customer asks for their data to be deleted
 * (GDPR right to erasure, CCPA opt-out of sale, etc.).
 *
 * AVA Pay stores NO Shopify customer data. We never receive customer
 * identifiers from the storefront proxy or from the orders webhook
 * beyond what's needed to attribute verified-agent revenue, and none of
 * that includes customer PII. So there is nothing to redact.
 *
 * We log the request so we have an audit trail of compliance handling.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, topic } = await authenticate.webhook(request);

  // Intentionally do NOT log customer identifiers. If we logged customerId
  // here, that log line would itself be customer data, contradicting the
  // "we store no customer data" claim. We log shop + topic + a fixed marker
  // for auditability only.
  console.log(
    JSON.stringify({
      event: 'gdpr.customers.redact',
      topic,
      shop,
      message: 'AVA Pay stores no customer data; nothing to redact.',
      ts: new Date().toISOString(),
    }),
  );

  return new Response();
}
