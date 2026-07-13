import type { ActionFunctionArgs } from 'react-router';
import { authenticate } from '../shopify.server.js';

/**
 * customers/data_request — Shopify mandatory compliance webhook.
 *
 * Shopify calls this when a shop owner asks for the data the app stores
 * about a specific customer (typically triggered by a GDPR/CCPA request
 * from the customer themselves).
 *
 * AVA Pay stores NO Shopify customer data. We only ever see:
 *   - shop domain (not customer)
 *   - agent identifiers (agent_*, not customer)
 *   - boolean trusted/blocked verdicts + reason codes
 *
 * No customer PII enters our database, our logs, or the AVA Pay verifier.
 * So the correct response is acknowledge with no payload.
 *
 * We still log the request for our own audit trail so we can prove
 * compliance if Shopify or a regulator asks later.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, topic } = await authenticate.webhook(request);

  // Intentionally do NOT log customer identifiers. If we logged customerId
  // here, that log line would itself be customer data, contradicting the
  // "we store no customer data" claim. We log shop + topic + a fixed marker
  // for auditability only.
  console.log(
    JSON.stringify({
      event: 'gdpr.customers.data_request',
      topic,
      shop,
      message: 'AVA Pay stores no customer data; nothing to return.',
      ts: new Date().toISOString(),
    }),
  );

  return new Response();
}
