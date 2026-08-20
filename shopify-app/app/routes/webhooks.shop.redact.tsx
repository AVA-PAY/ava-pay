import type { ActionFunctionArgs } from 'react-router';
import { authenticateWebhookRequest } from '../lib/webhook-auth.server.js';
import prisma from '../db.server.js';

/**
 * shop/redact — Shopify mandatory compliance webhook.
 *
 * Shopify calls this 48 hours after a shop uninstalls our app, asking us
 * to delete all data we hold about that shop. Unlike customers/redact,
 * we DO store shop-scoped data:
 *
 *   - Session (OAuth tokens, may already be gone via app/uninstalled)
 *   - ShopSettings (toggle + discount caps, may already be gone)
 *   - VerificationEvent + AgentCommerceEvent (kept after uninstall for
 *     audit/billing; deleted here)
 *
 * The existing app/uninstalled webhook deletes Session + ShopSettings
 * immediately. We intentionally retain the telemetry tables there because
 * we may need them for billing (per-verification pricing). When Shopify
 * formally invokes shop/redact 48h later we delete everything, fulfilling
 * the right-to-erasure window.
 *
 * There is no ordering constraint between these deletes: this webhook is
 * authenticated by HMAC, not by the stored session (an earlier comment said
 * sessions had to be deleted last, but the session plays no part in
 * authenticating the request, and the deletes below run concurrently).
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, topic } = await authenticateWebhookRequest(request);

  const [events, commerce, settings, sessions] = await Promise.all([
    prisma.verificationEvent.deleteMany({ where: { shop } }),
    prisma.agentCommerceEvent.deleteMany({ where: { shop } }),
    prisma.shopSettings.deleteMany({ where: { shop } }),
    prisma.session.deleteMany({ where: { shop } }),
  ]);

  console.log(
    JSON.stringify({
      event: 'gdpr.shop.redact',
      topic,
      shop,
      deletedVerificationEvents: events.count,
      deletedCommerceEvents: commerce.count,
      deletedShopSettings: settings.count,
      deletedSessions: sessions.count,
      ts: new Date().toISOString(),
    }),
  );

  return new Response();
}
