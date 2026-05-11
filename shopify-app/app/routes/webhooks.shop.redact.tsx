import type { ActionFunctionArgs } from '@remix-run/node';
import { authenticate } from '../shopify.server.js';
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
 *   - VerificationLog (kept after uninstall for audit/billing; deleted here)
 *
 * The existing app/uninstalled webhook deletes Session + ShopSettings
 * immediately. We intentionally retain VerificationLog there because we
 * may need it for billing (per-verification pricing). When Shopify
 * formally invokes shop/redact 48h later we delete everything, fulfilling
 * the right-to-erasure window.
 *
 * Order of operations matters: delete sessions LAST so we still have
 * access to authenticate this exact webhook request.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, topic } = await authenticate.webhook(request);

  const [logs, settings, sessions] = await Promise.all([
    prisma.verificationLog.deleteMany({ where: { shop } }),
    prisma.shopSettings.deleteMany({ where: { shop } }),
    prisma.session.deleteMany({ where: { shop } }),
  ]);

  console.log(
    JSON.stringify({
      event: 'gdpr.shop.redact',
      topic,
      shop,
      deletedVerificationLogs: logs.count,
      deletedShopSettings: settings.count,
      deletedSessions: sessions.count,
      ts: new Date().toISOString(),
    }),
  );

  return new Response();
}
