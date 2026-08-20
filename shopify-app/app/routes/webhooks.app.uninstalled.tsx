import type { ActionFunctionArgs } from 'react-router';
import { authenticateWebhookRequest } from '../lib/webhook-auth.server.js';
import prisma from '../db.server.js';

/**
 * Cleanup on app uninstall: drop the merchant's stored sessions and settings.
 * Verification logs are kept for audit/billing.
 *
 * Sessions are deleted unconditionally. Webhooks are authenticated by HMAC,
 * not by the stored session, and the shop's offline token is revoked the
 * moment it uninstalls. A leftover Session row would make every later
 * webhook for this shop attempt (and fail) a token refresh.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop } = await authenticateWebhookRequest(request);

  await prisma.session.deleteMany({ where: { shop } });
  await prisma.shopSettings.deleteMany({ where: { shop } });

  return new Response();
}
