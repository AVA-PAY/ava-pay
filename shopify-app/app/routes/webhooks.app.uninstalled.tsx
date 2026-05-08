import type { ActionFunctionArgs } from '@remix-run/node';
import { authenticate } from '../shopify.server.js';
import prisma from '../db.server.js';

/**
 * Cleanup on app uninstall: drop the merchant's stored sessions and settings.
 * Verification logs are kept for audit/billing.
 */
export async function action({ request }: ActionFunctionArgs) {
  const { shop, session } = await authenticate.webhook(request);

  if (session) {
    await prisma.session.deleteMany({ where: { shop } });
  }
  await prisma.shopSettings.deleteMany({ where: { shop } });

  return new Response();
}
