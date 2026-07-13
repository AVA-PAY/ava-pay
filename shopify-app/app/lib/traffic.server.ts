import prisma from '../db.server.js';
import { buildTrafficView, TREND_DAYS, type TrafficIntelView } from './traffic.js';

/**
 * Thin query layer for the Agent Traffic Intelligence dashboard. Fetches the
 * trend window's rows shop-scoped (route layer enforces auth) and hands them
 * to the pure aggregation in traffic.ts. Per-shop volumes are small enough
 * that shaping in process beats a pile of groupBy round-trips.
 */
export async function getTrafficIntelligence(shop: string): Promise<TrafficIntelView> {
  const now = new Date();
  const since = new Date(now.getTime() - TREND_DAYS * 24 * 3600_000);

  const [events, commerce] = await Promise.all([
    prisma.verificationEvent.findMany({
      where: { shop, createdAt: { gte: since } },
      orderBy: { createdAt: 'desc' },
    }),
    prisma.agentCommerceEvent.findMany({
      where: { shop, createdAt: { gte: since } },
      orderBy: { createdAt: 'desc' },
    }),
  ]);

  return buildTrafficView(events, commerce, now);
}
