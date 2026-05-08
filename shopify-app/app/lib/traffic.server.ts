import prisma from '../db.server.js';

/**
 * Aggregate VerificationLog into a dashboard view. All queries are
 * shop-scoped; the route layer enforces auth. Pure data shaping here so the
 * UI route stays thin.
 */

export interface TrafficSummary {
  windowHours: number;
  total: number;
  verified: number;
  blocked: number;
  conversionPct: number;
  totalDiscountPct: number; // sum of discount % for verified rows (rough proxy for spend share)
  avgDiscountPct: number | null;
}

export interface RecentVerification {
  id: string;
  agentId: string | null;
  trusted: boolean;
  reason: string | null;
  discountPct: number | null;
  createdAt: string; // ISO string for serialization
}

export interface TopAgent {
  agentId: string;
  count: number;
  trustedCount: number;
}

export interface TrafficView {
  last24h: TrafficSummary;
  last7d: TrafficSummary;
  recent: RecentVerification[];
  topAgents: TopAgent[];
}

export async function getTrafficView(shop: string): Promise<TrafficView> {
  const now = new Date();
  const since24h = new Date(now.getTime() - 24 * 3600_000);
  const since7d = new Date(now.getTime() - 7 * 24 * 3600_000);

  const [last24h, last7d, recentRows, topAgentsRows] = await Promise.all([
    summarize(shop, since24h, 24),
    summarize(shop, since7d, 24 * 7),
    prisma.verificationLog.findMany({
      where: { shop, createdAt: { gte: since7d } },
      orderBy: { createdAt: 'desc' },
      take: 25,
    }),
    prisma.verificationLog.groupBy({
      by: ['agentId'],
      where: { shop, createdAt: { gte: since7d }, agentId: { not: null } },
      _count: { _all: true },
      orderBy: { _count: { agentId: 'desc' } },
      take: 5,
    }),
  ]);

  const topAgents: TopAgent[] = await Promise.all(
    (topAgentsRows as Array<{ agentId: string | null; _count: { _all: number } }>).map(async (row) => {
      const agentId = row.agentId ?? 'unknown';
      const trustedCount = await prisma.verificationLog.count({
        where: { shop, agentId, trusted: true, createdAt: { gte: since7d } },
      });
      return { agentId, count: row._count._all, trustedCount };
    }),
  );

  type LogRow = {
    id: string;
    agentId: string | null;
    trusted: boolean;
    reason: string | null;
    discountPct: number | null;
    createdAt: Date;
  };

  return {
    last24h,
    last7d,
    recent: (recentRows as LogRow[]).map((r) => ({
      id: r.id,
      agentId: r.agentId,
      trusted: r.trusted,
      reason: r.reason,
      discountPct: r.discountPct,
      createdAt: r.createdAt.toISOString(),
    })),
    topAgents,
  };
}

async function summarize(shop: string, since: Date, windowHours: number): Promise<TrafficSummary> {
  const where = { shop, createdAt: { gte: since } };

  const [total, verified, discountAgg] = await Promise.all([
    prisma.verificationLog.count({ where }),
    prisma.verificationLog.count({ where: { ...where, trusted: true } }),
    prisma.verificationLog.aggregate({
      where: { ...where, trusted: true, discountPct: { not: null } },
      _sum: { discountPct: true },
      _count: { discountPct: true },
    }),
  ]);

  const blocked = total - verified;
  const totalDiscountPct = discountAgg._sum.discountPct ?? 0;
  const discountedRows = discountAgg._count.discountPct ?? 0;

  return {
    windowHours,
    total,
    verified,
    blocked,
    conversionPct: total > 0 ? Math.round((verified / total) * 1000) / 10 : 0,
    totalDiscountPct,
    avgDiscountPct: discountedRows > 0 ? Math.round((totalDiscountPct / discountedRows) * 10) / 10 : null,
  };
}
