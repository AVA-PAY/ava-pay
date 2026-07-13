/**
 * Pure aggregation for the Agent Traffic Intelligence dashboard.
 *
 * Everything here is plain data-shaping over rows the server layer fetched —
 * no Prisma, no I/O — so the dashboard's numbers are unit-testable without a
 * database. `traffic.server.ts` owns the queries and calls buildTrafficView.
 */

/** Subset of prisma VerificationEvent the aggregation needs. */
export interface VerificationEventRow {
  id: string;
  createdAt: Date;
  protocol: string | null;
  platform: string | null;
  outcome: string;
  reason: string | null;
  identityOnly: boolean;
  discountPct: number | null;
  discountCode: string | null;
}

/** Subset of prisma AgentCommerceEvent the aggregation needs. */
export interface CommerceEventRow {
  createdAt: Date;
  kind: string;
  totalMinor: number | null;
  currency: string | null;
  platform: string | null;
}

export interface TrafficKpis {
  windowDays: number;
  requests: number;
  verified: number;
  /** Presented credentials that failed verification. */
  failed: number;
  /** No agent credentials at all (missing_agent_credentials). */
  unverified: number;
  /** Verified, but merchant settings rejected it. */
  policyBlocked: number;
  /** AVA Pay API unreachable — failed closed. */
  errors: number;
  identityOnly: number;
  discountsMinted: number;
  orders: number;
  revenueMinor: number;
  currency: string | null;
}

export interface PlatformStat {
  platform: string;
  protocols: string[];
  requests: number;
  verified: number;
  failed: number;
  orders: number;
  revenueMinor: number;
  /** orders / verified requests, percent with one decimal. Null when no verified traffic. */
  conversionPct: number | null;
  lastSeen: string; // ISO
}

export interface ReasonStat {
  reason: string;
  count: number;
}

export interface TrendDay {
  date: string; // YYYY-MM-DD (UTC)
  verified: number;
  /** Everything that was not admitted: failed + unverified + policy_blocked + error. */
  rejected: number;
  revenueMinor: number;
}

export interface RecentVerification {
  id: string;
  createdAt: string; // ISO
  platform: string | null;
  protocol: string | null;
  outcome: string;
  reason: string | null;
  discountPct: number | null;
}

export interface TrafficIntelView {
  kpis7d: TrafficKpis;
  kpis30d: TrafficKpis;
  platforms: PlatformStat[];
  failureReasons: ReasonStat[];
  trend: TrendDay[];
  recent: RecentVerification[];
  hasAnyData: boolean;
}

const DAY_MS = 24 * 3600_000;
export const TREND_DAYS = 30;

const UNVERIFIED_REASON = 'missing_agent_credentials';

function isVerified(e: VerificationEventRow): boolean {
  return e.outcome === 'verified';
}

function isUnverified(e: VerificationEventRow): boolean {
  return e.outcome === 'failed' && e.reason === UNVERIFIED_REASON;
}

function utcDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

function summarize(
  events: VerificationEventRow[],
  orders: CommerceEventRow[],
  windowDays: number,
): TrafficKpis {
  let verified = 0;
  let failed = 0;
  let unverified = 0;
  let policyBlocked = 0;
  let errors = 0;
  let identityOnly = 0;
  let discountsMinted = 0;

  for (const e of events) {
    if (isVerified(e)) {
      verified += 1;
      if (e.identityOnly) identityOnly += 1;
      if (e.discountCode) discountsMinted += 1;
    } else if (isUnverified(e)) {
      unverified += 1;
    } else if (e.outcome === 'failed') {
      failed += 1;
    } else if (e.outcome === 'policy_blocked') {
      policyBlocked += 1;
    } else {
      errors += 1;
    }
  }

  let revenueMinor = 0;
  const currencyCounts = new Map<string, number>();
  for (const o of orders) {
    revenueMinor += o.totalMinor ?? 0;
    if (o.currency) currencyCounts.set(o.currency, (currencyCounts.get(o.currency) ?? 0) + 1);
  }
  let currency: string | null = null;
  let best = 0;
  for (const [c, n] of currencyCounts) {
    if (n > best) {
      best = n;
      currency = c;
    }
  }

  return {
    windowDays,
    requests: events.length,
    verified,
    failed,
    unverified,
    policyBlocked,
    errors,
    identityOnly,
    discountsMinted,
    orders: orders.length,
    revenueMinor,
    currency,
  };
}

export function buildTrafficView(
  events: VerificationEventRow[],
  commerce: CommerceEventRow[],
  now: Date,
): TrafficIntelView {
  const since7d = new Date(now.getTime() - 7 * DAY_MS);
  const orders = commerce.filter((c) => c.kind === 'order');

  // Per-platform rollup (full 30d window).
  const byPlatform = new Map<
    string,
    { protocols: Set<string>; requests: number; verified: number; failed: number; lastSeen: Date }
  >();
  for (const e of events) {
    const key = e.platform ?? 'unknown';
    let stat = byPlatform.get(key);
    if (!stat) {
      stat = { protocols: new Set(), requests: 0, verified: 0, failed: 0, lastSeen: e.createdAt };
      byPlatform.set(key, stat);
    }
    stat.requests += 1;
    if (e.protocol) stat.protocols.add(e.protocol);
    if (isVerified(e)) stat.verified += 1;
    else stat.failed += 1;
    if (e.createdAt > stat.lastSeen) stat.lastSeen = e.createdAt;
  }

  const ordersByPlatform = new Map<string, { orders: number; revenueMinor: number }>();
  for (const o of orders) {
    const key = o.platform ?? 'unknown';
    const stat = ordersByPlatform.get(key) ?? { orders: 0, revenueMinor: 0 };
    stat.orders += 1;
    stat.revenueMinor += o.totalMinor ?? 0;
    ordersByPlatform.set(key, stat);
  }

  const platforms: PlatformStat[] = [...byPlatform.entries()]
    .map(([platform, s]) => {
      const o = ordersByPlatform.get(platform) ?? { orders: 0, revenueMinor: 0 };
      return {
        platform,
        protocols: [...s.protocols].sort(),
        requests: s.requests,
        verified: s.verified,
        failed: s.failed,
        orders: o.orders,
        revenueMinor: o.revenueMinor,
        conversionPct:
          s.verified > 0 ? Math.round((o.orders / s.verified) * 1000) / 10 : null,
        lastSeen: s.lastSeen.toISOString(),
      };
    })
    .sort((a, b) => b.requests - a.requests);

  // Failure-reason breakdown (every non-verified event with a reason).
  const reasonCounts = new Map<string, number>();
  for (const e of events) {
    if (isVerified(e) || !e.reason) continue;
    reasonCounts.set(e.reason, (reasonCounts.get(e.reason) ?? 0) + 1);
  }
  const failureReasons: ReasonStat[] = [...reasonCounts.entries()]
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => b.count - a.count);

  // Daily trend, zero-filled, oldest → newest, ending today (UTC).
  const trendIndex = new Map<string, TrendDay>();
  const trend: TrendDay[] = [];
  for (let i = TREND_DAYS - 1; i >= 0; i--) {
    const date = utcDay(new Date(now.getTime() - i * DAY_MS));
    const day: TrendDay = { date, verified: 0, rejected: 0, revenueMinor: 0 };
    trendIndex.set(date, day);
    trend.push(day);
  }
  for (const e of events) {
    const day = trendIndex.get(utcDay(e.createdAt));
    if (!day) continue;
    if (isVerified(e)) day.verified += 1;
    else day.rejected += 1;
  }
  for (const o of orders) {
    const day = trendIndex.get(utcDay(o.createdAt));
    if (day) day.revenueMinor += o.totalMinor ?? 0;
  }

  const recent: RecentVerification[] = [...events]
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .slice(0, 25)
    .map((e) => ({
      id: e.id,
      createdAt: e.createdAt.toISOString(),
      platform: e.platform,
      protocol: e.protocol,
      outcome: e.outcome,
      reason: e.reason,
      discountPct: e.discountPct,
    }));

  const events7d = events.filter((e) => e.createdAt >= since7d);
  const orders7d = orders.filter((o) => o.createdAt >= since7d);

  return {
    kpis7d: summarize(events7d, orders7d, 7),
    kpis30d: summarize(events, orders, 30),
    platforms,
    failureReasons,
    trend,
    recent,
    hasAnyData: events.length > 0 || orders.length > 0,
  };
}

/** Format minor units as a currency string for display (e.g. 123456 → "$1,234.56"). */
export function formatMoney(minor: number, currency: string | null): string {
  const amount = minor / 100;
  try {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency ?? 'USD',
    }).format(amount);
  } catch {
    return `${amount.toFixed(2)} ${currency ?? ''}`.trim();
  }
}
