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
  /**
   * 'storefront' for a proxy-delivered request, 'test' for one the merchant
   * sent from Settings. Optional so rows read before the column existed keep
   * their meaning instead of becoming untyped.
   */
  source?: string | null;
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
  /**
   * The verifier could not complete its checks (a trust root was unreachable).
   * Not admitted, and NOT a rejection: we never found out. Kept out of every
   * rejection total on purpose.
   */
  unverifiable: number;
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
  /** Definitively not admitted: failed verification or merchant policy. */
  failed: number;
  /** Never determined: unverifiable verdicts plus AVA Pay being unreachable. */
  unchecked: number;
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
  /** Definitively rejected: failed (incl. no credentials) + policy_blocked. */
  rejected: number;
  /** Never determined: unverifiable + error. Charted apart from rejections. */
  unchecked: number;
  revenueMinor: number;
}

/**
 * One row of the Recent verifications table.
 *
 * Every column VerificationEvent stores about a visit is here, so a merchant
 * can see the record rather than a summary of it. `shop` is the merchant
 * themselves and `id` is our own primary key; everything else the row holds is
 * carried across.
 */
export interface RecentVerification {
  id: string;
  createdAt: string; // ISO
  platform: string | null;
  protocol: string | null;
  outcome: string;
  reason: string | null;
  discountPct: number | null;
  /** The one-time code minted for this visit, when the policy granted one. */
  discountCode: string | null;
  /**
   * Verified on identity alone, with no buyer mandate behind it. Only means
   * anything once a verdict was actually reached, so the table shows it for
   * verified and policy-blocked rows and leaves it blank elsewhere rather than
   * reading a default `false` as "mandate-backed".
   */
  identityOnly: boolean;
  /** True when the merchant sent this from Settings rather than an agent arriving. */
  isTest: boolean;
}

export interface TrafficIntelView {
  kpis7d: TrafficKpis;
  kpis30d: TrafficKpis;
  platforms: PlatformStat[];
  /** Why agents were rejected. Could-not-check reasons are NOT in here. */
  failureReasons: ReasonStat[];
  /**
   * Why verifications could not be completed (unreachable directories, an
   * unreachable API). Separate from failureReasons because these say nothing
   * about the agents: they are a health signal about the trust roots.
   */
  unavailableReasons: ReasonStat[];
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

/**
 * Rows where we never found out. `unverifiable` means the verifier could not
 * complete its checks; `error` means we never reached the verifier at all.
 * Neither is a statement about the agent, so neither may be counted as a
 * rejection anywhere in this view. They still failed closed at request time.
 */
function isUnchecked(e: VerificationEventRow): boolean {
  return e.outcome === 'unverifiable' || e.outcome === 'error';
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
  let unverifiable = 0;
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
    } else if (e.outcome === 'unverifiable') {
      unverifiable += 1;
    } else {
      // 'error', and any outcome a future writer adds: counted here rather
      // than as a rejection, which is the conservative direction.
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
    unverifiable,
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
    {
      protocols: Set<string>;
      requests: number;
      verified: number;
      failed: number;
      unchecked: number;
      lastSeen: Date;
    }
  >();
  for (const e of events) {
    const key = e.platform ?? 'unknown';
    let stat = byPlatform.get(key);
    if (!stat) {
      stat = {
        protocols: new Set(),
        requests: 0,
        verified: 0,
        failed: 0,
        unchecked: 0,
        lastSeen: e.createdAt,
      };
      byPlatform.set(key, stat);
    }
    stat.requests += 1;
    if (e.protocol) stat.protocols.add(e.protocol);
    if (isVerified(e)) stat.verified += 1;
    else if (isUnchecked(e)) stat.unchecked += 1;
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
        unchecked: s.unchecked,
        orders: o.orders,
        revenueMinor: o.revenueMinor,
        conversionPct:
          s.verified > 0 ? Math.round((o.orders / s.verified) * 1000) / 10 : null,
        lastSeen: s.lastSeen.toISOString(),
      };
    })
    .sort((a, b) => b.requests - a.requests);

  // Reason breakdowns, kept apart. A directory we could not reach is not a
  // reason an agent was rejected, and listing it under "failure reasons" is the
  // same misreporting at the display layer that the verdict split removed at
  // the source.
  const reasonCounts = new Map<string, number>();
  const unavailableCounts = new Map<string, number>();
  for (const e of events) {
    if (isVerified(e) || !e.reason) continue;
    const target = isUnchecked(e) ? unavailableCounts : reasonCounts;
    target.set(e.reason, (target.get(e.reason) ?? 0) + 1);
  }
  const byCountDesc = (counts: Map<string, number>): ReasonStat[] =>
    [...counts.entries()]
      .map(([reason, count]) => ({ reason, count }))
      .sort((a, b) => b.count - a.count);
  const failureReasons = byCountDesc(reasonCounts);
  const unavailableReasons = byCountDesc(unavailableCounts);

  // Daily trend, zero-filled, oldest → newest, ending today (UTC).
  const trendIndex = new Map<string, TrendDay>();
  const trend: TrendDay[] = [];
  for (let i = TREND_DAYS - 1; i >= 0; i--) {
    const date = utcDay(new Date(now.getTime() - i * DAY_MS));
    const day: TrendDay = { date, verified: 0, rejected: 0, unchecked: 0, revenueMinor: 0 };
    trendIndex.set(date, day);
    trend.push(day);
  }
  for (const e of events) {
    const day = trendIndex.get(utcDay(e.createdAt));
    if (!day) continue;
    if (isVerified(e)) day.verified += 1;
    else if (isUnchecked(e)) day.unchecked += 1;
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
      discountCode: e.discountCode,
      identityOnly: e.identityOnly,
      isTest: e.source === 'test',
    }));

  const events7d = events.filter((e) => e.createdAt >= since7d);
  const orders7d = orders.filter((o) => o.createdAt >= since7d);

  return {
    kpis7d: summarize(events7d, orders7d, 7),
    kpis30d: summarize(events, orders, 30),
    platforms,
    failureReasons,
    unavailableReasons,
    trend,
    recent,
    hasAnyData: events.length > 0 || orders.length > 0,
  };
}

/**
 * How many requests we actually turned away.
 *
 * Deliberately excludes `unverifiable` and `errors`: those failed closed, but
 * nothing was proved about the agent behind them, and folding them in here
 * would tell a merchant we blocked traffic we never managed to check. That is
 * the display-layer half of the same honesty fix the verdict split makes at the
 * source, so keep the two counts apart wherever a total is shown.
 */
export function rejectedCount(kpis: TrafficKpis): number {
  return kpis.failed + kpis.unverified + kpis.policyBlocked;
}

/** Requests whose verdict was never determined. Not admitted, not rejected. */
export function uncheckedCount(kpis: TrafficKpis): number {
  return kpis.unverifiable + kpis.errors;
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
