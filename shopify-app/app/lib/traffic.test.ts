import { describe, expect, it } from 'vitest';
import {
  buildTrafficView,
  formatMoney,
  TREND_DAYS,
  type CommerceEventRow,
  type VerificationEventRow,
} from './traffic.js';

const NOW = new Date('2026-07-13T12:00:00Z');

let seq = 0;
function event(overrides: Partial<VerificationEventRow> = {}): VerificationEventRow {
  seq += 1;
  return {
    id: `evt_${seq}`,
    createdAt: NOW,
    protocol: 'web-bot-auth',
    platform: 'https://chatgpt.com',
    outcome: 'verified',
    reason: null,
    identityOnly: true,
    discountPct: 0,
    discountCode: null,
    ...overrides,
  };
}

function order(overrides: Partial<CommerceEventRow> = {}): CommerceEventRow {
  return {
    createdAt: NOW,
    kind: 'order',
    totalMinor: 12_050,
    currency: 'USD',
    platform: 'https://chatgpt.com',
    ...overrides,
  };
}

function daysAgo(n: number): Date {
  return new Date(NOW.getTime() - n * 24 * 3600_000);
}

describe('buildTrafficView', () => {
  it('reports an empty view with hasAnyData=false', () => {
    const view = buildTrafficView([], [], NOW);
    expect(view.hasAnyData).toBe(false);
    expect(view.kpis30d.requests).toBe(0);
    expect(view.platforms).toEqual([]);
    expect(view.trend).toHaveLength(TREND_DAYS);
    expect(view.trend.every((d) => d.verified === 0 && d.rejected === 0)).toBe(true);
  });

  it('is useful from the very first verified request (zero-config value)', () => {
    const view = buildTrafficView([event()], [], NOW);
    expect(view.hasAnyData).toBe(true);
    expect(view.kpis7d.verified).toBe(1);
    expect(view.platforms).toHaveLength(1);
    expect(view.platforms[0]!.platform).toBe('https://chatgpt.com');
    expect(view.recent).toHaveLength(1);
  });

  it('splits outcomes into verified / failed / unverified / policy_blocked / error', () => {
    const events = [
      event(),
      event({ outcome: 'failed', reason: 'invalid_signature' }),
      event({ outcome: 'failed', reason: 'missing_agent_credentials' }),
      event({ outcome: 'policy_blocked', reason: 'merchant_disabled' }),
      event({ outcome: 'error', reason: 'ava_timeout' }),
    ];
    const k = buildTrafficView(events, [], NOW).kpis30d;
    expect(k.requests).toBe(5);
    expect(k.verified).toBe(1);
    expect(k.failed).toBe(1); // credentialed failure only
    expect(k.unverified).toBe(1); // missing_agent_credentials
    expect(k.policyBlocked).toBe(1);
    expect(k.errors).toBe(1);
  });

  it('breaks down failure reasons sorted by count', () => {
    const events = [
      event({ outcome: 'failed', reason: 'invalid_signature' }),
      event({ outcome: 'failed', reason: 'invalid_signature' }),
      event({ outcome: 'failed', reason: 'signature_expired' }),
      event(), // verified — excluded
    ];
    const view = buildTrafficView(events, [], NOW);
    expect(view.failureReasons).toEqual([
      { reason: 'invalid_signature', count: 2 },
      { reason: 'signature_expired', count: 1 },
    ]);
  });

  it('aggregates per platform with conversion and revenue', () => {
    const events = [
      event({ discountCode: 'AVA-AAAA1111' }),
      event(),
      event({ platform: 'https://perplexity.ai', outcome: 'failed', reason: 'unknown_key' }),
    ];
    const commerce = [order(), order({ totalMinor: 5_000 })];
    const view = buildTrafficView(events, commerce, NOW);

    const chatgpt = view.platforms.find((p) => p.platform === 'https://chatgpt.com')!;
    expect(chatgpt.requests).toBe(2);
    expect(chatgpt.verified).toBe(2);
    expect(chatgpt.orders).toBe(2);
    expect(chatgpt.revenueMinor).toBe(17_050);
    expect(chatgpt.conversionPct).toBe(100);

    const pplx = view.platforms.find((p) => p.platform === 'https://perplexity.ai')!;
    expect(pplx.verified).toBe(0);
    expect(pplx.failed).toBe(1);
    expect(pplx.conversionPct).toBeNull(); // no verified traffic to convert

    // Sorted by request volume.
    expect(view.platforms[0]!.platform).toBe('https://chatgpt.com');
  });

  it('ignores checkout rows for revenue but keeps order rows', () => {
    const commerce = [order(), { ...order(), kind: 'checkout', totalMinor: 99_999 }];
    const k = buildTrafficView([], commerce, NOW).kpis30d;
    expect(k.orders).toBe(1);
    expect(k.revenueMinor).toBe(12_050);
  });

  it('windows KPIs: 8-day-old events count for 30d but not 7d', () => {
    const events = [event({ createdAt: daysAgo(8) }), event()];
    const view = buildTrafficView(events, [], NOW);
    expect(view.kpis7d.requests).toBe(1);
    expect(view.kpis30d.requests).toBe(2);
  });

  it('buckets the daily trend by UTC day, zero-filled, oldest first', () => {
    const events = [
      event({ createdAt: daysAgo(2) }),
      event({ createdAt: daysAgo(2), outcome: 'failed', reason: 'invalid_signature' }),
      event({ createdAt: daysAgo(0) }),
    ];
    const commerce = [order({ createdAt: daysAgo(2) })];
    const view = buildTrafficView(events, commerce, NOW);

    expect(view.trend).toHaveLength(TREND_DAYS);
    const dayMinus2 = view.trend[TREND_DAYS - 3]!;
    expect(dayMinus2.date).toBe('2026-07-11');
    expect(dayMinus2.verified).toBe(1);
    expect(dayMinus2.rejected).toBe(1);
    expect(dayMinus2.revenueMinor).toBe(12_050);
    const today = view.trend[TREND_DAYS - 1]!;
    expect(today.date).toBe('2026-07-13');
    expect(today.verified).toBe(1);
  });

  it('groups events without a platform under "unknown"', () => {
    const view = buildTrafficView(
      [event({ platform: null, outcome: 'failed', reason: 'missing_agent_credentials' })],
      [],
      NOW,
    );
    expect(view.platforms[0]!.platform).toBe('unknown');
  });

  it('caps recent at 25, newest first', () => {
    const events = Array.from({ length: 30 }, (_, i) => event({ createdAt: daysAgo(i / 24) }));
    const view = buildTrafficView(events, [], NOW);
    expect(view.recent).toHaveLength(25);
    const times = view.recent.map((r) => r.createdAt);
    expect([...times].sort().reverse()).toEqual(times);
  });

  it('picks the dominant currency for KPI display', () => {
    const commerce = [order(), order(), order({ currency: 'EUR' })];
    expect(buildTrafficView([], commerce, NOW).kpis30d.currency).toBe('USD');
  });
});

describe('formatMoney', () => {
  it('formats minor units with the currency', () => {
    expect(formatMoney(123_456, 'USD')).toBe('$1,234.56');
  });
  it('defaults to USD when currency is unknown', () => {
    expect(formatMoney(0, null)).toBe('$0.00');
  });
});
