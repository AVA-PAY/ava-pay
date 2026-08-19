import { useState } from 'react';
import { useLoaderData, type LoaderFunctionArgs } from 'react-router';
import {
  Badge,
  BlockStack,
  Box,
  Card,
  DataTable,
  Divider,
  EmptyState,
  InlineGrid,
  InlineStack,
  Layout,
  Page,
  Text,
} from '@shopify/polaris';
import { authenticate } from '../shopify.server.js';
import { getTrafficIntelligence } from '../lib/traffic.server.js';
import {
  formatMoney,
  rejectedCount,
  uncheckedCount,
  type ReasonStat,
  type TrafficIntelView,
  type TrafficKpis,
  type TrendDay,
} from '../lib/traffic.js';

export async function loader({ request }: LoaderFunctionArgs): Promise<TrafficIntelView> {
  const { session } = await authenticate.admin(request);
  return getTrafficIntelligence(session.shop);
}

/** Chart colors: verified is the story (accent), everything else recedes. */
const SERIES_VERIFIED = '#2a78d6';
const SERIES_REJECTED = '#818181';
/**
 * Could-not-check gets its own series rather than sitting inside rejections:
 * amber reads as "look into this" (usually an agent directory having a bad
 * day), which is what it is, and never as "these agents were turned away".
 */
const SERIES_UNCHECKED = '#b98900';

export default function TrafficPage() {
  const view = useLoaderData<typeof loader>();

  if (!view.hasAnyData) {
    return (
      <Page title="Agent traffic">
        <Layout>
          <Layout.Section>
            <Card>
              <EmptyState
                heading="No agent traffic yet"
                image="https://cdn.shopify.com/s/files/1/0262/4071/2726/files/emptystate-files.png"
              >
                <p>
                  As soon as an AI shopping agent hits your storefront, its verification shows up
                  here: which platform it was, whether it verified, and what it bought. Turn on the
                  AVA Pay app embed from Settings, then send a test agent visit from there to see
                  the whole path work before real traffic arrives.
                </p>
              </EmptyState>
            </Card>
          </Layout.Section>
        </Layout>
      </Page>
    );
  }

  return (
    <Page title="Agent traffic" subtitle="Last 30 days of AI agent activity on your storefront">
      <Layout>
        <Layout.Section>
          <KpiRow kpis={view.kpis7d} title="Last 7 days" />
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="300">
              <Text as="h2" variant="headingMd">
                Requests per day
              </Text>
              <TrendChart days={view.trend} currency={view.kpis30d.currency} />
            </BlockStack>
          </Card>
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="300">
              <Text as="h2" variant="headingMd">
                Agent platforms (30 days)
              </Text>
              {view.platforms.length === 0 ? (
                <Text as="p" tone="subdued">
                  No platform activity in this window.
                </Text>
              ) : (
                <DataTable
                  columnContentTypes={[
                    'text',
                    'text',
                    'numeric',
                    'numeric',
                    'numeric',
                    'numeric',
                    'numeric',
                    'numeric',
                    'text',
                  ]}
                  headings={[
                    'Platform',
                    'Protocols',
                    'Requests',
                    'Verified',
                    'Rejected',
                    'Not checked',
                    'Orders',
                    'Revenue',
                    'Conversion',
                  ]}
                  rows={view.platforms.map((p) => [
                    p.platform,
                    p.protocols.length > 0 ? p.protocols.join(', ') : '—',
                    p.requests,
                    p.verified,
                    p.failed,
                    p.unchecked,
                    p.orders,
                    p.revenueMinor > 0 ? formatMoney(p.revenueMinor, view.kpis30d.currency) : '—',
                    p.conversionPct !== null ? `${p.conversionPct}%` : '—',
                  ])}
                />
              )}
            </BlockStack>
          </Card>
        </Layout.Section>

        <Layout.Section>
          <InlineGrid columns={{ xs: 1, md: 2 }} gap="400">
            <Card>
              <BlockStack gap="300">
                <Text as="h2" variant="headingMd">
                  Outcomes (30 days)
                </Text>
                <OutcomeList kpis={view.kpis30d} />
                {view.failureReasons.length > 0 ? (
                  <>
                    <Divider />
                    <Text as="h3" variant="headingSm">
                      Failure reasons
                    </Text>
                    <ReasonList reasons={view.failureReasons} />
                  </>
                ) : null}
                {view.unavailableReasons.length > 0 ? (
                  <>
                    <Divider />
                    <Text as="h3" variant="headingSm">
                      Could not check
                    </Text>
                    <Text as="p" variant="bodySm" tone="subdued">
                      These say nothing about the agents. A trust root was
                      unreachable, so the check never completed and the request
                      was not admitted.
                    </Text>
                    <ReasonList reasons={view.unavailableReasons} />
                  </>
                ) : null}
              </BlockStack>
            </Card>

            <Card>
              <BlockStack gap="300">
                <Text as="h2" variant="headingMd">
                  Revenue (30 days)
                </Text>
                <BlockStack gap="100">
                  <Text as="p" variant="heading2xl">
                    {formatMoney(view.kpis30d.revenueMinor, view.kpis30d.currency)}
                  </Text>
                  <Text as="p" tone="subdued">
                    from {view.kpis30d.orders} agent-attributed{' '}
                    {view.kpis30d.orders === 1 ? 'order' : 'orders'}
                  </Text>
                </BlockStack>
                <Divider />
                <InlineStack align="space-between">
                  <Text as="span" tone="subdued">
                    Discounts minted
                  </Text>
                  <Text as="span" fontWeight="semibold">
                    {view.kpis30d.discountsMinted}
                  </Text>
                </InlineStack>
                <InlineStack align="space-between">
                  <Text as="span" tone="subdued">
                    Identity-only verifications
                  </Text>
                  <Text as="span" fontWeight="semibold">
                    {view.kpis30d.identityOnly}
                  </Text>
                </InlineStack>
              </BlockStack>
            </Card>
          </InlineGrid>
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="300">
              <Text as="h2" variant="headingMd">
                Recent verifications
              </Text>
              <DataTable
                columnContentTypes={['text', 'text', 'text', 'text', 'text', 'numeric', 'text']}
                headings={[
                  'Time',
                  'Source',
                  'Platform',
                  'Protocol',
                  'Outcome',
                  'Discount %',
                  'Reason',
                ]}
                rows={view.recent.map((r) => [
                  new Date(r.createdAt).toLocaleString(),
                  // A visit the merchant sent from Settings is real verification of a
                  // real signature, but it is not organic agent traffic and must not
                  // read as though it were.
                  r.isTest ? <Badge key={`${r.id}-src`}>Test</Badge> : 'Agent',
                  r.platform ?? '—',
                  r.protocol ?? '—',
                  <OutcomeBadge key={r.id} outcome={r.outcome} />,
                  r.discountPct ?? '—',
                  r.reason ?? '—',
                ])}
              />
            </BlockStack>
          </Card>
        </Layout.Section>
      </Layout>
    </Page>
  );
}

function KpiRow({ kpis, title }: { kpis: TrafficKpis; title: string }) {
  const unchecked = uncheckedCount(kpis);
  return (
    <InlineGrid columns={{ xs: 2, md: 5 }} gap="400">
      <KpiTile label={`Requests · ${title.toLowerCase()}`} value={String(kpis.requests)} />
      <KpiTile
        label="Verified"
        value={String(kpis.verified)}
        detail={kpis.identityOnly > 0 ? `${kpis.identityOnly} identity-only` : undefined}
      />
      <KpiTile
        label="Rejected"
        value={String(rejectedCount(kpis))}
        detail={kpis.unverified > 0 ? `${kpis.unverified} without credentials` : undefined}
      />
      <KpiTile
        label="Could not check"
        value={String(unchecked)}
        detail={
          unchecked > 0 ? 'not admitted, and not a rejection' : undefined
        }
      />
      <KpiTile
        label="Agent revenue"
        value={formatMoney(kpis.revenueMinor, kpis.currency)}
        detail={`${kpis.orders} ${kpis.orders === 1 ? 'order' : 'orders'}`}
      />
    </InlineGrid>
  );
}

function KpiTile({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <Card>
      <BlockStack gap="100">
        <Text as="p" variant="bodySm" tone="subdued">
          {label}
        </Text>
        <Text as="p" variant="headingXl">
          {value}
        </Text>
        {detail ? (
          <Text as="p" variant="bodySm" tone="subdued">
            {detail}
          </Text>
        ) : null}
      </BlockStack>
    </Card>
  );
}

function OutcomeList({ kpis }: { kpis: TrafficKpis }) {
  const rows: Array<{ label: string; value: number }> = [
    { label: 'Verified', value: kpis.verified },
    { label: 'Failed verification', value: kpis.failed },
    { label: 'No credentials presented', value: kpis.unverified },
    { label: 'Blocked by your settings', value: kpis.policyBlocked },
    { label: 'Could not be checked (failed closed)', value: kpis.unverifiable },
    { label: 'AVA Pay unreachable (failed closed)', value: kpis.errors },
  ];
  return (
    <BlockStack gap="100">
      {rows.map((r) => (
        <InlineStack key={r.label} align="space-between">
          <Text as="span" tone="subdued">
            {r.label}
          </Text>
          <Text as="span" fontWeight="semibold">
            {r.value}
          </Text>
        </InlineStack>
      ))}
    </BlockStack>
  );
}

function ReasonList({ reasons }: { reasons: ReasonStat[] }) {
  return (
    <BlockStack gap="100">
      {reasons.slice(0, 8).map((r) => (
        <InlineStack key={r.reason} align="space-between">
          <Text as="span" variant="bodySm">
            <code>{r.reason}</code>
          </Text>
          <Text as="span" variant="bodySm" fontWeight="semibold">
            {r.count}
          </Text>
        </InlineStack>
      ))}
    </BlockStack>
  );
}

function OutcomeBadge({ outcome }: { outcome: string }) {
  switch (outcome) {
    case 'verified':
      return <Badge tone="success">Verified</Badge>;
    case 'failed':
      return <Badge tone="critical">Failed</Badge>;
    case 'policy_blocked':
      return <Badge tone="attention">Policy blocked</Badge>;
    // Deliberately not critical: this row is not a rejection. The agent may
    // well have been legitimate; we could not reach a trust root to find out.
    case 'unverifiable':
      return <Badge tone="warning">Could not check</Badge>;
    default:
      return <Badge tone="warning">Error</Badge>;
  }
}

/**
 * 30-day stacked daily bars: verified (accent) on the baseline, then rejected
 * (gray), then could-not-check (amber) on top. HTML divs rather than SVG: no
 * viewBox distortion, and the whole column is the hover hit-target for the
 * tooltip.
 */
function TrendChart({ days, currency }: { days: TrendDay[]; currency: string | null }) {
  const [hovered, setHovered] = useState<number | null>(null);
  const max = Math.max(1, ...days.map((d) => d.verified + d.rejected + d.unchecked));
  const CHART_H = 140;

  const first = days[0];
  const last = days[days.length - 1];
  const hoveredDay = hovered !== null ? days[hovered] : undefined;

  return (
    <BlockStack gap="200">
      <InlineStack gap="400">
        <LegendItem color={SERIES_VERIFIED} label="Verified" />
        <LegendItem color={SERIES_REJECTED} label="Rejected" />
        <LegendItem color={SERIES_UNCHECKED} label="Could not check" />
      </InlineStack>

      <Box position="relative">
        {hoveredDay ? (
          <div
            style={{
              position: 'absolute',
              top: -8,
              left: `${(((hovered ?? 0) + 0.5) / days.length) * 100}%`,
              transform: 'translate(-50%, -100%)',
              background: 'var(--p-color-bg-surface, #fff)',
              border: '1px solid var(--p-color-border, #e3e3e3)',
              borderRadius: 8,
              padding: '6px 10px',
              boxShadow: '0 2px 8px rgba(0,0,0,0.12)',
              whiteSpace: 'nowrap',
              zIndex: 10,
              pointerEvents: 'none',
            }}
          >
            <Text as="p" variant="bodySm" fontWeight="semibold">
              {hoveredDay.date}
            </Text>
            <Text as="p" variant="bodySm">
              {hoveredDay.verified} verified · {hoveredDay.rejected} rejected
              {hoveredDay.unchecked > 0 ? ` · ${hoveredDay.unchecked} not checked` : ''}
              {hoveredDay.revenueMinor > 0
                ? ` · ${formatMoney(hoveredDay.revenueMinor, currency)}`
                : ''}
            </Text>
          </div>
        ) : null}

        <div
          style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: CHART_H }}
          onMouseLeave={() => setHovered(null)}
        >
          {days.map((d, i) => {
            const vH = Math.round((d.verified / max) * (CHART_H - 8));
            const rH = Math.round((d.rejected / max) * (CHART_H - 8));
            const uH = Math.round((d.unchecked / max) * (CHART_H - 8));
            const isHovered = hovered === i;
            return (
              <div
                key={d.date}
                onMouseEnter={() => setHovered(i)}
                style={{
                  flex: 1,
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'flex-end',
                  cursor: 'default',
                  background: isHovered ? 'var(--p-color-bg-surface-hover, #f6f6f6)' : undefined,
                  borderRadius: 4,
                }}
              >
                {uH > 0 ? (
                  <div
                    style={{
                      height: uH,
                      background: SERIES_UNCHECKED,
                      borderRadius: '4px 4px 0 0',
                      marginBottom: rH > 0 || vH > 0 ? 2 : 0,
                    }}
                  />
                ) : null}
                {rH > 0 ? (
                  <div
                    style={{
                      height: rH,
                      background: SERIES_REJECTED,
                      borderRadius: uH > 0 ? 0 : '4px 4px 0 0',
                      marginBottom: vH > 0 ? 2 : 0,
                    }}
                  />
                ) : null}
                {vH > 0 ? (
                  <div
                    style={{
                      height: vH,
                      background: SERIES_VERIFIED,
                      borderRadius: rH > 0 || uH > 0 ? 0 : '4px 4px 0 0',
                    }}
                  />
                ) : null}
                {vH === 0 && rH === 0 && uH === 0 ? (
                  <div style={{ height: 2, background: 'var(--p-color-border, #e3e3e3)' }} />
                ) : null}
              </div>
            );
          })}
        </div>
      </Box>

      <InlineStack align="space-between">
        <Text as="span" variant="bodySm" tone="subdued">
          {first?.date ?? ''}
        </Text>
        <Text as="span" variant="bodySm" tone="subdued">
          peak {max}/day
        </Text>
        <Text as="span" variant="bodySm" tone="subdued">
          {last?.date ?? ''}
        </Text>
      </InlineStack>
    </BlockStack>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <InlineStack gap="100" blockAlign="center">
      <span
        style={{
          width: 10,
          height: 10,
          borderRadius: 3,
          background: color,
          display: 'inline-block',
        }}
      />
      <Text as="span" variant="bodySm" tone="subdued">
        {label}
      </Text>
    </InlineStack>
  );
}
