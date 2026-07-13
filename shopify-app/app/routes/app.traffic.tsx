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
                  here — which platform it was, whether it verified, and what it bought. Make sure
                  the AVA Pay theme extension (or the embed script from Settings) is installed.
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
                    'text',
                  ]}
                  headings={[
                    'Platform',
                    'Protocols',
                    'Requests',
                    'Verified',
                    'Rejected',
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
                    <BlockStack gap="100">
                      {view.failureReasons.slice(0, 8).map((r) => (
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
                columnContentTypes={['text', 'text', 'text', 'text', 'numeric', 'text']}
                headings={['Time', 'Platform', 'Protocol', 'Outcome', 'Discount %', 'Reason']}
                rows={view.recent.map((r) => [
                  new Date(r.createdAt).toLocaleString(),
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
  return (
    <InlineGrid columns={{ xs: 2, md: 4 }} gap="400">
      <KpiTile label={`Requests · ${title.toLowerCase()}`} value={String(kpis.requests)} />
      <KpiTile
        label="Verified"
        value={String(kpis.verified)}
        detail={kpis.identityOnly > 0 ? `${kpis.identityOnly} identity-only` : undefined}
      />
      <KpiTile
        label="Rejected"
        value={String(kpis.failed + kpis.unverified + kpis.policyBlocked + kpis.errors)}
        detail={kpis.unverified > 0 ? `${kpis.unverified} without credentials` : undefined}
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

function OutcomeBadge({ outcome }: { outcome: string }) {
  switch (outcome) {
    case 'verified':
      return <Badge tone="success">Verified</Badge>;
    case 'failed':
      return <Badge tone="critical">Failed</Badge>;
    case 'policy_blocked':
      return <Badge tone="attention">Policy blocked</Badge>;
    default:
      return <Badge tone="warning">Error</Badge>;
  }
}

/**
 * 30-day stacked daily bars: verified (accent) on the baseline, rejected
 * (gray) above. HTML divs rather than SVG: no viewBox distortion, and the
 * whole column is the hover hit-target for the tooltip.
 */
function TrendChart({ days, currency }: { days: TrendDay[]; currency: string | null }) {
  const [hovered, setHovered] = useState<number | null>(null);
  const max = Math.max(1, ...days.map((d) => d.verified + d.rejected));
  const CHART_H = 140;

  const first = days[0];
  const last = days[days.length - 1];
  const hoveredDay = hovered !== null ? days[hovered] : undefined;

  return (
    <BlockStack gap="200">
      <InlineStack gap="400">
        <LegendItem color={SERIES_VERIFIED} label="Verified" />
        <LegendItem color={SERIES_REJECTED} label="Rejected" />
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
                {rH > 0 ? (
                  <div
                    style={{
                      height: rH,
                      background: SERIES_REJECTED,
                      borderRadius: '4px 4px 0 0',
                      marginBottom: vH > 0 ? 2 : 0,
                    }}
                  />
                ) : null}
                {vH > 0 ? (
                  <div
                    style={{
                      height: vH,
                      background: SERIES_VERIFIED,
                      borderRadius: rH > 0 ? 0 : '4px 4px 0 0',
                    }}
                  />
                ) : null}
                {vH === 0 && rH === 0 ? (
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
