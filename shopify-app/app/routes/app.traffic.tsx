import { useLoaderData, type LoaderFunctionArgs } from 'react-router';
import {
  Badge,
  BlockStack,
  Card,
  DataTable,
  EmptyState,
  InlineGrid,
  Layout,
  Page,
  Text,
} from '@shopify/polaris';
import { authenticate } from '../shopify.server.js';
import { getTrafficView, type TrafficSummary, type TrafficView } from '../lib/traffic.server.js';

export async function loader({ request }: LoaderFunctionArgs): Promise<TrafficView> {
  const { session } = await authenticate.admin(request);
  return getTrafficView(session.shop);
}

export default function TrafficPage() {
  const view = useLoaderData<typeof loader>();

  return (
    <Page title="Verified agent traffic">
      <Layout>
        <Layout.Section>
          <InlineGrid columns={{ xs: 1, sm: 2 }} gap="400">
            <KpiCard title="Last 24 hours" summary={view.last24h} />
            <KpiCard title="Last 7 days" summary={view.last7d} />
          </InlineGrid>
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="300">
              <Text as="h2" variant="headingMd">Top agents (last 7 days)</Text>
              {view.topAgents.length === 0 ? (
                <Text as="p" tone="subdued">No agent traffic yet.</Text>
              ) : (
                <DataTable
                  columnContentTypes={['text', 'numeric', 'numeric', 'text']}
                  headings={['Agent', 'Total requests', 'Trusted', 'Trust rate']}
                  rows={view.topAgents.map((a) => {
                    const rate = a.count > 0 ? Math.round((a.trustedCount / a.count) * 1000) / 10 : 0;
                    return [a.agentId, a.count, a.trustedCount, `${rate}%`];
                  })}
                />
              )}
            </BlockStack>
          </Card>
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="300">
              <Text as="h2" variant="headingMd">Recent verifications</Text>
              {view.recent.length === 0 ? (
                <EmptyState
                  heading="No traffic yet"
                  image="https://cdn.shopify.com/s/files/1/0262/4071/2726/files/emptystate-files.png"
                >
                  <p>
                    Once a verified AVA Pay agent visits your storefront, their requests will show up here. Try the
                    end-to-end demo described in the README.
                  </p>
                </EmptyState>
              ) : (
                <DataTable
                  columnContentTypes={['text', 'text', 'text', 'numeric', 'text']}
                  headings={['Time', 'Agent', 'Outcome', 'Discount %', 'Reason']}
                  rows={view.recent.map((r) => [
                    new Date(r.createdAt).toLocaleString(),
                    r.agentId ?? '—',
                    r.trusted ? <Badge tone="success" key={r.id}>Trusted</Badge> : <Badge tone="critical" key={r.id}>Blocked</Badge>,
                    r.discountPct ?? 0,
                    r.reason ?? '—',
                  ])}
                />
              )}
            </BlockStack>
          </Card>
        </Layout.Section>
      </Layout>
    </Page>
  );
}

function KpiCard({ title, summary }: { title: string; summary: TrafficSummary }) {
  return (
    <Card>
      <BlockStack gap="200">
        <Text as="h3" variant="headingSm" tone="subdued">{title}</Text>
        <Text as="p" variant="heading2xl">{summary.total}</Text>
        <Text as="p" tone="subdued">total verification requests</Text>
        <InlineGrid columns={3} gap="200">
          <KpiCell label="Trusted" value={summary.verified} tone="success" />
          <KpiCell label="Blocked" value={summary.blocked} tone="critical" />
          <KpiCell label="Trust rate" value={`${summary.conversionPct}%`} />
        </InlineGrid>
        {summary.avgDiscountPct !== null ? (
          <Text as="p" tone="subdued">
            Avg discount applied: <strong>{summary.avgDiscountPct}%</strong>
          </Text>
        ) : null}
      </BlockStack>
    </Card>
  );
}

function KpiCell({ label, value, tone }: { label: string; value: number | string; tone?: 'success' | 'critical' }) {
  return (
    <BlockStack gap="050">
      <Text as="p" variant="bodySm" tone="subdued">{label}</Text>
      <Text as="p" variant="headingLg" tone={tone}>{String(value)}</Text>
    </BlockStack>
  );
}
