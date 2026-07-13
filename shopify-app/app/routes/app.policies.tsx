import { useMemo, useState } from 'react';
import {
  data,
  useActionData,
  useLoaderData,
  useSubmit,
  type ActionFunctionArgs,
  type LoaderFunctionArgs,
} from 'react-router';
import {
  Banner,
  BlockStack,
  Button,
  Card,
  Divider,
  InlineGrid,
  InlineStack,
  Layout,
  Page,
  Select,
  Text,
  TextField,
} from '@shopify/polaris';
import { authenticate } from '../shopify.server.js';
import prisma from '../db.server.js';
import { getShopSettings, saveShopPolicy } from '../lib/settings.server.js';
import {
  parseAgentPolicy,
  serializeAgentPolicy,
  validateAgentPolicy,
  type AgentPolicy,
  type PlatformRule,
  type PolicyAction,
} from '../lib/agent-policy.js';

interface LoaderData {
  policy: AgentPolicy | null;
  /** Platforms observed in the last 30 days — suggestions for new rules. */
  seenPlatforms: string[];
}

interface ActionData {
  ok: boolean;
  error?: string;
  saved?: AgentPolicy | null;
}

export async function loader({ request }: LoaderFunctionArgs): Promise<LoaderData> {
  const { session } = await authenticate.admin(request);
  const settings = await getShopSettings(session.shop);
  const since = new Date(Date.now() - 30 * 24 * 3600_000);
  const rows = await prisma.verificationEvent.findMany({
    where: { shop: session.shop, createdAt: { gte: since }, platform: { not: null } },
    distinct: ['platform'],
    select: { platform: true },
    take: 20,
  });
  return {
    policy: settings.policy,
    seenPlatforms: rows.map((r) => r.platform!).sort(),
  };
}

export async function action({ request }: ActionFunctionArgs) {
  const { session } = await authenticate.admin(request);
  const form = await request.formData();
  const intent = form.get('intent');

  if (intent === 'clear') {
    await saveShopPolicy(session.shop, null);
    return data<ActionData>({ ok: true, saved: null });
  }

  // 'save' (from the rule editor) and 'import' (pasted JSON) share one
  // validation path: nothing unvalidated ever reaches the database.
  const raw = form.get('policyJson');
  if (typeof raw !== 'string' || raw.trim() === '') {
    return data<ActionData>({ ok: false, error: 'No policy provided.' }, { status: 400 });
  }
  const parsed = parseAgentPolicy(raw);
  if (!parsed.ok) {
    return data<ActionData>({ ok: false, error: parsed.error }, { status: 400 });
  }
  await saveShopPolicy(session.shop, parsed.policy);
  return data<ActionData>({ ok: true, saved: parsed.policy });
}

const ACTION_OPTIONS = [
  { label: 'Allow', value: 'allow' },
  { label: 'Challenge (require buyer mandate)', value: 'challenge' },
  { label: 'Block', value: 'block' },
];

/** Editable row state: numbers kept as strings for the text fields. */
interface RuleDraft {
  platform: string;
  action: PolicyAction;
  maxDiscountPct: string;
  maxSpend: string; // major units in the UI, stored as minor
  offerDiscountPct: string;
}

function toDraft(rule: PlatformRule): RuleDraft {
  return {
    platform: rule.platform,
    action: rule.action,
    maxDiscountPct: rule.maxDiscountPct !== undefined ? String(rule.maxDiscountPct) : '',
    maxSpend: rule.maxSpendMinor !== undefined ? String(rule.maxSpendMinor / 100) : '',
    offerDiscountPct: rule.offerDiscountPct !== undefined ? String(rule.offerDiscountPct) : '',
  };
}

function draftToRule(d: RuleDraft): Record<string, unknown> {
  const rule: Record<string, unknown> = { platform: d.platform.trim(), action: d.action };
  if (d.maxDiscountPct.trim() !== '') rule.maxDiscountPct = Number(d.maxDiscountPct);
  if (d.maxSpend.trim() !== '') rule.maxSpendMinor = Math.round(Number(d.maxSpend) * 100);
  if (d.offerDiscountPct.trim() !== '') rule.offerDiscountPct = Number(d.offerDiscountPct);
  return rule;
}

export default function PoliciesPage() {
  const { policy, seenPlatforms } = useLoaderData<typeof loader>();
  const actionData = useActionData<typeof action>();
  const submit = useSubmit();

  const effective = actionData?.ok ? (actionData.saved ?? null) : policy;

  const [drafts, setDrafts] = useState<RuleDraft[]>(
    (effective?.rules ?? []).map(toDraft),
  );
  const [importJson, setImportJson] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);

  const exportJson = useMemo(
    () => (effective ? serializeAgentPolicy(effective) : ''),
    [effective],
  );

  const setDraft = (i: number, patch: Partial<RuleDraft>) => {
    setDrafts((ds) => ds.map((d, j) => (j === i ? { ...d, ...patch } : d)));
  };

  const onSave = () => {
    // Preserve a defaultRule that came in via import — the visual editor
    // only edits platform rules, and saving must not silently drop it.
    const candidate = {
      version: 1,
      rules: drafts.map(draftToRule),
      ...(effective?.defaultRule ? { defaultRule: effective.defaultRule } : {}),
    };
    // Validate client-side first for an immediate, specific error message;
    // the action re-validates server-side regardless.
    const check = validateAgentPolicy(candidate);
    if (!check.ok) {
      setLocalError(check.error);
      return;
    }
    setLocalError(null);
    const fd = new FormData();
    fd.set('intent', 'save');
    fd.set('policyJson', JSON.stringify(candidate));
    submit(fd, { method: 'post' });
  };

  const onImport = () => {
    setLocalError(null);
    const fd = new FormData();
    fd.set('intent', 'import');
    fd.set('policyJson', importJson);
    submit(fd, { method: 'post' });
  };

  const onClear = () => {
    setLocalError(null);
    setDrafts([]);
    const fd = new FormData();
    fd.set('intent', 'clear');
    submit(fd, { method: 'post' });
  };

  const error = localError ?? (actionData && !actionData.ok ? actionData.error : undefined);

  return (
    <Page
      title="Agent policies"
      subtitle="Per-platform rules for verified agent traffic. No policy = every verified agent is admitted under your global settings."
    >
      <Layout>
        {error ? (
          <Layout.Section>
            <Banner tone="critical" title="Policy not saved">
              {error}
            </Banner>
          </Layout.Section>
        ) : null}
        {actionData?.ok ? (
          <Layout.Section>
            <Banner tone="success" title="Policy saved" onDismiss={() => {}} />
          </Layout.Section>
        ) : null}

        <Layout.Section>
          <Card>
            <BlockStack gap="400">
              <InlineStack align="space-between" blockAlign="center">
                <Text as="h2" variant="headingMd">
                  Platform rules
                </Text>
                <Button
                  onClick={() =>
                    setDrafts((ds) => [
                      ...ds,
                      {
                        platform: '',
                        action: 'allow',
                        maxDiscountPct: '',
                        maxSpend: '',
                        offerDiscountPct: '',
                      },
                    ])
                  }
                >
                  Add rule
                </Button>
              </InlineStack>

              <Text as="p" tone="subdued">
                Rules match a platform exactly (e.g.{' '}
                <code>https://chatgpt.com</code>). Platforms without a rule get the{' '}
                <strong>most restrictive</strong> treatment of any rule below — unknown agents
                never get a better deal than known ones. Identity-only traffic (verified, no
                buyer mandate) never receives offers; its discount stays governed by the
                identity-only setting.
                {seenPlatforms.length > 0
                  ? ` Seen in the last 30 days: ${seenPlatforms.join(', ')}.`
                  : ''}
              </Text>

              {drafts.length === 0 ? (
                <Text as="p" tone="subdued">
                  No rules yet — no policy is enforced. Add a rule or import a policy below.
                </Text>
              ) : null}

              {drafts.map((d, i) => (
                <BlockStack key={i} gap="200">
                  {i > 0 ? <Divider /> : null}
                  <InlineGrid columns={{ xs: 1, md: 5 }} gap="200">
                    <TextField
                      label="Platform"
                      value={d.platform}
                      onChange={(v) => setDraft(i, { platform: v })}
                      placeholder="https://chatgpt.com"
                      autoComplete="off"
                    />
                    <Select
                      label="Action"
                      options={ACTION_OPTIONS}
                      value={d.action}
                      onChange={(v) => setDraft(i, { action: v as PolicyAction })}
                    />
                    <TextField
                      label="Max discount %"
                      type="number"
                      value={d.maxDiscountPct}
                      onChange={(v) => setDraft(i, { maxDiscountPct: v })}
                      placeholder="global cap"
                      autoComplete="off"
                    />
                    <TextField
                      label="Max mandate spend"
                      type="number"
                      value={d.maxSpend}
                      onChange={(v) => setDraft(i, { maxSpend: v })}
                      placeholder="no limit"
                      prefix="$"
                      autoComplete="off"
                    />
                    <TextField
                      label="Offer discount %"
                      type="number"
                      value={d.offerDiscountPct}
                      onChange={(v) => setDraft(i, { offerDiscountPct: v })}
                      placeholder="none"
                      helpText="Mandate-backed only"
                      autoComplete="off"
                    />
                  </InlineGrid>
                  <InlineStack align="end">
                    <Button
                      tone="critical"
                      variant="plain"
                      onClick={() => setDrafts((ds) => ds.filter((_, j) => j !== i))}
                    >
                      Remove rule
                    </Button>
                  </InlineStack>
                </BlockStack>
              ))}

              <InlineStack align="end" gap="200">
                {effective ? (
                  <Button tone="critical" onClick={onClear}>
                    Remove policy
                  </Button>
                ) : null}
                <Button variant="primary" onClick={onSave} disabled={drafts.length === 0}>
                  Save policy
                </Button>
              </InlineStack>
            </BlockStack>
          </Card>
        </Layout.Section>

        <Layout.Section>
          <InlineGrid columns={{ xs: 1, md: 2 }} gap="400">
            <Card>
              <BlockStack gap="300">
                <Text as="h2" variant="headingMd">
                  Export
                </Text>
                <Text as="p" tone="subdued">
                  The saved policy as portable JSON — copy it to another store or keep it in
                  version control.
                </Text>
                <TextField
                  label="Policy JSON"
                  labelHidden
                  value={exportJson}
                  multiline={8}
                  readOnly
                  autoComplete="off"
                  placeholder="No policy saved."
                />
              </BlockStack>
            </Card>
            <Card>
              <BlockStack gap="300">
                <Text as="h2" variant="headingMd">
                  Import
                </Text>
                <Text as="p" tone="subdued">
                  Paste a policy JSON document. It is validated before anything is saved;
                  invalid policies are rejected whole.
                </Text>
                <TextField
                  label="Policy JSON"
                  labelHidden
                  value={importJson}
                  onChange={setImportJson}
                  multiline={8}
                  autoComplete="off"
                  placeholder='{"version":1,"rules":[{"platform":"https://chatgpt.com","action":"allow"}]}'
                />
                <InlineStack align="end">
                  <Button onClick={onImport} disabled={importJson.trim() === ''}>
                    Import policy
                  </Button>
                </InlineStack>
              </BlockStack>
            </Card>
          </InlineGrid>
        </Layout.Section>
      </Layout>
    </Page>
  );
}
