import {
  json,
  type ActionFunctionArgs,
  type LoaderFunctionArgs,
} from '@remix-run/node';
import { useActionData, useLoaderData, useSubmit } from '@remix-run/react';
import { useState } from 'react';
import {
  Banner,
  BlockStack,
  Button,
  Card,
  InlineStack,
  Layout,
  Page,
  Text,
  TextField,
  Checkbox,
} from '@shopify/polaris';
import { authenticate } from '../shopify.server.js';
import {
  getShopSettings,
  saveShopSettings,
  type ShopSettings,
} from '../lib/settings.server.js';

interface LoaderData {
  settings: ShopSettings;
  embedScriptUrl: string;
}

interface ActionData {
  ok: boolean;
  saved?: ShopSettings;
  error?: string;
}

export async function loader({ request }: LoaderFunctionArgs) {
  const { session } = await authenticate.admin(request);
  const settings = await getShopSettings(session.shop);
  return json<LoaderData>({
    settings,
    embedScriptUrl: `https://${session.shop}/apps/ava-pay/embed.js`,
  });
}

export async function action({ request }: ActionFunctionArgs) {
  const { session } = await authenticate.admin(request);
  const form = await request.formData();

  const acceptVerifiedAgents = form.get('acceptVerifiedAgents') === 'on';
  const defaultDiscountPct = Number(form.get('defaultDiscountPct') ?? 0);
  const maxDiscountPct = Number(form.get('maxDiscountPct') ?? 0);

  if (!Number.isFinite(defaultDiscountPct) || !Number.isFinite(maxDiscountPct)) {
    return json<ActionData>({ ok: false, error: 'Discount values must be numbers.' }, { status: 400 });
  }
  if (defaultDiscountPct < 0 || defaultDiscountPct > 100) {
    return json<ActionData>({ ok: false, error: 'Default discount must be 0–100%.' }, { status: 400 });
  }
  if (maxDiscountPct < 0 || maxDiscountPct > 100) {
    return json<ActionData>({ ok: false, error: 'Max discount must be 0–100%.' }, { status: 400 });
  }
  if (defaultDiscountPct > maxDiscountPct) {
    return json<ActionData>(
      { ok: false, error: 'Default discount cannot exceed the max cap.' },
      { status: 400 },
    );
  }

  const saved = await saveShopSettings(session.shop, {
    acceptVerifiedAgents,
    defaultDiscountPct,
    maxDiscountPct,
  });
  return json<ActionData>({ ok: true, saved });
}

export default function SettingsPage() {
  const { settings, embedScriptUrl } = useLoaderData<typeof loader>();
  const actionData = useActionData<typeof action>();
  const submit = useSubmit();

  const current: ShopSettings = actionData?.saved ?? settings;

  const [acceptVerifiedAgents, setAcceptVerifiedAgents] = useState(
    current.acceptVerifiedAgents,
  );
  const [defaultDiscountPct, setDefaultDiscountPct] = useState(
    String(current.defaultDiscountPct),
  );
  const [maxDiscountPct, setMaxDiscountPct] = useState(String(current.maxDiscountPct));

  const onSave = () => {
    const fd = new FormData();
    if (acceptVerifiedAgents) fd.set('acceptVerifiedAgents', 'on');
    fd.set('defaultDiscountPct', defaultDiscountPct);
    fd.set('maxDiscountPct', maxDiscountPct);
    submit(fd, { method: 'post' });
  };

  return (
    <Page title="AVA Pay settings">
      <Layout>
        {actionData && !actionData.ok && actionData.error ? (
          <Layout.Section>
            <Banner tone="critical" title="Couldn't save">{actionData.error}</Banner>
          </Layout.Section>
        ) : null}
        {actionData && actionData.ok ? (
          <Layout.Section>
            <Banner tone="success" title="Settings saved" onDismiss={() => {}} />
          </Layout.Section>
        ) : null}

        <Layout.Section>
          <Card>
            <BlockStack gap="400">
              <Text as="h2" variant="headingMd">Verified agent traffic</Text>
              <Text as="p" tone="subdued">
                When AVA Pay verifies an incoming AI shopping agent, this app applies a
                one-time discount and lets the order proceed. Toggle off to fall back to
                regular bot blocking.
              </Text>
              <Checkbox
                label="Accept verified agents"
                helpText="Master switch. When off, every agent request is treated as untrusted."
                checked={acceptVerifiedAgents}
                onChange={(v) => setAcceptVerifiedAgents(v)}
              />
              <InlineStack gap="400" wrap={false}>
                <div style={{ flex: 1 }}>
                  <TextField
                    label="Default discount %"
                    type="number"
                    min={0}
                    max={100}
                    value={defaultDiscountPct}
                    onChange={(v) => setDefaultDiscountPct(v)}
                    helpText="Used when AVA Pay returns a verified agent without a specific discount."
                    autoComplete="off"
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <TextField
                    label="Max discount %"
                    type="number"
                    min={0}
                    max={100}
                    value={maxDiscountPct}
                    onChange={(v) => setMaxDiscountPct(v)}
                    helpText="Hard cap, even if AVA Pay returns a higher discount."
                    autoComplete="off"
                  />
                </div>
              </InlineStack>
              <InlineStack align="end">
                <Button variant="primary" onClick={onSave}>Save</Button>
              </InlineStack>
            </BlockStack>
          </Card>
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="200">
              <Text as="h2" variant="headingMd">Storefront install</Text>
              <Text as="p" tone="subdued">
                The recommended install is the AVA Pay theme app extension (zero code).
                If you'd rather install manually, paste this single line into your
                <code> theme.liquid </code> &lt;head&gt;:
              </Text>
              <Card background="bg-surface-secondary">
                <Text as="p" variant="bodyMd" fontWeight="semibold">
                  &lt;script async src="{embedScriptUrl}"&gt;&lt;/script&gt;
                </Text>
              </Card>
            </BlockStack>
          </Card>
        </Layout.Section>
      </Layout>
    </Page>
  );
}
