import {
  data,
  useActionData,
  useLoaderData,
  useNavigation,
  useSubmit,
  type ActionFunctionArgs,
  type LoaderFunctionArgs,
} from 'react-router';
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
import { sendTestVisit } from '../lib/test-visit.server.js';
import { describeTestVisit, type TestVisitResult } from '../lib/test-visit.js';
import { themeAppEmbedDeepLink } from '../lib/theme-embed.js';

interface LoaderData {
  settings: ShopSettings;
  appEmbedUrl: string;
}

interface ActionData {
  ok: boolean;
  intent: 'save' | 'test-visit';
  saved?: ShopSettings;
  testVisit?: TestVisitResult;
  error?: string;
}

function badRequest(error: string) {
  return data<ActionData>({ ok: false, intent: 'save', error }, { status: 400 });
}

export async function loader({ request }: LoaderFunctionArgs) {
  const { session } = await authenticate.admin(request);
  const settings = await getShopSettings(session.shop);
  return {
    settings,
    appEmbedUrl: themeAppEmbedDeepLink(session.shop, process.env.SHOPIFY_API_KEY),
  } satisfies LoaderData;
}

export async function action({ request }: ActionFunctionArgs) {
  // Admin auth first, for every intent. The test visit writes a row and calls
  // the verifier on the shop's behalf, so it is exactly as privileged as saving
  // settings and is gated by the same check; `session.shop` is Shopify's word
  // for which store this is, never the form's.
  const { session } = await authenticate.admin(request);
  const form = await request.formData();
  const intent = form.get('intent');

  if (intent === 'test-visit') {
    const testVisit = await sendTestVisit(session.shop);
    return data<ActionData>({ ok: true, intent: 'test-visit', testVisit });
  }

  const acceptVerifiedAgents = form.get('acceptVerifiedAgents') === 'on';
  const defaultDiscountPct = Number(form.get('defaultDiscountPct') ?? 0);
  const maxDiscountPct = Number(form.get('maxDiscountPct') ?? 0);
  const identityOnlyDiscountPct = Number(form.get('identityOnlyDiscountPct') ?? 0);

  if (
    !Number.isFinite(defaultDiscountPct) ||
    !Number.isFinite(maxDiscountPct) ||
    !Number.isFinite(identityOnlyDiscountPct)
  ) {
    return badRequest('Discount values must be numbers.');
  }
  if (defaultDiscountPct < 0 || defaultDiscountPct > 100) {
    return badRequest('Default discount must be 0 to 100%.');
  }
  if (maxDiscountPct < 0 || maxDiscountPct > 100) {
    return badRequest('Max discount must be 0 to 100%.');
  }
  if (identityOnlyDiscountPct < 0 || identityOnlyDiscountPct > 100) {
    return badRequest('Identity-only discount must be 0 to 100%.');
  }
  if (defaultDiscountPct > maxDiscountPct) {
    return badRequest('Default discount cannot exceed the max cap.');
  }
  if (identityOnlyDiscountPct > maxDiscountPct) {
    return badRequest('Identity-only discount cannot exceed the max cap.');
  }

  const saved = await saveShopSettings(session.shop, {
    acceptVerifiedAgents,
    defaultDiscountPct,
    maxDiscountPct,
    identityOnlyDiscountPct,
  });
  return data<ActionData>({ ok: true, intent: 'save', saved });
}

export default function SettingsPage() {
  const { settings, appEmbedUrl } = useLoaderData<typeof loader>();
  const actionData = useActionData<typeof action>();
  const navigation = useNavigation();
  const submit = useSubmit();

  const current: ShopSettings = actionData?.saved ?? settings;

  const [acceptVerifiedAgents, setAcceptVerifiedAgents] = useState(
    current.acceptVerifiedAgents,
  );
  const [defaultDiscountPct, setDefaultDiscountPct] = useState(
    String(current.defaultDiscountPct),
  );
  const [maxDiscountPct, setMaxDiscountPct] = useState(String(current.maxDiscountPct));
  const [identityOnlyDiscountPct, setIdentityOnlyDiscountPct] = useState(
    String(current.identityOnlyDiscountPct),
  );

  const pendingIntent = navigation.formData?.get('intent');

  const onSave = () => {
    const fd = new FormData();
    fd.set('intent', 'save');
    if (acceptVerifiedAgents) fd.set('acceptVerifiedAgents', 'on');
    fd.set('defaultDiscountPct', defaultDiscountPct);
    fd.set('maxDiscountPct', maxDiscountPct);
    fd.set('identityOnlyDiscountPct', identityOnlyDiscountPct);
    submit(fd, { method: 'post' });
  };

  const onTestVisit = () => {
    const fd = new FormData();
    fd.set('intent', 'test-visit');
    submit(fd, { method: 'post' });
  };

  const testVisit =
    actionData?.intent === 'test-visit' && actionData.testVisit
      ? describeTestVisit(actionData.testVisit)
      : null;

  return (
    <Page title="AVA Pay settings">
      <Layout>
        {actionData && !actionData.ok && actionData.error ? (
          <Layout.Section>
            <Banner tone="critical" title="Couldn't save">{actionData.error}</Banner>
          </Layout.Section>
        ) : null}
        {actionData && actionData.ok && actionData.intent === 'save' ? (
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
              <TextField
                label="Identity-only agent discount %"
                type="number"
                min={0}
                max={100}
                value={identityOnlyDiscountPct}
                onChange={(v) => setIdentityOnlyDiscountPct(v)}
                helpText="For agents verified by identity alone, without a buyer mandate (e.g. ChatGPT via Web Bot Auth). They are admitted either way; 0 means no discount. Raise to opt this traffic into a discount."
                autoComplete="off"
              />
              <InlineStack align="end">
                <Button
                  variant="primary"
                  onClick={onSave}
                  loading={pendingIntent === 'save'}
                >
                  Save
                </Button>
              </InlineStack>
            </BlockStack>
          </Card>
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="300">
              <Text as="h2" variant="headingMd">Storefront install</Text>
              <Text as="p" tone="subdued">
                AVA Pay runs on your storefront through its theme app embed. Turn it on in
                the theme editor and every page starts checking incoming agents. There is
                no code to add and nothing in your theme to edit.
              </Text>
              <InlineStack align="start">
                <Button url={appEmbedUrl} target="_top">
                  Turn on in theme editor
                </Button>
              </InlineStack>
              <Text as="p" tone="subdued" variant="bodySm">
                The editor opens on App embeds with AVA Pay ready to switch on. Remember to
                Save in the theme editor.
              </Text>
            </BlockStack>
          </Card>
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="300">
              <Text as="h2" variant="headingMd">Check your setup</Text>
              <Text as="p" tone="subdued">
                Send a test agent visit to see the whole path work without waiting for a
                real AI shopping agent. AVA Pay signs a demo agent credential, verifies it
                the same way it verifies live traffic, applies your settings, and records
                the visit on the Traffic page marked as a test. No discount code is
                created and your storefront is not touched.
              </Text>
              {testVisit ? (
                <Banner tone={testVisit.tone} title={testVisit.title}>
                  <p>{testVisit.body}</p>
                </Banner>
              ) : null}
              <InlineStack align="start">
                <Button
                  onClick={onTestVisit}
                  loading={pendingIntent === 'test-visit'}
                >
                  Send test agent visit
                </Button>
              </InlineStack>
            </BlockStack>
          </Card>
        </Layout.Section>
      </Layout>
    </Page>
  );
}
