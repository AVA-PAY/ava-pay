import {
  data,
  useActionData,
  useLoaderData,
  useNavigation,
  useRevalidator,
  useSubmit,
  type ActionFunctionArgs,
  type LoaderFunctionArgs,
} from 'react-router';
import { useEffect, useRef, useState } from 'react';
import {
  Banner,
  BlockStack,
  Button,
  Card,
  InlineStack,
  Layout,
  Link,
  List,
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
import { themeAppEmbedDeepLink, themeListUrl } from '../lib/theme-embed.js';
import { buildStorefrontVisitUrl } from '../lib/storefront-visit.server.js';

interface LoaderData {
  settings: ShopSettings;
  appEmbedUrl: string;
  themesUrl: string;
  storefrontVisitUrl: string;
}

/**
 * How often the Settings page reissues the storefront visit link.
 *
 * The link carries a signed credential, and a signature is deliberately short
 * lived, so a link rendered once would quietly go stale on a page left open.
 * Reissuing well inside the verifier's window is what keeps the storefront
 * path a single click on a link that works, rather than a click that lands on
 * an expired-signature row.
 */
const STOREFRONT_VISIT_REFRESH_MS = 120_000;

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
    themesUrl: themeListUrl(session.shop),
    // Signed on the server, per load, so the merchant's storefront link is one
    // click on a real link rather than a button that has to go and fetch one.
    storefrontVisitUrl: buildStorefrontVisitUrl(session.shop),
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

/**
 * Keep the loader's storefront visit link fresh while this page is open.
 *
 * Only the link needs it, and only because it carries a signature with a life
 * measured in minutes. Revalidation is skipped while the tab is hidden, so a
 * page left open in a background tab costs nothing.
 */
function useStorefrontLinkRefresh(): void {
  const revalidator = useRevalidator();
  const revalidate = useRef(revalidator.revalidate);

  useEffect(() => {
    revalidate.current = revalidator.revalidate;
  });

  useEffect(() => {
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') revalidate.current();
    }, STOREFRONT_VISIT_REFRESH_MS);
    return () => clearInterval(timer);
  }, []);
}

/**
 * A drawn stand-in for the theme editor's App embeds panel, so the written
 * steps have something to point at. Decorative: the list above says everything
 * it shows, which is why it is hidden from assistive technology.
 */
function AppEmbedsIllustration() {
  return (
    <div
      aria-hidden="true"
      style={{
        border: '1px solid var(--p-color-border, #e3e3e3)',
        borderRadius: 8,
        padding: 12,
        maxWidth: 320,
        background: 'var(--p-color-bg-surface-secondary, #f7f7f7)',
      }}
    >
      <BlockStack gap="200">
        <Text as="span" variant="bodySm" tone="subdued">
          App embeds
        </Text>
        <InlineStack align="space-between" blockAlign="center" gap="300">
          <Text as="span" variant="bodySm">
            AVA Pay
          </Text>
          <span
            style={{
              width: 34,
              height: 20,
              borderRadius: 10,
              background: '#2a78d6',
              position: 'relative',
              display: 'inline-block',
              flex: 'none',
            }}
          >
            <span
              style={{
                position: 'absolute',
                top: 2,
                left: 16,
                width: 16,
                height: 16,
                borderRadius: '50%',
                background: '#ffffff',
              }}
            />
          </span>
        </InlineStack>
      </BlockStack>
    </div>
  );
}

export default function SettingsPage() {
  const { settings, appEmbedUrl, themesUrl, storefrontVisitUrl } =
    useLoaderData<typeof loader>();
  const actionData = useActionData<typeof action>();
  const navigation = useNavigation();
  const submit = useSubmit();
  useStorefrontLinkRefresh();

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

  // The banner reports an applied discount, so settings that grant no discount
  // mean a verified visit with nothing to display. Worth saying before someone
  // presses the button and reads silence as a broken widget. Policy rules can
  // still grant one, which is why this hedges rather than promises.
  const storefrontBannerUnlikely =
    !current.acceptVerifiedAgents || current.defaultDiscountPct === 0;

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
            <BlockStack gap="400">
              <Text as="h2" variant="headingMd">Storefront install</Text>
              <Text as="p" tone="subdued">
                AVA Pay runs on your storefront through its theme app embed. Turn it on
                once and every page starts checking incoming agents. There is no code to
                add and nothing in your theme to edit.
              </Text>

              <BlockStack gap="300">
                <Text as="h3" variant="headingSm">Turn it on</Text>
                <List type="number">
                  <List.Item>
                    Press Turn on in theme editor below. The editor opens on the App
                    embeds panel with AVA Pay ready to switch on. It opens the theme you
                    have published; to set it up on a different one, open{' '}
                    <Link url={themesUrl} target="_top">
                      Online Store themes
                    </Link>
                    , press Customize on that theme, then open App embeds.
                  </List.Item>
                  <List.Item>Switch the AVA Pay toggle on.</List.Item>
                  <List.Item>
                    Press Save in the theme editor. Nothing reaches your storefront until
                    you save.
                  </List.Item>
                </List>
                <AppEmbedsIllustration />
                <Text as="p" tone="subdued" variant="bodySm">
                  As soon as the toggle is on, the editor preview shows a sample of the
                  storefront banner, so you can see what shoppers get before you publish.
                </Text>
              </BlockStack>

              <BlockStack gap="300">
                <Text as="h3" variant="headingSm">Turn it off</Text>
                <Text as="p" tone="subdued">
                  The same panel: open App embeds in the theme editor, switch the AVA Pay
                  toggle off, and Save. Nothing is left behind in your theme, and
                  uninstalling the app removes it as well.
                </Text>
              </BlockStack>

              <BlockStack gap="300">
                <Text as="h3" variant="headingSm">Where it applies, and what it shows</Text>
                <List>
                  <List.Item>
                    Every page of your online store. There is no template to choose and no
                    section to place.
                  </List.Item>
                  <List.Item>
                    Shoppers see nothing unless a verified AI agent visit results in an
                    applied discount. Failed checks, checks that could not be completed,
                    and verified visits that earn no discount are all silent on the
                    storefront and recorded on the Traffic page instead.
                  </List.Item>
                  <List.Item>
                    The block has one setting: show shoppers a confirmation when a verified
                    agent visit gets a discount. It is on by default. Turning it off keeps
                    verification and discounts running with nothing displayed.
                  </List.Item>
                  <List.Item>
                    Theme app extensions cannot render inside Shopify checkout, so this
                    appears on storefront pages only.
                  </List.Item>
                </List>
              </BlockStack>

              <InlineStack align="start">
                <Button url={appEmbedUrl} target="_top">
                  Turn on in theme editor
                </Button>
              </InlineStack>
            </BlockStack>
          </Card>
        </Layout.Section>

        <Layout.Section>
          <Card>
            <BlockStack gap="400">
              <Text as="h2" variant="headingMd">Check your setup</Text>
              <Text as="p" tone="subdued">
                Two ways to watch the whole path work without waiting for a real AI
                shopping agent to turn up. Both sign a demo agent credential and put it
                through the same verification your live traffic goes through.
              </Text>

              <BlockStack gap="300">
                <Text as="h3" variant="headingSm">Inside the app</Text>
                <Text as="p" tone="subdued">
                  AVA Pay signs a demo agent credential, verifies it the same way it
                  verifies live traffic, applies your settings, and records the visit on
                  the Traffic page marked as a test. No discount code is created and your
                  storefront is not touched.
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

              <BlockStack gap="300">
                <Text as="h3" variant="headingSm">On your storefront</Text>
                <Text as="p" tone="subdued">
                  Opens your storefront home page carrying a freshly signed demo agent
                  credential. The app embed forwards it, the verifier checks it, and if
                  your policy grants a discount the code is applied and the confirmation
                  banner appears on the page. This one is a real storefront visit: it
                  creates a real single-use discount code in your store and records a real
                  row on the Traffic page, marked as a test. Turn the app embed on first,
                  or the page has nothing to forward.
                </Text>
                {storefrontBannerUnlikely ? (
                  <Banner tone="info" title="This visit will not show the banner">
                    <p>
                      {current.acceptVerifiedAgents
                        ? 'Your default discount is 0%, so a verified agent earns no code and there is nothing for the banner to report. Set a percentage above and Save first, unless a policy rule already grants one.'
                        : 'Accept verified agents is off, so every agent is turned away and nothing is shown on the storefront. Turn it on and Save first.'}
                    </p>
                  </Banner>
                ) : null}
                <InlineStack align="start">
                  <Button url={storefrontVisitUrl} target="_blank">
                    View a test agent visit on your storefront
                  </Button>
                </InlineStack>
                <Text as="p" tone="subdued" variant="bodySm">
                  If your storefront asks for its password first, enter it and press the
                  button again. The password page drops the signed parameters on its way
                  through.
                </Text>
              </BlockStack>
            </BlockStack>
          </Card>
        </Layout.Section>
      </Layout>
    </Page>
  );
}
