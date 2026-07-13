# AVA Pay — Shopify plugin

Drop-in Shopify app that calls the AVA Pay `/verify` endpoint, applies a one-time discount to verified AI shopping agents, and gives the merchant a settings page to control the policy.

**Now supporting real Visa Trusted Agent Protocol agents.** The proxy passes the agent's RFC 9421 signed request through to AVA Pay verbatim — `Signature`, `Signature-Input`, `Content-Digest`, `Host`, `x-ava-mandate`, and any other headers the agent sends. No allowlist, no JSON repackaging.

## Architecture in 30 seconds

```
                           ┌───────────────────────────┐
 storefront page ────────► │ /apps/ava-pay/embed.js    │  (App Proxy, this app)
                           └────────────┬──────────────┘
                                        ▼
                           ┌───────────────────────────┐
                           │ /apps/ava-pay/verify      │  (App Proxy → action())
                           └────────────┬──────────────┘
                                        ▼
                           ┌───────────────────────────┐
                           │ AVA Pay /verify           │  (Fastify API in ../)
                           └────────────┬──────────────┘
                                        ▼
                           ┌───────────────────────────┐
                           │ applyMerchantPolicy()     │  (toggle + max-cap)
                           └────────────┬──────────────┘
                                        ▼
                           ┌───────────────────────────┐
                           │ discountCodeBasicCreate   │  (Admin API)
                           └────────────┬──────────────┘
                                        ▼
                  storefront redirects to /discount/AVA-XYZ
```

If AVA Pay is unreachable, the proxy fails closed (`allow: false`) — the customer is never blocked, they just don't get the discount.

## How to install in 2 minutes

This assumes you already have a Shopify Partners account and a development store.

### 1. Set up the app locally

```bash
cd shopify-app
cp .env.example .env
# Fill in SHOPIFY_API_KEY/SECRET from https://partners.shopify.com → Apps → Your app
# Set AVA_PAY_API_URL=http://localhost:3000 (or wherever your AVA Pay API runs)
npm install
npm run setup        # prisma generate + initial migration (creates dev.sqlite)
npm run dev          # opens the app in your dev store via the Shopify CLI tunnel
```

The Shopify CLI prints a tunneled URL and pops open a browser window for you to install the app on your dev store. After install you'll see the AVA Pay settings page in the Shopify admin.

### 2. Turn on the storefront integration

There are two ways. Pick one:

**Option A — Theme app extension (recommended, zero code).**

In your Shopify admin: **Online Store → Themes → Customize → App embeds → AVA Pay → toggle ON → Save**. That's it. Every storefront page now loads the embed script via the App Proxy.

**Option B — Manual one-liner.**

In your Shopify theme editor, open `theme.liquid` and paste this single line into the `<head>`:

```liquid
<script async src="{{ shop.url }}/apps/ava-pay/embed.js"></script>
```

Save. Done.

### 3. Configure the policy

Open the AVA Pay app from your Shopify admin sidebar. You'll see:

- **Accept verified agents** — master toggle
- **Default discount %** — applied when AVA Pay returns a verified agent without a specific discount
- **Max discount %** — hard cap, even if AVA Pay returns a higher discount

Click **Save**. New verified agents will start getting one-time discount codes immediately.

## Verifying the integration end-to-end (in dev)

There are two flows — a real TAP agent flow and a storefront-script flow.

### Real Visa TAP agent (production path)

The agent calls the proxy directly with a real RFC 9421 signed request:

```
POST https://your-dev-store.myshopify.com/apps/ava-pay/verify
Signature: sig1=:<base64 signature>:
Signature-Input: sig1=("@method" "@target-uri" "host" "content-digest" "x-ava-mandate");created=...;keyid="agent_demo";alg="ed25519"
Content-Digest: sha-256=:<digest>:
Host: your-dev-store.myshopify.com
x-ava-mandate: <base64 JSON mandate>
```

The proxy reads those headers off the actual HTTP request — no allowlist, no JSON wrapper — reconstructs the URL the agent signed, and forwards verbatim to AVA Pay `/verify`. If trusted, the proxy mints a one-time discount code and returns `{ allow: true, discount: { code, percentage } }`. The agent uses the code at checkout.

### Storefront script (testing / lightweight integrations)

For agents that route the customer through a regular page load instead of calling our proxy directly, the embed script still works. Pass the signed payload as URL query parameters:

```
https://your-dev-store.myshopify.com/?signature=sig1%3D%3A...%3A&signature-input=...&content-digest=...&x-ava-mandate=<base64-mandate>
```

`/apps/ava-pay/embed.js` picks up those params, copies them into request headers (the browser sets `Host` automatically), and POSTs to the proxy. From there it's the same code path.

For end-to-end testing today, generate a signed request with the API repo's `tests/sign-helper.ts` — same primitives a production agent SDK would use.

## Files of interest

```
shopify-app/
├── shopify.app.toml                          # App config (proxy, scopes, webhooks)
├── prisma/schema.prisma                      # Sessions + ShopSettings + VerificationLog
├── app/
│   ├── shopify.server.ts                     # @shopify/shopify-app-react-router init
│   ├── lib/
│   │   ├── ava.server.ts                     # AVA Pay /verify client (fail-closed)
│   │   ├── ava-types.ts                      # mirror of API types
│   │   ├── policy.ts                         # applyMerchantPolicy() — pure
│   │   ├── settings.server.ts                # Prisma-backed merchant settings
│   │   └── discount.server.ts                # discountCodeBasicCreate via Admin API
│   └── routes/
│       ├── app.tsx                           # embedded admin shell (App Bridge)
│       ├── app._index.tsx                    # Polaris settings page
│       ├── proxy.verify.tsx                  # POST /apps/ava-pay/verify
│       ├── proxy.embed[.js].tsx              # GET  /apps/ava-pay/embed.js
│       ├── webhooks.checkouts.create.tsx     # telemetry
│       ├── webhooks.orders.create.tsx        # telemetry (realized discounts)
│       └── webhooks.app.uninstalled.tsx      # cleanup
└── extensions/ava-pay-embed/                 # theme app extension (Option A)
    ├── shopify.extension.toml
    └── blocks/ava-pay-embed.liquid           # the block users toggle ON
```

## Tests

```bash
npm test
```

Two suites today:

- `app/lib/ava.test.ts` — the AVA Pay client: request shape, 200/403 handling, network failure, timeout fail-closed.
- `app/lib/settings.test.ts` — `applyMerchantPolicy()`: toggle off blocks, AVA's discount wins, merchant max caps, default applies when AVA omits.

Polaris UI and OAuth flow aren't covered here — those need a real Shopify dev store, and the official Shopify CLI handles them.

## What's next

- Wire the AVA Pay API at `VISA_AGENT_DIRECTORY_URL` once Visa Partners credentials are provisioned (see the root README).
- Shopify Discount Function instead of generated codes (cleaner UX on Shopify Plus).
- Merchant dashboard pages (verified agent traffic, discount spend, top agents).
