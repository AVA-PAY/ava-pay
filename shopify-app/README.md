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
# Fill in SHOPIFY_API_KEY/SECRET from the Shopify Dev Dashboard → your app → Settings
# Set AVA_PAY_API_URL=http://localhost:3000 (or wherever your AVA Pay API runs)
npm install
npm run setup        # prisma generate + prisma migrate deploy
npm run dev          # opens the app in your dev store via the Shopify CLI tunnel
```

`npm run setup` needs a Postgres database to exist first — see **Local database** below.

The Shopify CLI prints a tunneled URL and pops open a browser window for you to install the app on your dev store. After install you'll see the AVA Pay settings page in the Shopify admin.

### Local database

The app runs on Postgres in every environment (production is Railway Postgres).
Prisma allows one provider per migration directory, so there is no sqlite path
any more: `shopify app dev` needs a local Postgres too.

On macOS with Homebrew:

```bash
brew install postgresql@17
brew services start postgresql@17
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"   # add to your shell profile

# One-time: a dev role and a database for this app.
psql -d postgres -c "CREATE ROLE ava_pay LOGIN PASSWORD 'ava_pay' CREATEDB;"
createdb -O ava_pay ava_pay_shopify
```

Then in `.env`:

```
DATABASE_URL=postgresql://ava_pay:ava_pay@localhost:5432/ava_pay_shopify
```

`ava_pay:ava_pay` is a local development credential on a database that listens
on localhost only. Production credentials come from the Railway Postgres plugin
and live only in Railway environment variables.

Any other Postgres works as well (a Docker container, Postgres.app, a remote
dev database) — only the `DATABASE_URL` changes. `prisma migrate dev` creates
and drops its own shadow database, which is why the dev role carries `CREATEDB`.

### 2. Turn on the storefront integration

**The theme app extension, which is the only path the app offers a merchant.**

In your Shopify admin: **Online Store → Themes → Customize → App embeds → AVA Pay → toggle ON → Save**. That's it. Every storefront page now loads the embed script via the App Proxy.

The app's Settings page has a button that deep-links straight into the theme
editor with this embed ready to activate (`app/lib/theme-embed.ts`).

**Developer path: the script tag the embed block emits.**

For local experiments against a theme you control, or for a headless/custom
storefront that has no app embeds to toggle, the block's entire payload is one
line:

```liquid
<script async src="{{ shop.url }}/apps/ava-pay/embed.js"></script>
```

This is documentation for developers working on this repo, **not** an install
instruction for merchants, and it must not reappear anywhere in the merchant
UI. Shopify's App Store policy 2.1.1 prohibits an app asking a merchant to
hand-edit theme code when a theme app extension exists, and ours does. The
submission was paused on exactly that in August 2026.

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

### Test agent visit (in-app, no terminal)

Settings has a **Send test agent visit** button. It signs a Visa Trusted Agent
Protocol request server side with the public demo credential (`signWithVisa`
from `@ava-pay/agent`), puts it through the same `/verify` call and the same
`decideVerification()` the App Proxy path uses, and records the same
VerificationEvent with `source='test'` so the Traffic page can label it.

It never routes through the storefront, so a development store's password gate
is irrelevant, and it never mints a discount code: the verdict reports the
percentage your policy *would* apply. `app/lib/test-visit.ts` holds the
verdict and its wording (browser safe), `test-visit-request.ts` the signing,
`test-visit.server.ts` the I/O.

The standalone `scripts/simulate-verified-agent.mjs` in the API repo remains
the tool for exercising the real storefront path end to end. It is a developer
tool, and it is deliberately not part of any merchant or reviewer instruction.

## Deploying to production

The app runs as its own Railway service alongside the AVA Pay API, in project
`incredible-passion`.

**Service configuration**

- **Root Directory** `shopify-app`, so the build context is this directory and
  Railway picks up `shopify-app/railway.json` automatically.
- **Builder** Dockerfile (`shopify-app/Dockerfile`). Two stages: build the
  Prisma client and the React Router bundle, then install production
  dependencies only and drop to the `node` user.
- **Database** Railway Postgres, wired in as `DATABASE_URL=${{Postgres.DATABASE_URL}}`.
  Use the private URL, not `DATABASE_PUBLIC_URL`.

**Environment variables**

```
DATABASE_URL=${{Postgres.DATABASE_URL}}
SHOPIFY_API_KEY=<client id from the Dev Dashboard>
SHOPIFY_API_SECRET=<client secret from the Dev Dashboard>
SHOPIFY_APP_URL=https://<the service's public domain>
SCOPES=read_orders,write_discounts,write_checkouts
AVA_PAY_API_URL=https://pay.avalayer.com
PORT=3000
```

Never set `HOST`: `react-router-serve` reads it as the bind address, and the
public URL is `SHOPIFY_APP_URL`. Secrets belong in Railway's variables only,
never in a file or a commit.

**Migrations** run at container start. `docker-entrypoint.sh` runs
`prisma migrate deploy` and then execs the server, so a failed migration fails
the deploy instead of serving against a stale schema.

**Releasing app config** (URLs, scopes, webhooks, app proxy) is separate from
deploying code:

```bash
npx shopify app deploy --allow-updates --config ava-pay
```

Confirm afterwards in the Dev Dashboard that the released version carries the
production URLs, the webhook subscriptions including the three compliance
topics, and the app proxy.

### Expiring offline access tokens

`future.expiringOfflineAccessTokens` is on in `app/shopify.server.ts` and must
stay on. Public apps have been required to use expiring offline access tokens
since 2026-04-01. Without the flag, token exchange mints a non-expiring token
and Shopify rejects it with a bare `403 Forbidden` and an empty body *before
the query runs*, so every Admin API call fails identically, including ones
needing no scopes at all. The `Session.refreshToken` and
`Session.refreshTokenExpires` columns exist to persist what the flag produces.

If you ever see blanket 403s from the Admin API, check that a freshly minted
offline session has a non-null `expires` before suspecting scopes.

### Keeping `shopify app dev` working

The production config sets `automatically_update_urls_on_dev = false`, so a
dev run can no longer repoint the live app's URLs at a tunnel and break
installed stores. Development therefore needs its **own** Shopify app:

1. Create a second app in the Dev Dashboard, e.g. "AVA Pay Dev".
2. `npx shopify app config link` and select it, naming the config `dev`, which
   writes `shopify.app.dev.toml`.
3. Leave `automatically_update_urls_on_dev = true` in that file only.
4. Develop with `npx shopify app dev --config dev`, and release production with
   `npx shopify app deploy --config ava-pay`.

## Files of interest

```
shopify-app/
├── shopify.app.toml                          # App config (proxy, scopes, webhooks)
├── prisma/schema.prisma                      # Sessions + ShopSettings + VerificationEvent + AgentCommerceEvent
├── app/
│   ├── shopify.server.ts                     # @shopify/shopify-app-react-router init
│   ├── lib/
│   │   ├── ava.server.ts                     # AVA Pay /verify client (fail-closed)
│   │   ├── ava-types.ts                      # mirror of API types
│   │   ├── policy.ts                         # applyMerchantPolicy() — pure
│   │   ├── settings.server.ts                # Prisma-backed merchant settings
│   │   ├── discount.server.ts                # discountCodeBasicCreate via Admin API
│   │   ├── theme-embed.ts                    # theme editor app-embed deep link
│   │   ├── test-visit.ts                     # test agent visit: verdict + wording
│   │   ├── test-visit-request.ts             # test agent visit: signing (node:crypto)
│   │   └── test-visit.server.ts              # test agent visit: settings, verify, record
│   └── routes/
│       ├── app.tsx                           # embedded admin shell (App Bridge)
│       ├── app._index.tsx                    # Polaris settings page + test visit
│       ├── proxy.verify.tsx                  # POST /apps/ava-pay/verify
│       ├── proxy.embed[.js].tsx              # GET  /apps/ava-pay/embed.js
│       ├── webhooks.checkouts.create.tsx     # telemetry
│       ├── webhooks.orders.create.tsx        # telemetry (realized discounts)
│       └── webhooks.app.uninstalled.tsx      # cleanup
└── extensions/ava-pay-embed/                 # theme app extension (the only install path)
    ├── shopify.extension.toml
    └── blocks/ava-pay-embed.liquid           # the block merchants toggle ON
```

## Tests

```bash
npm test
```

117 tests over the pure logic, no Prisma and no network:

- `app/lib/ava.test.ts` — the AVA Pay client: request shape, 200/403 handling, network failure, timeout fail-closed.
- `app/lib/settings.test.ts` — `applyMerchantPolicy()`: toggle off blocks, AVA's discount wins, merchant max caps, default applies when AVA omits.
- `app/lib/agent-policy.test.ts` — versioned policy documents, unknown platforms synthesised to the most restrictive rule, the identity-only invariant.
- `app/lib/traffic.test.ts` — dashboard aggregation.
- `app/lib/commerce.test.ts` — checkout and order attribution.
- `app/lib/discount.test.ts` — discount minting never throws at its caller, including on a 403 from the Admin API.
- `app/lib/request-hints.test.ts` — protocol and agent labels sniffed from request headers.
- `app/lib/test-visit.test.ts`: the test agent visit, a real Ed25519 signature verified over the recomputed RFC 9421 base, the demo key still deriving the seeded public half, and every verdict recorded in the same vocabulary as the proxy path.
- `app/lib/theme-embed.test.ts`: the theme editor deep link, including the fallback when the API key is absent.
- `app/routes/app._index.test.ts`: the Settings action's auth boundary, no test visit and no settings write without `authenticate.admin`, and the shop always taken from the session.

Note that `app/routes.ts` must keep ignoring `*.test.ts`, or the flat-routes
convention turns a test file next to a route into a route and the client build
fails on its top-level await.

Polaris UI and OAuth flow aren't covered here — those need a real Shopify dev store, and the official Shopify CLI handles them.

To exercise the whole path against a real install, use the simulator in
`../scripts/simulate-verified-agent.mjs`, which signs a real request and sends
it through a store's App Proxy. `../tests/simulate-script.test.ts` keeps its
standalone signing byte-compatible with the SDK.

## What's next

- Wire the AVA Pay API at `VISA_AGENT_DIRECTORY_URL` once Visa Partners credentials are provisioned (see the root README).
- Shopify Discount Function instead of generated codes (cleaner UX on Shopify Plus).
- App Store submission prep and the WooCommerce plugin (roadmap 2.3).
