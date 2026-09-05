# AVA Pay for WooCommerce (developer notes)

Merchant-facing documentation lives in `readme.txt` (the WordPress.org
format). This file is for people working on the plugin.

## Layout

- `includes/core/` is pure PHP with no WordPress dependencies. All decision
  logic lives here, ported from `shopify-app/app/lib/policy.ts`,
  `agent-policy.ts` and the `proxy.verify.tsx` orchestration. Parity with the
  TypeScript is enforced by a generated golden file, so change the TypeScript
  first, regenerate, then port.
- Everything else in `includes/` is thin I/O: the REST controller, dbDelta
  storage, `WC_Coupon` minting, the settings screen, the storefront embed.

## Unit tests

```bash
composer install
./vendor/bin/phpunit
```

`tests/bootstrap.php` loads only `includes/core/*`. The WordPress and
WooCommerce integration layer is not covered here; exercise it in wp-env
(below).

Regenerate the parity fixtures after any change to the Shopify policy code:

```bash
npx tsx scripts/generate-policy-golden.ts
npx tsx scripts/generate-verify-fixtures.ts
```

## QUICKSTART: running the plugin in real WordPress

`.wp-env.json` in this directory brings up WordPress plus WooCommerce with
the working tree mounted as a live plugin, so edits take effect on the next
request with no rebuild. It needs Docker Desktop running.

```bash
cd woocommerce-plugin
npx @wordpress/env start        # http://localhost:8888, admin / password
npx @wordpress/env stop
npx @wordpress/env destroy      # wipes the database and starts over
```

WooCommerce is listed before `"."` in `.wp-env.json` on purpose. The plugin
header declares `Requires Plugins: woocommerce`, so WordPress refuses to
activate it while WooCommerce is inactive, and wp-env activates the list in
order.

Run WP-CLI against the running site:

```bash
npx @wordpress/env run cli -- wp plugin list
npx @wordpress/env run cli -- wp db query "SELECT * FROM wp_ava_pay_verification_events"
```

The plugin directory is mounted read-write from your working tree. Do **not**
run `wp plugin uninstall` without `--skip-delete`: WP-CLI would delete the
mounted directory, which is your checkout.

```bash
npx @wordpress/env run cli -- wp plugin uninstall woocommerce-plugin --skip-delete
```

Debug output goes to `wp-content/debug.log` inside the container
(`WP_DEBUG_LOG` is on, `WP_DEBUG_DISPLAY` is off, matching production):

```bash
npx @wordpress/env run cli -- wp eval 'echo WP_CONTENT_DIR;'
docker exec $(docker ps -qf name=wordpress) cat /var/www/html/wp-content/debug.log
```

### Things to know when testing locally

- **The site is http, so it is not signable.** `GET /wp-json/ava-pay/v1/verify-agent`
  reports `{"signable": false, "problems": ["not_https"]}` and the settings
  screen shows the matching error notice. That is correct: agents sign the
  canonical `https://.../wp-json/...` URL. Verification still works end to end
  locally, because the plugin presents whatever `rest_url()` returns and an
  agent that signs that same URL matches.
- **The plugin slug is the directory name.** Mounted from this checkout it is
  `woocommerce-plugin`, not the `ava-pay-for-woocommerce` a WordPress.org
  release would use. Anything that hardcodes the slug (asset URLs in page
  source, WP-CLI commands) differs from a released install.
- **Uninstall keeps minted coupons.** They are ordinary store records that
  completed orders reference by code. Tables, options and rate-limit
  transients are removed.

### Sending a signed request

`scripts/simulate-verified-agent.mjs` at the repo root targets Shopify App
Proxy URLs, not this route. To exercise the WooCommerce endpoint, sign against
the URL the plugin itself presents:

```
POST http://localhost:8888/wp-json/ava-pay/v1/verify-agent
```

The signature base must cover that exact `@target-uri` and a `host` of
`localhost:8888`, because the REST controller rebuilds both from `rest_url()`
and never from the incoming `Host` header. Send the agent's signed values as
real HTTP headers; there is no JSON wrapper.
