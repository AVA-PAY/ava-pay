=== AVA Pay for WooCommerce ===
Contributors: avalayer
Tags: ai agents, agentic commerce, bot verification, coupons, security
Requires at least: 6.5
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 0.1.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Verify AI shopping agents on your WooCommerce store. Know which agents to trust, set the rules, and record the traffic.

== Description ==

AI agents are already shopping your store — ChatGPT browses product pages, agentic checkouts are rolling out across the ecosystem. AVA Pay tells you which agents to trust, lets you set the rules, and records every verification and attributed order so you can see the traffic when reporting lands.

This plugin connects your WooCommerce store to the AVA Pay verification API, which cryptographically verifies agent traffic across protocols (Visa Trusted Agent Protocol, IETF Web Bot Auth, Google AP2) through a single endpoint.

**What it does**

* Adds a verify endpoint (`/wp-json/ava-pay/v1/verify-agent`) that proxies signed agent requests to the AVA Pay API — signatures are verified server-side against the agent platforms' published keys.
* Applies YOUR policy: accept/reject verified agents, per-platform allow/challenge/block rules, discount caps, and spend limits — as a portable JSON policy document.
* Optionally mints a single-use, expiring WooCommerce coupon for verified agents.
* Records every verification and every attributed order in local database tables. (This version records the data; a traffic/revenue dashboard is planned — nothing is displayed yet.)

**Trust model, honestly stated**

* Verification proves *agent identity and request integrity*. A discount is only granted beyond your identity-only tier when the request carries a buyer mandate.
* Everything fails closed: if the verification API is unreachable, agents are not admitted (and the outcome is recorded as an error).
* The plugin never blocks human shoppers. A failed agent verification means "no discount, proceed normally."

== Installation ==

1. Upload the plugin to `/wp-content/plugins/ava-pay-for-woocommerce/`, or install through the WordPress plugins screen.
2. Activate the plugin. WooCommerce must be active.
3. Go to WooCommerce → AVA Pay to review settings. The defaults work out of the box against the hosted AVA Pay API.
4. Requirements for verification to work: pretty permalinks (Settings → Permalinks, any structure other than "Plain") and an https site address — agents sign the canonical `https://…/wp-json/…` URL. The settings page warns you if either is missing.

== Frequently Asked Questions ==

= Does this slow my store down? =

No. The verify endpoint is only exercised by agent traffic, and the storefront script loads only on page views that carry agent signature parameters.

= What data leaves my site? =

Only the signed agent request (its headers and body) is forwarded to the verification API. No customer or order data is sent.

= My store is behind Cloudflare or a reverse proxy — does rate limiting still work? =

The verify endpoint is rate-limited per client IP (REMOTE_ADDR). If your host does not restore the real client IP, all traffic shares the proxy's IP and one rate-limit bucket. Preferably fix real-IP restoration at the server level (mod_remoteip / ngx_http_realip); alternatively, use the `ava_pay_client_ip` filter to supply the client IP from a header only your trusted proxy can set (e.g. CF-Connecting-IP when only Cloudflare can reach the origin).

= Can agents get discounts without my consent? =

No. Discounts are capped by your maximum, identity-only agents get 0% unless you explicitly raise the identity-only tier, and platform offers apply only to mandate-backed requests.

== Changelog ==

= 0.1.0 =
* Initial release: verify endpoint, merchant policy engine (per-platform rules), single-use coupon minting, verification + commerce event recording.
