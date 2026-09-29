=== AVA Pay for WooCommerce ===
Contributors: avalayer
Tags: ai agents, agentic commerce, bot verification, coupons, security
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.4.1
License: MIT
License URI: https://opensource.org/licenses/MIT

Verify AI shopping agents on your WooCommerce store. Know which agents to trust, set the rules, and record the traffic.

== Description ==

AI agents are already shopping your store. ChatGPT browses product pages, agentic checkouts are rolling out across the ecosystem. AVA Pay tells you which agents to trust, lets you set the rules, and records every verification and attributed order so you can see the traffic when reporting lands.

This plugin connects your WooCommerce store to the AVA Pay verification API, which cryptographically verifies agent traffic across protocols (Visa Trusted Agent Protocol, IETF Web Bot Auth, Google AP2) through a single endpoint.

**What it does**

* Adds a verify endpoint (`/wp-json/ava-pay/v1/verify-agent`) that proxies signed agent requests to the AVA Pay API. Signatures are verified server-side against the agent platforms' published keys.
* Applies YOUR policy: accept/reject verified agents, per-platform allow/challenge/block rules, discount caps, and spend limits, kept as a portable JSON policy document.
* Optionally mints a single-use, expiring WooCommerce coupon for verified agents.
* Shows signed AI agent visits to your store. When an AI agent loads a page with its requests signed (ChatGPT's agent does; most crawlers do not), the plugin checks the signature with the AVA Pay API after the page has been sent and lists the result under WooCommerce, Agent visits: counts for the last 7 and 30 days by agent platform and outcome, and the last 50 visits. This only observes: a page view is never blocked, redirected or given a coupon because of it. You can turn it off in the settings.
* Records every verification and every attributed order in local database tables. (Agent page visits are shown as above; a traffic and revenue dashboard for the verify endpoint and orders is planned, and that data is not displayed yet.)

**Trust model, honestly stated**

* Verification proves *agent identity and request integrity*. A discount is only granted beyond your identity-only tier when the request carries a buyer mandate.
* Everything fails closed: if the verification API is unreachable, agents are not admitted (and the outcome is recorded as an error).
* We do not claim to have blocked an agent we never managed to check. When the verification API cannot reach an agent's trust root, the request is still not admitted, but it is recorded as `unverifiable` rather than as a rejection, and the storefront response says `verification_unavailable` instead of `agent_blocked`.
* The plugin never blocks human shoppers. A failed agent verification means "no discount, proceed normally."

== Installation ==

1. Upload the plugin to `/wp-content/plugins/ava-pay-for-woocommerce/`, or install through the WordPress plugins screen.
2. Activate the plugin. WooCommerce must be active.
3. Go to WooCommerce → AVA Pay to review settings. The defaults work out of the box against the hosted AVA Pay API.
4. Requirements for verification to work: pretty permalinks (Settings → Permalinks, any structure other than "Plain") and an https site address, because agents sign the canonical `https://…/wp-json/…` URL. The settings page warns you if either is missing.

== Frequently Asked Questions ==

= Does this slow my store down? =

Not for human shoppers: a page view without agent signature headers costs one check and nothing else. The verify endpoint is only exercised by agent traffic, and the storefront script loads only on page views that carry agent signature parameters.

For a page view that does carry agent signature headers, the check runs after the page has been generated. On PHP-FPM and LiteSpeed hosts (most hosting) the response is finished first, so the agent is not kept waiting. On other server setups, such as Apache with mod_php, the page has been sent but the connection can stay open for up to about 2 seconds while the check completes. Only one check runs at a time for the whole site, checks are capped per agent and per site (see the question below), and you can turn them off in the settings.

= What data leaves my site? =

Only agent requests are forwarded to the verification API: a request that reached the verify endpoint, and a page view that carried agent signature headers. For each, the plugin sends its method, its URL, its body if it has one (a page view has none), and the headers verification needs (the agent's signature headers, the headers that signature covers, and the protocol headers the verifier reads). Cookies, credentials, and other request headers are not forwarded. No customer, order, or session data is sent. See External services below for the full detail.

= My store is behind Cloudflare or a reverse proxy. Does rate limiting still work? =

The verify endpoint is rate-limited per client IP (REMOTE_ADDR). If your host does not restore the real client IP, all traffic shares the proxy's IP and one rate-limit bucket. Preferably fix real-IP restoration at the server level (mod_remoteip / ngx_http_realip); alternatively, use the `ava_pay_client_ip` filter to supply the client IP from a header only your trusted proxy can set (e.g. CF-Connecting-IP when only Cloudflare can reach the origin).

= I have enabled full-page caching. Will I see agent visits? =

Only for pages that are not served from the cache. A cached page is sent by your host or caching plugin without running WordPress or PHP, so the plugin never sees that visit and it is not shown under Agent visits. A cache that varies on, or bypasses for, the Signature header lets those visits through; most caches do neither by default.

= Why don't I see any agent visits? =

Check these, in this order:

1. Coming soon mode. While WooCommerce's Coming soon mode is on, everyone except store managers, AI agents and logged-in customers included, sees a placeholder page instead of your store pages (or your whole site, depending on the setting). You see the store normally because you are a store manager. Agents that visit are still listed under Agent visits, but they see the placeholder, not your products, so they cannot browse on to them. The AVA Pay settings page and the Agent visits screen warn you while it is on. To go live, open WooCommerce, Settings, Site visibility, choose Live and save. AVA Pay never changes this setting for you.
2. The site must be publicly reachable. An AI agent cannot visit a local development site, or a site behind a password or a maintenance page.
3. Full-page caching. Visits to cached pages never reach the plugin; see "I have enabled full-page caching. Will I see agent visits?" above.
4. Most AI crawlers do not sign their requests, so they cannot be verified and are not listed. ChatGPT's agent does sign its requests.
5. To try it, ask ChatGPT to open one of your product pages by its full address, then reload WooCommerce, Agent visits.

= How many agent visits are checked? =

Up to 30 a minute and 2,000 a day for each agent, and up to 20 a minute and 2,000 a day for the whole site, one at a time. A visit is also skipped while another check is running, and an agent whose last check could not be completed (the verification service or the agent's key directory did not answer) is skipped for 10 minutes. Skipped visits are not listed; they are counted as "Not checked" under Agent visits, with the reason. Each check waits at most 2 seconds for the verification service. Developers can change the numbers with the `ava_pay_page_visit_agent_per_minute`, `ava_pay_page_visit_agent_per_day`, `ava_pay_page_visit_site_per_minute`, `ava_pay_page_visit_site_per_day`, `ava_pay_page_visit_timeout` and `ava_pay_page_visit_backoff_seconds` filters.

= How long are agent visits kept? =

90 days. A daily scheduled task deletes older agent visit records (only those; verification and order records used for coupon attribution are not touched). Developers can change the period with the `ava_pay_page_visit_retention_days` filter. Deactivating or deleting the plugin removes the scheduled task.

= Can agents get discounts without my consent? =

No. Discounts are capped by your maximum, identity-only agents get 0% unless you explicitly raise the identity-only tier, and platform offers apply only to mandate-backed requests.

== Screenshots ==

1. The AVA Pay settings page under WooCommerce: API URL, verified-agent admission, discount tiers, and the per-platform policy document.

== External services ==

This plugin connects to the AVA Pay verification API, operated by Agentic Verification Architecture LLC, to check whether an AI agent's signed request is genuine. Your store cannot verify agent signatures on its own; this API does the cryptographic check against the agent platforms' published keys.

* **Service:** AVA Pay verification API. The plugin sends `POST https://pay.avalayer.com/verify`. The base URL is the "AVA Pay API URL" setting (default `https://pay.avalayer.com`) and can also be changed with the `ava_pay_api_url` filter.
* **When data is sent:** in two cases. (1) When a request is POSTed to the plugin's verify endpoint, `/wp-json/ava-pay/v1/verify-agent`, and passes the local rate limit. That endpoint is how signed agent requests reach the plugin, either directly from the agent or from the storefront script on a page view that carries agent signature parameters. (2) When a front-end page request (GET or HEAD) carries agent signature headers (`Signature` and `Signature-Input`), the "Verify signed AI agent page visits" setting is on, and the visit is not skipped (checks run one at a time, within a per-agent and per-site budget, and an agent whose last check could not complete is paused for 10 minutes); this happens after the page has been sent. The plugin forwards each such request, with only the headers listed below, and lets the API decide; a request without valid signature material is rejected there. Nothing is sent for page views without agent signature headers, in the admin, or during checkout.
* **What is sent:** the incoming request's HTTP method; the URL, which for the verify endpoint is its canonical URL built from your site's own address rather than from the incoming request, and for a page visit is the page's URL as the agent requested it (the `Host` header it sent plus the path and query string); only the request headers verification needs, which are `Signature`, `Signature-Input` and `Signature-Agent`, every header the agent's signature names as covered, the protocol headers the verifier reads by name (`X-Ava-Mandate`, `X-Ava-Discount-Hint`, the AP2 mandate headers, `Content-Digest`, and `Content-Type` when there is a body), and `Host`, replaced by your site's own host on the verify endpoint and sent as received for a page visit; and the request body, if there is one (a page visit has none). Every other header is dropped before the request leaves your site, including `X-Forwarded-For` and `User-Agent` (unless the agent's signature covers it). `Cookie`, `Authorization`, `Proxy-Authorization` and `X-WP-Nonce` are never forwarded, even when the agent's signature covers them.
* **What is not sent:** no customer, order, or session data. No cookies, no logged-in user information, no cart contents, no visitor IP address, and no store settings or policy.

Terms of service: https://avalayer.com/terms
Privacy policy: https://avalayer.com/privacy

== Changelog ==

= 0.4.1 =
* Security hardening: verdicts from AVA Pay's public demo agent (the credential behind the landing-page demo, whose signing key is published on purpose) never create a coupon, whatever your discount settings, per-platform rules or identity-only percentage say. The verification API already refuses such verdicts a buyer mandate; this release adds the plugin's own check on top. Demo verify requests are recorded as test visits, and demo page visits are marked `demo_agent` on the Agent visits screen. The verify endpoint's answer to a demo request now includes `"demo": true`.
* New: while WooCommerce's Coming soon mode hides your store, the AVA Pay settings page and the Agent visits screen say so, say which pages agents cannot see, and link to WooCommerce's Site visibility settings. The plugin only tells you; it never changes your store's visibility. Nothing is shown on other admin screens.
* The Agent visits screen, before the first visit, now explains how to try it with ChatGPT, and that the store must be live and publicly reachable.

= 0.4.0 =
* New: Agent visits (WooCommerce, Agent visits). When an AI agent loads a page with signed requests, the plugin checks the signature with the AVA Pay API after the page has been sent and shows the result: counts for the last 7 and 30 days by agent platform and outcome (verified, failed, unverifiable, error, not checked), and the last 50 visits with time, platform, outcome, reason and path. The page view itself is never blocked, redirected or given a coupon.
* New setting: "Verify signed AI agent page visits", on by default.
* Page-visit checks run one at a time per site, wait at most 2 seconds for the verification service, and are capped at 30 a minute and 2,000 a day per agent and 20 a minute and 2,000 a day per site. An agent whose last check could not complete is skipped for 10 minutes. All of these are adjustable with filters. Skipped visits are counted as not checked, with the reason, instead of being sent.
* Agent visit records are deleted after 90 days by a daily scheduled task.
* The verification events table gains two columns: `source` (whether a row came from the verify endpoint or a page visit; existing rows are marked as verify endpoint) and `path` (the page path, with the query string removed). No IP address, user agent or header values are stored.

= 0.3.0 =
* Less data leaves your site. When the plugin asks the verification service to check an agent request, it now sends only what verification needs: the agent's signature headers, the headers that signature covers, the protocol headers verification reads, and your site's own host. Every other header is dropped, including `X-Forwarded-For` and `User-Agent` unless the agent's signature covers them. Cookies and credentials are never sent, even when an agent's signature names them (such a request fails verification).
* A discount is recorded on a verification event only when a coupon was actually created. If creating the coupon fails, the verification result stands, no discount is recorded, and one line is written to the PHP error log.

= 0.2.0 =
* Honest verdicts: a verification the API could not complete (an unreachable agent directory or key source) is no longer reported as a blocked agent. It is recorded with the new `unverifiable` outcome and answers the storefront with `verification_unavailable`. Fail-closed behaviour is unchanged: such a request is still not admitted.
* Verification events now record which protocol a request was attempting, so failed and unverifiable rows can be told apart.
* The verify endpoint now returns fail-closed JSON instead of a PHP error page if anything unexpected throws.

= 0.1.0 =
* Initial release: verify endpoint, merchant policy engine (per-platform rules), single-use coupon minting, verification + commerce event recording.

== Upgrade Notice ==

= 0.4.1 =
Demo agent visits never create a coupon, and the plugin now tells you when Coming soon mode hides your store from AI agents.

= 0.4.0 =
Shows signed AI agent visits to your store.

= 0.3.0 =
Sends less data to the verification service: only the headers verification needs, never cookies or credentials. Recommended for all sites.
