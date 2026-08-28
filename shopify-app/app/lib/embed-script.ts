/**
 * The storefront script the theme app embed loads through the App Proxy.
 *
 * Two jobs, in this order:
 *
 *   1. Forward a signed agent request. Real HTTP Message Signature headers
 *      arrive as URL parameters on a storefront page load and go back out as
 *      actual request headers to /apps/ava-pay/verify, which is exactly what
 *      the RFC 9421 verifier expects to see. Production agents speaking TAP or
 *      Web Bot Auth do not need this: they call the proxy endpoint directly.
 *      This path serves agents redirected through a normal page load, and the
 *      merchant's own "View a test agent visit on your storefront" link.
 *
 *   2. Show the shopper what happened, once, when it is worth saying. The
 *      banner is reachable from exactly one state: a trusted verdict that
 *      minted a discount code, carried across the /discount redirect that
 *      applied it. Every failure, every could-not-check verdict and every
 *      verified visit that earned no code stays silent on the storefront, so
 *      nothing the buyer reads can outrun what was actually proved.
 *
 * Constraints this file is written to, and a review will check: vanilla DOM,
 * inline styles, no dependencies, its own container at a high z-index, fixed
 * position so nothing on the page moves, a dismiss control, role="status" with
 * aria-live, idempotent on repeat loads, and no console output at all.
 *
 * It lives here rather than inline in the route so its behaviour can be read
 * and asserted on without booting an App Proxy request.
 */

/** Banner text. Deliberately free of any app or company name (5.1.4). */
export const BANNER_PREFIX = 'This AI agent visit was verified. Discount code ';
export const BANNER_SUFFIX = " was applied by this store's policy.";

/** Attribute the app embed block uses to carry its banner_enabled setting. */
export const BANNER_SETTING_ATTRIBUTE = 'data-agent-banner';

/** Container id, so a second load can tell the banner is already on the page. */
export const BANNER_ELEMENT_ID = 'ava-pay-agent-banner';

const BANNER_STYLE = [
  'position:fixed',
  'left:50%',
  'bottom:16px',
  'transform:translateX(-50%)',
  'z-index:2147483000',
  'box-sizing:border-box',
  'width:max-content',
  'max-width:calc(100vw - 32px)',
  'display:flex',
  'align-items:center',
  'gap:16px',
  'margin:0',
  'padding:12px 16px',
  'border:1px solid #d9d9d9',
  'border-radius:10px',
  'background:#ffffff',
  'color:#1a1a1a',
  'font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif',
  'font-size:14px',
  'font-weight:400',
  'line-height:1.4',
  'text-align:left',
  'box-shadow:0 4px 16px rgba(0,0,0,0.14)',
].join(';');

const DISMISS_STYLE = [
  'flex:none',
  '-webkit-appearance:none',
  'appearance:none',
  'background:none',
  'border:0',
  'margin:0',
  'padding:0',
  'color:#4a4a4a',
  'font:inherit',
  'text-decoration:underline',
  'cursor:pointer',
].join(';');

/**
 * The script body, verbatim. No template interpolation reaches the browser:
 * everything the storefront needs is either a literal here or read off the DOM
 * at run time, so nothing merchant-supplied can end up inside the source.
 */
export const EMBED_SCRIPT = `(() => {
  // AVA Pay embed v0.3 - Visa TAP / RFC 9421, plus the verification banner.
  if (window.__avaPayLoaded) return;
  window.__avaPayLoaded = true;

  // Headers the agent's signature requires. signature, signature-input and
  // content-digest are the RFC 9421 trio; signature-agent carries a Web Bot
  // Auth operator origin; x-ava-mandate carries the base64 buyer mandate. Any
  // other x-* parameter travels too, which is how the mandate and the
  // merchant's test marker get across. Host is set by the browser.
  const SIG_PARAMS = ['signature', 'signature-input', 'content-digest', 'signature-agent', 'x-ava-mandate'];
  const BANNER_ID = '${BANNER_ELEMENT_ID}';
  const PENDING_KEY = 'ava_pay_banner_pending';
  const APPLIED_KEY = 'ava_pay_applied';

  // sessionStorage throws outright under some privacy settings. Nothing here is
  // load bearing, so every access degrades to "no memory" instead of an error.
  const store = {
    get: (key) => { try { return sessionStorage.getItem(key); } catch (e) { return null; } },
    set: (key, value) => { try { sessionStorage.setItem(key, value); } catch (e) { /* no memory */ } },
    clear: (key) => { try { sessionStorage.removeItem(key); } catch (e) { /* no memory */ } },
  };

  // The merchant's App embed setting, carried on the script tag by the block.
  // No tag at all means an older block than this script: show it, which is the
  // setting's default.
  const bannerEnabled = () => {
    const tag = document.querySelector('script[${BANNER_SETTING_ATTRIBUTE}]');
    return !tag || tag.getAttribute('${BANNER_SETTING_ATTRIBUTE}') !== 'false';
  };

  const isAgentParam = (name) => SIG_PARAMS.indexOf(name) !== -1 || name.indexOf('x-') === 0;

  const collectAgentHeaders = () => {
    const params = new URLSearchParams(window.location.search);
    const headers = {};
    let any = false;
    for (const [name, value] of params.entries()) {
      const lower = name.toLowerCase();
      if (value && isAgentParam(lower) && !(lower in headers)) {
        headers[lower] = value;
        any = true;
      }
    }
    return any ? headers : null;
  };

  // Where the discount redirect lands: this page without the signed parameters.
  // They are single use, so leaving them in the address bar buys nothing but a
  // replay rejection on the next reload and a failure row on the merchant's
  // Traffic page that they would have to explain to themselves.
  const cleanTarget = () => {
    const params = new URLSearchParams(window.location.search);
    for (const name of Array.from(params.keys())) {
      if (isAgentParam(name.toLowerCase())) params.delete(name);
    }
    const query = params.toString();
    return window.location.pathname + (query ? '?' + query : '');
  };

  const showBanner = (code) => {
    if (!code || !document.body || document.getElementById(BANNER_ID)) return;

    const banner = document.createElement('div');
    banner.id = BANNER_ID;
    banner.setAttribute('role', 'status');
    banner.setAttribute('aria-live', 'polite');
    banner.style.cssText = '${BANNER_STYLE}';

    const message = document.createElement('span');
    message.textContent = ${JSON.stringify(BANNER_PREFIX)} + code + ${JSON.stringify(BANNER_SUFFIX)};

    const dismiss = document.createElement('button');
    dismiss.type = 'button';
    dismiss.textContent = 'Dismiss';
    dismiss.setAttribute('aria-label', 'Dismiss this message');
    dismiss.style.cssText = '${DISMISS_STYLE}';
    dismiss.addEventListener('click', () => { banner.remove(); });

    banner.appendChild(message);
    banner.appendChild(dismiss);
    document.body.appendChild(banner);
  };

  const apply = async () => {
    // Second half of a discount redirect. The verdict already happened, on the
    // load before this one, and the code below is the one Shopify just applied.
    const pending = store.get(PENDING_KEY);
    if (pending) {
      store.clear(PENDING_KEY);
      if (bannerEnabled()) showBanner(pending);
      return;
    }

    const agentHeaders = collectAgentHeaders();
    if (!agentHeaders) return;

    let res;
    try {
      // The agent's signed headers go out as request headers, no JSON wrapper.
      res = await fetch('/apps/ava-pay/verify', {
        method: 'POST',
        headers: agentHeaders,
        body: '',
      });
    } catch (e) {
      // Network blip. Never block the customer, and never shout about it.
      return;
    }

    if (!res.ok) return;
    const data = await res.json().catch(() => null);
    if (!data || !data.allow) return;

    const code = data.discount && data.discount.code;
    if (!code || store.get(APPLIED_KEY)) return;

    store.set(APPLIED_KEY, code);
    if (bannerEnabled()) store.set(PENDING_KEY, code);

    // Shopify's /discount/CODE endpoint applies the code and 302s back.
    window.location.href = '/discount/' + encodeURIComponent(code) +
      '?redirect=' + encodeURIComponent(cleanTarget());
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', apply);
  } else {
    apply();
  }
})();`;
