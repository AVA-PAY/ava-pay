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
 *   2. Show the shopper what happened, when it is worth saying. The banner is
 *      reachable from exactly one state: a trusted verdict that minted a
 *      discount code. Every failure, every could-not-check verdict and every
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

/**
 * How the banner survives an unknown number of documents.
 *
 * Observed live on a test store, and still true after the banner was moved out
 * of the body and given a MutationObserver: it appears and is gone a fraction
 * of a second later. That combination rules out removal. An observer that
 * re-appends on removal cannot lose to a removal, and the element is parented
 * where a body diff does not reach. So the banner is not being taken off the
 * page; the page is being replaced under it. Something navigates the document
 * again after the discount redirect lands, market or locale redirection being
 * the ordinary cause and the preview environment re-attaching another. The
 * banner went with the document that was discarded, and the state it was drawn
 * from had already been consumed by the load that drew it, so the document that
 * arrived next had nothing to draw.
 *
 * The state is therefore a window rather than a one-shot key. A trusted verdict
 * that mints a code opens it; every document loaded while it is open shows the
 * banner; showing does not close it. It closes when the shopper dismisses the
 * banner, or when it expires. That survives one redirect or five without
 * knowing in advance how many there will be.
 *
 * Sixty seconds is sized for a redirect chain and nothing longer: several
 * server round trips have room, and a shopper who is still browsing a minute
 * later has left the visit that earned the code well behind.
 */
export const BANNER_WINDOW_MS = 60_000;

/**
 * sessionStorage keys the window lives in. Exported so the tests and a
 * merchant reading their own session can name the same things this does.
 *
 * The state entry is JSON: the minted `code`, the `expires` timestamp, and
 * `navigations`, a count of the documents that have shown the banner. The
 * count is the cheap diagnostic for exactly the failure above. If this comes
 * back again, that number says how many documents the banner had to survive,
 * which is the fact nobody could read off the page while it was flickering.
 */
export const BANNER_STATE_KEY = 'ava_pay_banner';
export const BANNER_DISMISSED_KEY = 'ava_pay_banner_dismissed';

/**
 * Belt and braces from the load before this one, kept because the diagnosis
 * changed rather than because it was wrong.
 *
 *   1. The banner is appended to document.documentElement, not to the body.
 *      Morph runtimes diff the body and the section markup inside it, so an
 *      element parented outside the body is outside their scope entirely.
 *      A fixed-position element lays out identically from there.
 *   2. Whatever removals still reach it are answered by a MutationObserver
 *      rather than by polling. It watches childList on both the document
 *      element and the body, for the life of the page rather than for a window
 *      of it, and puts our held element back whenever it finds it disconnected.
 *
 * The cap is the stop against a theme that removes the banner as fast as we can
 * put it back: far more restores than a settling re-render needs, and far short
 * of a loop worth leaving running. Past it we concede the page.
 */
export const BANNER_RESTORE_LIMIT = 50;

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
  // AVA Pay embed v0.4 - Visa TAP / RFC 9421, plus the verification banner.
  if (window.__avaPayLoaded) return;
  window.__avaPayLoaded = true;

  // Headers the agent's signature requires. signature, signature-input and
  // content-digest are the RFC 9421 trio; signature-agent carries a Web Bot
  // Auth operator origin; x-ava-mandate carries the base64 buyer mandate. Any
  // other x-* parameter travels too, which is how the mandate and the
  // merchant's test marker get across. Host is set by the browser.
  const SIG_PARAMS = ['signature', 'signature-input', 'content-digest', 'signature-agent', 'x-ava-mandate'];
  const BANNER_ID = '${BANNER_ELEMENT_ID}';
  const STATE_KEY = '${BANNER_STATE_KEY}';
  const DISMISSED_KEY = '${BANNER_DISMISSED_KEY}';
  const APPLIED_KEY = 'ava_pay_applied';
  const WINDOW_MS = ${BANNER_WINDOW_MS};

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

  // The open window, or null. Anything malformed, expired, or dismissed is
  // nothing to show, and a state entry that will never be shown again is
  // cleared here rather than left to sit out the session.
  const readWindow = () => {
    if (store.get(DISMISSED_KEY)) return null;
    const raw = store.get(STATE_KEY);
    if (!raw) return null;
    let entry = null;
    try { entry = JSON.parse(raw); } catch (e) { entry = null; }
    const usable = entry && typeof entry.code === 'string' && entry.code &&
      typeof entry.expires === 'number' && entry.expires > Date.now();
    if (!usable) { store.clear(STATE_KEY); return null; }
    return entry;
  };

  // The one place a code is ever written to storage, reached only after
  // data.allow and a minted code. Nothing else in this script can put a code
  // where a later document would read one.
  const openBannerWindow = (code) => {
    // A fresh verdict is a fresh window: the two keys never disagree.
    store.clear(DISMISSED_KEY);
    store.set(STATE_KEY, JSON.stringify({ code: code, expires: Date.now() + WINDOW_MS, navigations: 0 }));
  };

  // How many documents the banner has had to survive. Rebuilt from the entry
  // just read, field by field, so the count cannot smuggle in anything else and
  // the window is neither extended nor closed by having been shown.
  const countNavigation = (entry) => {
    const seen = typeof entry.navigations === 'number' ? entry.navigations : 0;
    store.set(STATE_KEY, JSON.stringify({
      code: entry.code,
      expires: entry.expires,
      navigations: seen + 1,
    }));
  };

  // What the banner is showing, once it has shown. Held here so a restore does
  // not have to go back to storage: this is the code from the one verdict that
  // produced it, and putting the same element back is not a second claim.
  let bannerCode = null;
  let bannerElement = null;
  let bannerDismissed = false;
  let bannerObserver = null;
  let bannerRestores = 0;

  const stopBannerGuard = () => {
    if (bannerObserver !== null) {
      bannerObserver.disconnect();
      bannerObserver = null;
    }
  };

  // Put the element back if the theme took it out, at the document element so
  // a re-render of the body cannot carry it away again. Never a second banner:
  // an element already carrying our id, ours or a copy the theme made of it, is
  // left alone. At the cap we stop watching rather than keep trading removals
  // with a theme that has made its position clear.
  //
  // The observer is the only caller, and dismissing disconnects it for good, so
  // there is no second flag to keep in step here: a dismissed banner is never a
  // candidate to restore because nothing is left watching for its removal.
  const restoreBanner = () => {
    if (!bannerElement) return;
    if (bannerElement.isConnected || document.getElementById(BANNER_ID)) return;
    if (bannerRestores >= ${BANNER_RESTORE_LIMIT}) { stopBannerGuard(); return; }
    bannerRestores += 1;
    document.documentElement.appendChild(bannerElement);
  };

  // Watch for the removal instead of polling for one. childList on the two
  // parents our element can be taken out of is the whole of what we need to
  // see, and it costs nothing on a page that never removes it. A browser
  // without MutationObserver simply gets the banner without the guard.
  const startBannerGuard = () => {
    stopBannerGuard();
    if (typeof MutationObserver !== 'function') return;
    bannerObserver = new MutationObserver(restoreBanner);
    bannerObserver.observe(document.documentElement, { childList: true });
    if (document.body) bannerObserver.observe(document.body, { childList: true });
  };

  const showBanner = (code) => {
    if (!code || bannerDismissed) return;
    if (document.getElementById(BANNER_ID)) return;

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
    // Dismissed is final, and final now outlives the document: the window is
    // closed in storage as well as on the page, so the next document in the
    // chain has nothing to draw either.
    dismiss.addEventListener('click', () => {
      bannerDismissed = true;
      store.set(DISMISSED_KEY, '1');
      store.clear(STATE_KEY);
      stopBannerGuard();
      banner.remove();
    });

    banner.appendChild(message);
    banner.appendChild(dismiss);
    document.documentElement.appendChild(banner);

    bannerCode = code;
    bannerElement = banner;
    startBannerGuard();
  };

  // A bfcache restore replays the page from a snapshot instead of loading it,
  // so nothing in this script runs again and any guard that was running is
  // gone. Re-show from the held code, which showBanner will decline if the
  // restored snapshot still has the banner in it. This is the same document
  // coming back, not a new one, so it is not a navigation to count.
  window.addEventListener('pageshow', () => {
    if (bannerDismissed || !bannerCode) return;
    showBanner(bannerCode);
  });

  const apply = async () => {
    // A window an earlier verdict opened. Whichever document this is, the
    // discount landing or a market or locale redirect after it, the banner
    // belongs on it, and drawing it here does not use the window up.
    const live = readWindow();
    if (live && bannerEnabled()) {
      countNavigation(live);
      showBanner(live.code);
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
    if (bannerEnabled()) openBannerWindow(code);

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
