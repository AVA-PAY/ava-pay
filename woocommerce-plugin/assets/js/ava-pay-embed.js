(() => {
  // AVA Pay embed for WooCommerce — mirror of the Shopify app-proxy embed.
  // Forwards real HTTP Message Signature headers from URL params to the
  // verify endpoint, then applies any minted coupon via the Store API.
  // Every failure path is silent: never block the customer.
  if (window.__avaPayLoaded) return;
  window.__avaPayLoaded = true;

  const cfg = window.avaPayEmbed;
  if (!cfg || !cfg.endpoint) return;

  // Headers the agent's signature requires. The list is owned by PHP
  // (AVA_Pay_Frontend::SIG_PARAMS, delivered via wp_localize_script) so the
  // enqueue gate and this collection can't drift; the literal below is only
  // a fallback. Host is set automatically by the browser from
  // window.location; x-ava-mandate carries the base64 mandate. We also
  // forward any other x-* params the agent supplies (e.g. discount hints).
  const SIG_PARAMS = cfg.sigParams ||
    ['signature', 'signature-input', 'signature-agent', 'content-digest', 'x-ava-mandate'];

  const collectAgentHeaders = () => {
    const params = new URLSearchParams(window.location.search);
    const headers = {};
    let any = false;

    for (const name of SIG_PARAMS) {
      const v = params.get(name);
      if (v) { headers[name] = v; any = true; }
    }
    for (const [k, v] of params.entries()) {
      const lower = k.toLowerCase();
      if (lower.startsWith('x-') && !(lower in headers)) {
        headers[lower] = v;
        any = true;
      }
    }
    return any ? headers : null;
  };

  const applyCoupon = async (code) => {
    // Store API cart mutations need the cart nonce; a GET on the cart
    // endpoint hands it back while also establishing the cart session.
    const cartRes = await fetch(cfg.storeApiCart, { credentials: 'same-origin' });
    if (!cartRes.ok) return false;
    const nonce = cartRes.headers.get('Nonce');
    if (!nonce) return false;

    const res = await fetch(cfg.storeApiCart + '/apply-coupon', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Nonce: nonce },
      body: JSON.stringify({ code }),
    });
    return res.ok;
  };

  const apply = async () => {
    const agentHeaders = collectAgentHeaders();
    if (!agentHeaders) return;

    let res;
    try {
      // Pass the agent's signed headers AS request headers — the endpoint
      // reads them off the actual HTTP request, no JSON wrapper. The browser
      // sets Host automatically.
      res = await fetch(cfg.endpoint, {
        method: 'POST',
        credentials: 'same-origin',
        headers: agentHeaders,
        body: '',
      });
    } catch (err) {
      console.warn('[ava-pay] verify call failed', err);
      return;
    }

    if (!res.ok) return;
    const data = await res.json().catch(() => null);
    if (!data || !data.allow) return;

    if (data.discount && data.discount.code && !sessionStorage.getItem('ava_pay_applied')) {
      // Mark applied only AFTER the Store API accepts the coupon — a
      // transient failure (cache stripping the Nonce header, Store API
      // hiccup) must not permanently suppress retries for the session.
      try {
        if (await applyCoupon(data.discount.code)) {
          sessionStorage.setItem('ava_pay_applied', data.discount.code);
        }
      } catch (err) {
        console.warn('[ava-pay] coupon apply failed', err);
      }
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', apply);
  } else {
    apply();
  }
})();
