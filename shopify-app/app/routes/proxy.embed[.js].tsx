import type { LoaderFunctionArgs } from '@remix-run/node';
import { authenticate } from '../shopify.server.js';

/**
 * Serves the storefront JS via the App Proxy at:
 *   https://{shop}.myshopify.com/apps/ava-pay/embed.js
 *
 * The script forwards a Visa Trusted Agent Protocol request from URL query
 * params into a real fetch to /apps/ava-pay/verify. The proxy receives the
 * agent's signed headers as actual HTTP headers (not wrapped in JSON), which
 * is exactly what AVA Pay's RFC 9421 verifier expects to see.
 *
 * Production note: real TAP-speaking agents do NOT need this script — they
 * call /apps/ava-pay/verify directly with their signed request. This path is
 * for storefronts where the agent has been redirected through a regular page
 * load (e.g. for testing, or for older agents that hint via URL params).
 *
 * The browser auto-sets the Host header to the storefront origin, so the
 * agent's signature over `host` matches as long as the agent was signing
 * against the merchant's myshopify.com domain.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  await authenticate.public.appProxy(request);

  const body = `(() => {
  // AVA Pay embed v0.2 — Visa TAP / RFC 9421.
  // Forwards real HTTP Message Signature headers from URL params to the proxy.
  if (window.__avaPayLoaded) return;
  window.__avaPayLoaded = true;

  // Headers the agent's TAP signature requires.
  // signature, signature-input, content-digest are the RFC 9421 trio.
  // Host is set automatically by the browser based on window.location.
  // x-ava-mandate carries the base64 mandate.
  // We also forward any other x-* params the agent supplies (e.g. discount hints).
  const SIG_PARAMS = ['signature', 'signature-input', 'content-digest', 'x-ava-mandate'];

  const collectAgentHeaders = () => {
    const params = new URLSearchParams(window.location.search);
    const headers = {};
    let any = false;

    // Named TAP parameters.
    for (const name of SIG_PARAMS) {
      const v = params.get(name);
      if (v) { headers[name] = v; any = true; }
    }
    // Any additional x-* params the agent wants forwarded.
    for (const [k, v] of params.entries()) {
      const lower = k.toLowerCase();
      if (lower.startsWith('x-') && !(lower in headers)) {
        headers[lower] = v;
        any = true;
      }
    }
    return any ? headers : null;
  };

  const apply = async () => {
    const agentHeaders = collectAgentHeaders();
    if (!agentHeaders) return;

    let res;
    try {
      // Pass the agent's signed headers AS request headers — the proxy reads
      // them off the actual HTTP request, no JSON wrapper. The browser sets
      // Host automatically.
      res = await fetch('/apps/ava-pay/verify', {
        method: 'POST',
        headers: agentHeaders,
        body: '',
      });
    } catch (err) {
      // Network blip — never block the customer.
      console.warn('[ava-pay] verify call failed', err);
      return;
    }

    if (!res.ok) return;
    const data = await res.json().catch(() => null);
    if (!data || !data.allow) return;

    if (data.discount && data.discount.code && !sessionStorage.getItem('ava_pay_applied')) {
      sessionStorage.setItem('ava_pay_applied', data.discount.code);
      const here = window.location.pathname + window.location.search;
      // Shopify's /discount/CODE endpoint applies the code and 302s back.
      window.location.href = '/discount/' + encodeURIComponent(data.discount.code) +
        '?redirect=' + encodeURIComponent(here);
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', apply);
  } else {
    apply();
  }
})();`;

  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'application/javascript; charset=utf-8',
      'cache-control': 'public, max-age=60',
    },
  });
}
