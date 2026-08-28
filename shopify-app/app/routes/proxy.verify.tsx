import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { authenticate } from '../shopify.server.js';
import { getAvaPayClient } from '../lib/ava.server.js';
import { getShopSettings } from '../lib/settings.server.js';
import { createOneTimeDiscount } from '../lib/discount.server.js';
import prisma from '../db.server.js';
import type { IncomingRequest } from '../lib/ava-types.js';
import { decideVerification, type ProxyResponseBody } from '../lib/verify-flow.js';
import { resolveVisitSource } from '../lib/storefront-visit.js';

/**
 * App Proxy endpoint:  https://{shop}.myshopify.com/apps/ava-pay/verify
 *
 * V0.2 — Real Visa TAP / RFC 9421:
 *   The agent (or the storefront embed.js on the agent's behalf) sends a
 *   request whose actual HTTP headers carry the signed payload —
 *   `Signature`, `Signature-Input`, `Content-Digest`, `Host`,
 *   `x-ava-mandate`, and anything else the agent attaches.
 *
 *   We pass that request through to AVA Pay /verify EXACTLY as we received
 *   it: no header allowlist, no JSON wrapper. The only construction we do is
 *   reconstructing the URL the agent originally signed, since by the time
 *   Shopify forwards the request to our app the Host header reflects our
 *   internal app domain rather than the storefront myshopify host.
 *
 * Failure mode unchanged: if AVA Pay is unreachable or the agent fails
 * verification, we fail closed (`allow: false`). Storefront JS treats that as
 * "no discount, proceed normally" — never blocks the customer.
 *
 * Every branch of that decision lives in `lib/verify-flow.ts` so it can be
 * tested without Shopify auth or a database; this route is I/O around it.
 */

/** Resource route: always emit a real JSON Response (no UI data serialization). */
function proxyJson(body: ProxyResponseBody, status = 200): Response {
  return Response.json(body, { status });
}

export async function loader({ request }: LoaderFunctionArgs) {
  await authenticate.public.appProxy(request);
  return Response.json({ ok: true, service: 'ava-pay-proxy' });
}

/**
 * Anything unexpected must still leave this route as fail-closed JSON. Without
 * this boundary an unhandled throw returns React Router's HTML error page,
 * which Shopify renders inside the merchant's theme as a storefront 500 — the
 * opposite of "never block the customer", and unparseable by the storefront
 * script that called us.
 */
export async function action(args: ActionFunctionArgs) {
  try {
    return await handleVerify(args);
  } catch (error) {
    // The Shopify library signals auth outcomes by throwing a Response (401s,
    // redirects). Those are control flow, not failures: let them through
    // untouched or app proxy authentication silently turns into "allow: false".
    if (error instanceof Response) throw error;

    // eslint-disable-next-line no-console
    console.error(
      JSON.stringify({
        event: 'proxy.verify.unhandled',
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      }),
    );
    return proxyJson({ allow: false, reason: 'internal_error' });
  }
}

async function handleVerify({ request }: ActionFunctionArgs) {
  const { session, admin } = await authenticate.public.appProxy(request);

  if (!session || !admin) {
    return proxyJson({ allow: false, reason: 'no_session' }, 401);
  }

  const shop = session.shop;

  // Pass-through: collect every incoming header verbatim, lower-cased so the
  // verifier on the AVA Pay side can index consistently. No allowlist.
  const headers: Record<string, string> = {};
  for (const [k, v] of request.headers.entries()) {
    headers[k.toLowerCase()] = v;
  }

  // Reconstruct the URL + Host the agent signed against. Shopify's app proxy
  // strips the storefront host as it forwards to our internal domain — but
  // the agent signed against `https://{shop}.myshopify.com/apps/ava-pay/verify`
  // and Host: {shop}.myshopify.com. We restore both so the signature base
  // recomputes correctly on the AVA Pay side.
  const signedUrl = `https://${shop}/apps/ava-pay/verify`;
  headers['host'] = shop;

  const body = await request.text();

  const incoming: IncomingRequest = {
    method: request.method,
    url: signedUrl,
    headers,
    ...(body ? { body } : {}),
  };

  const settings = await getShopSettings(shop);

  const ava = getAvaPayClient();
  const verifyCall = await ava.verify(incoming);

  const { event, response, mintDiscountPct } = decideVerification(settings, verifyCall, headers);

  // The perk is separate from the verification: a code that cannot be minted
  // leaves the verdict standing, it just comes back without a discount.
  const discount =
    response.allow && mintDiscountPct > 0
      ? await createOneTimeDiscount(admin, mintDiscountPct)
      : null;

  // Whether the merchant sent this themselves from Settings. Honoured only for
  // a marker that was inside a signature the verifier accepted, so a passing
  // visitor cannot label their own request a test; see resolveVisitSource.
  const source = resolveVisitSource(headers, verifyCall.ok && verifyCall.result.trusted);

  await prisma.verificationEvent.create({
    data: {
      shop,
      ...event,
      source,
      ...(discount ? { discountCode: discount.code } : {}),
    },
  });

  return proxyJson({
    ...response,
    ...(discount ? { discount: { code: discount.code, percentage: discount.percentage } } : {}),
  });
}
