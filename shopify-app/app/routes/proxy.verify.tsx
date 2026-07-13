import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { authenticate } from '../shopify.server.js';
import { getAvaPayClient } from '../lib/ava.server.js';
import { applyMerchantPolicy, getShopSettings } from '../lib/settings.server.js';
import { createOneTimeDiscount } from '../lib/discount.server.js';
import prisma from '../db.server.js';
import type { IncomingRequest } from '../lib/ava-types.js';

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
 */

interface ProxyResponseBody {
  allow: boolean;
  discount?: {
    code: string;
    percentage: number;
  };
  reason: string;
}

/** Resource route: always emit a real JSON Response (no UI data serialization). */
function proxyJson(body: ProxyResponseBody, status = 200): Response {
  return Response.json(body, { status });
}

export async function loader({ request }: LoaderFunctionArgs) {
  await authenticate.public.appProxy(request);
  return Response.json({ ok: true, service: 'ava-pay-proxy' });
}

export async function action({ request }: ActionFunctionArgs) {
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

  const platformHint = extractAgentIdHint(headers);

  if (!verifyCall.ok) {
    await prisma.verificationEvent.create({
      data: {
        shop,
        platform: platformHint,
        outcome: 'error',
        reason: `ava_${verifyCall.error}`,
      },
    });
    return proxyJson({ allow: false, reason: `ava_${verifyCall.error}` });
  }

  const result = verifyCall.result;

  if (!result.trusted) {
    await prisma.verificationEvent.create({
      data: {
        shop,
        platform: platformHint,
        outcome: 'failed',
        reason: result.reason,
      },
    });
    return proxyJson({ allow: false, reason: 'agent_blocked' });
  }

  const platform = result.agent?.id ?? platformHint;
  const protocol = result.protocol ?? result.agent?.protocol ?? null;

  const decision = applyMerchantPolicy(settings, result, platform);

  if (!decision.allow) {
    await prisma.verificationEvent.create({
      data: {
        shop,
        platform,
        protocol,
        outcome: 'policy_blocked',
        reason: decision.reason,
        identityOnly: !result.mandate,
      },
    });
    return proxyJson({ allow: false, reason: decision.reason });
  }

  const discount = await createOneTimeDiscount(admin, decision.discountPct);

  await prisma.verificationEvent.create({
    data: {
      shop,
      platform,
      protocol,
      outcome: 'verified',
      identityOnly: !result.mandate,
      discountPct: decision.discountPct,
      discountCode: discount?.code ?? null,
    },
  });

  return proxyJson({
    allow: true,
    reason: 'verified',
    ...(discount ? { discount: { code: discount.code, percentage: discount.percentage } } : {}),
  });
}

/**
 * Best-effort agent ID for the verification log — telemetry only; the
 * signature verifier on the API side is the authority.
 *
 * Web Bot Auth requests carry the agent operator's origin in Signature-Agent
 * (e.g. "https://chatgpt.com") — a far better dashboard label than the key
 * thumbprint in keyid, which rotates and means nothing to a merchant. TAP
 * requests have no Signature-Agent, so they keep using keyid (the agent ID).
 */
function extractAgentIdHint(headers: Record<string, string>): string | null {
  const sigAgent = headers['signature-agent'];
  if (sigAgent) {
    // Matches both wire forms: "https://origin" and sig1="https://origin".
    const m = sigAgent.match(/"(https:\/\/[^"]+)"/);
    if (m?.[1]) {
      try {
        return new URL(m[1]).origin.toLowerCase();
      } catch {
        // fall through to keyid
      }
    }
  }
  const sigInput = headers['signature-input'];
  if (!sigInput) return null;
  const match = sigInput.match(/keyid="([^"]+)"/);
  return match?.[1] ?? null;
}
