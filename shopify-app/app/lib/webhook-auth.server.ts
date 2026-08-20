import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * Webhook authentication that survives a dead offline session.
 *
 * `authenticate.webhook` validates the webhook HMAC first, then loads the
 * shop's offline session and, with `future.expiringOfflineAccessTokens` on,
 * refreshes the token when it is at or past expiry
 * (@shopify/shopify-app-react-router dist/esm/server/helpers/
 * ensure-offline-token-is-not-expired.mjs). For a shop that has uninstalled,
 * the stored token can never be refreshed, and the library converts the
 * refresh failure into a thrown `Response` with status 500
 * (dist/esm/server/helpers/refresh-token.mjs). React Router returns a thrown
 * Response as-is, so the webhook fails with a bare 500, Shopify retries, the
 * stale Session row is still there, and every retry fails the same way. This
 * hit every app/uninstalled and shop/redact delivery in production for shops
 * that still had a Session row.
 *
 * Webhooks are authenticated by HMAC, not by the shop's access token, so a
 * dead session must never fail one. The wrapper below lets the library's own
 * request rejections (401 invalid HMAC, 400 bad headers, 405 wrong method)
 * pass through untouched, and only when the library fails AFTER validation,
 * in its session load/refresh plumbing, falls back to a session-less webhook
 * context. The fallback independently re-verifies the HMAC with the app
 * secret before trusting anything, so this cannot weaken authentication no
 * matter what the library threw.
 */

/** The context shape the fallback produces: everything but session/admin. */
export interface SessionlessWebhookContext {
  apiVersion: string;
  shop: string;
  topic: string;
  webhookId: string;
  subTopic?: string;
  payload: unknown;
  session: undefined;
  admin: undefined;
}

type LibWebhookContext = Awaited<
  ReturnType<(typeof import('../shopify.server.js'))['authenticate']['webhook']>
>;

export type WebhookAuthContext = LibWebhookContext | SessionlessWebhookContext;

/** Constant-time comparison of the webhook HMAC header against the raw body. */
export function webhookHmacMatches(
  rawBody: string,
  hmacHeader: string,
  apiSecret: string,
): boolean {
  const expected = createHmac('sha256', apiSecret).update(rawBody, 'utf8').digest();
  const provided = Buffer.from(hmacHeader, 'base64');
  return expected.length === provided.length && timingSafeEqual(expected, provided);
}

/**
 * Build a webhook context from the request alone, verifying the HMAC with the
 * app secret exactly as Shopify computes it (SHA-256 over the raw body,
 * base64). Throws 401 on a bad or missing HMAC and 400 on missing headers,
 * mirroring the library. The topic is normalized the same way the library
 * stores it (app/uninstalled becomes APP_UNINSTALLED).
 */
export function buildSessionlessWebhookContext(
  rawBody: string,
  headers: Headers,
  apiSecret: string,
): SessionlessWebhookContext {
  if (!apiSecret) {
    // No secret means nothing can be verified. Fail closed.
    throw new Response(undefined, { status: 500, statusText: 'Internal Server Error' });
  }
  const hmacHeader = headers.get('x-shopify-hmac-sha256');
  if (!hmacHeader || !webhookHmacMatches(rawBody, hmacHeader, apiSecret)) {
    throw new Response(undefined, { status: 401, statusText: 'Unauthorized' });
  }
  const shop = headers.get('x-shopify-shop-domain');
  const topic = headers.get('x-shopify-topic');
  const webhookId = headers.get('x-shopify-webhook-id');
  const apiVersion = headers.get('x-shopify-api-version');
  if (!shop || !topic || !webhookId || !apiVersion) {
    throw new Response(undefined, { status: 400, statusText: 'Bad Request' });
  }
  return {
    apiVersion,
    shop,
    topic: topic.toUpperCase().replace(/\/|\./g, '_'),
    webhookId,
    subTopic: headers.get('x-shopify-sub-topic') ?? undefined,
    payload: JSON.parse(rawBody) as unknown,
    session: undefined,
    admin: undefined,
  };
}

/**
 * Run the library authenticator; on a post-validation failure, fall back to
 * the HMAC-verified session-less context. Exported separately so tests can
 * inject a real library instance with test credentials.
 */
export async function authenticateWebhookWith(
  webhookAuthenticate: (request: Request) => Promise<LibWebhookContext>,
  request: Request,
  apiSecret: string,
): Promise<WebhookAuthContext> {
  // Clone before the library consumes the body.
  const fallbackRequest = request.clone();
  try {
    return await webhookAuthenticate(request);
  } catch (error) {
    if (error instanceof Response && error.status < 500) {
      // The library rejecting the request itself: 401 invalid HMAC, 400
      // missing headers, 405 non-POST. Never soften these.
      throw error;
    }
    // Anything else escaped from the session load/refresh plumbing, which
    // only runs after the library's HMAC validation passed. Log it, then
    // process the webhook session-less behind our own HMAC check.
    console.error(
      JSON.stringify({
        event: 'webhook.session_auth_failed',
        message:
          'authenticate.webhook failed after HMAC validation; continuing with an HMAC-verified session-less context',
        status: error instanceof Response ? error.status : null,
        error: error instanceof Response ? error.statusText : String(error),
        ts: new Date().toISOString(),
      }),
    );
    const rawBody = await fallbackRequest.text();
    return buildSessionlessWebhookContext(rawBody, fallbackRequest.headers, apiSecret);
  }
}

/** What the webhook routes call in place of authenticate.webhook. */
export async function authenticateWebhookRequest(
  request: Request,
): Promise<WebhookAuthContext> {
  // Imported lazily so tests can load this module without the production
  // Shopify app instance (which needs env vars and a database) coming along.
  const { authenticate } = await import('../shopify.server.js');
  return authenticateWebhookWith(
    (req) => authenticate.webhook(req),
    request,
    process.env.SHOPIFY_API_SECRET ?? '',
  );
}
