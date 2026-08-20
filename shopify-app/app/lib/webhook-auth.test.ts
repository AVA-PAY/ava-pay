/**
 * The webhook session-failure fallback, in isolation.
 *
 * Production context: for a shop that uninstalled but still had a Session
 * row, authenticate.webhook validated the HMAC, then tried to refresh the
 * shop's expired offline token, and the library turned the refusal into a
 * thrown Response(500) with no stack trace. Every app/uninstalled and
 * shop/redact retry for Shopify's review stores failed that way. These tests
 * pin the wrapper's contract: library request rejections pass through
 * untouched, session plumbing failures fall back to a context that is only
 * produced after an independent HMAC check with real crypto.
 */

import { describe, expect, it } from 'vitest';
import { createHmac } from 'node:crypto';
import {
  authenticateWebhookWith,
  buildSessionlessWebhookContext,
  webhookHmacMatches,
} from './webhook-auth.server.js';

const SECRET = 'unit-test-webhook-secret';
const SHOP = 'gone.myshopify.com';

function sign(body: string, secret: string): string {
  return createHmac('sha256', secret).update(body, 'utf8').digest('base64');
}

function webhookRequest({
  body = JSON.stringify({ id: 12345, domain: SHOP }),
  secret = SECRET,
  topic = 'app/uninstalled',
  overrides = {},
}: {
  body?: string;
  secret?: string;
  topic?: string;
  overrides?: Record<string, string | null>;
} = {}): Request {
  const headers = new Headers({
    'Content-Type': 'application/json',
    'X-Shopify-Topic': topic,
    'X-Shopify-Shop-Domain': SHOP,
    'X-Shopify-Hmac-SHA256': sign(body, secret),
    'X-Shopify-API-Version': '2026-01',
    'X-Shopify-Webhook-Id': 'a5e2f2f6-0000-4000-8000-000000000001',
  });
  for (const [name, value] of Object.entries(overrides)) {
    if (value === null) headers.delete(name);
    else headers.set(name, value);
  }
  return new Request('https://app.example.com/webhooks/app/uninstalled', {
    method: 'POST',
    headers,
    body,
  });
}

async function caughtResponse(promise: Promise<unknown>): Promise<Response> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof Response) return error;
    throw error;
  }
  throw new Error('expected a thrown Response');
}

describe('webhookHmacMatches', () => {
  const body = '{"id":1}';

  it('accepts the digest Shopify would compute', () => {
    expect(webhookHmacMatches(body, sign(body, SECRET), SECRET)).toBe(true);
  });

  it('rejects a digest signed with another secret', () => {
    expect(webhookHmacMatches(body, sign(body, 'other-secret'), SECRET)).toBe(false);
  });

  it('rejects a digest over a different body', () => {
    expect(webhookHmacMatches(body, sign('{"id":2}', SECRET), SECRET)).toBe(false);
  });

  it('rejects a truncated header without throwing', () => {
    expect(webhookHmacMatches(body, sign(body, SECRET).slice(0, 10), SECRET)).toBe(false);
  });
});

describe('buildSessionlessWebhookContext', () => {
  const body = JSON.stringify({ id: 12345, domain: SHOP });

  it('returns a session-less context for a validly signed request', () => {
    const request = webhookRequest({ body });
    const context = buildSessionlessWebhookContext(body, request.headers, SECRET);
    expect(context.shop).toBe(SHOP);
    expect(context.topic).toBe('APP_UNINSTALLED');
    expect(context.apiVersion).toBe('2026-01');
    expect(context.webhookId).toBe('a5e2f2f6-0000-4000-8000-000000000001');
    expect(context.payload).toEqual({ id: 12345, domain: SHOP });
    expect(context.session).toBeUndefined();
    expect(context.admin).toBeUndefined();
  });

  it('normalizes dotted topics the way the library stores them', () => {
    const request = webhookRequest({ body, topic: 'domain.sub_topic/created' });
    const context = buildSessionlessWebhookContext(body, request.headers, SECRET);
    expect(context.topic).toBe('DOMAIN_SUB_TOPIC_CREATED');
  });

  it('throws 401 for a body signed with the wrong secret', async () => {
    const request = webhookRequest({ body, secret: 'wrong-secret' });
    const response = await caughtResponse(
      Promise.resolve().then(() => buildSessionlessWebhookContext(body, request.headers, SECRET)),
    );
    expect(response.status).toBe(401);
  });

  it('throws 401 when the HMAC header is missing', async () => {
    const request = webhookRequest({ body, overrides: { 'X-Shopify-Hmac-SHA256': null } });
    const response = await caughtResponse(
      Promise.resolve().then(() => buildSessionlessWebhookContext(body, request.headers, SECRET)),
    );
    expect(response.status).toBe(401);
  });

  it('throws 400 when a required header is missing on a validly signed request', async () => {
    const request = webhookRequest({ body, overrides: { 'X-Shopify-Webhook-Id': null } });
    const response = await caughtResponse(
      Promise.resolve().then(() => buildSessionlessWebhookContext(body, request.headers, SECRET)),
    );
    expect(response.status).toBe(400);
  });

  it('fails closed with 500 when no secret is configured', async () => {
    const request = webhookRequest({ body });
    const response = await caughtResponse(
      Promise.resolve().then(() => buildSessionlessWebhookContext(body, request.headers, '')),
    );
    expect(response.status).toBe(500);
  });
});

describe('authenticateWebhookWith', () => {
  const libraryContext = { shop: SHOP, topic: 'APP_UNINSTALLED' };

  it('returns the library context untouched when the library succeeds', async () => {
    const result = await authenticateWebhookWith(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      async () => libraryContext as any,
      webhookRequest(),
      SECRET,
    );
    expect(result).toBe(libraryContext);
  });

  it('passes a library 401 through untouched (HMAC rejection stays a rejection)', async () => {
    const libraryRejection = new Response(undefined, { status: 401, statusText: 'Unauthorized' });
    const response = await caughtResponse(
      authenticateWebhookWith(
        async () => {
          throw libraryRejection;
        },
        webhookRequest(),
        SECRET,
      ),
    );
    expect(response).toBe(libraryRejection);
  });

  it('passes library 400 and 405 rejections through untouched', async () => {
    for (const status of [400, 405]) {
      const rejection = new Response(undefined, { status });
      const response = await caughtResponse(
        authenticateWebhookWith(
          async () => {
            throw rejection;
          },
          webhookRequest(),
          SECRET,
        ),
      );
      expect(response.status).toBe(status);
    }
  });

  it('falls back to a session-less context when the library throws its refresh 500', async () => {
    const result = await authenticateWebhookWith(
      async (request) => {
        // The library consumes the body before failing, as the real one does.
        await request.text();
        throw new Response(undefined, { status: 500, statusText: 'Internal Server Error' });
      },
      webhookRequest(),
      SECRET,
    );
    expect(result.shop).toBe(SHOP);
    expect(result.topic).toBe('APP_UNINSTALLED');
    expect(result.session).toBeUndefined();
  });

  it('falls back for a non-Response session plumbing error', async () => {
    const result = await authenticateWebhookWith(
      async () => {
        throw new Error('database unreachable while loading the offline session');
      },
      webhookRequest(),
      SECRET,
    );
    expect(result.shop).toBe(SHOP);
    expect(result.session).toBeUndefined();
  });

  it('still rejects with 401 when the fallback request itself has a bad HMAC', async () => {
    // A request that somehow reaches the fallback without a valid signature
    // must not be processed: the fallback re-verifies rather than trusting
    // that the library got as far as the session plumbing.
    const response = await caughtResponse(
      authenticateWebhookWith(
        async () => {
          throw new Response(undefined, { status: 500 });
        },
        webhookRequest({ secret: 'wrong-secret' }),
        SECRET,
      ),
    );
    expect(response.status).toBe(401);
  });
});
