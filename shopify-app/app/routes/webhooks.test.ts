/**
 * Webhook routes against the REAL @shopify/shopify-app-react-router library.
 *
 * Production failure being pinned here: a shop uninstalls but its Session
 * row survives; the next webhook passes HMAC validation, then the library
 * tries to refresh the shop's expired offline token, Shopify refuses, and
 * the library throws a bare Response(500). Every app/uninstalled and
 * shop/redact delivery for Shopify's review stores failed that way, and the
 * cleanup that would have removed the stale row never ran, so every retry
 * failed too.
 *
 * The library here is real: a shopifyApp instance with test credentials, the
 * webhook HMAC computed with real crypto, and only two seams substituted,
 * the session storage (in-memory map instead of Postgres) and the outbound
 * HTTP transport (Shopify's token endpoint answering 401, which is what it
 * does for a revoked refresh token).
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createHmac } from 'node:crypto';
import '@shopify/shopify-app-react-router/adapters/node';
import { Session } from '@shopify/shopify-api';

// vi.hoisted runs before any import, so the node adapter (which captures
// globalThis.fetch at import time) binds this stub. Shopify's answer to a
// token refresh for an uninstalled shop is a refusal; anything the app
// package does not allowlist becomes its thrown 500. Every other URL is a
// test bug, not a feature, so it fails loudly.
const h = vi.hoisted(() => {
  const state = {
    secret: 'integration-test-webhook-secret',
    sessions: new Map<string, unknown>(),
    prismaCalls: [] as Array<{ model: string; method: string; args: unknown }>,
    fetchCalls: [] as string[],
  };
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input instanceof Request ? input.url : input);
    state.fetchCalls.push(url);
    if (!url.includes('/admin/oauth/access_token')) {
      throw new Error(`unexpected outbound fetch in webhook test: ${url}`);
    }
    return new Response(
      JSON.stringify({ error: 'invalid_grant', error_description: 'refresh token revoked' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    );
  }) as typeof fetch;
  return state;
});

function recordingModel(model: string) {
  return {
    deleteMany: async (args: unknown) => {
      h.prismaCalls.push({ model, method: 'deleteMany', args });
      return { count: 1 };
    },
  };
}

vi.mock('../db.server.js', () => ({
  default: {
    session: recordingModel('session'),
    shopSettings: recordingModel('shopSettings'),
    verificationEvent: recordingModel('verificationEvent'),
    agentCommerceEvent: recordingModel('agentCommerceEvent'),
  },
}));

vi.mock('../shopify.server.js', async () => {
  const { shopifyApp, ApiVersion, AppDistribution } = await import(
    '@shopify/shopify-app-react-router/server'
  );
  const shopify = shopifyApp({
    apiKey: 'test-api-key',
    apiSecretKey: h.secret,
    apiVersion: ApiVersion.January26,
    scopes: ['write_discounts'],
    appUrl: 'https://webhook-test.example.com',
    distribution: AppDistribution.AppStore,
    sessionStorage: {
      loadSession: async (id: string) => h.sessions.get(id),
      storeSession: async () => true,
      deleteSession: async (id: string) => h.sessions.delete(id),
      deleteSessions: async (ids: string[]) => {
        for (const id of ids) h.sessions.delete(id);
        return true;
      },
      findSessionsByShop: async () => [],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
    future: {
      // Mirrors production (public apps must use expiring offline tokens).
      // Without this flag the refresh path this suite exercises is dead code.
      expiringOfflineAccessTokens: true,
    },
  });
  return { authenticate: shopify.authenticate };
});

const { authenticate } = await import('../shopify.server.js');
const uninstalledAction = (await import('./webhooks.app.uninstalled.js')).action;
const shopRedactAction = (await import('./webhooks.shop.redact.js')).action;

const SHOP = 'stale-review-store.myshopify.com';

function seedStaleSession() {
  // What production held for the review stores: an expired expiring offline
  // token plus the refresh token that Shopify will no longer honor.
  h.sessions.set(
    `offline_${SHOP}`,
    new Session({
      id: `offline_${SHOP}`,
      shop: SHOP,
      state: '',
      isOnline: false,
      scope: 'write_discounts',
      accessToken: 'shpua_revoked',
      expires: new Date(Date.now() - 60_000),
      refreshToken: 'shpur_stale',
      refreshTokenExpires: new Date(Date.now() + 86_400_000),
    }),
  );
}

function signedWebhook(topic: string, { secret = h.secret } = {}): Request {
  const body = JSON.stringify({ id: 12345, domain: SHOP, shop_domain: SHOP });
  return new Request(`https://webhook-test.example.com/webhooks/${topic}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Topic': topic,
      'X-Shopify-Shop-Domain': SHOP,
      'X-Shopify-Hmac-SHA256': createHmac('sha256', secret).update(body, 'utf8').digest('base64'),
      'X-Shopify-API-Version': '2026-01',
      'X-Shopify-Webhook-Id': 'b6f3a3c7-0000-4000-8000-000000000002',
    },
    body,
  });
}

function deleteManyShops(model: string): unknown[] {
  return h.prismaCalls
    .filter((call) => call.model === model && call.method === 'deleteMany')
    .map((call) => call.args);
}

beforeEach(() => {
  h.sessions.clear();
  h.prismaCalls.length = 0;
  h.fetchCalls.length = 0;
  process.env.SHOPIFY_API_SECRET = h.secret;
});

describe('the library alone (the behavior production hit)', () => {
  it('rejects a valid webhook with a thrown 500 when the stale session cannot be refreshed', async () => {
    // If a library upgrade makes this pass without throwing, the fallback in
    // webhook-auth.server.ts is no longer load-bearing and can be removed.
    seedStaleSession();
    let thrown: unknown;
    try {
      await authenticate.webhook(signedWebhook('app/uninstalled'));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Response);
    expect((thrown as Response).status).toBe(500);
    expect(h.fetchCalls.some((url) => url.includes(`${SHOP}/admin/oauth/access_token`))).toBe(true);
  });
});

describe('app/uninstalled', () => {
  it('returns 200 and completes cleanup for a shop with a stale revoked session', async () => {
    seedStaleSession();
    const response = await uninstalledAction({
      request: signedWebhook('app/uninstalled'),
      params: {},
      context: {},
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    expect(response.status).toBe(200);
    // The refresh really was attempted and refused before the fallback ran.
    expect(h.fetchCalls.some((url) => url.includes(`${SHOP}/admin/oauth/access_token`))).toBe(true);
    // Cleanup completed: the poison Session row and the settings both went.
    expect(deleteManyShops('session')).toEqual([{ where: { shop: SHOP } }]);
    expect(deleteManyShops('shopSettings')).toEqual([{ where: { shop: SHOP } }]);
  });

  it('returns 200 and still cleans up for a shop with no session at all', async () => {
    const response = await uninstalledAction({
      request: signedWebhook('app/uninstalled'),
      params: {},
      context: {},
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    expect(response.status).toBe(200);
    expect(h.fetchCalls).toEqual([]);
    expect(deleteManyShops('session')).toEqual([{ where: { shop: SHOP } }]);
    expect(deleteManyShops('shopSettings')).toEqual([{ where: { shop: SHOP } }]);
  });

  it('still rejects an invalid HMAC with 401 and touches nothing', async () => {
    seedStaleSession();
    let thrown: unknown;
    try {
      await uninstalledAction({
        request: signedWebhook('app/uninstalled', { secret: 'attacker-secret' }),
        params: {},
        context: {},
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Response);
    expect((thrown as Response).status).toBe(401);
    expect(h.prismaCalls).toEqual([]);
    expect(h.fetchCalls).toEqual([]);
  });
});

describe('shop/redact', () => {
  it('returns 200 and deletes everything for a shop with a stale revoked session', async () => {
    seedStaleSession();
    const response = await shopRedactAction({
      request: signedWebhook('shop/redact'),
      params: {},
      context: {},
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    expect(response.status).toBe(200);
    for (const model of ['verificationEvent', 'agentCommerceEvent', 'shopSettings', 'session']) {
      expect(deleteManyShops(model)).toEqual([{ where: { shop: SHOP } }]);
    }
  });

  it('returns 200 for a shop whose rows are already gone', async () => {
    const response = await shopRedactAction({
      request: signedWebhook('shop/redact'),
      params: {},
      context: {},
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    expect(response.status).toBe(200);
    expect(h.fetchCalls).toEqual([]);
  });

  it('still rejects an invalid HMAC with 401', async () => {
    let thrown: unknown;
    try {
      await shopRedactAction({
        request: signedWebhook('shop/redact', { secret: 'attacker-secret' }),
        params: {},
        context: {},
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Response);
    expect((thrown as Response).status).toBe(401);
    expect(h.prismaCalls).toEqual([]);
  });
});
