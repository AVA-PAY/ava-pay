/**
 * The Settings action's auth boundary.
 *
 * The "Send test agent visit" intent makes the app sign a request and write a
 * VerificationEvent for a shop, so it must be exactly as privileged as saving
 * settings: `authenticate.admin` first, and the shop taken from the session
 * Shopify handed us rather than from anything the form said.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';

const authenticateAdmin = vi.fn();
const sendTestVisit = vi.fn();
const saveShopSettings = vi.fn();
const getShopSettings = vi.fn();

vi.mock('../shopify.server.js', () => ({
  authenticate: {
    admin: (request: Request) => authenticateAdmin(request),
  },
}));

vi.mock('../lib/test-visit.server.js', () => ({
  sendTestVisit: (shop: string) => sendTestVisit(shop),
}));

// Mocked so importing the route never constructs a Prisma client.
vi.mock('../lib/settings.server.js', () => ({
  getShopSettings: (shop: string) => getShopSettings(shop),
  saveShopSettings: (shop: string, patch: unknown) => saveShopSettings(shop, patch),
}));

const { action } = await import('./app._index.js');

const SHOP = 'ava-pay-test-store.myshopify.com';

function postForm(fields: Record<string, string>): Request {
  const body = new URLSearchParams(fields);
  return new Request('https://app.avalayer.com/app', { method: 'POST', body });
}

/** What the Shopify library does to an unauthenticated admin request. */
const UNAUTHENTICATED = new Response(null, { status: 302 });

describe('Settings action auth boundary', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authenticateAdmin.mockResolvedValue({ session: { shop: SHOP } });
    sendTestVisit.mockResolvedValue({
      outcome: 'verified',
      reason: null,
      protocol: 'ava-tap',
      platform: 'agent_demo_public',
      discountPct: 10,
    });
    saveShopSettings.mockResolvedValue({
      shop: SHOP,
      acceptVerifiedAgents: true,
      defaultDiscountPct: 10,
      maxDiscountPct: 20,
      identityOnlyDiscountPct: 0,
      policy: null,
    });
  });

  it('refuses a test visit when admin authentication fails', async () => {
    authenticateAdmin.mockRejectedValue(UNAUTHENTICATED);

    await expect(
      action({ request: postForm({ intent: 'test-visit' }) } as never),
    ).rejects.toBe(UNAUTHENTICATED);

    expect(sendTestVisit).not.toHaveBeenCalled();
  });

  it('refuses a settings save when admin authentication fails', async () => {
    authenticateAdmin.mockRejectedValue(UNAUTHENTICATED);

    await expect(
      action({ request: postForm({ intent: 'save', defaultDiscountPct: '5' }) } as never),
    ).rejects.toBe(UNAUTHENTICATED);

    expect(saveShopSettings).not.toHaveBeenCalled();
  });

  it('sends the test visit for the session shop, never a shop from the form', async () => {
    const response = await action({
      request: postForm({ intent: 'test-visit', shop: 'attacker.myshopify.com' }),
    } as never);

    expect(sendTestVisit).toHaveBeenCalledTimes(1);
    expect(sendTestVisit).toHaveBeenCalledWith(SHOP);

    // react-router's data() wraps the payload rather than returning a Response.
    const { data } = response as { data: { intent: string; testVisit: { outcome: string } } };
    expect(data.intent).toBe('test-visit');
    expect(data.testVisit.outcome).toBe('verified');
  });

  it('does not send a test visit when the intent is a settings save', async () => {
    await action({
      request: postForm({
        intent: 'save',
        acceptVerifiedAgents: 'on',
        defaultDiscountPct: '10',
        maxDiscountPct: '20',
        identityOnlyDiscountPct: '0',
      }),
    } as never);

    expect(sendTestVisit).not.toHaveBeenCalled();
    expect(saveShopSettings).toHaveBeenCalledWith(SHOP, {
      acceptVerifiedAgents: true,
      defaultDiscountPct: 10,
      maxDiscountPct: 20,
      identityOnlyDiscountPct: 0,
    });
  });

  it('rejects invalid discount values without touching the store', async () => {
    const response = await action({
      request: postForm({
        intent: 'save',
        defaultDiscountPct: '90',
        maxDiscountPct: '20',
        identityOnlyDiscountPct: '0',
      }),
    } as never);

    const { data, init } = response as { data: { ok: boolean }; init: ResponseInit };
    expect(init.status).toBe(400);
    expect(data.ok).toBe(false);
    expect(saveShopSettings).not.toHaveBeenCalled();
  });
});
