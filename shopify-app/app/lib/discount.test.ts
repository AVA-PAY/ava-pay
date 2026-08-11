import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { createOneTimeDiscount } from './discount.server.js';

/**
 * createOneTimeDiscount must never throw at its caller. The App Proxy route
 * treats a null return as "verified, but no discount minted"; an exception
 * escaping instead becomes an HTML error page rendered inside the merchant's
 * storefront theme, which is what a production 403 actually did.
 */

type GraphqlStub = (query: string, options?: unknown) => Promise<unknown>;
const adminWith = (graphql: GraphqlStub) => ({ graphql }) as never;

const okResponse = {
  json: async () => ({ data: { discountCodeBasicCreate: { userErrors: [] } } }),
};

describe('createOneTimeDiscount', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns a prefixed code on success', async () => {
    const result = await createOneTimeDiscount(adminWith(async () => okResponse), 15);
    expect(result?.percentage).toBe(15);
    expect(result?.code).toMatch(/^AVA-[A-Z0-9]{8}$/);
  });

  it('sends the percentage as a fraction, as the Admin API expects', async () => {
    let captured: any;
    await createOneTimeDiscount(
      adminWith(async (_q, options) => {
        captured = options;
        return okResponse;
      }),
      15,
    );
    expect(captured.variables.basicCodeDiscount.customerGets.value.percentage).toBe(0.15);
    expect(captured.variables.basicCodeDiscount.usageLimit).toBe(1);
  });

  it('mints nothing for a zero or negative percentage', async () => {
    const graphql = vi.fn();
    expect(await createOneTimeDiscount(adminWith(graphql), 0)).toBeNull();
    expect(await createOneTimeDiscount(adminWith(graphql), -5)).toBeNull();
    expect(graphql).not.toHaveBeenCalled();
  });

  it('returns null on GraphQL userErrors', async () => {
    const result = await createOneTimeDiscount(
      adminWith(async () => ({
        json: async () => ({
          data: { discountCodeBasicCreate: { userErrors: [{ message: 'nope' }] } },
        }),
      })),
      10,
    );
    expect(result).toBeNull();
  });

  // The production failure: Admin API answers 403 when the access token lacks
  // write_discounts, and the client throws rather than returning userErrors.
  it('returns null instead of throwing when the Admin API answers 403', async () => {
    const forbidden = Object.assign(new Error('GraphQL Client: Forbidden'), {
      response: { status: 403 },
    });
    const result = await createOneTimeDiscount(
      adminWith(async () => {
        throw forbidden;
      }),
      10,
    );
    expect(result).toBeNull();
    const logged = vi.mocked(console.error).mock.calls[0]?.[0] as string;
    expect(JSON.parse(logged)).toMatchObject({
      event: 'discount.create_failed',
      status: 403,
      forbidden: true,
    });
  });

  it('returns null instead of throwing on a transport failure', async () => {
    const result = await createOneTimeDiscount(
      adminWith(async () => {
        throw new Error('socket hang up');
      }),
      10,
    );
    expect(result).toBeNull();
  });

  it('returns null instead of throwing when the response body is not JSON', async () => {
    const result = await createOneTimeDiscount(
      adminWith(async () => ({
        json: async () => {
          throw new SyntaxError('Unexpected token < in JSON');
        },
      })),
      10,
    );
    expect(result).toBeNull();
  });
});
