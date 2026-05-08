import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AvaPayClient } from './ava.server.js';
import type { VerificationResult } from './ava-types.js';

describe('AvaPayClient', () => {
  const baseUrl = 'http://ava-pay.test';

  function makeFetch(handler: (req: Request) => Response | Promise<Response>): typeof fetch {
    return vi.fn(async (input, init) => {
      const url = typeof input === 'string' ? input : (input as URL).toString();
      const req = new Request(url, init);
      return handler(req);
    }) as unknown as typeof fetch;
  }

  beforeEach(() => {
    vi.useRealTimers();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('forwards the IncomingRequest snapshot to /verify', async () => {
    let captured: { url: string; method: string; body: string | null } | null = null;
    const fetcher = makeFetch(async (req) => {
      captured = { url: req.url, method: req.method, body: await req.text() };
      const result: VerificationResult = {
        trusted: true,
        buyerInfo: { buyerId: 'b1' },
        mandate: {
          id: 'm',
          iat: 0,
          exp: 1,
          maxAmountMinor: 0,
          currency: 'USD',
          allowedMerchants: ['*'],
        },
        ttlSeconds: 60,
      };
      return new Response(JSON.stringify(result), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });

    const client = new AvaPayClient({ baseUrl, fetcher });
    const out = await client.verify({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      headers: { 'x-ava-agent-id': 'agent_demo' },
      body: 'hello',
    });

    expect(captured).not.toBeNull();
    expect(captured!.url).toBe(`${baseUrl}/verify`);
    expect(captured!.method).toBe('POST');
    const sent = JSON.parse(captured!.body!);
    expect(sent.headers['x-ava-agent-id']).toBe('agent_demo');
    expect(out.ok).toBe(true);
    if (out.ok) expect(out.result.trusted).toBe(true);
  });

  it('treats 403 (blocked) as a successful call with trusted=false', async () => {
    const fetcher = makeFetch(
      async () =>
        new Response(
          JSON.stringify({
            trusted: false,
            reason: 'invalid_signature',
            message: 'nope',
          }),
          { status: 403, headers: { 'content-type': 'application/json' } },
        ),
    );
    const client = new AvaPayClient({ baseUrl, fetcher });
    const out = await client.verify({ method: 'POST', url: 'http://x', headers: {} });
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.result.trusted).toBe(false);
      if (!out.result.trusted) expect(out.result.reason).toBe('invalid_signature');
    }
  });

  it('returns ok=false on a 5xx response so the caller can fail closed', async () => {
    const fetcher = makeFetch(async () => new Response('bad', { status: 502 }));
    const client = new AvaPayClient({ baseUrl, fetcher });
    const out = await client.verify({ method: 'POST', url: 'http://x', headers: {} });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toBe('bad_response');
  });

  it('returns ok=false on network failure', async () => {
    const fetcher = makeFetch(async () => {
      throw new Error('ECONNREFUSED');
    });
    const client = new AvaPayClient({ baseUrl, fetcher });
    const out = await client.verify({ method: 'POST', url: 'http://x', headers: {} });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toBe('network');
  });

  it('returns ok=false with error=timeout when the request exceeds the budget', async () => {
    const fetcher = makeFetch(async (req) => {
      // Honor the abort signal so the test runs fast.
      await new Promise((_resolve, reject) => {
        req.signal.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
      return new Response();
    });
    const client = new AvaPayClient({ baseUrl, fetcher, timeoutMs: 5 });
    const out = await client.verify({ method: 'POST', url: 'http://x', headers: {} });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.error).toBe('timeout');
  });
});
