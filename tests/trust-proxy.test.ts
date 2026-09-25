import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer, trustProxyHops } from '../src/server.js';

/**
 * Task #44: the rate limiter keys on request.ip. Behind Railway's edge that
 * is the proxy unless trustProxy is set to the right hop count, in which case
 * it is the caller. These tests pin the derivation, the spoof resistance, and
 * the per-client buckets that follow from it.
 *
 * fastify.inject connects from 127.0.0.1, which stands in for the edge proxy.
 */

const SOCKET = '127.0.0.1';

async function server(hops: number): Promise<FastifyInstance> {
  const app = await buildServer({
    logger: false,
    mountDirectory: false,
    servePublic: false,
    trustProxyHops: hops,
  });
  await app.ready();
  return app;
}

async function healthz(app: FastifyInstance, xff?: string) {
  const res = await app.inject({
    method: 'GET',
    url: '/healthz',
    ...(xff !== undefined ? { headers: { 'x-forwarded-for': xff } } : {}),
  });
  return { status: res.statusCode, body: res.json() as Record<string, unknown> };
}

describe('trustProxyHops (TRUST_PROXY_HOPS)', () => {
  it('defaults to 1, Railway\'s single edge hop', () => {
    expect(trustProxyHops({})).toBe(1);
    expect(trustProxyHops({ TRUST_PROXY_HOPS: '' })).toBe(1);
    expect(trustProxyHops({ TRUST_PROXY_HOPS: '  ' })).toBe(1);
  });

  it('reads a non-negative integer', () => {
    expect(trustProxyHops({ TRUST_PROXY_HOPS: '0' })).toBe(0);
    expect(trustProxyHops({ TRUST_PROXY_HOPS: '2' })).toBe(2);
    expect(trustProxyHops({ TRUST_PROXY_HOPS: ' 3 ' })).toBe(3);
  });

  it('fails the boot on anything else, never guessing a hop count', () => {
    for (const bad of ['true', '-1', '1.5', 'one', '1,2', '0x1']) {
      expect(() => trustProxyHops({ TRUST_PROXY_HOPS: bad })).toThrow(/TRUST_PROXY_HOPS/);
    }
  });

  it('buildServer reads the env var when no option is passed', async () => {
    const prev = process.env.TRUST_PROXY_HOPS;
    process.env.TRUST_PROXY_HOPS = '0';
    try {
      const app = await buildServer({ logger: false, mountDirectory: false, servePublic: false });
      await app.ready();
      expect((await healthz(app, '203.0.113.9')).body.clientIp).toBe(SOCKET);
      await app.close();
    } finally {
      if (prev === undefined) delete process.env.TRUST_PROXY_HOPS;
      else process.env.TRUST_PROXY_HOPS = prev;
    }
  });
});

describe('client IP derivation', () => {
  let app: FastifyInstance;
  beforeEach(async () => {
    app = await server(1);
  });
  afterEach(async () => {
    await app.close();
  });

  it('with no X-Forwarded-For, request.ip is the socket address', async () => {
    const { body } = await healthz(app);
    expect(body.clientIp).toBe(SOCKET);
    expect(body.forwardedFor).toBeNull();
  });

  it('with hops=1, takes the entry the edge appended', async () => {
    const { body } = await healthz(app, '198.51.100.7');
    expect(body.clientIp).toBe('198.51.100.7');
  });

  it('ignores a spoofed entry beyond the trusted hops', async () => {
    const { body } = await healthz(app, 'spoofed, 198.51.100.7');
    expect(body.clientIp).toBe('198.51.100.7');
    expect(body.clientIp).not.toBe('spoofed');
  });

  it('with hops=2, trusts exactly one more hop and no further', async () => {
    const two = await server(2);
    try {
      const { body } = await healthz(two, '192.0.2.1, 198.51.100.7, 10.0.0.5');
      expect(body.clientIp).toBe('198.51.100.7');
    } finally {
      await two.close();
    }
  });

  it('with hops=0, X-Forwarded-For is ignored entirely', async () => {
    const zero = await server(0);
    try {
      const { body } = await healthz(zero, '198.51.100.7');
      expect(body.clientIp).toBe(SOCKET);
    } finally {
      await zero.close();
    }
  });
});

describe('/healthz diagnostic fields', () => {
  it('echoes ok, the derived clientIp and the raw X-Forwarded-For', async () => {
    const app = await server(1);
    try {
      const { status, body } = await healthz(app, 'spoofed, 198.51.100.7');
      expect(status).toBe(200);
      expect(body).toEqual({
        ok: true,
        clientIp: '198.51.100.7',
        forwardedFor: 'spoofed, 198.51.100.7',
      });
    } finally {
      await app.close();
    }
  });
});

describe('per-client rate-limit buckets', () => {
  let prev: string | undefined;
  beforeEach(() => {
    prev = process.env.RATE_LIMIT_MAX;
    process.env.RATE_LIMIT_MAX = '2';
  });
  afterEach(() => {
    if (prev === undefined) delete process.env.RATE_LIMIT_MAX;
    else process.env.RATE_LIMIT_MAX = prev;
  });

  it('two client IPs behind the same proxy get two buckets', async () => {
    const app = await server(1);
    try {
      const a = [];
      for (let i = 0; i < 3; i++) a.push((await healthz(app, '198.51.100.1')).status);
      expect(a).toEqual([200, 200, 429]);
      // A different caller is untouched by the first one exhausting its bucket.
      expect((await healthz(app, '198.51.100.2')).status).toBe(200);
      expect((await healthz(app, '198.51.100.2')).status).toBe(200);
      expect((await healthz(app, '198.51.100.2')).status).toBe(429);
    } finally {
      await app.close();
    }
  });

  it('rotating a spoofed prefix does not buy a fresh bucket', async () => {
    const app = await server(1);
    try {
      const codes = [];
      for (const fake of ['10.0.0.1', '10.0.0.2', '10.0.0.3']) {
        codes.push((await healthz(app, `${fake}, 198.51.100.9`)).status);
      }
      expect(codes).toEqual([200, 200, 429]);
    } finally {
      await app.close();
    }
  });

  it('the 429 body stays machine-readable JSON', async () => {
    const app = await server(1);
    try {
      await healthz(app, '198.51.100.3');
      await healthz(app, '198.51.100.3');
      const res = await app.inject({
        method: 'GET',
        url: '/healthz',
        headers: { 'x-forwarded-for': '198.51.100.3' },
      });
      expect(res.statusCode).toBe(429);
      expect(res.headers['content-type']).toMatch(/^application\/json/);
      const body = res.json() as Record<string, unknown>;
      expect(body.statusCode).toBe(429);
      expect(typeof body.error).toBe('string');
      expect(typeof body.message).toBe('string');
    } finally {
      await app.close();
    }
  });
});
