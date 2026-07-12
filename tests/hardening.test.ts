import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';
import { directoryRoutes } from '../src/directory/routes.js';
import { InMemoryDirectoryStorage } from '../src/directory/storage.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { InMemoryReplayGuard } from '../src/verifier/replay.js';
import type { Mandate, VerificationResult } from '../src/types.js';
import { generateAgentKeyPair, signRequest, type KeyPair } from './sign-helper.js';
import {
  buildCheckoutMandateChain,
  makeCheckoutJwt,
  type AgentKeyPair,
} from '../src/sdk/index.js';

/**
 * Production-hardening tests (Phase 0):
 *   - replay protection (Visa nonce, AP2 cart jti)
 *   - mandatory alg / created / nonce signature parameters
 *   - server-side max signature age cap
 *   - fail-closed directory writes
 *   - rate limiting
 */

const FIXED_NOW = 1_750_000_000;
const MERCHANT = 'shop.example.com';
const BODY = JSON.stringify({ items: [{ sku: 'SKU-1', qty: 1 }] });

function mandate(overrides: Partial<Mandate> = {}): Mandate {
  return {
    id: 'mandate_hardening',
    iat: FIXED_NOW - 60,
    exp: FIXED_NOW + 600,
    maxAmountMinor: 50_000,
    currency: 'USD',
    allowedMerchants: [MERCHANT],
    ...overrides,
  };
}

describe('Visa TAP hardening', () => {
  let app: FastifyInstance;
  let keys: KeyPair;

  beforeAll(async () => {
    keys = generateAgentKeyPair();
    const directory = new StaticAgentDirectory();
    directory.add('agent_demo', keys.publicKey);
    const verifier = new VisaAgentVerifier({ directory, now: () => FIXED_NOW });
    app = await buildServer({ verifier, logger: false, rateLimit: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  function signedPayload(opts: { nonce?: string; created?: number; expires?: number } = {}) {
    return signRequest({
      method: 'POST',
      url: `https://${MERCHANT}/cart`,
      body: BODY,
      agentId: 'agent_demo',
      privateKey: keys.privateKey,
      mandate: mandate(),
      created: opts.created ?? FIXED_NOW - 5,
      expires: opts.expires ?? FIXED_NOW + 30,
      ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
    });
  }

  async function verify(payload: unknown): Promise<VerificationResult> {
    const res = await app.inject({
      method: 'POST',
      url: '/verify',
      payload: payload as Record<string, unknown>,
      headers: { 'content-type': 'application/json' },
    });
    return res.json() as VerificationResult;
  }

  it('accepts the first use of a nonce, rejects the replay', async () => {
    const signed = signedPayload();

    const first = await verify(signed);
    expect(first.trusted).toBe(true);

    const second = await verify(signed);
    expect(second.trusted).toBe(false);
    if (!second.trusted) expect(second.reason).toBe('replay_detected');
  });

  it('two different requests (fresh nonces) both verify', async () => {
    const a = await verify(signedPayload());
    const b = await verify(signedPayload());
    expect(a.trusted).toBe(true);
    expect(b.trusted).toBe(true);
  });

  it('rejects a signature without a nonce parameter', async () => {
    const signed = signedPayload();
    signed.headers['signature-input'] = signed.headers['signature-input']!.replace(
      /;nonce="[^"]*"/,
      '',
    );
    const result = await verify(signed);
    expect(result.trusted).toBe(false);
    if (!result.trusted) {
      expect(result.reason).toBe('malformed_signature_header');
      expect(result.message).toMatch(/nonce/i);
    }
  });

  it('rejects a signature without an alg parameter', async () => {
    const signed = signedPayload();
    signed.headers['signature-input'] = signed.headers['signature-input']!.replace(
      /;alg="ed25519"/,
      '',
    );
    const result = await verify(signed);
    expect(result.trusted).toBe(false);
    if (!result.trusted) expect(result.reason).toBe('unsupported_algorithm');
  });

  it('rejects a signature without a created parameter', async () => {
    const signed = signedPayload();
    signed.headers['signature-input'] = signed.headers['signature-input']!.replace(
      /;created=\d+/,
      '',
    );
    const result = await verify(signed);
    expect(result.trusted).toBe(false);
    if (!result.trusted) {
      expect(result.reason).toBe('malformed_signature_header');
      expect(result.message).toMatch(/created/i);
    }
  });

  it('caps signature lifetime server-side even when the signer volunteers a long expires', async () => {
    // created 400s ago, signer claims expires far in the future. Max age is
    // 300s, so the effective window closed ~70s ago (skew 30s).
    const result = await verify(
      signedPayload({ created: FIXED_NOW - 400, expires: FIXED_NOW + 3600 }),
    );
    expect(result.trusted).toBe(false);
    if (!result.trusted) expect(result.reason).toBe('signature_expired');
  });
});

describe('AP2 hardening', () => {
  let app: FastifyInstance;
  let keys: AgentKeyPair;

  beforeAll(async () => {
    keys = generateAgentKeyPair();
    const directory = new StaticAgentDirectory();
    directory.add('agent_demo', keys.publicKey);
    const ap2 = new Ap2AgentVerifier({ directory, now: () => FIXED_NOW });
    const visa = new VisaAgentVerifier({ directory, now: () => FIXED_NOW });
    const { MultiProtocolVerifier } = await import('../src/verifier/multi.js');
    const { WebBotAuthVerifier, StaticSignatureAgentKeys } = await import(
      '../src/verifier/web-bot-auth.js'
    );
    const { VisaTapVerifier } = await import('../src/verifier/visa-tap.js');
    const webBotAuth = new WebBotAuthVerifier({
      resolver: new StaticSignatureAgentKeys(),
      now: () => FIXED_NOW,
    });
    const visaTap = new VisaTapVerifier({ directory, now: () => FIXED_NOW });
    const verifier = new MultiProtocolVerifier({ visa, visaTap, ap2, webBotAuth });
    app = await buildServer({ verifier, logger: false, rateLimit: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('rejects a replayed mandate presentation (same nonce twice)', async () => {
    const agentKeys = generateAgentKeyPair();
    const merchantKeys = generateAgentKeyPair();
    const checkoutJwt = makeCheckoutJwt(
      {
        id: 'checkout_hardening',
        merchant: { name: 'Shop', url: `https://${MERCHANT}` },
        line_items: [{ item: { id: 'SKU-1', title: 'Widget' }, quantity: 1 }],
        status: 'ready_for_complete',
        currency: 'USD',
        totals: [
          { type: 'subtotal', amount: 5000 },
          { type: 'total', amount: 5000 },
        ],
      },
      merchantKeys.privateKey,
    );
    const chain = buildCheckoutMandateChain({
      user: { privateKey: keys.privateKey, kid: 'agent_demo' },
      agentPrivateKey: agentKeys.privateKey,
      agentPublicKey: agentKeys.publicKey,
      constraints: [
        { type: 'checkout.allowed_merchants', allowed: [{ name: 'Shop', url: `https://${MERCHANT}` }] },
      ],
      checkoutJwt,
      aud: `https://${MERCHANT}`,
      nonce: 'hardening_nonce_1',
      iat: FIXED_NOW - 5,
    });

    const payload = {
      method: 'POST',
      url: `https://${MERCHANT}/cart`,
      headers: { host: MERCHANT, 'ap2-checkout-mandate': chain },
      body: '',
    };

    const first = await app.inject({ method: 'POST', url: '/verify', payload });
    expect((first.json() as VerificationResult).trusted).toBe(true);

    const second = await app.inject({ method: 'POST', url: '/verify', payload });
    const result = second.json() as VerificationResult;
    expect(result.trusted).toBe(false);
    if (!result.trusted) expect(result.reason).toBe('replay_detected');
  });
});

describe('InMemoryReplayGuard', () => {
  it('forgets identifiers after their window closes', async () => {
    let now = 1_000;
    const guard = new InMemoryReplayGuard({ now: () => now });

    expect(await guard.checkAndStore('k1', now + 60)).toBe(true);
    expect(await guard.checkAndStore('k1', now + 60)).toBe(false);

    now += 120; // window closed
    expect(await guard.checkAndStore('k1', now + 60)).toBe(true);
  });

  it('enforces the max-entries cap without refusing fresh identifiers', async () => {
    const guard = new InMemoryReplayGuard({ maxEntries: 10, now: () => 1_000 });
    for (let i = 0; i < 25; i++) {
      expect(await guard.checkAndStore(`k${i}`, 2_000 + i)).toBe(true);
    }
    expect(guard.size).toBeLessThanOrEqual(10);
  });
});

describe('Directory writes fail closed', () => {
  const registerBody = {
    agentId: 'agent_new',
    issuer: 'Example Corp',
    keys: [{ alg: 'ed25519', jwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, protocols: ['visa'] }],
  };

  async function buildDirApp(opts: { registrationToken?: string; allowOpenWrites?: boolean }) {
    const app = Fastify({ logger: false });
    await app.register(directoryRoutes, { storage: new InMemoryDirectoryStorage(), ...opts });
    await app.ready();
    return app;
  }

  it('disables writes when no token and no explicit opt-in', async () => {
    const app = await buildDirApp({});
    const res = await app.inject({ method: 'POST', url: '/directory/agents', payload: registerBody });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: 'registration_disabled' });

    const revoke = await app.inject({ method: 'POST', url: '/directory/agents/whatever/revoke' });
    expect(revoke.statusCode).toBe(403);
    await app.close();
  });

  it('still serves reads when writes are disabled', async () => {
    const app = await buildDirApp({});
    const res = await app.inject({ method: 'GET', url: '/directory/agents' });
    expect(res.statusCode).toBe(200);
    await app.close();
  });

  it('allows tokenless writes only with the explicit dev flag', async () => {
    const app = await buildDirApp({ allowOpenWrites: true });
    const res = await app.inject({ method: 'POST', url: '/directory/agents', payload: registerBody });
    expect(res.statusCode).toBe(201);
    await app.close();
  });

  it('with a token configured, correct bearer works and wrong bearer is rejected', async () => {
    const app = await buildDirApp({ registrationToken: 'secret_token_123' });

    const wrong = await app.inject({
      method: 'POST',
      url: '/directory/agents',
      payload: registerBody,
      headers: { authorization: 'Bearer nope' },
    });
    expect(wrong.statusCode).toBe(401);

    const right = await app.inject({
      method: 'POST',
      url: '/directory/agents',
      payload: registerBody,
      headers: { authorization: 'Bearer secret_token_123' },
    });
    expect(right.statusCode).toBe(201);
    await app.close();
  });
});

describe('Rate limiting', () => {
  it('returns 429 once the per-window limit is exceeded', async () => {
    const prev = process.env.RATE_LIMIT_MAX;
    process.env.RATE_LIMIT_MAX = '3';
    try {
      const app = await buildServer({ logger: false, mountDirectory: false, servePublic: false });
      await app.ready();
      const codes: number[] = [];
      for (let i = 0; i < 5; i++) {
        const res = await app.inject({ method: 'GET', url: '/healthz' });
        codes.push(res.statusCode);
      }
      expect(codes.slice(0, 3)).toEqual([200, 200, 200]);
      expect(codes[3]).toBe(429);
      expect(codes[4]).toBe(429);
      await app.close();
    } finally {
      if (prev === undefined) delete process.env.RATE_LIMIT_MAX;
      else process.env.RATE_LIMIT_MAX = prev;
    }
  });
});
