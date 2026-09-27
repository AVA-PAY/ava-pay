import { readFileSync } from 'node:fs';
import { createPublicKey, type JsonWebKey } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { VisaTapVerifier } from '../src/verifier/visa-tap.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import type { IncomingRequest, VerificationResult } from '../src/types.js';

/**
 * WooCommerce plugin 0.4.0, signed page visits: the other half of the loop
 * PageVisitTest (PHPUnit) starts. The fixtures are page requests signed with
 * the SDK, as PHP's $_SERVER would carry them, plus the request that should
 * leave the site (woocommerce-plugin/scripts/generate-page-visit-fixtures.ts).
 * PHPUnit proves the plugin's reconstruction produces exactly `expected`;
 * this suite proves `expected` verifies against the real route and real
 * verifiers. Nothing is mocked; the clock is pinned to the fixtures'
 * `created` because the signatures are committed.
 */

interface PageVisitCase {
  name: string;
  protocol: string;
  server: Record<string, string>;
  expected: IncomingRequest;
}
interface Fixtures {
  created: number;
  webBotAuth: { origin: string; publicJwk: JsonWebKey };
  visaTap: { keyid: string; publicJwk: JsonWebKey };
  cases: PageVisitCase[];
}

const fixtures = JSON.parse(
  readFileSync(new URL('../woocommerce-plugin/tests/fixtures/page-visit-fixtures.json', import.meta.url), 'utf8'),
) as Fixtures;

describe('Woo page visits: the reconstructed request verifies', () => {
  let app: FastifyInstance;

  async function verify(request: IncomingRequest): Promise<VerificationResult> {
    const res = await app.inject({ method: 'POST', url: '/verify', payload: request });
    return res.json() as VerificationResult;
  }

  beforeAll(async () => {
    const now = () => fixtures.created + 5;
    const directory = new StaticAgentDirectory();
    directory.add(fixtures.visaTap.keyid, createPublicKey({ key: fixtures.visaTap.publicJwk, format: 'jwk' }));
    const wbaKeys = new StaticSignatureAgentKeys();
    wbaKeys.add(fixtures.webBotAuth.origin, { keys: [fixtures.webBotAuth.publicJwk] });

    const verifier = new MultiProtocolVerifier({
      visa: new VisaAgentVerifier({ directory }),
      visaTap: new VisaTapVerifier({ directory, now }),
      ap2: new Ap2AgentVerifier({ directory }),
      webBotAuth: new WebBotAuthVerifier({ resolver: wbaKeys, now }),
    });
    app = await buildServer({ verifier, logger: false, rateLimit: false });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('has the cases the plugin relies on: a port, a query string, HEAD, a covered header, both protocols', () => {
    const names = fixtures.cases.map((c) => c.name);
    expect(names).toEqual([
      'wba_port_and_query',
      'wba_bare_string_head',
      'wba_covers_user_agent',
      'visa_tap_port_and_query',
    ]);
    expect(fixtures.cases.some((c) => c.expected.url.includes(':8443/') && c.expected.url.includes('?'))).toBe(true);
  });

  for (const c of fixtures.cases) {
    it(`${c.name}: verifies as ${c.protocol}, with no credentials or spoofable headers forwarded`, async () => {
      const names = Object.keys(c.expected.headers);
      for (const never of ['cookie', 'authorization', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for']) {
        expect(names).not.toContain(never);
      }
      expect(c.expected.body).toBeUndefined();

      const result = await verify(c.expected);
      if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
      expect(result.protocol).toBe(c.protocol);
    });
  }

  it('a reconstruction that believed X-Forwarded-Host would not verify: HTTP_HOST is what the agent signed', async () => {
    const c = fixtures.cases.find((x) => x.name === 'wba_port_and_query')!;
    const spoofedHost = c.server.HTTP_X_FORWARDED_HOST!;
    const wrong: IncomingRequest = {
      ...c.expected,
      url: `https://${spoofedHost}${c.server.REQUEST_URI}`,
      headers: { ...c.expected.headers, host: spoofedHost },
    };
    const result = await verify(wrong);
    expect(result).toMatchObject({ trusted: false, reason: 'invalid_signature' });
  });

  it('a reconstruction that dropped the query string would not verify when @query is covered', async () => {
    const c = fixtures.cases.find((x) => x.name === 'wba_port_and_query')!;
    const result = await verify({ ...c.expected, url: c.expected.url.split('?')[0]! });
    expect(result).toMatchObject({ trusted: false, reason: 'invalid_signature' });
  });
});
