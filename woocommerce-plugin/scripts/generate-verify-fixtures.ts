/**
 * Signed-request fixture generator — real crypto, no mocks.
 *
 * Uses the SDK's actual signers (@ava-pay/agent code via src/sdk) to produce
 * signed requests against a WooCommerce verify URL, runs each through the
 * REAL multi-protocol verifier (in-process API server, same wiring as
 * examples/agent-demo.ts), and captures request + verdict pairs. The PHP
 * suite replays the captured verdicts through the plugin's decision port —
 * so every PHP round-trip test is anchored to output the production
 * verifier actually emitted for a cryptographically genuine request.
 *
 * Regenerate (SDK must be built first):
 *
 *   npm run build -w @ava-pay/agent
 *   npx tsx woocommerce-plugin/scripts/generate-verify-fixtures.ts
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildServer } from '../../src/server.js';
import { StaticAgentDirectory } from '../../src/verifier/agent-directory.js';
import { VisaAgentVerifier } from '../../src/verifier/visa.js';
import { Ap2AgentVerifier } from '../../src/verifier/ap2.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../../src/verifier/web-bot-auth.js';
import { VisaTapVerifier } from '../../src/verifier/visa-tap.js';
import { MultiProtocolVerifier } from '../../src/verifier/multi.js';
import { generateAgentKeyPair, signWithVisa, signWithWebBotAuth } from '../../src/sdk/index.js';
import type { Mandate } from '../../src/types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'tests', 'fixtures', 'verify-fixtures.json');

const AGENT_ID = 'agent_woo_fixture';
const SIGNATURE_AGENT = 'https://agent-demo.ava.example';
const MERCHANT_HOST = 'demo-store.example';
const VERIFY_URL = `https://${MERCHANT_HOST}/wp-json/ava-pay/v1/verify-agent`;

function fixtureMandate(): Mandate {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: `mandate_woo_${now}`,
    iat: now - 5,
    exp: now + 600,
    maxAmountMinor: 50_000,
    currency: 'USD',
    allowedMerchants: [MERCHANT_HOST],
    buyer: { buyerId: 'buyer_fixture_001', country: 'US', displayName: 'Fixture Buyer' },
  } as Mandate;
}

interface SignedPayload {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

async function main(): Promise<void> {
  const keyPair = generateAgentKeyPair();
  const directory = new StaticAgentDirectory();
  directory.add(AGENT_ID, keyPair.publicKey);

  const jwk = keyPair.publicKey.export({ format: 'jwk' });
  const signatureAgentKeys = new StaticSignatureAgentKeys();
  signatureAgentKeys.add(SIGNATURE_AGENT, { keys: [jwk] });

  const verifier = new MultiProtocolVerifier({
    visa: new VisaAgentVerifier({ directory }),
    visaTap: new VisaTapVerifier({ directory }),
    ap2: new Ap2AgentVerifier({ directory }),
    webBotAuth: new WebBotAuthVerifier({ resolver: signatureAgentKeys }),
  });

  const app = await buildServer({ verifier, logger: false });
  await app.ready();

  const mandateBacked = signWithVisa({
    method: 'POST',
    url: VERIFY_URL,
    body: JSON.stringify({ cart: [{ sku: 'WOO-1', qty: 1, price_minor: 4999 }], total_minor: 4999, currency: 'USD' }),
    agentId: AGENT_ID,
    privateKey: keyPair.privateKey,
    mandate: fixtureMandate(),
  });

  const identityOnly = signWithWebBotAuth({
    method: 'GET',
    url: VERIFY_URL,
    signatureAgent: SIGNATURE_AGENT,
    privateKey: keyPair.privateKey,
  });

  // Tamper AFTER signing: flip bytes inside the signature value so the
  // request is structurally valid but cryptographically broken.
  const tamperedWba = signWithWebBotAuth({
    method: 'GET',
    url: VERIFY_URL,
    signatureAgent: SIGNATURE_AGENT,
    privateKey: keyPair.privateKey,
  });
  tamperedWba.headers['signature'] = tamperedWba.headers['signature'].replace(
    /:([A-Za-z0-9+/]{8})/,
    (_m, first8: string) => `:${first8.split('').reverse().join('')}`,
  );

  const noCredentials: SignedPayload = {
    method: 'GET',
    url: VERIFY_URL,
    headers: { host: MERCHANT_HOST, 'user-agent': 'definitely-not-an-agent/1.0' },
  };

  const cases: Array<{ name: string; note: string; request: SignedPayload }> = [
    {
      name: 'ava_tap_mandate_backed',
      note: 'AVA TAP profile, Ed25519, buyer mandate — expects trusted with mandate',
      request: strip(mandateBacked),
    },
    {
      name: 'web_bot_auth_identity_only',
      note: 'Web Bot Auth — expects trusted, identity-only (no mandate)',
      request: strip(identityOnly),
    },
    {
      name: 'web_bot_auth_tampered_signature',
      note: 'Same WBA request with signature bytes flipped — expects invalid_signature',
      request: strip(tamperedWba),
    },
    {
      name: 'no_credentials',
      note: 'Plain browser-ish request — expects missing_agent_credentials',
      request: noCredentials,
    },
  ];

  const fixtures = [];
  for (const c of cases) {
    const res = await app.inject({ method: 'POST', url: '/verify', payload: c.request });
    fixtures.push({
      name: c.name,
      note: c.note,
      request: c.request,
      response: { status: res.statusCode, body: res.json() },
    });
    console.log(`${c.name}: HTTP ${res.statusCode} → ${JSON.stringify(res.json()).slice(0, 120)}`);
  }

  await app.close();

  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(
    OUT,
    JSON.stringify(
      {
        generatedBy: 'woocommerce-plugin/scripts/generate-verify-fixtures.ts',
        note: 'Real SDK signatures verified by the real multi-protocol verifier at generation time.',
        verifyUrl: VERIFY_URL,
        fixtures,
      },
      null,
      2,
    ) + '\n',
  );
  console.log(`wrote ${OUT}: ${fixtures.length} fixtures`);
}

function strip(out: { method: string; url: string; headers: Record<string, string>; body?: string }): SignedPayload {
  return {
    method: out.method,
    url: out.url,
    headers: out.headers,
    ...(out.body !== undefined ? { body: out.body } : {}),
  };
}

await main();
