/**
 * AVA Pay agent demo — multi-protocol.
 *
 *   npm run demo               # Visa Trusted Agent Protocol (RFC 9421 + Ed25519)
 *   npm run demo -- --ap2      # Google Agent Payments Protocol (JWS chain)
 *   npm run demo -- --wba      # IETF Web Bot Auth (what real ChatGPT agent traffic speaks)
 *   npm run demo -- --http     # Same TAP demo against a running API at AVA_PAY_API_URL
 *
 * In default (in-process) mode the script builds an isolated server with the
 * fresh agent keypair pre-registered, signs a real request, and prints the
 * verifier's verdict. No setup. The same primitives a production agent SDK
 * would use.
 */

import { buildServer } from '../src/server.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import { VisaTapVerifier } from '../src/verifier/visa-tap.js';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import {
  buildCheckoutMandateChain,
  buildPaymentMandateChain,
  computeCheckoutHash,
  generateAgentKeyPair,
  makeCheckoutJwt,
  signWithVisa,
  signWithVisaTap,
  signWithWebBotAuth,
} from '../src/sdk/index.js';
import type { Mandate, VerificationResult } from '../src/types.js';

const args = process.argv.slice(2);
const useAp2 = args.includes('--ap2');
const useWba = args.includes('--wba');
const useTap = args.includes('--tap');
const SIGNATURE_AGENT = 'https://agent-demo.ava.example';
const mode = args.includes('--http') ? 'http' : 'inproc';
const apiUrl = process.env.AVA_PAY_API_URL ?? 'http://localhost:3000';

const AGENT_ID = 'agent_demo';
const MERCHANT_HOST = 'shop.example.com';

function visaMandate(): Mandate {
  const now = Math.floor(Date.now() / 1000);
  return {
    id: `mandate_${Date.now()}`,
    iat: now - 5,
    exp: now + 600,
    maxAmountMinor: 50_000,
    currency: 'USD',
    allowedMerchants: [MERCHANT_HOST],
    buyer: { buyerId: 'buyer_alex_001', country: 'US', displayName: 'Alex' },
  };
}

function purchaseBody(): string {
  return JSON.stringify({
    cart: [{ sku: 'TOOL-1234', qty: 1, price_minor: 4999 }],
    total_minor: 4999,
    currency: 'USD',
  });
}

interface SignedPayload {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

async function inProcessRun(): Promise<void> {
  const protocol = useAp2
    ? 'AP2'
    : useWba
      ? 'Web Bot Auth'
      : useTap
        ? 'Visa TAP (real wire format)'
        : 'AVA TAP profile';
  console.log(`▶ Mode: in-process · Protocol: ${protocol}\n`);

  const keyPair = generateAgentKeyPair();
  const directory = new StaticAgentDirectory();
  directory.add(AGENT_ID, keyPair.publicKey);

  // Publish the demo key the way a real agent operator would: as a JWKS at
  // the Signature-Agent origin's well-known key directory.
  const jwk = keyPair.publicKey.export({ format: 'jwk' });
  const signatureAgentKeys = new StaticSignatureAgentKeys();
  signatureAgentKeys.add(SIGNATURE_AGENT, { keys: [jwk] });

  const visa = new VisaAgentVerifier({ directory });
  const visaTap = new VisaTapVerifier({ directory });
  const ap2 = new Ap2AgentVerifier({ directory });
  const webBotAuth = new WebBotAuthVerifier({ resolver: signatureAgentKeys });
  const verifier = new MultiProtocolVerifier({ visa, visaTap, ap2, webBotAuth });

  const app = await buildServer({ verifier, logger: false });
  await app.ready();

  const signed: SignedPayload = useAp2
    ? buildAp2Demo(keyPair)
    : useWba
      ? buildWbaDemo(keyPair)
      : useTap
        ? buildTapDemo(keyPair)
        : buildVisaDemo(keyPair);
  printSignedRequest(signed);

  const res = await app.inject({ method: 'POST', url: '/verify', payload: signed });
  const body = res.json() as VerificationResult;
  printVerdict(res.statusCode, body, res.headers['x-ava-verify-ms'] as string | undefined);

  await app.close();
}

function buildVisaDemo(keyPair: { privateKey: any }): SignedPayload {
  const out = signWithVisa({
    method: 'POST',
    url: `https://${MERCHANT_HOST}/cart`,
    body: purchaseBody(),
    agentId: AGENT_ID,
    privateKey: keyPair.privateKey,
    mandate: visaMandate(),
  });
  return {
    method: out.method,
    url: out.url,
    headers: out.headers,
    ...(out.body !== undefined ? { body: out.body } : {}),
  };
}

function buildAp2Demo(keyPair: { privateKey: any; publicKey: any }): SignedPayload {
  // v0.2: user-signed open mandate delegating to the agent (cnf), closed over
  // a merchant-signed checkout. The demo's registered key plays the user root;
  // a fresh keypair plays the agent; another plays the merchant.
  const agentKeys = generateAgentKeyPair();
  const merchantKeys = generateAgentKeyPair();
  const checkoutJwt = makeCheckoutJwt(
    {
      id: 'checkout_demo_1',
      merchant: { name: 'Demo Shop', url: `https://${MERCHANT_HOST}` },
      line_items: [{ item: { id: 'TOOL-1234', title: 'Demo Tool' }, quantity: 1 }],
      status: 'ready_for_complete',
      currency: 'USD',
      totals: [
        { type: 'subtotal', amount: 4999 },
        { type: 'total', amount: 4999 },
      ],
    },
    merchantKeys.privateKey,
  );
  const aud = `https://${MERCHANT_HOST}`;
  const checkoutChain = buildCheckoutMandateChain({
    user: { privateKey: keyPair.privateKey, kid: AGENT_ID },
    agentPrivateKey: agentKeys.privateKey,
    agentPublicKey: agentKeys.publicKey,
    constraints: [
      {
        type: 'checkout.allowed_merchants',
        allowed: [{ name: 'Demo Shop', url: `https://${MERCHANT_HOST}` }],
      },
    ],
    checkoutJwt,
    aud,
    nonce: `nonce_${Date.now()}`,
  });
  const paymentChain = buildPaymentMandateChain({
    user: { privateKey: keyPair.privateKey, kid: AGENT_ID },
    agentPrivateKey: agentKeys.privateKey,
    agentPublicKey: agentKeys.publicKey,
    constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 50_000 }],
    payment: {
      transaction_id: computeCheckoutHash(checkoutJwt),
      payee: { name: 'Demo Shop', url: `https://${MERCHANT_HOST}` },
      payment_amount: { currency: 'USD', amount: 4999 },
      payment_instrument: { type: 'card', last_four: '4242' },
    },
    aud,
    nonce: `pnonce_${Date.now()}`,
  });
  return {
    method: 'POST',
    url: `https://${MERCHANT_HOST}/cart`,
    headers: {
      host: MERCHANT_HOST,
      'ap2-checkout-mandate': checkoutChain,
      'ap2-payment-mandate': paymentChain,
    },
    body: purchaseBody(),
  };
}

function buildTapDemo(keyPair: { privateKey: any }): SignedPayload {
  const out = signWithVisaTap({
    url: `https://${MERCHANT_HOST}/products/tool-1234`,
    privateKey: keyPair.privateKey,
    keyid: AGENT_ID,
    tag: 'agent-browser-auth',
  });
  return { method: out.method, url: out.url, headers: out.headers };
}

function buildWbaDemo(keyPair: { privateKey: any }): SignedPayload {
  const out = signWithWebBotAuth({
    method: 'GET',
    url: `https://${MERCHANT_HOST}/products/tool-1234`,
    signatureAgent: SIGNATURE_AGENT,
    privateKey: keyPair.privateKey,
  });
  return { method: out.method, url: out.url, headers: out.headers };
}

async function httpRun(): Promise<void> {
  console.log(`▶ Mode: http (target ${apiUrl}/verify) · Protocol: Visa TAP\n`);
  console.error(
    '   ⚠ Generated a fresh keypair, which the running API does not know about.\n' +
      '     Expect "unknown_agent" unless you wire it into the API\'s directory yourself.\n',
  );

  const keyPair = generateAgentKeyPair();
  const signed = buildVisaDemo(keyPair);
  printSignedRequest(signed);

  const res = await fetch(`${apiUrl}/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(signed),
  });
  const body = (await res.json()) as VerificationResult;
  printVerdict(res.status, body, res.headers.get('x-ava-verify-ms') ?? undefined);
}

function printSignedRequest(signed: SignedPayload): void {
  console.log('▶ Signed request');
  console.log(`  ${signed.method} ${signed.url}`);
  for (const [k, v] of Object.entries(signed.headers)) {
    const display = v.length > 100 ? v.slice(0, 96) + ' …' : v;
    console.log(`    ${k}: ${display}`);
  }
  if (signed.body) console.log(`  body: ${signed.body}`);
  console.log();
}

function printVerdict(status: number, body: VerificationResult, elapsed: string | undefined): void {
  console.log('▶ Verdict');
  console.log(`  HTTP ${status}${elapsed ? `   verify-ms: ${elapsed}` : ''}`);
  if (body.trusted) {
    console.log(`  ✓ trusted`);
    if (body.agent) {
      const scope = body.mandate ? 'mandate-backed' : 'identity-only — no mandate';
      console.log(`    agent: ${body.agent.id} (${body.agent.protocol}, ${scope})`);
    }
    if (body.buyerInfo) {
      console.log(`    buyer: ${body.buyerInfo.displayName ?? body.buyerInfo.buyerId}`);
    }
    if (body.mandate) {
      console.log(
        `    mandate: ${body.mandate.id} (max $${body.mandate.maxAmountMinor / 100} ${body.mandate.currency})`,
      );
    }
    if (body.discount !== undefined) console.log(`    discount hint: ${(body.discount * 100).toFixed(1)}%`);
    console.log(`    decision ttl: ${body.ttlSeconds}s`);
  } else {
    console.log(`  ✗ blocked: ${body.reason}`);
    console.log(`    ${body.message}`);
  }
}

if (mode === 'inproc') {
  await inProcessRun();
} else {
  await httpRun();
}
