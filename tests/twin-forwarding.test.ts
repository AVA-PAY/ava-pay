import { createPublicKey } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { VisaTapVerifier } from '../src/verifier/visa-tap.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import { DEMO_AGENT_ID, DEMO_AGENT_PUBLIC_JWK } from '../src/directory/seed-demo.js';
import {
  buildCheckoutMandateChain,
  buildPaymentMandateChain,
  computeCheckoutHash,
  generateAgentKeyPair,
  makeCheckoutJwt,
  signWithVisaTap,
  signWithWebBotAuth,
  type AgentKeyPair,
} from '../src/sdk/index.js';
import type { IncomingRequest, VerificationResult } from '../src/types.js';
import { AvaPayClient } from '../shopify-app/app/lib/ava.server.js';
import { buildTestVisitRequest } from '../shopify-app/app/lib/test-visit-request.js';

/**
 * The Shopify app forwards only what the verifier needs (lib/forwarded-headers.ts,
 * applied inside AvaPayClient.verify). This is the end-to-end proof that a
 * minimized request still verifies: the real client, its real outbound JSON,
 * the real /verify route and the real verifiers, one per protocol. Nothing is
 * mocked but the network hop, which app.inject replaces.
 */

const SHOP = 'ava-pay-test-store.myshopify.com';
const SIGNED_URL = `https://${SHOP}/apps/ava-pay/verify`;
const AGENT_ORIGIN = 'https://agent.example';
const TAP_AGENT_ID = 'tap_agent_demo';
const USER_KID = 'user_wallet_1';
const AUD = `https://${SHOP}`;

/** What Shopify's App Proxy hands the app alongside an agent's own headers. */
const APP_PROXY_HEADERS: Record<string, string> = {
  'x-forwarded-for': '203.0.113.7, 10.0.0.1',
  'x-forwarded-proto': 'https',
  'x-forwarded-host': SHOP,
  'user-agent': 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36',
  cookie: '_shopify_y=abc; cart=xyz',
  accept: 'application/json',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, br',
  'x-shopify-shop-domain': SHOP,
  'x-shopify-request-id': '4f1c-8a2e',
  'x-request-id': 'req-1',
};

/** The route's own construction: every header, then the host it rebuilt. */
function throughAppProxy(signed: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}): IncomingRequest {
  return {
    method: signed.method,
    url: signed.url,
    headers: { ...APP_PROXY_HEADERS, ...signed.headers, host: SHOP },
    ...(signed.body !== undefined ? { body: signed.body } : {}),
  };
}

describe('Shopify twin: minimized forwarding still verifies', () => {
  let app: FastifyInstance;
  let client: AvaPayClient;
  let sent: IncomingRequest[];
  let wbaKeys: AgentKeyPair;
  let tapKeys: AgentKeyPair;
  let userKeys: AgentKeyPair;
  let agentKeys: AgentKeyPair;
  let checkoutJwt: string;

  async function verify(request: IncomingRequest): Promise<VerificationResult> {
    const call = await client.verify(request);
    if (!call.ok) throw new Error(`client call failed: ${call.error}`);
    return call.result;
  }

  const lastSentNames = () => Object.keys(sent[sent.length - 1]!.headers).sort();

  beforeAll(async () => {
    wbaKeys = generateAgentKeyPair();
    tapKeys = generateAgentKeyPair();
    userKeys = generateAgentKeyPair();
    agentKeys = generateAgentKeyPair();
    const merchantKeys = generateAgentKeyPair();
    checkoutJwt = makeCheckoutJwt(
      {
        id: 'checkout_1',
        merchant: { name: 'Demo Shop', url: AUD },
        line_items: [{ item: { id: 'SKU-1', title: 'Widget' }, quantity: 1 }],
        status: 'ready_for_complete',
        currency: 'USD',
        totals: [
          { type: 'subtotal', amount: 4999 },
          { type: 'total', amount: 4999 },
        ],
      },
      merchantKeys.privateKey,
    );

    const directory = new StaticAgentDirectory();
    directory.add(TAP_AGENT_ID, tapKeys.publicKey);
    directory.add(USER_KID, userKeys.publicKey);
    directory.add(DEMO_AGENT_ID, createPublicKey({ key: { ...DEMO_AGENT_PUBLIC_JWK }, format: 'jwk' }));
    const wbaResolver = new StaticSignatureAgentKeys();
    wbaResolver.add(AGENT_ORIGIN, {
      keys: [wbaKeys.publicKey.export({ format: 'jwk' }) as object],
    });

    const verifier = new MultiProtocolVerifier({
      visa: new VisaAgentVerifier({ directory }),
      visaTap: new VisaTapVerifier({ directory }),
      ap2: new Ap2AgentVerifier({ directory }),
      webBotAuth: new WebBotAuthVerifier({ resolver: wbaResolver }),
    });
    app = await buildServer({ verifier, logger: false });
    await app.ready();

    sent = [];
    const fetcher = (async (_url: unknown, init?: RequestInit) => {
      const payload = JSON.parse(String(init?.body)) as IncomingRequest;
      sent.push(payload);
      const res = await app.inject({ method: 'POST', url: '/verify', payload });
      return new Response(res.body, {
        status: res.statusCode,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
    client = new AvaPayClient({ baseUrl: 'http://ava-pay.test', fetcher, timeoutMs: 10_000 });
  });

  afterAll(async () => {
    await app.close();
  });

  it('Web Bot Auth: forwards signature, signature-input, signature-agent and host, and verifies', async () => {
    const signed = signWithWebBotAuth({
      method: 'POST',
      url: SIGNED_URL,
      signatureAgent: AGENT_ORIGIN,
      signatureAgentFormat: 'dictionary',
      components: ['@authority', 'signature-agent'],
      privateKey: wbaKeys.privateKey,
    });
    const result = await verify(throughAppProxy(signed));

    expect(lastSentNames()).toEqual(['host', 'signature', 'signature-agent', 'signature-input']);
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.protocol).toBe('web-bot-auth');
    expect(result.agent?.id).toBe(AGENT_ORIGIN);
  });

  it('Web Bot Auth with a covered body: content-digest and content-type travel and verify', async () => {
    const body = '{"cart":[]}';
    const signed = signWithWebBotAuth({
      method: 'POST',
      url: SIGNED_URL,
      body,
      signatureAgent: AGENT_ORIGIN,
      signatureAgentFormat: 'dictionary',
      components: ['@authority', 'signature-agent', 'content-digest', 'content-type'],
      extraHeaders: { 'content-type': 'application/json' },
      privateKey: wbaKeys.privateKey,
    });
    const result = await verify(throughAppProxy(signed));

    expect(lastSentNames()).toEqual([
      'content-digest',
      'content-type',
      'host',
      'signature',
      'signature-agent',
      'signature-input',
    ]);
    expect(result.trusted).toBe(true);
  });

  it('Visa TAP (real wire format): verifies after minimization', async () => {
    const signed = signWithVisaTap({
      url: SIGNED_URL,
      privateKey: tapKeys.privateKey,
      keyid: TAP_AGENT_ID,
    });
    const result = await verify(throughAppProxy(signed));

    expect(lastSentNames()).toEqual(['host', 'signature', 'signature-input']);
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.protocol).toBe('visa-tap');
  });

  it('AVA TAP profile (the Settings test visit): the mandate and body headers travel and verify', async () => {
    const request = buildTestVisitRequest(SHOP);
    const result = await verify(throughAppProxy(request));

    expect(lastSentNames()).toEqual([
      'content-digest',
      'content-type',
      'host',
      'signature',
      'signature-input',
      'x-ava-mandate',
    ]);
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.protocol).toBe('ava-tap');
  });

  it('AP2: the checkout and payment mandate chains travel and verify', async () => {
    const iat = Math.floor(Date.now() / 1000) - 5;
    const checkout = buildCheckoutMandateChain({
      user: { privateKey: userKeys.privateKey, kid: USER_KID },
      agentPrivateKey: agentKeys.privateKey,
      agentPublicKey: agentKeys.publicKey,
      constraints: [
        { type: 'checkout.allowed_merchants', allowed: [{ name: 'Demo Shop', url: AUD }] },
      ],
      checkoutJwt,
      aud: AUD,
      nonce: 'twin-checkout-1',
      iat,
    });
    const payment = buildPaymentMandateChain({
      user: { privateKey: userKeys.privateKey, kid: USER_KID },
      agentPrivateKey: agentKeys.privateKey,
      agentPublicKey: agentKeys.publicKey,
      constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 50_000 }],
      payment: {
        transaction_id: computeCheckoutHash(checkoutJwt),
        payee: { name: 'Demo Shop', url: AUD },
        payment_amount: { currency: 'USD', amount: 4999 },
        payment_instrument: { type: 'card', last_four: '4242' },
      },
      aud: AUD,
      nonce: 'twin-payment-1',
      iat,
    });
    const result = await verify(
      throughAppProxy({
        method: 'POST',
        url: SIGNED_URL,
        headers: { 'ap2-checkout-mandate': checkout, 'ap2-payment-mandate': payment },
      }),
    );

    expect(lastSentNames()).toEqual(['ap2-checkout-mandate', 'ap2-payment-mandate', 'host']);
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.protocol).toBe('ap2');
  });

  it('a signature covering the cookie fails at the API: credentials never travel', async () => {
    const signed = signWithWebBotAuth({
      method: 'POST',
      url: SIGNED_URL,
      signatureAgent: AGENT_ORIGIN,
      signatureAgentFormat: 'dictionary',
      components: ['@authority', 'signature-agent', 'cookie'],
      extraHeaders: { cookie: APP_PROXY_HEADERS.cookie as string },
      privateKey: wbaKeys.privateKey,
    });
    const result = await verify(throughAppProxy(signed));

    expect(lastSentNames()).toEqual(['host', 'signature', 'signature-agent', 'signature-input']);
    // Intended: an agent covering the shopper's cookies is misconfigured or
    // hostile, and the verifier reports the covered header it did not get.
    expect(result).toMatchObject({ trusted: false, reason: 'covered_component_missing' });
  });

  it('an unreadable Signature-Input still reaches the verifier and gets the same honest reason', async () => {
    const request = throughAppProxy({
      method: 'POST',
      url: SIGNED_URL,
      headers: {
        signature: 'sig1=:AAAA:',
        'signature-input': 'sig1=("user-agent"',
        'x-ava-mandate': 'e30=',
      },
    });
    const result = await verify(request);

    expect(lastSentNames()).toEqual(['host', 'signature', 'signature-input', 'x-ava-mandate']);
    expect(result).toMatchObject({ trusted: false, reason: 'malformed_signature_header' });

    // The same request unminimized gets the same verdict: dropping headers the
    // signature does not name cannot change what the verifier concludes.
    const full = await app.inject({ method: 'POST', url: '/verify', payload: request });
    expect(full.json()).toMatchObject({ trusted: false, reason: 'malformed_signature_header' });
  });
});
