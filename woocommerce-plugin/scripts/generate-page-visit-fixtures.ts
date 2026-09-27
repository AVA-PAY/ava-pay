/**
 * Fixtures for the signed page-visit path (plugin 0.4.0).
 *
 * Each case is a front-end page request signed with the SDK's real signers,
 * turned into the $_SERVER array PHP would hand WordPress for it (the agent's
 * headers plus the noise a real request carries: cookies, a user agent,
 * spoofed X-Forwarded-* headers, an Authorization header). Alongside it, the
 * request that should leave the site: the signed method and URL, and the
 * headers as the REAL Shopify-app minimizer would forward them.
 *
 * Two suites consume the file, and together they close the loop:
 *
 *   - PHPUnit (PageVisitTest) asserts AVA_Pay_Page_Visit::reconstruct() turns
 *     each `server` into exactly `expected`;
 *   - the API suite (tests/woo-page-visit.test.ts) posts each `expected` to
 *     the real /verify route and real verifiers, and requires a trusted
 *     verdict.
 *
 * Keys come from fixed seeds and every signature parameter is fixed, and
 * Ed25519 is deterministic, so the output is byte-stable and CI can diff it:
 *
 *   npx tsx woocommerce-plugin/scripts/generate-page-visit-fixtures.ts
 */

import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signWithVisaTap, signWithWebBotAuth } from '../../src/sdk/index.js';
import { minimizeForwardedHeaders } from '../../shopify-app/app/lib/forwarded-headers.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'tests', 'fixtures', 'page-visit-fixtures.json');

const CREATED = 1790345533;
const WBA_ORIGIN = 'https://agent.example';
const TAP_KEYID = 'tap_agent_page_visit';

/** Test-only Ed25519 key from a fixed 32-byte seed (PKCS#8 wrapper + seed). */
function ed25519FromSeed(seedHex: string): { privateKey: KeyObject; publicKey: KeyObject } {
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(seedHex, 'hex'),
  ]);
  const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

const wbaKey = ed25519FromSeed('11'.repeat(32));
const tapKey = ed25519FromSeed('22'.repeat(32));

/** What else a real page request carries, as $_SERVER keys. */
const NOISE: Record<string, string> = {
  HTTP_ACCEPT: 'text/html,application/xhtml+xml',
  HTTP_ACCEPT_LANGUAGE: 'en-US,en;q=0.9',
  HTTP_ACCEPT_ENCODING: 'gzip, br',
  HTTP_USER_AGENT: 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36',
  HTTP_COOKIE: 'wordpress_logged_in_x=abc; woocommerce_cart_hash=def',
  HTTP_AUTHORIZATION: 'Basic dXNlcjpwYXNz',
  // Spoofed: the reconstruction must never read these.
  HTTP_X_FORWARDED_HOST: 'attacker.example',
  HTTP_X_FORWARDED_PROTO: 'http',
  HTTP_X_FORWARDED_FOR: '198.51.100.9, 10.0.0.1',
};

interface Signed {
  method: string;
  url: string;
  headers: Record<string, string>;
}

function serverFor(signed: Signed, port: string): Record<string, string> {
  const origin = /^https:\/\/[^/]+/.exec(signed.url)?.[0] ?? '';
  const server: Record<string, string> = {
    REQUEST_METHOD: signed.method,
    // Raw, exactly as requested: not URL-normalized.
    REQUEST_URI: signed.url.slice(origin.length),
    HTTPS: 'on',
    SERVER_PORT: port,
    SERVER_NAME: 'shop.example',
    REMOTE_ADDR: '203.0.113.7',
    SCRIPT_NAME: '/index.php',
    ...NOISE,
  };
  for (const [name, value] of Object.entries(signed.headers)) {
    server[`HTTP_${name.toUpperCase().replace(/-/g, '_')}`] = value;
  }
  return server;
}

/** The header map PHP should build from `server`, before minimizing. */
function headersOf(server: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(server)) {
    if (key.startsWith('HTTP_')) out[key.slice(5).toLowerCase().replace(/_/g, '-')] = value;
  }
  return out;
}

function fixture(name: string, protocol: string, signed: Signed, port: string, path: string) {
  const server = serverFor(signed, port);
  return {
    name,
    protocol,
    server,
    isSsl: true,
    expected: {
      method: signed.method,
      url: signed.url,
      headers: minimizeForwardedHeaders(headersOf(server), { hasBody: false }),
    },
    expectedPath: path,
  };
}

const cases = [
  fixture(
    'wba_port_and_query',
    'web-bot-auth',
    signWithWebBotAuth({
      method: 'GET',
      url: 'https://shop.example:8443/product/widget?color=blue&size=m',
      signatureAgent: WBA_ORIGIN,
      signatureAgentFormat: 'dictionary',
      components: ['@authority', '@method', '@path', '@query', 'signature-agent'],
      privateKey: wbaKey.privateKey,
      created: CREATED,
      nonce: 'cGFnZS12aXNpdC0x',
    }),
    '8443',
    '/product/widget',
  ),
  fixture(
    'wba_bare_string_head',
    'web-bot-auth',
    signWithWebBotAuth({
      method: 'HEAD',
      url: 'https://shop.example/shop/',
      signatureAgent: WBA_ORIGIN,
      privateKey: wbaKey.privateKey,
      created: CREATED,
      nonce: 'cGFnZS12aXNpdC0y',
    }),
    '443',
    '/shop/',
  ),
  fixture(
    'wba_covers_user_agent',
    'web-bot-auth',
    signWithWebBotAuth({
      method: 'GET',
      url: 'https://shop.example/product/caf%C3%A9-mug?ref=chat&q=a%20b',
      signatureAgent: WBA_ORIGIN,
      signatureAgentFormat: 'dictionary',
      components: ['@authority', '@method', '@path', '@query', 'signature-agent', 'user-agent'],
      extraHeaders: { 'user-agent': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0' },
      privateKey: wbaKey.privateKey,
      created: CREATED,
      nonce: 'cGFnZS12aXNpdC0z',
    }),
    '443',
    '/product/caf%C3%A9-mug',
  ),
  fixture(
    'visa_tap_port_and_query',
    'visa-tap',
    signWithVisaTap({
      url: 'https://shop.example:8443/product/widget?color=blue',
      privateKey: tapKey.privateKey,
      keyid: TAP_KEYID,
      created: CREATED,
      nonce: 'page-visit-tap-1',
    }),
    '8443',
    '/product/widget',
  ),
];

const out = {
  generatedBy: 'woocommerce-plugin/scripts/generate-page-visit-fixtures.ts',
  note: 'Do not edit by hand. Test keys only.',
  created: CREATED,
  webBotAuth: {
    origin: WBA_ORIGIN,
    publicJwk: wbaKey.publicKey.export({ format: 'jwk' }),
  },
  visaTap: {
    keyid: TAP_KEYID,
    publicJwk: tapKey.publicKey.export({ format: 'jwk' }),
  },
  cases,
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, `${JSON.stringify(out, null, 2)}\n`);
// eslint-disable-next-line no-console
console.log(`wrote ${cases.length} page-visit cases to ${OUT}`);
