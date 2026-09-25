import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { signWithWebBotAuth } from '@ava-pay/agent';
import {
  coveredHeaderFields,
  minimizeForwardedHeaders,
  splitDictionaryMembers,
} from './forwarded-headers.js';

const SHOP = 'ava-pay-test-store.myshopify.com';
const URL_SIGNED = `https://${SHOP}/apps/ava-pay/verify`;

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
  'x-ava-agent-id': 'claimed-agent',
};

const { privateKey } = generateKeyPairSync('ed25519');

function wba(
  options: Partial<Parameters<typeof signWithWebBotAuth>[0]> = {},
): Record<string, string> {
  const signed = signWithWebBotAuth({
    method: 'POST',
    url: URL_SIGNED,
    signatureAgent: 'https://agent.example',
    signatureAgentFormat: 'dictionary',
    components: ['@authority', 'signature-agent'],
    privateKey,
    ...options,
  });
  return { ...APP_PROXY_HEADERS, ...signed.headers, host: SHOP };
}

const names = (h: Record<string, string>) => Object.keys(h).sort();

describe('minimizeForwardedHeaders', () => {
  it('forwards only the signature and host for a Web Bot Auth request behind the App Proxy', () => {
    const headers = wba();
    expect(headers['signature-input']).toContain('"signature-agent";key="sig1"');

    expect(names(minimizeForwardedHeaders(headers, { hasBody: false }))).toEqual([
      'host',
      'signature',
      'signature-agent',
      'signature-input',
    ]);
  });

  it('forwards content-digest and content-type when the signature covers them', () => {
    const headers = wba({
      body: '{"cart":[]}',
      components: ['@authority', 'signature-agent', 'content-digest', 'content-type'],
      extraHeaders: { 'content-type': 'application/json' },
    });

    const out = minimizeForwardedHeaders(headers, { hasBody: true });
    expect(names(out)).toEqual([
      'content-digest',
      'content-type',
      'host',
      'signature',
      'signature-agent',
      'signature-input',
    ]);
    expect(out['content-type']).toBe('application/json');
  });

  it('forwards a covered custom header', () => {
    const headers = wba({
      components: ['@authority', 'signature-agent', 'x-example'],
      extraHeaders: { 'x-example': 'kept' },
    });
    expect(minimizeForwardedHeaders(headers, { hasBody: false })['x-example']).toBe('kept');
  });

  it('drops an uncovered user-agent and forwards a covered one', () => {
    expect(minimizeForwardedHeaders(wba(), { hasBody: false })).not.toHaveProperty('user-agent');

    const covered = wba({
      components: ['@authority', 'signature-agent', 'user-agent'],
      extraHeaders: { 'user-agent': APP_PROXY_HEADERS['user-agent'] as string },
    });
    expect(minimizeForwardedHeaders(covered, { hasBody: false })['user-agent']).toBe(
      APP_PROXY_HEADERS['user-agent'],
    );
  });

  it('forwards the fixed set only when Signature-Input is unreadable', () => {
    const headers = {
      ...APP_PROXY_HEADERS,
      host: SHOP,
      signature: 'sig1=:AAAA:',
      'signature-input': 'sig1=("user-agent" "accept-language"',
      'x-ava-mandate': 'e30=',
    };
    expect(names(minimizeForwardedHeaders(headers, { hasBody: false }))).toEqual([
      'host',
      'signature',
      'signature-input',
      'x-ava-mandate',
    ]);
  });

  it('forwards the fixed set when there is no Signature-Input at all', () => {
    const headers = { ...APP_PROXY_HEADERS, host: SHOP, 'ap2-checkout-mandate': 'a~b~c' };
    expect(names(minimizeForwardedHeaders(headers, { hasBody: false }))).toEqual([
      'ap2-checkout-mandate',
      'host',
    ]);
  });

  it('forwards content-type only alongside a body, and content-digest either way', () => {
    const headers = {
      host: SHOP,
      'content-type': 'application/json',
      'content-digest': 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
    };
    expect(names(minimizeForwardedHeaders(headers, { hasBody: false }))).toEqual([
      'content-digest',
      'host',
    ]);
    expect(names(minimizeForwardedHeaders(headers, { hasBody: true }))).toEqual([
      'content-digest',
      'content-type',
      'host',
    ]);
  });

  it('never forwards credentials, even when the signature covers them', () => {
    const headers = wba({
      components: ['@authority', 'signature-agent', 'cookie', 'authorization'],
      extraHeaders: { cookie: '_shopify_y=abc', authorization: 'Bearer secret' },
    });
    expect(coveredHeaderFields(headers['signature-input'])).toEqual([
      'signature-agent',
      'cookie',
      'authorization',
    ]);

    const out = minimizeForwardedHeaders(
      { ...headers, 'proxy-authorization': 'Basic x', 'x-wp-nonce': 'n' },
      { hasBody: false },
    );
    expect(names(out)).toEqual(['host', 'signature', 'signature-agent', 'signature-input']);
  });

  it('lower-cases names on the way out', () => {
    const out = minimizeForwardedHeaders({ Host: SHOP, 'X-Ava-Mandate': 'e30=' }, { hasBody: false });
    expect(out).toEqual({ host: SHOP, 'x-ava-mandate': 'e30=' });
  });
});

describe('coveredHeaderFields', () => {
  it('reads every member, strips component parameters and skips derived components', () => {
    expect(
      coveredHeaderFields(
        'sig1=("@authority" "signature-agent";key="sig1" "Content-Digest";sf);created=1, ' +
          'sig2=("@method" "x-example";bs "content-digest");created=2',
      ),
    ).toEqual(['signature-agent', 'content-digest', 'x-example']);
  });

  it('does not split on a comma inside a quoted parameter', () => {
    expect(
      coveredHeaderFields('sig1=("@authority" "x-a");created=1;nonce="a,b=(\\"x-b\\")"'),
    ).toEqual(['x-a']);
  });

  it('returns null for an unreadable field', () => {
    expect(coveredHeaderFields(undefined)).toBeNull();
    expect(coveredHeaderFields('')).toBeNull();
    expect(coveredHeaderFields('sig1=("x-a"')).toBeNull();
    expect(coveredHeaderFields('sig1=("x-a"), ')).toBeNull();
    expect(coveredHeaderFields('sig1="x-a"')).toBeNull();
    expect(coveredHeaderFields('sig1=("x-a");created=soon')).toBeNull();
  });

  it('splits a dictionary at top-level commas only', () => {
    expect(splitDictionaryMembers('a=("x, y"), b=(1 2);p="q,r"')).toEqual([
      'a=("x, y")',
      'b=(1 2);p="q,r"',
    ]);
    expect(splitDictionaryMembers('a=("x"')).toBeNull();
    expect(splitDictionaryMembers('a="x')).toBeNull();
  });
});
