import { describe, expect, it } from 'vitest';
import {
  FORWARDED_HEADERS,
  VISIT_SOURCE_HEADER,
  VISIT_SOURCE_TEST,
  agentUrlParams,
  resolveVisitSource,
  storefrontVisitUrl,
} from './storefront-visit.js';
import { EMBED_SCRIPT } from './embed-script.js';

const SHOP = 'ava-pay-test-store.myshopify.com';

/** A plausible signed header set, minus anything the URL should not carry. */
const SIGNED = {
  host: SHOP,
  'content-type': 'application/json',
  'content-digest': 'sha-256=:abc:',
  'x-ava-mandate': 'eyJpZCI6Im0ifQ==',
  [VISIT_SOURCE_HEADER]: VISIT_SOURCE_TEST,
  'signature-input': `sig1=("@method" "x-ava-mandate" "${VISIT_SOURCE_HEADER}");created=1;keyid="k"`,
  signature: 'sig1=:AAA+/BB==:',
};

describe('agentUrlParams', () => {
  it('carries the signed material and drops what the browser sets itself', () => {
    const params = agentUrlParams(SIGNED);

    expect(params.get('signature')).toBe(SIGNED.signature);
    expect(params.get('signature-input')).toBe(SIGNED['signature-input']);
    expect(params.get('content-digest')).toBe(SIGNED['content-digest']);
    expect(params.get('x-ava-mandate')).toBe(SIGNED['x-ava-mandate']);
    expect(params.get(VISIT_SOURCE_HEADER)).toBe(VISIT_SOURCE_TEST);

    // Host comes from the URL the browser is loading, content-type from the
    // fetch the embed makes. Neither is ours to put in an address bar.
    expect(params.has('host')).toBe(false);
    expect(params.has('content-type')).toBe(false);
  });

  it('survives the round trip through a query string intact', () => {
    // Base64 signatures carry + / = and the signature input carries spaces and
    // quotes. All of it has to come back byte for byte or the base recomputes
    // to something else and a genuine signature reads as forged.
    const url = new URL(storefrontVisitUrl(SHOP, SIGNED));

    for (const [name, value] of agentUrlParams(SIGNED)) {
      expect(url.searchParams.get(name), name).toBe(value);
    }
  });
});

describe('storefrontVisitUrl', () => {
  it('points at the shop home page by default', () => {
    const url = new URL(storefrontVisitUrl(SHOP, SIGNED));
    expect(url.origin).toBe(`https://${SHOP}`);
    expect(url.pathname).toBe('/');
  });

  it('can land on any storefront path', () => {
    const url = new URL(storefrontVisitUrl(SHOP, SIGNED, '/collections/all'));
    expect(url.pathname).toBe('/collections/all');
  });
});

describe('resolveVisitSource', () => {
  it('labels a signed marker on a trusted verdict as a merchant test', () => {
    expect(resolveVisitSource(SIGNED, true)).toBe(VISIT_SOURCE_TEST);
  });

  it('ignores the marker when the verdict was not trusted', () => {
    expect(resolveVisitSource(SIGNED, false)).toBe('storefront');
  });

  it('ignores a marker that was not inside the signature', () => {
    // Exactly what a passing visitor can do: append the parameter to a
    // storefront URL. Only the cover set is beyond their reach.
    const headers = {
      ...SIGNED,
      'signature-input': 'sig1=("@method" "x-ava-mandate");created=1;keyid="k"',
    };
    expect(resolveVisitSource(headers, true)).toBe('storefront');
  });

  it('ignores a marker with no signature-input at all', () => {
    const { 'signature-input': _dropped, ...headers } = SIGNED;
    expect(resolveVisitSource(headers, true)).toBe('storefront');
  });

  it('ignores any value other than test', () => {
    expect(resolveVisitSource({ ...SIGNED, [VISIT_SOURCE_HEADER]: 'organic' }, true)).toBe(
      'storefront',
    );
  });

  it('leaves ordinary agent traffic alone', () => {
    const { [VISIT_SOURCE_HEADER]: _marker, ...headers } = SIGNED;
    expect(resolveVisitSource(headers, true)).toBe('storefront');
  });
});

describe('the forwarded header list', () => {
  it('is the same list the storefront script reads out of the URL', () => {
    // The two live in different files because one runs in the browser as text.
    // If they drift, a signed component silently stops travelling and every
    // signature fails to recompute.
    const declared = EMBED_SCRIPT.match(/const SIG_PARAMS = \[([^\]]*)\]/)?.[1];
    expect(declared).toBeDefined();

    const names = [...(declared ?? '').matchAll(/'([^']+)'/g)].map((m) => m[1]);
    expect(names).toEqual([...FORWARDED_HEADERS]);
  });

  it('lets the mandate and the test marker through on the x- rule', () => {
    for (const name of ['x-ava-mandate', VISIT_SOURCE_HEADER]) {
      expect(name.startsWith('x-'), name).toBe(true);
    }
  });
});
