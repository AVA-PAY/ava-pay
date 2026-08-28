import { createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import { InMemoryReplayGuard } from '../src/verifier/replay.js';
import { DEMO_AGENT_ID, DEMO_AGENT_PUBLIC_JWK } from '../src/directory/seed-demo.js';
import type { IncomingRequest } from '../src/types.js';
import { buildStorefrontVisitUrl } from '../shopify-app/app/lib/storefront-visit.server.js';
import {
  FORWARDED_HEADERS,
  VISIT_SOURCE_HEADER,
  resolveVisitSource,
} from '../shopify-app/app/lib/storefront-visit.js';
import {
  storefrontVisitUrl as scriptStorefrontVisitUrl,
  buildSignedAgentRequest,
  // @ts-expect-error: plain .mjs helper script, deliberately untyped and
  // dependency-free so app reviewers can run it with nothing but Node.
} from '../scripts/simulate-verified-agent.mjs';

/**
 * "View a test agent visit on your storefront" is the path an app reviewer
 * takes to see the storefront banner, so the thing that has to be true is that
 * the URL it produces really does verify, through the real verifier, after
 * making the round trip through a page URL and back out as headers.
 *
 * Nothing here is mocked: the signature is genuine, the directory holds the
 * demo agent's real public half, and a tampered parameter has to fail.
 */

const SHOP = 'ava-pay-test-store.myshopify.com';

function verifier() {
  const directory = new StaticAgentDirectory();
  directory.add(
    DEMO_AGENT_ID,
    createPublicKey({ key: { ...DEMO_AGENT_PUBLIC_JWK }, format: 'jwk' }),
  );
  return new VisaAgentVerifier({ directory, replayGuard: new InMemoryReplayGuard() });
}

/**
 * What the storefront does with the link: the app embed lifts the signed
 * parameters off the page URL and posts them to the App Proxy as headers, with
 * an empty body, and routes/proxy.verify.tsx restores the host and target URL
 * the agent signed against. This mirrors both halves.
 */
function deliverThroughEmbed(shop: string, visitUrl: string): IncomingRequest {
  const headers: Record<string, string> = {};
  for (const [name, value] of new URL(visitUrl).searchParams) {
    const lower = name.toLowerCase();
    const forwarded =
      (FORWARDED_HEADERS as readonly string[]).includes(lower) || lower.startsWith('x-');
    if (forwarded && value) headers[lower] = value;
  }
  headers['host'] = shop;
  return { method: 'POST', url: `https://${shop}/apps/ava-pay/verify`, headers };
}

describe('storefront test visit', () => {
  it('lands on the storefront, not on the app proxy endpoint', () => {
    const url = new URL(buildStorefrontVisitUrl(SHOP));
    expect(url.origin).toBe(`https://${SHOP}`);
    expect(url.pathname).toBe('/');
  });

  it('verifies for real once the embed forwards it back', async () => {
    const request = deliverThroughEmbed(SHOP, buildStorefrontVisitUrl(SHOP));
    const result = await verifier().verify(request);

    expect(result.trusted).toBe(true);
    if (!result.trusted) return;
    expect(result.protocol).toBe('ava-tap');
    expect(result.mandate?.allowedMerchants).toEqual([SHOP]);
    expect(result.buyerInfo?.buyerId).toBe('buyer_demo_001');
  });

  it('carries no body, so the Content-Digest describes what actually arrives', async () => {
    const request = deliverThroughEmbed(SHOP, buildStorefrontVisitUrl(SHOP));
    expect(request.body).toBeUndefined();
    // The digest is still a covered component and still has to be the digest of
    // an empty body, or the signature base would not recompute.
    expect(request.headers['content-digest']).toBe(
      'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
    );
    expect((await verifier().verify(request)).trusted).toBe(true);
  });

  it('is labelled a test visit, because the marker was inside the signature', async () => {
    const request = deliverThroughEmbed(SHOP, buildStorefrontVisitUrl(SHOP));
    const result = await verifier().verify(request);

    expect(request.headers['signature-input']).toContain(`"${VISIT_SOURCE_HEADER}"`);
    expect(resolveVisitSource(request.headers, result.trusted)).toBe('test');
  });

  it('gives every link a fresh nonce, so a second click is not a replay', () => {
    const nonceOf = (url: string) =>
      new URL(url).searchParams.get('signature-input')?.match(/nonce="([^"]+)"/)?.[1];

    expect(nonceOf(buildStorefrontVisitUrl(SHOP))).not.toBe(
      nonceOf(buildStorefrontVisitUrl(SHOP)),
    );
  });

  it('signs the store it was asked for, so the mandate matches the host', () => {
    const other = 'someone-elses-store.myshopify.com';
    const request = deliverThroughEmbed(other, buildStorefrontVisitUrl(other));
    expect(request.headers['host']).toBe(other);
  });

  it('fails verification when a parameter is edited in the address bar', async () => {
    const url = new URL(buildStorefrontVisitUrl(SHOP));
    const mandate = JSON.parse(
      Buffer.from(url.searchParams.get('x-ava-mandate') ?? '', 'base64').toString('utf-8'),
    );
    mandate.maxAmountMinor = 999_999_99;
    url.searchParams.set(
      'x-ava-mandate',
      Buffer.from(JSON.stringify(mandate), 'utf-8').toString('base64'),
    );

    const result = await verifier().verify(deliverThroughEmbed(SHOP, url.toString()));
    expect(result.trusted).toBe(false);
    if (result.trusted) return;
    expect(result.reason).toBe('invalid_signature');
  });
});

describe('the test-visit marker', () => {
  const signed = () => deliverThroughEmbed(SHOP, buildStorefrontVisitUrl(SHOP)).headers;

  it('is ignored on a verdict that was never trusted', () => {
    // An untrusted verdict proves nothing about anything the request claimed,
    // including which button it came from.
    expect(resolveVisitSource(signed(), false)).toBe('storefront');
  });

  it('is ignored when it was not inside the signature', () => {
    // What a passing visitor can do: append the parameter to a storefront URL.
    // The cover set is what they cannot forge, so that is what is checked.
    const headers = signed();
    const covered = headers['signature-input'] ?? '';
    headers['signature-input'] = covered.replace(` "${VISIT_SOURCE_HEADER}"`, '');
    expect(headers['signature-input']).not.toContain(VISIT_SOURCE_HEADER);
    expect(resolveVisitSource(headers, true)).toBe('storefront');
  });

  it('is ignored when it says anything other than test', () => {
    expect(resolveVisitSource({ ...signed(), [VISIT_SOURCE_HEADER]: 'agent' }, true)).toBe(
      'storefront',
    );
  });

  it('is absent from ordinary agent traffic, which stays storefront traffic', () => {
    const request = buildSignedAgentRequest(SHOP) as IncomingRequest;
    expect(request.headers[VISIT_SOURCE_HEADER]).toBeUndefined();
    expect(resolveVisitSource(request.headers, true)).toBe('storefront');
  });
});

describe('simulate-verified-agent.mjs --emit-url', () => {
  it('emits a URL that verifies through the same embed round trip', async () => {
    const url = scriptStorefrontVisitUrl(
      SHOP,
      buildSignedAgentRequest(SHOP, { body: '' }).headers,
    );
    const result = await verifier().verify(deliverThroughEmbed(SHOP, url));

    expect(result.trusted).toBe(true);
  });

  it('forwards the same parameter set the app does', () => {
    const url = scriptStorefrontVisitUrl(
      SHOP,
      buildSignedAgentRequest(SHOP, { body: '' }).headers,
    );
    const names = [...new URL(url).searchParams.keys()].sort();

    expect(names).toEqual(
      ['signature', 'signature-input', 'content-digest', 'x-ava-mandate'].sort(),
    );
    // Host is set by the browser from the URL itself, and content-type by the
    // fetch the embed makes; neither belongs in the address bar.
    expect(names).not.toContain('host');
    expect(names).not.toContain('content-type');
  });

  it('leaves the demo credential as ordinary agent traffic, not a merchant test', () => {
    const url = scriptStorefrontVisitUrl(
      SHOP,
      buildSignedAgentRequest(SHOP, { body: '' }).headers,
    );
    expect(new URL(url).searchParams.get(VISIT_SOURCE_HEADER)).toBeNull();
  });
});
