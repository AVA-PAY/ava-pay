import { createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
// @ts-expect-error — plain .mjs helper script, deliberately untyped and
// dependency-free so app reviewers can run it with nothing but Node.
import { buildSignedAgentRequest, contentDigest } from '../scripts/simulate-verified-agent.mjs';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import { InMemoryReplayGuard } from '../src/verifier/replay.js';
import { DEMO_AGENT_ID, DEMO_AGENT_PUBLIC_JWK } from '../src/directory/seed-demo.js';
import type { IncomingRequest } from '../src/types.js';

/**
 * scripts/simulate-verified-agent.mjs is the copy-paste command in the Shopify
 * app review testing instructions. It re-implements Visa-profile RFC 9421
 * signing with no dependencies, so a reviewer needs nothing but Node — which
 * means its signing code can drift from the SDK's. These tests close that gap
 * by verifying its output with the real verifier and real crypto.
 */

const SHOP = 'ava-pay-test-store.myshopify.com';

function verifier() {
  // The same public half the API seeds into its hosted directory on boot.
  const directory = new StaticAgentDirectory();
  directory.add(
    DEMO_AGENT_ID,
    createPublicKey({ key: { ...DEMO_AGENT_PUBLIC_JWK }, format: 'jwk' }),
  );
  return new VisaAgentVerifier({ directory, replayGuard: new InMemoryReplayGuard() });
}

describe('simulate-verified-agent.mjs', () => {
  it('produces a request the real verifier trusts', async () => {
    const signed = buildSignedAgentRequest(SHOP) as IncomingRequest;
    const result = await verifier().verify(signed);

    expect(result.trusted).toBe(true);
    if (!result.trusted) return;
    expect(result.mandate?.allowedMerchants).toEqual([SHOP]);
    expect(result.buyerInfo?.buyerId).toBe('buyer_demo_001');
  });

  it('signs the store the reviewer named, so the mandate matches the host', () => {
    const other = 'someone-elses-store.myshopify.com';
    const signed = buildSignedAgentRequest(other);
    expect(signed.url).toBe(`https://${other}/apps/ava-pay/verify`);
    expect(signed.headers.host).toBe(other);
  });

  it('computes the same Content-Digest the SDK does', async () => {
    const { computeContentDigest } = await import('@ava-pay/agent/protocol/visa');
    for (const body of ['', '{"a":1}', 'unicode: ✓ é 🙂']) {
      expect(contentDigest(body)).toBe(computeContentDigest(body));
    }
  });

  // Tamper checks: proof the signature really covers the request, so a
  // reviewer's verified event cannot be faked by editing headers.
  it('fails verification when the body is altered after signing', async () => {
    const signed = buildSignedAgentRequest(SHOP) as IncomingRequest;
    const tampered = { ...signed, body: '{"cart":[{"sku":"FREE","qty":99}]}' };
    const result = await verifier().verify(tampered);
    expect(result.trusted).toBe(false);
  });

  it('fails verification when the mandate is swapped after signing', async () => {
    const signed = buildSignedAgentRequest(SHOP) as IncomingRequest;
    const forged = Buffer.from(
      JSON.stringify({
        id: 'mandate_forged',
        iat: Math.floor(Date.now() / 1000) - 5,
        exp: Math.floor(Date.now() / 1000) + 600,
        maxAmountMinor: 100_000_000,
        currency: 'USD',
        allowedMerchants: [SHOP],
        buyer: { buyerId: 'buyer_demo_001', country: 'US', displayName: 'Demo Shopper' },
      }),
      'utf-8',
    ).toString('base64');
    const tampered = {
      ...signed,
      headers: { ...signed.headers, 'x-ava-mandate': forged },
    };
    const result = await verifier().verify(tampered);
    expect(result.trusted).toBe(false);
  });

  // Why the script signs immediately before each send rather than once up
  // front: a request signed before a password prompt ages past the verifier's
  // maximum signature age while the human types, and comes back
  // signature_expired. Production reproduced exactly this.
  it('rejects a request signed several minutes before it is sent', async () => {
    const stale = buildSignedAgentRequest(SHOP, {
      created: Math.floor(Date.now() / 1000) - 600,
    }) as IncomingRequest;
    const result = await verifier().verify(stale);
    expect(result.trusted).toBe(false);
    if (result.trusted) return;
    expect(result.reason).toBe('signature_expired');
  });

  it('gives every build a fresh nonce, so a retry is not seen as a replay', async () => {
    const v = verifier();
    const first = buildSignedAgentRequest(SHOP) as IncomingRequest;
    const second = buildSignedAgentRequest(SHOP) as IncomingRequest;
    expect(second.headers['signature-input']).not.toBe(first.headers['signature-input']);
    expect((await v.verify(first)).trusted).toBe(true);
    expect((await v.verify(second)).trusted).toBe(true);
  });

  it('rejects a replayed request, since the nonce is single use', async () => {
    const v = verifier();
    const signed = buildSignedAgentRequest(SHOP) as IncomingRequest;
    expect((await v.verify(signed)).trusted).toBe(true);
    const replayed = await v.verify(signed);
    expect(replayed.trusted).toBe(false);
  });
});
