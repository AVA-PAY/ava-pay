import { createPublicKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  buildSignedAgentRequest,
  buildWebBotAuthRequest,
  contentDigest,
  ed25519JwkThumbprint,
  parseArgs,
  PROBE_SIGNATURE_AGENT,
  // @ts-expect-error: plain .mjs helper script, deliberately untyped and
  // dependency-free so app reviewers can run it with nothing but Node.
} from '../scripts/simulate-verified-agent.mjs';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import { InMemoryReplayGuard } from '../src/verifier/replay.js';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import { DEMO_AGENT_ID, DEMO_AGENT_PUBLIC_JWK } from '../src/directory/seed-demo.js';
import type { AgentVerifier } from '../src/verifier/interface.js';
import type { IncomingRequest, VerificationResult } from '../src/types.js';

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

/**
 * The --web-bot-auth probe. Its job in production is to reach one specific
 * state: a Web Bot Auth agent whose key directory cannot be resolved, so the
 * verifier returns an INCONCLUSIVE verdict rather than a rejection. Since the
 * live probe never gets its signature checked (there is no key to check it
 * against), these tests are the only thing proving the request is well formed
 * at all, and they use the real WebBotAuthVerifier to do it.
 */
describe('simulate-verified-agent.mjs --web-bot-auth', () => {
  /** The public half of the demo credential, as a key directory would serve it. */
  const DEMO_DIRECTORY = { keys: [DEMO_AGENT_PUBLIC_JWK] };

  function wbaVerifier(configure: (keys: StaticSignatureAgentKeys) => void) {
    const resolver = new StaticSignatureAgentKeys();
    configure(resolver);
    return new WebBotAuthVerifier({ resolver, replayGuard: new InMemoryReplayGuard() });
  }

  it('is dispatched to the Web Bot Auth verifier, not the Visa-profile one', async () => {
    const marker = (name: string): AgentVerifier => ({
      verify: async () =>
        ({ trusted: false, reason: 'unknown_agent', message: name, conclusive: true }) as
          VerificationResult,
    });
    const dispatcher = new MultiProtocolVerifier({
      visa: marker('visa'),
      visaTap: marker('visa-tap'),
      ap2: marker('ap2'),
      webBotAuth: marker('web-bot-auth'),
    });

    const result = await dispatcher.verify(buildWebBotAuthRequest(SHOP) as IncomingRequest);
    expect(result.trusted).toBe(false);
    if (result.trusted) return;
    expect(result.message).toBe('web-bot-auth');
  });

  // The point of the probe: an unreachable directory must read as could-not-
  // check, never as a rejection. conclusive:false is what the Shopify app keys
  // "Could not check" off, so this is the API half of that display contract.
  it('produces an inconclusive verdict when the directory cannot be resolved', async () => {
    const v = wbaVerifier((keys) => keys.markUnavailable(PROBE_SIGNATURE_AGENT));
    const result = await v.verify(buildWebBotAuthRequest(SHOP) as IncomingRequest);

    expect(result.trusted).toBe(false);
    if (result.trusted) return;
    expect(result.reason).toBe('key_directory_unavailable');
    expect(result.conclusive).toBe(false);
  });

  // The signing itself has to be right even though production never checks it,
  // or the probe would be proving the wrong thing: an unreachable directory has
  // to be the ONLY reason the verdict is inconclusive. Stand the same directory
  // up and the identical request verifies.
  it('is a valid signature: the same request verifies once the directory resolves', async () => {
    const v = wbaVerifier((keys) => keys.add(PROBE_SIGNATURE_AGENT, DEMO_DIRECTORY));
    const result = await v.verify(buildWebBotAuthRequest(SHOP) as IncomingRequest);

    expect(result.trusted).toBe(true);
    if (!result.trusted) return;
    expect(result.protocol).toBe('web-bot-auth');
    expect(result.agent?.id).toBe(PROBE_SIGNATURE_AGENT);
    // Identity only. Web Bot Auth carries no buyer mandate, so no spend authority.
    expect(result.mandate).toBeUndefined();
    // A well-known directory on the named origin binds the key to that domain.
    expect(result.agent?.binding).toBe('domain');
  });

  it('uses the RFC 7638 thumbprint of the demo key as keyid', () => {
    const signed = buildWebBotAuthRequest(SHOP);
    const expected = ed25519JwkThumbprint(DEMO_AGENT_PUBLIC_JWK.x);
    expect(signed.headers['signature-input']).toContain(`keyid="${expected}"`);
    // Web Bot Auth pins the thumbprint shape: 32 bytes as unpadded base64url.
    expect(expected).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('sends the tag and Signature-Agent shape the profile requires', () => {
    const signed = buildWebBotAuthRequest(SHOP);
    expect(signed.headers['signature-input']).toContain('tag="web-bot-auth"');
    // Dictionary form keyed by the signature label, which the draft tells
    // signers to send (verifiers also accept the deployed bare-string form).
    expect(signed.headers['signature-agent']).toBe(`sig1="${PROBE_SIGNATURE_AGENT}"`);
    expect(signed.headers['x-ava-mandate']).toBeUndefined();
  });

  // Tamper checks, against a directory that DOES resolve, so a failure can only
  // come from the signature itself.
  it('fails verification when Signature-Agent is re-pointed after signing', async () => {
    const other = 'https://directory-test-2.avalayer.com';
    const v = wbaVerifier((keys) => {
      keys.add(PROBE_SIGNATURE_AGENT, DEMO_DIRECTORY);
      keys.add(other, DEMO_DIRECTORY);
    });
    const signed = buildWebBotAuthRequest(SHOP) as IncomingRequest;
    const tampered = {
      ...signed,
      headers: { ...signed.headers, 'signature-agent': `sig1="${other}"` },
    };

    const result = await v.verify(tampered);
    expect(result.trusted).toBe(false);
    if (result.trusted) return;
    expect(result.reason).toBe('invalid_signature');
  });

  it('fails verification when the cart body is altered after signing', async () => {
    const v = wbaVerifier((keys) => keys.add(PROBE_SIGNATURE_AGENT, DEMO_DIRECTORY));
    const signed = buildWebBotAuthRequest(SHOP) as IncomingRequest;
    const tampered = { ...signed, body: '{"cart":[{"sku":"FREE","qty":99}]}' };

    const result = await v.verify(tampered);
    expect(result.trusted).toBe(false);
    if (result.trusted) return;
    expect(result.reason).toBe('content_digest_mismatch');
  });

  it('signs the store the caller named', () => {
    const other = 'someone-elses-store.myshopify.com';
    const signed = buildWebBotAuthRequest(other);
    expect(signed.url).toBe(`https://${other}/apps/ava-pay/verify`);
    expect(signed.headers.host).toBe(other);
  });

  it('gives every build a fresh nonce, so a retry is not seen as a replay', async () => {
    const v = wbaVerifier((keys) => keys.add(PROBE_SIGNATURE_AGENT, DEMO_DIRECTORY));
    const first = buildWebBotAuthRequest(SHOP) as IncomingRequest;
    const second = buildWebBotAuthRequest(SHOP) as IncomingRequest;
    expect(second.headers['signature-input']).not.toBe(first.headers['signature-input']);
    expect((await v.verify(first)).trusted).toBe(true);
    expect((await v.verify(second)).trusted).toBe(true);
    expect((await v.verify(first)).trusted).toBe(false);
  });
});

/**
 * Argument parsing. The store used to be "the first token that is not a flag",
 * which made `--password hunter2 store.myshopify.com` resolve the store to
 * `hunter2` and then print it in "Sending a signed agent request to
 * https://hunter2/...". REVIEWER-TESTING-INSTRUCTIONS.md tells the app reviewer
 * that the storefront password is never echoed or stored, so that path had to
 * go. These tests cover the parser directly: the two orders a reviewer might
 * type, and the rule that a store which does not look like a hostname stops the
 * run without repeating the value that was misread.
 */
describe('simulate-verified-agent.mjs argument parsing', () => {
  /** Parse with a clean environment, so an ambient password cannot colour a result. */
  const parse = (...argv: string[]) => parseArgs(argv, {});

  it('takes the value after --password as the password, never as the store', () => {
    const parsed = parse('--password', 'hunter2', SHOP);
    expect(parsed.shop).toBe(SHOP);
    expect(parsed.password).toBe('hunter2');
    expect(parsed.error).toBeUndefined();
  });

  it('parses the documented store-then-password order unchanged', () => {
    const parsed = parse(SHOP, '--password', 'hunter2');
    expect(parsed.shop).toBe(SHOP);
    expect(parsed.password).toBe('hunter2');
  });

  it('parses the default path, one bare store and nothing else', () => {
    const parsed = parse(SHOP);
    expect(parsed).toEqual({ shop: SHOP, probe: false, password: '' });
  });

  // The whole point of the fix: a misread argument fails without printing what
  // it misread, because what it misread may be the password.
  it('refuses a store that does not look like a hostname, without echoing it', () => {
    const parsed = parse('hunter2');
    expect(parsed.shop).toBeUndefined();
    expect(parsed.error).toBeTruthy();
    expect(parsed.error).not.toContain('hunter2');
    expect(parsed.error).toContain('your-store.myshopify.com');
  });

  it('refuses every other shape a mis-parsed secret could take, without echoing it', () => {
    for (const value of [
      'hunter2',
      's3cret with spaces',
      'p@ssw0rd.example',
      'https://user:s3cret@store.myshopify.com',
      '.leading-dot.com',
      'trailing-dot.com.',
    ]) {
      const parsed = parse(value);
      expect(parsed.error, `expected ${value} to be refused`).toBeTruthy();
      expect(parsed.error).not.toContain(value);
    }
  });

  it('names the usage and exits when no store is given at all', () => {
    const parsed = parse('--password', 'hunter2');
    expect(parsed.shop).toBeUndefined();
    expect(parsed.error).toContain('Usage:');
    expect(parsed.error).not.toContain('hunter2');
  });

  it('leaves --web-bot-auth working in either position', () => {
    expect(parse(SHOP, '--web-bot-auth').probe).toBe(true);
    expect(parse('--web-bot-auth', SHOP).probe).toBe(true);
    expect(parse('--web-bot-auth', '--password', 'hunter2', SHOP)).toEqual({
      shop: SHOP,
      probe: true,
      password: 'hunter2',
    });
    expect(parse(SHOP).probe).toBe(false);
  });

  it('leaves --help and -h working, before or after everything else', () => {
    for (const argv of [['--help'], ['-h'], [SHOP, '--help'], ['--password', 'hunter2', '-h']]) {
      const parsed = parseArgs(argv, {});
      expect(parsed.help).toBe(true);
      expect(parsed.error).toBeUndefined();
    }
  });

  it('normalizes a pasted URL back to the store domain', () => {
    for (const pasted of [
      `https://${SHOP}/`,
      `https://${SHOP}`,
      `http://${SHOP}/admin`,
      `${SHOP}/`,
      `https://${SHOP.toUpperCase()}/`,
    ]) {
      expect(parse(pasted).shop, pasted).toBe(SHOP);
    }
  });

  it('accepts --password=value as well as a separate token', () => {
    expect(parse(`--password=hunter2`, SHOP).password).toBe('hunter2');
    // A password containing an = keeps everything after the first one.
    expect(parse(`--password=a=b=c`, SHOP).password).toBe('a=b=c');
  });

  // --password consumes the next token whatever it looks like, so a password
  // that happens to start with a dash is taken verbatim rather than re-read as
  // a flag, and still cannot be mistaken for the store.
  it('takes a flag-shaped password verbatim', () => {
    const parsed = parse('--password', '--web-bot-auth', SHOP);
    expect(parsed.password).toBe('--web-bot-auth');
    expect(parsed.shop).toBe(SHOP);
    expect(parsed.probe).toBe(false);
  });

  it('falls back to AVA_STOREFRONT_PASSWORD, and prefers the flag over it', () => {
    const env = { AVA_STOREFRONT_PASSWORD: 'from-env' };
    expect(parseArgs([SHOP], env).password).toBe('from-env');
    expect(parseArgs([SHOP, '--password', 'from-flag'], env).password).toBe('from-flag');
    // --password with nothing after it is the same as not passing it.
    expect(parseArgs([SHOP, '--password'], env).password).toBe('from-env');
  });
});
