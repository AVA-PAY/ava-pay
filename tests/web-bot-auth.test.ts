import { beforeEach, describe, expect, it } from 'vitest';
import {
  DEFAULT_SIGNATURE_AGENTS,
  FetchingKeyDirectoryResolver,
  StaticSignatureAgentKeys,
  WebBotAuthVerifier,
} from '../src/verifier/web-bot-auth.js';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { VisaTapVerifier } from '../src/verifier/visa-tap.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import { InMemoryReplayGuard } from '../src/verifier/replay.js';
import {
  ed25519JwkThumbprint,
  parseKeyDirectory,
  parseSignatureAgent,
  signDirectoryResponse,
  WebBotAuthParseError,
} from '@ava-pay/agent/protocol/web-bot-auth';
import { generateAgentKeyPair, signWithVisa, signWithWebBotAuth, webBotAuthKeyId } from '../src/sdk/index.js';
import type { AgentKeyPair } from '../src/sdk/index.js';
import type { IncomingRequest, Mandate } from '../src/types.js';

/**
 * Web Bot Auth verifier tests — real Ed25519 crypto end to end, per repo
 * convention. Every signed fixture is produced by the SDK signer, which is
 * byte-compatible with deployed agent traffic (see the ChatGPT wire-shape
 * test below).
 */

const FIXED_NOW = 1_750_000_000;
const AGENT_ORIGIN = 'https://agent.example';
const MERCHANT_URL = 'https://shop.example.com/products/tool-1234';

function jwksFor(...keys: AgentKeyPair[]): { keys: object[] } {
  return {
    keys: keys.map((k) => k.publicKey.export({ format: 'jwk' }) as object),
  };
}

function toIncoming(signed: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}): IncomingRequest {
  return {
    method: signed.method,
    url: signed.url,
    headers: signed.headers,
    ...(signed.body !== undefined ? { body: signed.body } : {}),
  };
}

describe('WebBotAuthVerifier', () => {
  let keys: AgentKeyPair;
  let strangerKeys: AgentKeyPair;
  let resolver: StaticSignatureAgentKeys;
  let verifier: WebBotAuthVerifier;

  function sign(overrides: Partial<Parameters<typeof signWithWebBotAuth>[0]> = {}) {
    return signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: AGENT_ORIGIN,
      privateKey: keys.privateKey,
      created: FIXED_NOW - 5,
      ...overrides,
    });
  }

  beforeEach(() => {
    keys = generateAgentKeyPair();
    strangerKeys = generateAgentKeyPair();
    resolver = new StaticSignatureAgentKeys();
    resolver.add(AGENT_ORIGIN, jwksFor(keys));
    verifier = new WebBotAuthVerifier({ resolver, now: () => FIXED_NOW });
  });

  it('verifies a valid signed request and returns an identity-only result', async () => {
    const result = await verifier.verify(toIncoming(sign()));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.conclusive).toBe(true);
    expect(result.protocol).toBe('web-bot-auth');
    expect(result.agent).toEqual({
      id: AGENT_ORIGIN,
      protocol: 'web-bot-auth',
      keyThumbprint: webBotAuthKeyId(keys.publicKey),
      // Discovered via the well-known directory path → domain-bound (D3).
      binding: 'domain',
    });
    // Identity is not payment authority.
    expect(result.mandate).toBeUndefined();
    expect(result.buyerInfo).toBeUndefined();
  });

  it('marks a jwks_uri-typed Signature-Agent as url-only binding (D3)', async () => {
    // Same origin + key, but the agent declares the jwks_uri discovery type,
    // which gives key continuity without an origin association. The verdict
    // must surface that as url-only so a merchant can price it lower.
    const result = await verifier.verify(
      toIncoming(sign({ signatureAgentFormat: 'dictionary', signatureAgentType: 'jwks_uri' })),
    );
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.agent?.binding).toBe('url-only');
  });

  it('accepts a padded-base64 nonce (D5 tolerance; -01 grammar says base64url)', async () => {
    // Shopify production sends a padded base64 nonce. It must not be rejected.
    const result = await verifier.verify(toIncoming(sign({ nonce: 'YWJjZGVarw==' })));
    expect(result.trusted).toBe(true);
  });

  it('accepts the dictionary Signature-Agent form of the restructured draft', async () => {
    const result = await verifier.verify(
      toIncoming(sign({ signatureAgentFormat: 'dictionary' })),
    );
    expect(result.trusted).toBe(true);
  });

  it('rejects a signature made with a key the directory does not publish → unknown_key (conclusive=true)', async () => {
    const signed = sign({ privateKey: strangerKeys.privateKey });
    const result = await verifier.verify(toIncoming(signed));
    // Directory fetched fine, key simply absent: definitive, so conclusive stays
    // true (contrast the unavailable-directory case, which is inconclusive).
    expect(result).toMatchObject({ trusted: false, reason: 'unknown_key', conclusive: true });
  });

  it('rejects a forged signature under a published keyid → invalid_signature', async () => {
    // Signed by the stranger but claiming the directory key's thumbprint.
    const signed = sign({
      privateKey: strangerKeys.privateKey,
      keyid: webBotAuthKeyId(keys.publicKey),
    });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'invalid_signature' });
  });

  it('rejects when a covered component is tampered post-signing → invalid_signature', async () => {
    const signed = sign();
    const tampered = { ...toIncoming(signed), url: 'https://shop.example.com/admin' };
    const result = await verifier.verify(tampered);
    expect(result).toMatchObject({ trusted: false, reason: 'invalid_signature' });
  });

  it('rejects an origin outside the trust set → unknown_signature_agent', async () => {
    const signed = signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: 'https://rogue.example',
      privateKey: keys.privateKey,
      created: FIXED_NOW - 5,
    });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'unknown_signature_agent' });
  });

  it('fails closed when the key directory is unavailable → key_directory_unavailable (conclusive=false)', async () => {
    resolver.markUnavailable(AGENT_ORIGIN);
    const result = await verifier.verify(toIncoming(sign()));
    // Could-not-check: reason unchanged for backward compatibility, now
    // carrying conclusive=false alongside the fail-closed trusted=false.
    expect(result).toMatchObject({
      trusted: false,
      reason: 'key_directory_unavailable',
      conclusive: false,
    });
  });

  it('tolerates an absent Appendix B proof by default (grace on)', async () => {
    // The default verifier has no proofRequiredOrigins, and the static resolver
    // carries no proof, so an unsigned directory still verifies.
    expect((await verifier.verify(toIncoming(sign()))).trusted).toBe(true);
  });

  it('drops an absent-proof key when the source requires proof → unsigned_key (conclusive true)', async () => {
    // Grace off for this origin: "no proof offered" is now a definitive
    // rejection, distinct from a directory-level fetch failure.
    const strict = new WebBotAuthVerifier({
      resolver,
      proofRequiredOrigins: [AGENT_ORIGIN],
      now: () => FIXED_NOW,
    });
    expect(await strict.verify(toIncoming(sign()))).toMatchObject({
      trusted: false,
      reason: 'unsigned_key',
      conclusive: true,
    });
  });

  it('rejects an expired signature → signature_expired', async () => {
    const signed = sign({ created: FIXED_NOW - 4000, expires: FIXED_NOW - 3600 });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_expired' });
  });

  it('caps signature lifetime server-side regardless of a generous expires', async () => {
    // created 10 minutes ago with a 24h expires: the 300s max-age cap rules.
    const signed = sign({ created: FIXED_NOW - 600, expires: FIXED_NOW + 86_400 });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_expired' });
  });

  it('rejects a future-dated signature → signature_expired', async () => {
    const signed = sign({ created: FIXED_NOW + 3600, expires: FIXED_NOW + 7200 });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_expired' });
  });

  it('rejects a missing expires parameter → malformed_signature_header', async () => {
    const signed = sign({ expires: null });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'malformed_signature_header' });
  });

  it('rejects a wrong or missing tag → malformed_signature_header', async () => {
    for (const tag of ['something-else', null] as const) {
      const result = await verifier.verify(toIncoming(sign({ tag })));
      expect(result).toMatchObject({ trusted: false, reason: 'malformed_signature_header' });
    }
  });

  it('accepts an omitted alg (directory key pins ed25519) but rejects a contradicting one', async () => {
    const omitted = await verifier.verify(toIncoming(sign({ alg: null })));
    expect(omitted.trusted).toBe(true);

    const contradicting = await verifier.verify(toIncoming(sign({ alg: 'rsa-pss-sha512' })));
    expect(contradicting).toMatchObject({ trusted: false, reason: 'unsupported_algorithm' });
  });

  it('requires signature-agent to be covered by the signature', async () => {
    const signed = sign({ components: ['@authority', '@method', '@path'] });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'malformed_signature_header' });
    if (!result.trusted) expect(result.message).toContain('signature-agent');
  });

  it('requires @authority or @target-uri in the cover set', async () => {
    const signed = sign({ components: ['@method', '@path', 'signature-agent'] });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'malformed_signature_header' });
  });

  it('rejects a non-https Signature-Agent → malformed_signature_header', async () => {
    // Signer refuses http origins? It doesn't care — but the verifier must.
    const signed = sign();
    signed.headers['signature-agent'] = '"http://agent.example"';
    const result = await verifier.verify(toIncoming(signed));
    // Header no longer matches the signed value, but the parse gate fires first.
    expect(result).toMatchObject({ trusted: false, reason: 'malformed_signature_header' });
  });

  it('rejects missing credentials and missing Signature-Agent → missing_agent_credentials', async () => {
    const bare = await verifier.verify({ method: 'GET', url: MERCHANT_URL, headers: {} });
    expect(bare).toMatchObject({ trusted: false, reason: 'missing_agent_credentials' });

    const signed = sign();
    delete signed.headers['signature-agent'];
    const noAgent = await verifier.verify(toIncoming(signed));
    expect(noAgent).toMatchObject({ trusted: false, reason: 'missing_agent_credentials' });
  });

  it('detects replay of a nonce-bearing request → replay_detected', async () => {
    const signed = toIncoming(sign());
    expect((await verifier.verify(signed)).trusted).toBe(true);
    const replayed = await verifier.verify(signed);
    expect(replayed).toMatchObject({ trusted: false, reason: 'replay_detected' });
  });

  it('detects replay even when the agent sent no nonce (signature-bytes key)', async () => {
    const signed = toIncoming(sign({ nonce: null }));
    expect((await verifier.verify(signed)).trusted).toBe(true);
    const replayed = await verifier.verify(signed);
    expect(replayed).toMatchObject({ trusted: false, reason: 'replay_detected' });
  });

  it('shares the replay namespace through an injected guard', async () => {
    const guard = new InMemoryReplayGuard({ now: () => FIXED_NOW });
    const a = new WebBotAuthVerifier({ resolver, replayGuard: guard, now: () => FIXED_NOW });
    const b = new WebBotAuthVerifier({ resolver, replayGuard: guard, now: () => FIXED_NOW });
    const signed = toIncoming(sign());
    expect((await a.verify(signed)).trusted).toBe(true);
    expect(await b.verify(signed)).toMatchObject({ trusted: false, reason: 'replay_detected' });
  });

  it('rejects a directory key that is expired or not yet valid → unknown_key', async () => {
    const jwk = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const expired = new StaticSignatureAgentKeys();
    expired.add(AGENT_ORIGIN, { keys: [{ ...jwk, exp: FIXED_NOW - 3600 }] });
    const notYet = new StaticSignatureAgentKeys();
    notYet.add(AGENT_ORIGIN, { keys: [{ ...jwk, nbf: FIXED_NOW + 3600 }] });

    for (const r of [expired, notYet]) {
      const v = new WebBotAuthVerifier({ resolver: r, now: () => FIXED_NOW });
      const result = await v.verify(toIncoming(sign()));
      expect(result).toMatchObject({ trusted: false, reason: 'unknown_key' });
    }
  });

  it('validates a covered Content-Digest on bodied requests', async () => {
    const body = JSON.stringify({ q: 'availability' });
    const signed = sign({
      method: 'POST',
      body,
      components: ['@authority', '@method', '@path', 'signature-agent', 'content-digest'],
    });
    const good = await verifier.verify(toIncoming(signed));
    expect(good.trusted).toBe(true);

    const tampered = { ...toIncoming(signed), body: JSON.stringify({ q: 'tampered' }) };
    const result = await verifier.verify(tampered);
    expect(result).toMatchObject({ trusted: false, reason: 'content_digest_mismatch' });
  });
});

describe('wire-format compatibility (real ChatGPT agent traffic shape)', () => {
  it('verifies a request matching the deployed OpenAI wire format exactly', async () => {
    // Same covered components, parameter set, and bare-string Signature-Agent
    // as production ChatGPT agent traffic (chatgpt.com), fresh local key.
    const keys = generateAgentKeyPair();
    const resolver = new StaticSignatureAgentKeys();
    resolver.add('https://chatgpt.com', {
      keys: [
        {
          ...(keys.publicKey.export({ format: 'jwk' }) as object),
          kid: webBotAuthKeyId(keys.publicKey),
          use: 'sig',
          nbf: FIXED_NOW - 86_400,
          exp: FIXED_NOW + 86_400,
        },
      ],
      signature_agent: 'https://chatgpt.com',
      purpose: 'ai',
    });
    const verifier = new WebBotAuthVerifier({ resolver, now: () => FIXED_NOW });

    const signed = signWithWebBotAuth({
      method: 'GET',
      url: 'https://shop.example.com/collections/all',
      signatureAgent: 'https://chatgpt.com',
      privateKey: keys.privateKey,
      created: FIXED_NOW - 1,
      expires: FIXED_NOW + 3599, // real traffic uses a 3600s window
    });
    expect(signed.headers['signature-agent']).toBe('"https://chatgpt.com"');
    expect(signed.headers['signature-input']).toContain(
      '("@authority" "@method" "@path" "signature-agent")',
    );
    expect(signed.headers['signature-input']).toContain('tag="web-bot-auth"');

    const result = await verifier.verify(toIncoming(signed));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.agent?.id).toBe('https://chatgpt.com');
  });
});

describe('web-bot-auth protocol primitives', () => {
  it('computes the RFC 8037 A.3 thumbprint test vector', () => {
    expect(ed25519JwkThumbprint('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo')).toBe(
      'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
    );
  });

  it('parses bare-string and dictionary Signature-Agent forms (bare string is directory type)', () => {
    expect(parseSignatureAgent('"https://ChatGPT.com"')).toEqual({
      target: 'https://ChatGPT.com',
      origin: 'https://chatgpt.com',
      type: 'directory',
    });
    expect(parseSignatureAgent('sig1="https://agent.example"', 'sig1').origin).toBe(
      'https://agent.example',
    );
    // Label-aware: picks the matching member, not the first.
    expect(
      parseSignatureAgent('sig0="https://other.example", sig1="https://agent.example"', 'sig1')
        .origin,
    ).toBe('https://agent.example');
  });

  it('parses the §5.5 discovery type; default directory only when NO type param is present', () => {
    expect(parseSignatureAgent('sig1="https://agent.example";type=jwks_uri', 'sig1').type).toBe(
      'jwks_uri',
    );
    expect(parseSignatureAgent('sig1="https://agent.example";type=cimd', 'sig1').type).toBe('cimd');
    // Quoted token form is tolerated.
    expect(parseSignatureAgent('sig1="https://agent.example";type="cimd"', 'sig1').type).toBe(
      'cimd',
    );
    // No type param at all → the default directory.
    expect(parseSignatureAgent('sig1="https://agent.example"', 'sig1').type).toBe('directory');
    // A path that looks like a jwks_uri does NOT change the type (never inferred).
    expect(parseSignatureAgent('sig1="https://agent.example/jwks.json"', 'sig1').type).toBe(
      'directory',
    );
  });

  it('rejects a label-matched member with an unrecognized type (never upgraded to directory)', () => {
    // The spec says to ignore an unrecognized type; granting it directory (and
    // thus domain binding) would be exactly the misbinding to avoid. The
    // authoritative label-matched member is therefore rejected, fail closed.
    expect(() =>
      parseSignatureAgent('sig1="https://agent.example";type=bogus', 'sig1'),
    ).toThrow(WebBotAuthParseError);
  });

  it('skips an unrecognized-type member when choosing an unlabeled fallback', () => {
    // First member has an unrecognized type and must be passed over; the
    // second, well-typed member is chosen instead. Called without a label.
    const parsed = parseSignatureAgent(
      'sig1="https://skip.example";type=bogus, sig2="https://good.example"',
    );
    expect(parsed.origin).toBe('https://good.example');
    expect(parsed.type).toBe('directory');
  });

  it('rejects malformed and non-https Signature-Agent values', () => {
    for (const bad of [
      '',
      '"',
      '"not a url"',
      '"http://agent.example"',
      '"https://user:pw@agent.example"',
    ]) {
      expect(() => parseSignatureAgent(bad, 'sig1')).toThrow(WebBotAuthParseError);
    }
  });

  it('drops directory keys that are malformed, mislabelled, or wrong-type', () => {
    const keys = generateAgentKeyPair();
    const jwk = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const parsed = parseKeyDirectory({
      keys: [
        jwk, // good
        { ...jwk, kid: 'not-the-thumbprint' }, // kid lies about the material → dropped
        { ...jwk, use: 'enc' }, // wrong use → dropped
        { ...jwk, alg: 'RS256' }, // wrong algorithm → dropped
        { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }, // wrong key type → dropped
        { kty: 'OKP', crv: 'Ed25519', x: 'too-short' }, // malformed x → dropped
        'garbage',
      ],
    });
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.thumbprint).toBe(webBotAuthKeyId(keys.publicKey));

    // Both registry spellings of the Ed25519 algorithm survive.
    for (const alg of ['ed25519', 'EdDSA']) {
      expect(parseKeyDirectory({ keys: [{ ...jwk, alg }] })).toHaveLength(1);
    }
  });

  it('accepts a bare single JWK directory (www.shopify.com shape) as a one-key list', () => {
    const keys = generateAgentKeyPair();
    const jwk = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    // No "keys" wrapper: the whole document is one JWK, as Shopify serves it.
    const parsed = parseKeyDirectory({ ...jwk, alg: 'EdDSA', use: 'sig' });
    expect(parsed).toHaveLength(1);
    expect(parsed[0]?.thumbprint).toBe(webBotAuthKeyId(keys.publicKey));
  });

  it('parses both live directory body shapes observed 2026-08-09', () => {
    // chatgpt.com: JWKS wrapper with extra signature_agent/purpose metadata.
    const chatgpt = {
      keys: [
        {
          crv: 'Ed25519',
          kty: 'OKP',
          x: '7F_3jDlxaquwh291MiACkcS3Opq88NksyHiakzS-Y1g',
          kid: 'otMqcjr17mGyruktGvJU8oojQTSMHlVm7uO-lrcqbdg',
          use: 'sig',
          nbf: 1735689600,
          exp: 1786913274,
        },
      ],
      signature_agent: 'https://chatgpt.com',
      purpose: 'ai',
    };
    // www.shopify.com: bare single JWK.
    const shopify = {
      crv: 'Ed25519',
      kty: 'OKP',
      x: 'Mt6otbtH_mqWe1Qsm0cW9GVfknDvrGXXMpyXhiW0Dr4',
      use: 'sig',
      alg: 'EdDSA',
      kid: 'SjjyXvQ2cGhsRXs9DXEaV6ClyCun0Pj5yxjV67dLGOk',
      nbf: 1773401952,
      exp: 1804937952,
    };
    expect(parseKeyDirectory(chatgpt).map((k) => k.thumbprint)).toEqual([
      'otMqcjr17mGyruktGvJU8oojQTSMHlVm7uO-lrcqbdg',
    ]);
    expect(parseKeyDirectory(shopify).map((k) => k.thumbprint)).toEqual([
      'SjjyXvQ2cGhsRXs9DXEaV6ClyCun0Pj5yxjV67dLGOk',
    ]);
  });

  it('rejects a document that is neither a keys array nor a JWK', () => {
    expect(() => parseKeyDirectory({ nope: true })).toThrow(WebBotAuthParseError);
    expect(() => parseKeyDirectory(42)).toThrow(WebBotAuthParseError);
  });
});

describe('FetchingKeyDirectoryResolver', () => {
  const ORIGIN = 'https://agent.example';
  let keys: AgentKeyPair;
  let directoryBody: string;

  beforeEach(() => {
    keys = generateAgentKeyPair();
    directoryBody = JSON.stringify({
      keys: [keys.publicKey.export({ format: 'jwk' })],
    });
  });

  function fakeFetch(handler: (url: string) => Response): { impl: typeof fetch; calls: string[] } {
    const calls: string[] = [];
    const impl = (async (input: any) => {
      const url = String(input);
      calls.push(url);
      return handler(url);
    }) as typeof fetch;
    return { impl, calls };
  }

  it('never fetches origins outside the allowlist (SSRF guard)', async () => {
    const { impl, calls } = fakeFetch(() => new Response(directoryBody));
    const resolver = new FetchingKeyDirectoryResolver({ allowedOrigins: [ORIGIN], fetchImpl: impl });
    expect(await resolver.resolve('https://internal.metadata.example')).toEqual({
      status: 'not_allowed',
    });
    expect(calls).toHaveLength(0);
  });

  it('fetches, parses, and caches an allowlisted directory', async () => {
    const { impl, calls } = fakeFetch(() => new Response(directoryBody));
    const resolver = new FetchingKeyDirectoryResolver({ allowedOrigins: [ORIGIN], fetchImpl: impl });

    const first = await resolver.resolve(ORIGIN);
    if (first.status !== 'ok') throw new Error(`expected ok, got ${JSON.stringify(first)}`);
    expect(first.keys[0]?.thumbprint).toBe(webBotAuthKeyId(keys.publicKey));
    expect(calls).toEqual([`${ORIGIN}/.well-known/http-message-signatures-directory`]);

    await resolver.resolve(ORIGIN);
    expect(calls).toHaveLength(1); // served from cache
  });

  it('reports unavailable on HTTP errors, junk bodies, and thrown fetches', async () => {
    for (const handler of [
      () => new Response('nope', { status: 404 }),
      () => new Response('<!doctype html><html></html>'), // SPA shell, like claude.ai today
      () => {
        throw new Error('network down');
      },
    ]) {
      const resolver = new FetchingKeyDirectoryResolver({
        allowedOrigins: [ORIGIN],
        fetchImpl: fakeFetch(handler as (url: string) => Response).impl,
      });
      expect((await resolver.resolve(ORIGIN)).status).toBe('unavailable');
    }
  });

  it('rejects oversized directory responses', async () => {
    const huge = JSON.stringify({ keys: [], pad: 'x'.repeat(100_000) });
    const resolver = new FetchingKeyDirectoryResolver({
      allowedOrigins: [ORIGIN],
      fetchImpl: fakeFetch(() => new Response(huge)).impl,
    });
    expect((await resolver.resolve(ORIGIN)).status).toBe('unavailable');
  });

  it('follows a redirect to an allowlisted https origin', async () => {
    const ORIGIN2 = 'https://cdn.agent.example';
    const { impl, calls } = fakeFetch((url) =>
      url.startsWith(ORIGIN2)
        ? new Response(directoryBody)
        : new Response(null, {
            status: 301,
            headers: { location: `${ORIGIN2}/.well-known/http-message-signatures-directory` },
          }),
    );
    const resolver = new FetchingKeyDirectoryResolver({
      allowedOrigins: [ORIGIN, ORIGIN2],
      fetchImpl: impl,
    });
    expect((await resolver.resolve(ORIGIN)).status).toBe('ok');
    expect(calls).toHaveLength(2);
  });

  it('refuses a non-https redirect and never fetches it (no plaintext key hop)', async () => {
    const { impl, calls } = fakeFetch((url) =>
      url.startsWith('http://')
        ? new Response(directoryBody) // a plaintext fetch here would be the bug
        : new Response(null, {
            status: 302,
            headers: { location: 'http://agent.example/.well-known/http-message-signatures-directory' },
          }),
    );
    const resolver = new FetchingKeyDirectoryResolver({ allowedOrigins: [ORIGIN], fetchImpl: impl });
    expect((await resolver.resolve(ORIGIN)).status).toBe('unavailable');
    expect(calls).toHaveLength(1);
    expect(calls.every((u) => u.startsWith('https://'))).toBe(true);
  });

  it('refuses a redirect to a non-allowlisted https origin (SSRF guard)', async () => {
    const { impl } = fakeFetch(() =>
      new Response(null, {
        status: 301,
        headers: { location: 'https://evil.example/.well-known/http-message-signatures-directory' },
      }),
    );
    const resolver = new FetchingKeyDirectoryResolver({ allowedOrigins: [ORIGIN], fetchImpl: impl });
    expect((await resolver.resolve(ORIGIN)).status).toBe('unavailable');
  });

  it('gives up (fail closed) after too many redirects', async () => {
    const { impl, calls } = fakeFetch(() =>
      new Response(null, {
        status: 301,
        headers: { location: `${ORIGIN}/.well-known/http-message-signatures-directory` },
      }),
    );
    const resolver = new FetchingKeyDirectoryResolver({ allowedOrigins: [ORIGIN], fetchImpl: impl });
    expect((await resolver.resolve(ORIGIN)).status).toBe('unavailable');
    // Bounded: it terminates rather than following the loop forever.
    expect(calls.length).toBeGreaterThan(1);
    expect(calls.length).toBeLessThanOrEqual(4);
  });

  it('ships chatgpt.com as the only default trusted signature agent', () => {
    expect(DEFAULT_SIGNATURE_AGENTS).toEqual(['https://chatgpt.com']);
  });
});

describe('WebBotAuthVerifier Appendix B proof-of-possession (real crypto)', () => {
  const ORIGIN = 'https://agent.example';
  const HOST = 'agent.example';
  let keys: AgentKeyPair;

  beforeEach(() => {
    keys = generateAgentKeyPair();
  });

  /** A fetch that serves the directory with an Appendix B proof bound to `proofAuthority`. */
  function signedDirectoryFetch(proofAuthority: string): typeof fetch {
    const body = JSON.stringify({ keys: [keys.publicKey.export({ format: 'jwk' })] });
    const proof = signDirectoryResponse({
      signers: [{ privateKey: keys.privateKey, keyid: webBotAuthKeyId(keys.publicKey) }],
      authority: proofAuthority,
      body,
      created: FIXED_NOW - 5,
      expires: FIXED_NOW + 3600,
    });
    return (async () =>
      new Response(body, {
        headers: {
          'content-digest': proof['content-digest'],
          'signature-input': proof['signature-input'],
          signature: proof.signature,
        },
      })) as unknown as typeof fetch;
  }

  function fetchingResolver(fetchImpl: typeof fetch): FetchingKeyDirectoryResolver {
    return new FetchingKeyDirectoryResolver({
      allowedOrigins: [ORIGIN],
      fetchImpl,
      nowMs: () => FIXED_NOW * 1000,
    });
  }

  function signedRequest(): IncomingRequest {
    return toIncoming(
      signWithWebBotAuth({
        method: 'GET',
        url: MERCHANT_URL,
        signatureAgent: ORIGIN,
        privateKey: keys.privateKey,
        created: FIXED_NOW - 5,
      }),
    );
  }

  it('classifies proof status at the resolver: valid when it verifies, invalid otherwise', async () => {
    const good = await fetchingResolver(signedDirectoryFetch(HOST)).resolve(ORIGIN);
    if (good.status !== 'ok') throw new Error(`expected ok, got ${JSON.stringify(good)}`);
    expect(good.keys[0]?.proof).toBe('valid');

    // Proof signed for the wrong authority does not bind to the serving host.
    const bad = await fetchingResolver(signedDirectoryFetch('wrong.example')).resolve(ORIGIN);
    if (bad.status !== 'ok') throw new Error(`expected ok, got ${JSON.stringify(bad)}`);
    expect(bad.keys[0]?.proof).toBe('invalid');
  });

  it('marks proof absent when the directory serves no response signature', async () => {
    const plain = (async () =>
      new Response(
        JSON.stringify({ keys: [keys.publicKey.export({ format: 'jwk' })] }),
      )) as unknown as typeof fetch;
    const res = await fetchingResolver(plain).resolve(ORIGIN);
    if (res.status !== 'ok') throw new Error(`expected ok, got ${JSON.stringify(res)}`);
    expect(res.keys[0]?.proof).toBe('absent');
  });

  it('accepts a request when the directory proof verifies', async () => {
    const verifier = new WebBotAuthVerifier({
      resolver: fetchingResolver(signedDirectoryFetch(HOST)),
      now: () => FIXED_NOW,
    });
    expect((await verifier.verify(signedRequest())).trusted).toBe(true);
  });

  it('rejects a present-but-invalid proof → key_proof_invalid (conclusive true), even under grace on', async () => {
    // No proofRequiredOrigins, so grace is ON. An invalid proof is still never
    // tolerated: the determination is definitive, so conclusive stays true.
    const verifier = new WebBotAuthVerifier({
      resolver: fetchingResolver(signedDirectoryFetch('wrong.example')),
      now: () => FIXED_NOW,
    });
    expect(await verifier.verify(signedRequest())).toMatchObject({
      trusted: false,
      reason: 'key_proof_invalid',
      conclusive: true,
    });
  });
});

describe('MultiProtocolVerifier dispatch with Web Bot Auth', () => {
  const FIXED = FIXED_NOW;
  let visaKeys: AgentKeyPair;
  let wbaKeys: AgentKeyPair;
  let multi: MultiProtocolVerifier;

  beforeEach(() => {
    visaKeys = generateAgentKeyPair();
    wbaKeys = generateAgentKeyPair();

    const directory = new StaticAgentDirectory();
    directory.add('agent_demo', visaKeys.publicKey);
    const wbaResolver = new StaticSignatureAgentKeys();
    wbaResolver.add(AGENT_ORIGIN, jwksFor(wbaKeys));

    multi = new MultiProtocolVerifier({
      visa: new VisaAgentVerifier({ directory, now: () => FIXED }),
      visaTap: new VisaTapVerifier({ directory, now: () => FIXED }),
      ap2: new Ap2AgentVerifier({ directory, now: () => FIXED }),
      webBotAuth: new WebBotAuthVerifier({ resolver: wbaResolver, now: () => FIXED }),
    });
  });

  function visaMandate(): Mandate {
    return {
      id: 'mandate_demo',
      iat: FIXED - 60,
      exp: FIXED + 600,
      maxAmountMinor: 50_000,
      currency: 'USD',
      allowedMerchants: ['shop.example.com'],
    };
  }

  it('routes tag="web-bot-auth" traffic to the WBA verifier', async () => {
    const signed = signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: AGENT_ORIGIN,
      privateKey: wbaKeys.privateKey,
      created: FIXED - 5,
    });
    const result = await multi.verify(toIncoming(signed));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.protocol).toBe('web-bot-auth');
  });

  it('still routes plain RFC 9421 (no tag, no Signature-Agent) to Visa TAP', async () => {
    const body = JSON.stringify({ items: [{ sku: 'SKU-1', qty: 1 }] });
    const signed = signWithVisa({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body,
      agentId: 'agent_demo',
      privateKey: visaKeys.privateKey,
      mandate: visaMandate(),
      created: FIXED - 5,
      expires: FIXED + 60,
    });
    const result = await multi.verify(toIncoming({ ...signed, body }));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.mandate?.id).toBe('mandate_demo');
  });

  it('flags RFC 9421 + AP2 credentials together as ambiguous_protocol', async () => {
    const signed = signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: AGENT_ORIGIN,
      privateKey: wbaKeys.privateKey,
      created: FIXED - 5,
    });
    signed.headers['ap2-attestation'] = 'whatever';
    const result = await multi.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'ambiguous_protocol' });
  });
});
