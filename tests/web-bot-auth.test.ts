import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
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
  ecP256JwkThumbprint,
  ed25519JwkThumbprint,
  parseKeyDirectory,
  parseSignatureAgent,
  readKeyDirectory,
  signDirectoryResponse,
  WebBotAuthParseError,
} from '@ava-pay/agent/protocol/web-bot-auth';
import { parseSignatureInput } from '../src/verifier/http-signatures.js';
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
/** A key directory response served under its registered media type. */
const DIRECTORY_TYPE = { headers: { 'content-type': 'application/http-message-signatures-directory+json' } };

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

  it('accepts a padded-base64 nonce, which -02 makes simply correct', async () => {
    // Shopify production sends a padded base64 nonce, which the -01 grammar
    // said should be base64url. -02 §5.2.3 removed that grammar and defers
    // nonce handling entirely to RFC 9421 §7.2.2, so this stopped being a
    // tolerance and became conformance. We never validated nonce shape anyway:
    // it is only a replay key.
    const result = await verifier.verify(toIncoming(sign({ nonce: 'YWJjZGVarw==' })));
    expect(result.trusted).toBe(true);
  });

  it('accepts the dictionary Signature-Agent form of the restructured draft', async () => {
    const result = await verifier.verify(
      toIncoming(sign({ signatureAgentFormat: 'dictionary' })),
    );
    expect(result.trusted).toBe(true);
  });

  it('treats a key the directory does not publish as could-not-check → unknown_key (conclusive=false)', async () => {
    const signed = sign({ privateKey: strangerKeys.privateKey });
    const result = await verifier.verify(toIncoming(signed));
    // Directory fetched fine, key absent. From here a bad keyid, a mid-rotation
    // key, and a stale cached copy all look the same, so the verdict is
    // could-not-check: trusted stays false, conclusive goes false, and the
    // message says this is not a definitive rejection.
    expect(result).toMatchObject({ trusted: false, reason: 'unknown_key', conclusive: false });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('not a definitive rejection');
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

  it('rejects an origin outside the trust set → unknown_signature_agent (a policy refusal, inconclusive)', async () => {
    const signed = signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: 'https://rogue.example',
      privateKey: keys.privateKey,
      created: FIXED_NOW - 5,
    });
    const result = await verifier.verify(toIncoming(signed));
    // No directory is allowlisted, so nothing was fetched and the signature
    // was never evaluated: could-not-check, and the message must read as the
    // policy fact it is, never as a bad signature.
    expect(result).toMatchObject({
      trusted: false,
      reason: 'unknown_signature_agent',
      conclusive: false,
    });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('No key directory is allowlisted');
    expect(result.message).not.toMatch(/invalid|failed/i);
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

  it('rejects a future-dated signature → signature_created_in_future, not signature_expired', async () => {
    const signed = sign({ created: FIXED_NOW + 3600, expires: FIXED_NOW + 7200 });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({
      trusted: false,
      reason: 'signature_created_in_future',
      conclusive: true,
    });
  });

  it('keeps signature_expired for actual expiry', async () => {
    const signed = sign({ created: FIXED_NOW - 1000, expires: FIXED_NOW - 500 });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_expired', conclusive: true });
  });

  it('tolerates created up to the skew ahead of the clock (the boundary of the split)', async () => {
    const atSkew = await verifier.verify(toIncoming(sign({ created: FIXED_NOW + 30, expires: FIXED_NOW + 90 })));
    expect(atSkew.trusted).toBe(true);
    const pastSkew = await verifier.verify(toIncoming(sign({ created: FIXED_NOW + 31, expires: FIXED_NOW + 90 })));
    expect(pastSkew).toMatchObject({ trusted: false, reason: 'signature_created_in_future' });
  });

  it('rejects a missing expires parameter → signature_parameter_missing', async () => {
    const signed = sign({ expires: null });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_parameter_missing', conclusive: true });
  });

  it('rejects a foreign tag → foreign_signature_tag, and a missing one → signature_parameter_missing', async () => {
    const foreign = await verifier.verify(toIncoming(sign({ tag: 'something-else' })));
    expect(foreign).toMatchObject({ trusted: false, reason: 'foreign_signature_tag', conclusive: true });
    const absent = await verifier.verify(toIncoming(sign({ tag: null })));
    expect(absent).toMatchObject({ trusted: false, reason: 'signature_parameter_missing', conclusive: true });
  });

  it('accepts an omitted alg (the directory key pins the algorithm) but rejects what we do not verify', async () => {
    const omitted = await verifier.verify(toIncoming(sign({ alg: null })));
    expect(omitted.trusted).toBe(true);

    // An algorithm outside {ed25519, ecdsa-p256-sha256} is refused before any
    // directory I/O, and the message names what we verify. RSA is a stated
    // non-goal, said out loud rather than left as an accident.
    const rsa = await verifier.verify(toIncoming(sign({ alg: 'rsa-pss-sha512' })));
    expect(rsa).toMatchObject({ trusted: false, reason: 'unsupported_algorithm' });
    if (rsa.trusted) throw new Error('unreachable');
    expect(rsa.message).toContain('ed25519 and ecdsa-p256-sha256');
    expect(rsa.message).toContain('RSA');
  });

  it('rejects alg ecdsa-p256-sha256 when the selected key is Ed25519 (alg/key mismatch)', async () => {
    // ecdsa-p256-sha256 is an algorithm we verify, so it passes the early
    // gate, but the key the keyid selects is Ed25519 and cannot have made
    // that signature. The mismatch is refused by name, not by a failed verify.
    const result = await verifier.verify(toIncoming(sign({ alg: 'ecdsa-p256-sha256' })));
    expect(result).toMatchObject({ trusted: false, reason: 'unsupported_algorithm', conclusive: true });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('does not match');
    expect(result.message).toContain('ed25519');
  });

  it('requires signature-agent to be covered by the signature', async () => {
    const signed = sign({ components: ['@authority', '@method', '@path'] });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'required_component_not_covered' });
    if (!result.trusted) expect(result.message).toContain('signature-agent');
  });

  it('requires @authority or @target-uri in the cover set → required_component_not_covered', async () => {
    const signed = sign({ components: ['@method', '@path', 'signature-agent'] });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'required_component_not_covered', conclusive: true });
  });

  it('rejects a non-https Signature-Agent → signature_agent_not_origin', async () => {
    // Signer refuses http origins? It doesn't care — but the verifier must.
    const signed = sign();
    signed.headers['signature-agent'] = '"http://agent.example"';
    const result = await verifier.verify(toIncoming(signed));
    // Header no longer matches the signed value, but the parse gate fires first.
    expect(result).toMatchObject({ trusted: false, reason: 'signature_agent_not_origin', conclusive: true });
  });

  it('separates "no credentials at all" from "signed but no Signature-Agent"', async () => {
    // Nothing offered: the request never claimed to be a signed agent request.
    const bare = await verifier.verify({ method: 'GET', url: MERCHANT_URL, headers: {} });
    expect(bare).toMatchObject({
      trusted: false,
      reason: 'missing_agent_credentials',
      conclusive: true,
    });

    // Signed, but missing the header -02 Section 5.2.1 makes mandatory. This is
    // its own story: the agent signed and left out the discovery root, so we
    // reject conclusively rather than resolving the bare keyid against anything
    // we happen to hold.
    const signed = sign();
    delete signed.headers['signature-agent'];
    const noAgent = await verifier.verify(toIncoming(signed));
    expect(noAgent).toMatchObject({
      trusted: false,
      reason: 'missing_signature_agent',
      conclusive: true,
    });
  });

  // ── draft -02 Section 5.2.1: the keyed Signature-Agent component ──────────

  it('verifies the draft -02 Appendix E.2.1 vector byte for byte', async () => {
    // The strongest oracle available: the working group's own published Ed25519
    // request vector, signed with the RFC 9421 Appendix B.1.4 test key, in the
    // keyed dictionary form -02 requires. Nothing here is produced by our own
    // signer, so it cannot drift into agreeing with us.
    const VECTOR_ORIGIN = 'https://signature-agent.test';
    const CREATED = 1_735_689_600;
    const vectorResolver = new StaticSignatureAgentKeys();
    vectorResolver.add(VECTOR_ORIGIN, {
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs',
          use: 'sig',
        },
      ],
    });
    const vectorVerifier = new WebBotAuthVerifier({
      resolver: vectorResolver,
      // The vector is dated 2025-01-01 with a century-long expires, so the
      // server-side max-age cap has to be lifted to replay it at all.
      now: () => CREATED + 60,
      maxAgeSeconds: 3600,
    });

    const result = await vectorVerifier.verify({
      method: 'POST',
      url: 'https://example.com/foo?param=Value&Pet=dog',
      headers: {
        host: 'example.com',
        'signature-agent': 'agent2="https://signature-agent.test"',
        'signature-input':
          'sig2=("@authority" "signature-agent";key="agent2");created=1735689600' +
          ';keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519"' +
          ';expires=4889289600' +
          ';nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=="' +
          ';tag="web-bot-auth"',
        signature:
          'sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:',
      },
    });

    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.agent?.id).toBe(VECTOR_ORIGIN);
    expect(result.agent?.keyThumbprint).toBe('poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U');
    expect(result.agent?.binding).toBe('domain');
  });

  it('verifies the keyed component form round-trip through the SDK signer', async () => {
    const signed = sign({ signatureAgentFormat: 'dictionary' });
    // The signer must be emitting the -02 shape, not just something we accept.
    expect(signed.headers['signature-input']).toContain('"signature-agent";key="sig1"');
    expect(signed.headers['signature-agent']).toBe(`sig1="${AGENT_ORIGIN}"`);
    expect((await verifier.verify(toIncoming(signed))).trusted).toBe(true);
  });

  it('attributes a keyed signature to the member it covers, never to another member', async () => {
    // Section 5.2.2: a verifier MUST NOT attribute a signature to a member that
    // signature does not cover. The header carries a trusted member and an
    // impostor's; the signature covers the impostor's. Resolving the trusted
    // one because it matches the label would launder the impostor into an
    // allowlisted identity, so the covered member is the one that counts.
    const signed = sign({ signatureAgentFormat: 'dictionary' });
    signed.headers['signature-input'] = signed.headers['signature-input']!.replace(
      '"signature-agent";key="sig1"',
      '"signature-agent";key="other"',
    );
    signed.headers['signature-agent'] =
      `sig1="${AGENT_ORIGIN}", other="https://impostor.example"`;

    const result = await verifier.verify(toIncoming(signed));
    if (result.trusted) throw new Error('impostor member must not be admitted');
    // Resolved as the impostor, which is not in the trust set. The one answer
    // that would be a real failure is a trusted verdict naming AGENT_ORIGIN.
    expect(result.reason).toBe('unknown_signature_agent');
    expect(result.message).toContain('impostor.example');
  });

  it('refuses a keyed component whose member is absent rather than falling back → signature_agent_member_missing', async () => {
    // The signature says it covers member "absent". There is no such member, so
    // there is nothing to attribute to; picking the only member present would
    // be attributing the signature to something it never covered.
    const signed = sign({ signatureAgentFormat: 'dictionary' });
    signed.headers['signature-input'] = signed.headers['signature-input']!.replace(
      '"signature-agent";key="sig1"',
      '"signature-agent";key="absent"',
    );
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_agent_member_missing', conclusive: true });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('no member keyed "absent"');
  });

  it('still accepts the deployed unkeyed component with a dictionary header', async () => {
    // chatgpt.com signs the whole field rather than a member. Covering the
    // field covers every member, so the label-matched member is still what the
    // signer committed to, and -02 Section 5.2.1 lets a verifier accept it.
    const signed = sign({
      signatureAgentFormat: 'dictionary',
      keyedSignatureAgentComponent: false,
    });
    expect(signed.headers['signature-input']).toContain('"signature-agent")');
    expect((await verifier.verify(toIncoming(signed))).trusted).toBe(true);
  });

  it('reports a redirected key directory apart from an unreachable one', async () => {
    // -02 Section 5.5 turned our redirect tolerance into non-conformance. The
    // merchant-facing story has to stay specific: this directory answered and
    // is misconfigured, which is not the same as being down, and neither one is
    // "we checked and this agent is unknown".
    const redirecting = new FetchingKeyDirectoryResolver({
      allowedOrigins: [AGENT_ORIGIN],
      fetchImpl: (async () =>
        new Response(null, {
          status: 301,
          headers: { location: 'https://www.agent.example/.well-known/http-message-signatures-directory' },
        })) as unknown as typeof fetch,
    });
    const redirectVerifier = new WebBotAuthVerifier({
      resolver: redirecting,
      now: () => FIXED_NOW,
    });

    const result = await redirectVerifier.verify(toIncoming(sign()));
    expect(result).toMatchObject({
      trusted: false,
      reason: 'key_directory_redirected',
      // Could-not-check: we never reached key material, so we do not claim to
      // have rejected the agent.
      conclusive: false,
    });
    if (result.trusted) throw new Error('unreachable');
    expect(result.reason).not.toBe('unknown_agent');
    expect(result.reason).not.toBe('key_directory_unavailable');
  });

  it('accepts directory keys whether alg is absent, JOSE, or the registry name', async () => {
    // Joshua Ashcroft's implementer report (list, 2026-08-18): stock WebCrypto
    // rejects alg "ed25519", so directories reasonably omit alg or send the
    // JOSE spelling. Dropping those keys would fail agents for a field -02
    // Section 5.5.1 never required them to send.
    const jwk = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    for (const alg of [undefined, 'EdDSA', 'eddsa', 'ed25519']) {
      const altResolver = new StaticSignatureAgentKeys();
      altResolver.add(AGENT_ORIGIN, {
        keys: [alg === undefined ? { ...jwk } : { ...jwk, alg }],
      });
      const altVerifier = new WebBotAuthVerifier({
        resolver: altResolver,
        now: () => FIXED_NOW,
      });
      const result = await altVerifier.verify(toIncoming(sign()));
      expect(result.trusted, `alg=${String(alg)} should verify`).toBe(true);
    }

    // A genuinely different algorithm is still dropped: the key cannot have
    // signed an ed25519 request.
    const wrongAlg = new StaticSignatureAgentKeys();
    wrongAlg.add(AGENT_ORIGIN, { keys: [{ ...jwk, alg: 'rsa-pss-sha512' }] });
    const wrongVerifier = new WebBotAuthVerifier({ resolver: wrongAlg, now: () => FIXED_NOW });
    expect((await wrongVerifier.verify(toIncoming(sign()))).trusted).toBe(false);
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

  it('rejects a published key outside its window → key_outside_validity_window (conclusive=true)', async () => {
    // Unlike an absent key (could-not-check), a key the directory publishes
    // with a window that excludes now is a definitive answer about that key.
    const jwk = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const expired = new StaticSignatureAgentKeys();
    expired.add(AGENT_ORIGIN, { keys: [{ ...jwk, exp: FIXED_NOW - 3600 }] });
    const notYet = new StaticSignatureAgentKeys();
    notYet.add(AGENT_ORIGIN, { keys: [{ ...jwk, nbf: FIXED_NOW + 3600 }] });

    for (const r of [expired, notYet]) {
      const v = new WebBotAuthVerifier({ resolver: r, now: () => FIXED_NOW });
      const result = await v.verify(toIncoming(sign()));
      expect(result).toMatchObject({
        trusted: false,
        reason: 'key_outside_validity_window',
        conclusive: true,
      });
      if (result.trusted) throw new Error('unreachable');
      expect(result.message).toContain('is published but');
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

  it('computes the RFC 7638 Section 3.2 EC thumbprint (pinned independent vector)', () => {
    // RFC 9421 Appendix B.1.3 test-key-ecc-p256. RFC 7638 publishes no EC
    // example, so the expected value was computed independently (Python
    // hashlib over the canonical {"crv","kty","x","y"} members, the same
    // script reproducing the RFC 7638 Section 3.1 RSA example exactly) and is
    // pinned here.
    expect(
      ecP256JwkThumbprint(
        'qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA',
        'Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0',
      ),
    ).toBe('ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI');
    // Coordinates must be whole 32-byte values, both of them.
    expect(() => ecP256JwkThumbprint('short', 'Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0')).toThrow(
      WebBotAuthParseError,
    );
    expect(() => ecP256JwkThumbprint('qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA', '')).toThrow(
      WebBotAuthParseError,
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
    // A path that looks like a jwks_uri does NOT change the type: the type is
    // never inferred from the path shape. With no type param the member is a
    // `directory` value, and §5.5 requires a directory value to be a bare
    // origin, so it is refused rather than silently read as a jwks_uri.
    expect(() => parseSignatureAgent('sig1="https://agent.example/jwks.json"', 'sig1')).toThrow(
      /not an origin serialization/,
    );
    // Declared as jwks_uri, the same URL is fine: that type points at a file.
    expect(
      parseSignatureAgent('sig1="https://agent.example/jwks.json";type=jwks_uri', 'sig1').type,
    ).toBe('jwks_uri');
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

  it('drops only material it cannot use, and reports what it dropped and why', () => {
    const keys = generateAgentKeyPair();
    const ecKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const jwk = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const ecJwk = ecKeys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const { keys: parsed, dropped } = readKeyDirectory({
      keys: [
        jwk, // good Ed25519
        { ...jwk, kid: 'not-the-thumbprint' }, // mislabelled, but the material is fine → KEPT
        ecJwk, // good EC P-256 → KEPT (algorithm agility)
        { ...jwk, use: 'enc' }, // wrong use → dropped
        { ...jwk, alg: 'RS256' }, // alg contradicts the OKP key → dropped
        { ...jwk, alg: 'ES256' }, // EC alg on an Ed25519 key → dropped (mismatch)
        { ...ecJwk, alg: 'EdDSA' }, // Ed25519 alg on an EC key → dropped (mismatch)
        p384.publicKey.export({ format: 'jwk' }), // unsupported curve → dropped
        { kty: 'RSA', n: 'xxx', e: 'AQAB' }, // RSA: a stated non-goal → dropped
        { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }, // malformed coordinates → dropped
        { kty: 'OKP', crv: 'Ed25519', x: 'too-short' }, // malformed x → dropped
        'garbage',
      ],
    });
    // A kid that differs from the thumbprint never drops the key: the label
    // rides along as a hint and the identity stays the computed thumbprint.
    expect(parsed).toHaveLength(3);
    expect(parsed[0]?.thumbprint).toBe(webBotAuthKeyId(keys.publicKey));
    expect(parsed[0]?.kid).toBeUndefined();
    expect(parsed[1]).toMatchObject({
      thumbprint: webBotAuthKeyId(keys.publicKey),
      kid: 'not-the-thumbprint',
    });
    expect(parsed[2]).toMatchObject({
      thumbprint: ecP256JwkThumbprint(ecJwk.x as string, ecJwk.y as string),
      crv: 'P-256',
    });
    expect(dropped.map((d) => d.index)).toEqual([3, 4, 5, 6, 7, 8, 9, 10, 11]);
    for (const d of dropped) expect(d.reason).toBeTruthy();
    // The reasons are truthful: mismatches say so, RSA is a decision, curves
    // are named.
    expect(dropped[2]?.reason).toContain('mismatched alg');
    expect(dropped[3]?.reason).toContain('mismatched alg');
    expect(dropped[4]?.reason).toContain('P-384');
    expect(dropped[5]?.reason).toContain('RSA keys are not supported');
    expect(dropped[5]?.reason).toContain('non-goal');

    // Registry and JOSE spellings survive on their own key types.
    for (const alg of ['ed25519', 'EdDSA']) {
      expect(parseKeyDirectory({ keys: [{ ...jwk, alg }] })).toHaveLength(1);
    }
    expect(parseKeyDirectory({ keys: [{ ...ecJwk, alg: 'ES256' }] })).toHaveLength(1);
  });

  it('treats a directory of more than 100 entries as unusable, never truncated', () => {
    const keys = generateAgentKeyPair();
    const jwk = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    expect(parseKeyDirectory({ keys: Array(100).fill(jwk) })).toHaveLength(100);
    expect(() => parseKeyDirectory({ keys: Array(101).fill(jwk) })).toThrow(WebBotAuthParseError);
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
    const { impl, calls } = fakeFetch(() => new Response(directoryBody, DIRECTORY_TYPE));
    const resolver = new FetchingKeyDirectoryResolver({ allowedOrigins: [ORIGIN], fetchImpl: impl });
    expect(await resolver.resolve('https://internal.metadata.example')).toEqual({
      status: 'not_allowed',
    });
    expect(calls).toHaveLength(0);
  });

  it('fetches, parses, and caches an allowlisted directory', async () => {
    const { impl, calls } = fakeFetch(() => new Response(directoryBody, DIRECTORY_TYPE));
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
      // Junk under the right media type: parsed, fails, so unavailable.
      () => new Response('<!doctype html><html></html>', DIRECTORY_TYPE),
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
      fetchImpl: fakeFetch(() => new Response(huge, DIRECTORY_TYPE)).impl,
    });
    expect((await resolver.resolve(ORIGIN)).status).toBe('unavailable');
  });

  // -02 Section 5.5 requires 200 (OK) and forbids following redirects. These
  // replace four tests that asserted the -01 era tolerance (up to three https,
  // allowlisted hops), which the draft made non-conformant.
  it('refuses a redirect instead of following it, and never fetches the target', async () => {
    const ORIGIN2 = 'https://cdn.agent.example';
    const { impl, calls } = fakeFetch((url) =>
      url.startsWith(ORIGIN2)
        ? new Response(directoryBody, DIRECTORY_TYPE) // following this hop would be the bug
        : new Response(null, {
            status: 301,
            headers: { location: `${ORIGIN2}/.well-known/http-message-signatures-directory` },
          }),
    );
    const resolver = new FetchingKeyDirectoryResolver({
      allowedOrigins: [ORIGIN, ORIGIN2],
      fetchImpl: impl,
    });
    // Even with the redirect target allowlisted, and serving a directory that
    // would have parsed, the hop is not taken.
    expect((await resolver.resolve(ORIGIN)).status).toBe('redirected');
    expect(calls).toEqual([`${ORIGIN}/.well-known/http-message-signatures-directory`]);
  });

  it('reports every redirect status as redirected, not unavailable', async () => {
    for (const status of [301, 302, 303, 307, 308]) {
      const resolver = new FetchingKeyDirectoryResolver({
        allowedOrigins: [ORIGIN],
        fetchImpl: fakeFetch(() =>
          new Response(null, {
            status,
            headers: { location: 'https://elsewhere.example/.well-known/http-message-signatures-directory' },
          }),
        ).impl,
      });
      const resolution = await resolver.resolve(ORIGIN);
      expect(resolution.status).toBe('redirected');
      expect(resolution.status === 'redirected' && resolution.detail).toBe(`HTTP ${status}`);
    }
  });

  it('refuses a same-origin redirect loop with a single fetch', async () => {
    const { impl, calls } = fakeFetch(() =>
      new Response(null, {
        status: 301,
        headers: { location: `${ORIGIN}/.well-known/http-message-signatures-directory` },
      }),
    );
    const resolver = new FetchingKeyDirectoryResolver({ allowedOrigins: [ORIGIN], fetchImpl: impl });
    expect((await resolver.resolve(ORIGIN)).status).toBe('redirected');
    expect(calls).toHaveLength(1);
  });

  it('requires exactly 200, so a 2xx carrying no key set is unavailable', async () => {
    for (const status of [201, 202, 204]) {
      const resolver = new FetchingKeyDirectoryResolver({
        allowedOrigins: [ORIGIN],
        fetchImpl: fakeFetch(() => new Response(null, { status })).impl,
      });
      const resolution = await resolver.resolve(ORIGIN);
      expect(resolution.status).toBe('unavailable');
      expect(resolution.status === 'unavailable' && resolution.detail).toBe(`HTTP ${status}`);
    }
  });

  it('ships chatgpt.com and agent.bot.goog as the default trusted signature agents', () => {
    expect(DEFAULT_SIGNATURE_AGENTS).toEqual(['https://chatgpt.com', 'https://agent.bot.goog']);
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
          ...DIRECTORY_TYPE.headers,
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
        DIRECTORY_TYPE,
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

/**
 * Regressions from the ParallaxGrain negative-vector cross-check
 * (github.com/ParallaxGrain/webbotauth-negative-vectors, offered on
 * thibmeu/http-message-signatures-directory issue #11).
 *
 * Three of his seventeen vectors VERIFIED against our verifier before this
 * block existed. Each is a request that must not verify, and each got through
 * a different hole. Kept here as behavior tests with our own keys rather than
 * as a copy of his set: the vectors are still under review and pinning them is
 * a separate call. See CROSSCHECK-REPORT.md in the strategy folder.
 */
describe('WebBotAuthVerifier: negative-vector cross-check regressions', () => {
  const FIXED_NOW = 1_750_000_000;
  const AGENT_ORIGIN = 'https://agent.example';
  const MERCHANT_URL = 'https://shop.example.com/products/tool-1234';

  let keys: AgentKeyPair;
  let resolver: StaticSignatureAgentKeys;
  let verifier: WebBotAuthVerifier;

  beforeEach(() => {
    keys = generateAgentKeyPair();
    resolver = new StaticSignatureAgentKeys();
    resolver.add(AGENT_ORIGIN, jwksFor(keys));
    verifier = new WebBotAuthVerifier({ resolver, now: () => FIXED_NOW });
  });

  // NV-19. RFC 9421 §2.5 step 2.1: "If the component identifier (including its
  // parameters) has already been added to the signature base, produce an
  // error." We used to build the base anyway, and a signature made over that
  // base then verified.
  it('refuses a Signature-Input that covers the same component identifier twice → duplicate_covered_component', async () => {
    const signed = signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: AGENT_ORIGIN,
      privateKey: keys.privateKey,
      created: FIXED_NOW - 5,
      components: ['@authority', '@authority', 'signature-agent'],
    });
    // The signer produced a real signature over the repeated base, so this is
    // rejected on the rule and not because the crypto failed.
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'duplicate_covered_component', conclusive: true });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toMatch(/more than once/);
  });

  // The same identifier with DIFFERENT parameters is a different identifier and
  // stays legal, which is the half a name-only duplicate check would break.
  it('still accepts the same component name under two different key parameters', () => {
    const parsed = parseSignatureInput(
      'sig1=("signature-agent";key="a" "signature-agent";key="b" "@authority");' +
        'created=1;expires=2;keyid="k";tag="web-bot-auth"',
    );
    expect(parsed.components).toEqual(['signature-agent', 'signature-agent', '@authority']);
  });

  // NV-13. §5.2.2: "A verifier MUST NOT attribute a signature to a member that
  // signature does not cover." With several usable members and no label match
  // we used to take the first one in header order and verify against it.
  it('refuses to attribute a signature when several Signature-Agent members could match → signature_agent_ambiguous', async () => {
    const signed = signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: AGENT_ORIGIN,
      privateKey: keys.privateKey,
      created: FIXED_NOW - 5,
    });
    // Two members, neither keyed to the signature label, and the covered
    // component is the unkeyed whole field. The signature itself is untouched.
    signed.headers['signature-agent'] =
      `first="${AGENT_ORIGIN}", second="https://other-agent.example"`;
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_agent_ambiguous', conclusive: true });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toMatch(/cannot be attributed/);
  });

  // One usable member that is not label-matched is still resolved: that is the
  // published -00 E.2.1 shape (signature sig2, member agent2; re-keyed to sig2
  // in the editor's copy by WG PR #138 on 2026-10-09) and the deployed
  // bare-string traffic. The NV-13 fix must not cost us either.
  it('still resolves a single Signature-Agent member that does not match the label', () => {
    const parsed = parseSignatureAgent(`only="${AGENT_ORIGIN}"`, 'sig1');
    expect(parsed.origin).toBe(AGENT_ORIGIN);
    expect(parsed.type).toBe('directory');
  });

  // NV-17. §5.5: the directory member value "MUST be the ASCII serialization of
  // an origin ... and a verifier MUST ignore a member carrying anything else".
  // We used to take url.origin and discard the path, then verify the request
  // and report binding="domain" for it.
  it('refuses a directory-type Signature-Agent that carries a path → signature_agent_not_origin', async () => {
    const signed = signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: `${AGENT_ORIGIN}/keys`,
      privateKey: keys.privateKey,
      created: FIXED_NOW - 5,
    });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_agent_not_origin', conclusive: true });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toMatch(/not an origin serialization/);
  });

  // A bare origin's URL pathname is "/", which §5.5 exempts explicitly.
  it('still accepts a bare origin, whose parsed path is a single slash', () => {
    expect(parseSignatureAgent(`sig1="${AGENT_ORIGIN}"`, 'sig1').origin).toBe(AGENT_ORIGIN);
    expect(parseSignatureAgent(`sig1="${AGENT_ORIGIN}/"`, 'sig1').origin).toBe(AGENT_ORIGIN);
  });
});

/**
 * Regression for the agent.bot.goog defect (2026-09-29, wba-kid-is-a-hint):
 * Google's live directory publishes five Ed25519 keys under six-char kids
 * (none the RFC 7638 thumbprint) and its requests may sign with those kids as
 * keyid. Three code sites assumed thumbprints everywhere: parseDirectoryKey
 * dropped every mislabelled key (Google parsed to ZERO keys), the verifier
 * failed any non-43-char keyid as signature_input_malformed before fetching,
 * and unknown_key then claimed a published key "is not published". Principle:
 * the identity of a key is its material; kid and keyid are selectors, and a
 * selector that does not follow -00 is a warning, never a reason to drop a
 * key or fail a request that verifies.
 */
describe('WebBotAuthVerifier: kid is a hint, not an identity (agent.bot.goog regression)', () => {
  const FIXED_NOW = 1_750_000_000;
  const AGENT_ORIGIN = 'https://agent.example';
  const MERCHANT_URL = 'https://shop.example.com/products/tool-1234';
  const SHORT_KID = 'mhxuPw';

  let keys: AgentKeyPair;
  let resolver: StaticSignatureAgentKeys;
  let warnings: string[];
  let verifier: WebBotAuthVerifier;

  beforeEach(() => {
    keys = generateAgentKeyPair();
    resolver = new StaticSignatureAgentKeys();
    const jwk = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    // Google's shape: EdDSA alg, use sig, and a kid that is not the thumbprint.
    resolver.add(AGENT_ORIGIN, { keys: [{ ...jwk, alg: 'EdDSA', use: 'sig', kid: SHORT_KID }] });
    warnings = [];
    verifier = new WebBotAuthVerifier({
      resolver,
      now: () => FIXED_NOW,
      onWarning: (message) => warnings.push(message),
    });
  });

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

  it('verifies a request whose keyid is the advertised six-char kid, with a warning', async () => {
    const result = await verifier.verify(toIncoming(sign({ keyid: SHORT_KID })));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    // The identity reported downstream is the COMPUTED thumbprint, never the
    // wire label, so the (URL, key) keying of Section 5.5.2 is unchanged.
    expect(result.agent?.keyThumbprint).toBe(webBotAuthKeyId(keys.publicKey));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(AGENT_ORIGIN);
    expect(warnings[0]).toContain('draft-ietf-webbotauth-httpsig-protocol-00');
  });

  it('verifies a thumbprint keyid against the same directory with no warning', async () => {
    const result = await verifier.verify(toIncoming(sign()));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.agent?.keyThumbprint).toBe(webBotAuthKeyId(keys.publicKey));
    expect(warnings).toHaveLength(0);
  });

  it('says exactly what unknown_key means: matched by neither thumbprint nor kid', async () => {
    const stranger = generateAgentKeyPair();
    const result = await verifier.verify(
      toIncoming(sign({ privateKey: stranger.privateKey })),
    );
    // Could-not-check since the conclusiveness split: absence is not evidence.
    expect(result).toMatchObject({ trusted: false, reason: 'unknown_key', conclusive: false });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('matched none of the 1 keys');
    expect(result.message).toContain('by thumbprint or by advertised kid');
    // The old false claim is impossible for a key that is present.
    expect(result.message).not.toContain('is not published');
  });

  it('still rejects a keyid beyond the sanity bound as signature_input_malformed', async () => {
    // Non-empty printable ASCII up to 128 chars reaches the directory; only a
    // shape no label could have is still malformed.
    const long = 'k'.repeat(129);
    const result = await verifier.verify(toIncoming(sign({ keyid: long })));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_input_malformed' });
  });

  it('treats a fetched directory whose entries are all unusable as could-not-check', async () => {
    // Entries present, zero usable keys: this says nothing about the signer,
    // so it must be the inconclusive key_directory_unavailable, never a
    // conclusive unknown_key.
    const fetchImpl = (async () =>
      new Response(
        JSON.stringify({ keys: [{ kty: 'RSA', n: 'xxx', e: 'AQAB' }, { kty: 'OKP', crv: 'Ed25519', x: 'short' }] }),
        { headers: { 'content-type': 'application/http-message-signatures-directory+json' } },
      )) as unknown as typeof fetch;
    const fetching = new WebBotAuthVerifier({
      resolver: new FetchingKeyDirectoryResolver({
        allowedOrigins: [AGENT_ORIGIN],
        fetchImpl,
        nowMs: () => FIXED_NOW * 1000,
        onWarning: () => {},
      }),
      now: () => FIXED_NOW,
    });
    const result = await fetching.verify(toIncoming(sign()));
    expect(result).toMatchObject({
      trusted: false,
      reason: 'key_directory_unavailable',
      conclusive: false,
    });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('2 entries, none usable');
  });

  it('fails unknown_key against a directory that truly publishes no keys', async () => {
    // An EMPTY key list with nothing dropped still refuses the request, but
    // since the conclusiveness split it reads as could-not-check like any
    // other absent key: a cached or mid-rotation empty list is
    // indistinguishable from a permanent one, and the table fixes the outcome
    // per reason.
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ keys: [] }), {
        headers: { 'content-type': 'application/http-message-signatures-directory+json' },
      })) as unknown as typeof fetch;
    const fetching = new WebBotAuthVerifier({
      resolver: new FetchingKeyDirectoryResolver({
        allowedOrigins: [AGENT_ORIGIN],
        fetchImpl,
        nowMs: () => FIXED_NOW * 1000,
      }),
      now: () => FIXED_NOW,
    });
    const result = await fetching.verify(toIncoming(sign()));
    expect(result).toMatchObject({ trusted: false, reason: 'unknown_key', conclusive: false });
  });

  it('refuses to select by an advertised kid that appears on two keys', async () => {
    const other = generateAgentKeyPair();
    const dup = new StaticSignatureAgentKeys();
    const jwkA = keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const jwkB = other.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    dup.add(AGENT_ORIGIN, { keys: [{ ...jwkA, kid: SHORT_KID }, { ...jwkB, kid: SHORT_KID }] });
    const ambiguous = new WebBotAuthVerifier({ resolver: dup, now: () => FIXED_NOW });
    const result = await ambiguous.verify(toIncoming(sign({ keyid: SHORT_KID })));
    expect(result).toMatchObject({ trusted: false, reason: 'unknown_key' });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('appears on 2 keys');
  });
});

/**
 * Algorithm agility (2026-10-26): -00 §5.2 defines keyids for RSA and EC keys
 * too, §5.5.1 (editor's copy, WG PR #139) lets a directory JWK carry
 * alg "ES256", and UCP's published signatures spec recommends ES256 with a WBA
 * dual-audience shape. ecdsa-p256-sha256 verifies beside ed25519; RSA stays a
 * stated non-goal. Real P-256 crypto throughout.
 */
describe('WebBotAuthVerifier algorithm agility (ES256 / ecdsa-p256-sha256)', () => {
  let ecKeys: { publicKey: KeyObject; privateKey: KeyObject };
  let resolver: StaticSignatureAgentKeys;
  let verifier: WebBotAuthVerifier;

  beforeEach(() => {
    ecKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    resolver = new StaticSignatureAgentKeys();
    resolver.add(AGENT_ORIGIN, {
      keys: [{ ...(ecKeys.publicKey.export({ format: 'jwk' }) as object), alg: 'ES256', use: 'sig' }],
    });
    verifier = new WebBotAuthVerifier({ resolver, now: () => FIXED_NOW });
  });

  function signEc(overrides: Partial<Parameters<typeof signWithWebBotAuth>[0]> = {}) {
    return signWithWebBotAuth({
      method: 'GET',
      url: MERCHANT_URL,
      signatureAgent: AGENT_ORIGIN,
      privateKey: ecKeys.privateKey,
      created: FIXED_NOW - 5,
      ...overrides,
    });
  }

  it('verifies an ES256-signed request; identity is the computed EC thumbprint', async () => {
    const signed = signEc();
    // The SDK signer derives the wire alg and keyid from the key itself.
    expect(signed.headers['signature-input']).toContain('alg="ecdsa-p256-sha256"');
    const result = await verifier.verify(toIncoming(signed));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.agent).toEqual({
      id: AGENT_ORIGIN,
      protocol: 'web-bot-auth',
      keyThumbprint: webBotAuthKeyId(ecKeys.publicKey),
      binding: 'domain',
    });
  });

  it('verifies with alg omitted: the selected key type decides', async () => {
    expect((await verifier.verify(toIncoming(signEc({ alg: null })))).trusted).toBe(true);
  });

  it('rejects alg ed25519 on a signature whose key is EC → unsupported_algorithm (mismatch)', async () => {
    const result = await verifier.verify(toIncoming(signEc({ alg: 'ed25519' })));
    expect(result).toMatchObject({ trusted: false, reason: 'unsupported_algorithm', conclusive: true });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('ecdsa-p256-sha256');
  });

  it('rejects a DER-encoded ECDSA signature: RFC 9421 §3.3.4 requires raw r||s', async () => {
    const signed = signEc();
    const rawB64 = signed.headers['signature']!.match(/^sig1=:(.+):$/)![1]!;
    const der = rawToDer(Buffer.from(rawB64, 'base64'));
    expect(der.length).not.toBe(64);
    signed.headers['signature'] = `sig1=:${der.toString('base64')}:`;
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'signature_value_malformed' });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('64 bytes');
  });

  it('rejects a forged ES256 signature under the published keyid → invalid_signature, named truthfully', async () => {
    const stranger = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const signed = signEc({
      privateKey: stranger.privateKey,
      keyid: webBotAuthKeyId(ecKeys.publicKey),
    });
    const result = await verifier.verify(toIncoming(signed));
    expect(result).toMatchObject({ trusted: false, reason: 'invalid_signature' });
    if (result.trusted) throw new Error('unreachable');
    expect(result.message).toContain('ECDSA P-256');
  });

  it('drops a P-384 key: a single-key P-384 directory resolves to zero usable keys', async () => {
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const jwk = p384.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const { keys: parsed, dropped } = readKeyDirectory({ keys: [jwk] });
    expect(parsed).toHaveLength(0);
    expect(dropped[0]?.reason).toContain('P-384');
  });

  it('verifies the UCP dual-audience shape in both algorithms', async () => {
    // UCP layers its own UCP-Agent header over a Web Bot Auth signature:
    // Signature-Agent with tag="web-bot-auth", keyid = the key thumbprint
    // (EC for UCP's recommended ES256 default). The extra header changes
    // nothing for this verifier and must not be mistaken for another protocol.
    const edKeys = generateAgentKeyPair();
    const dualResolver = new StaticSignatureAgentKeys();
    dualResolver.add(AGENT_ORIGIN, {
      keys: [
        ecKeys.publicKey.export({ format: 'jwk' }) as object,
        edKeys.publicKey.export({ format: 'jwk' }) as object,
      ],
    });
    const dualVerifier = new WebBotAuthVerifier({ resolver: dualResolver, now: () => FIXED_NOW });

    for (const privateKey of [ecKeys.privateKey, edKeys.privateKey]) {
      const signed = signWithWebBotAuth({
        method: 'GET',
        url: MERCHANT_URL,
        signatureAgent: AGENT_ORIGIN,
        privateKey,
        created: FIXED_NOW - 5,
        signatureAgentFormat: 'dictionary',
        extraHeaders: { 'ucp-agent': 'profile="https://ucp.example/profiles/shopping"' },
      });
      expect(signed.headers['signature-input']).toContain('tag="web-bot-auth"');
      const result = await dualVerifier.verify(toIncoming(signed));
      if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
      expect(result.agent?.id).toBe(AGENT_ORIGIN);
    }
  });
});

/** Minimal DER encoding of an ECDSA r||s pair, for the negative test only. */
function rawToDer(raw: Buffer): Buffer {
  const int = (bytes: Buffer): Buffer => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.subarray(i);
    if ((v[0]! & 0x80) !== 0) v = Buffer.concat([Buffer.from([0]), v]);
    return Buffer.concat([Buffer.from([0x02, v.length]), v]);
  };
  const body = Buffer.concat([int(raw.subarray(0, 32)), int(raw.subarray(32))]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

describe('FetchingKeyDirectoryResolver cache freshness (Cache-Control / Age)', () => {
  const ORIGIN = 'https://agent.example';
  let directoryBody: string;

  beforeEach(() => {
    const keys = generateAgentKeyPair();
    directoryBody = JSON.stringify({ keys: [keys.publicKey.export({ format: 'jwk' })] });
  });

  function countingFetch(headers: Record<string, string>): { impl: typeof fetch; calls: string[] } {
    const calls: string[] = [];
    const impl = (async (input: unknown) => {
      calls.push(String(input));
      return new Response(directoryBody, { headers });
    }) as typeof fetch;
    return { impl, calls };
  }

  it('expires the cached directory with the edge copy: Age 290 of max-age 300 leaves 10 seconds', async () => {
    let nowMs = 1_000_000;
    const { impl, calls } = countingFetch({
      ...DIRECTORY_TYPE.headers,
      'cache-control': 'public, max-age=300',
      age: '290',
    });
    const resolver = new FetchingKeyDirectoryResolver({
      allowedOrigins: [ORIGIN],
      fetchImpl: impl,
      nowMs: () => nowMs,
    });
    await resolver.resolve(ORIGIN);
    expect(calls).toHaveLength(1);
    nowMs += 9_000; // still inside the 10 s the edge's copy has left
    await resolver.resolve(ORIGIN);
    expect(calls).toHaveLength(1);
    nowMs += 2_000; // 11 s after our fetch: the copy has expired everywhere
    await resolver.resolve(ORIGIN);
    expect(calls).toHaveLength(2);
  });

  it('keeps the configured TTL without max-age, and as the ceiling under a longer max-age', async () => {
    const variants: Record<string, string>[] = [{}, { 'cache-control': 'max-age=86400' }];
    for (const extra of variants) {
      let nowMs = 1_000_000;
      const { impl, calls } = countingFetch({ ...DIRECTORY_TYPE.headers, ...extra });
      const resolver = new FetchingKeyDirectoryResolver({
        allowedOrigins: [ORIGIN],
        fetchImpl: impl,
        nowMs: () => nowMs,
        cacheTtlMs: 60_000,
      });
      await resolver.resolve(ORIGIN);
      nowMs += 59_000;
      await resolver.resolve(ORIGIN);
      expect(calls).toHaveLength(1);
      nowMs += 2_000;
      await resolver.resolve(ORIGIN);
      expect(calls).toHaveLength(2);
    }
  });
});

/**
 * Frozen ES256 fixture: directory body, Appendix B response proof, and a
 * signed request, all made with the RFC 9421 B.1.3 P-256 test key (generator:
 * scripts/generate-es256-wba-fixture.mjs). The clock is pinned inside the
 * fixture, so it does not age.
 */
describe('the frozen ES256 Web Bot Auth fixture', () => {
  const fixture = JSON.parse(
    readFileSync(new URL('./fixtures/es256-web-bot-auth-2026-10-26.json', import.meta.url), 'utf8'),
  ) as {
    origin: string;
    now: number;
    thumbprint: string;
    directory: { body: string; headers: Record<string, string> };
    request: IncomingRequest;
  };

  const fetchImpl = (async () =>
    new Response(fixture.directory.body, { headers: fixture.directory.headers })) as unknown as typeof fetch;

  function fixtureResolver(): FetchingKeyDirectoryResolver {
    return new FetchingKeyDirectoryResolver({
      allowedOrigins: [fixture.origin],
      fetchImpl,
      nowMs: () => fixture.now * 1000,
      onWarning: () => {},
    });
  }

  it('pins the key thumbprint to the independently computed vector', () => {
    expect(fixture.thumbprint).toBe('ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI');
  });

  it('classifies the EC Appendix B proof valid at the resolver', async () => {
    const res = await fixtureResolver().resolve(fixture.origin);
    if (res.status !== 'ok') throw new Error(`expected ok, got ${JSON.stringify(res)}`);
    expect(res.keys.map((k) => [k.thumbprint, k.proof])).toEqual([[fixture.thumbprint, 'valid']]);
  });

  it('verifies the signed request end to end, with the proof REQUIRED for this origin', async () => {
    const verifier = new WebBotAuthVerifier({
      resolver: fixtureResolver(),
      proofRequiredOrigins: [fixture.origin],
      now: () => fixture.now,
      onWarning: () => {},
    });
    const result = await verifier.verify(fixture.request);
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.agent).toEqual({
      id: fixture.origin,
      protocol: 'web-bot-auth',
      keyThumbprint: fixture.thumbprint,
      binding: 'domain',
    });
  });

  it('fails the request when a covered component is tampered', async () => {
    const tampered = { ...fixture.request, url: 'https://shop.example.com/admin' };
    const verifier = new WebBotAuthVerifier({
      resolver: fixtureResolver(),
      now: () => fixture.now,
      onWarning: () => {},
    });
    expect(await verifier.verify(tampered)).toMatchObject({
      trusted: false,
      reason: 'invalid_signature',
    });
  });
});
