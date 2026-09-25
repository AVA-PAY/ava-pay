import { createHash, sign as nodeSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  FetchingKeyDirectoryResolver,
  WebBotAuthVerifier,
} from '../src/verifier/web-bot-auth.js';
import {
  parseKeyDirectory,
  verifyDirectoryProofs,
  type KeyProofStatus,
} from '@ava-pay/agent/protocol/web-bot-auth';
import { generateAgentKeyPair, signWithWebBotAuth, webBotAuthKeyId } from '../src/sdk/index.js';
import type { AgentKeyPair } from '../src/sdk/index.js';

/**
 * Appendix B directory proofs are verified over the bytes the directory sent.
 *
 * Until this suite existed the verifier rebuilt `@signature-params` from a
 * fixed template of created/expires/keyid/tag. chatgpt.com's live proof also
 * carries `alg="ed25519"`, so the rebuilt base differed from the signed one and
 * every ChatGPT key came back `invalid`, which rejected every ChatGPT-signed
 * request as key_proof_invalid. RFC 9421 Section 2.3 makes the line the
 * Signature-Input member value exactly as received.
 *
 * Every proof below other than the frozen ChatGPT one is signed here over a
 * base this file builds by hand from the member text, NOT through the SDK's
 * signDirectoryResponse (whose template is the thing that could not express
 * these shapes). Real Ed25519 throughout.
 */

const TAG = 'http-message-signatures-directory';
const COVERED = '("@authority";req "content-digest")';

interface ResponseFixture {
  body: string;
  contentDigest: string;
  signatureInput: string;
  signature: string;
}

/** chatgpt.com's key directory response, captured 2026-09-25T14:25:27Z. */
const chatgpt = JSON.parse(
  readFileSync(new URL('./fixtures/chatgpt-directory-proof-2026-09-25.json', import.meta.url), 'utf8'),
) as ResponseFixture;
const CHATGPT_AUTHORITY = 'chatgpt.com';
const CHATGPT_KEYID = 'ArwjqcCqtA5oxEWkzXGC-To_0A9whHmajCHtfe8I9aY';
const CHATGPT_CREATED = 1790346327;

function classify(
  response: ResponseFixture | (Omit<ResponseFixture, 'contentDigest'> & { contentDigest?: string }),
  opts: { authority: string; now: number; keyid: string },
): KeyProofStatus | undefined {
  const keys = parseKeyDirectory(JSON.parse(response.body));
  return verifyDirectoryProofs({
    authority: opts.authority,
    body: response.body,
    contentDigest: response.contentDigest,
    signatureInput: response.signatureInput,
    signature: response.signature,
    now: opts.now,
    skewSeconds: 0,
    keys,
  }).get(opts.keyid);
}

describe('the frozen chatgpt.com directory proof', () => {
  it('pins the captured response bytes', () => {
    expect(Buffer.byteLength(chatgpt.body)).toBe(243);
    expect(chatgpt.contentDigest).toBe(
      `sha-256=:${createHash('sha256').update(chatgpt.body).digest('base64')}:`,
    );
    expect(chatgpt.signatureInput).toContain(';alg="ed25519"');
    expect(chatgpt.signatureInput).toContain(`created=${CHATGPT_CREATED}`);
  });

  it('classifies the live ChatGPT key valid', () => {
    expect(
      classify(chatgpt, { authority: CHATGPT_AUTHORITY, now: CHATGPT_CREATED, keyid: CHATGPT_KEYID }),
    ).toBe('valid');
  });

  it('still binds the proof to the authority that served it', () => {
    expect(
      classify(chatgpt, { authority: 'chatgpt.example', now: CHATGPT_CREATED, keyid: CHATGPT_KEYID }),
    ).toBe('invalid');
  });

  it('is invalid, not absent, when the response Content-Digest header is missing', () => {
    const { contentDigest: _dropped, ...withoutDigest } = chatgpt;
    expect(
      classify(withoutDigest, { authority: CHATGPT_AUTHORITY, now: CHATGPT_CREATED, keyid: CHATGPT_KEYID }),
    ).toBe('invalid');
  });

  it('classifies valid through the fetching resolver, headers as served', async () => {
    const fetchImpl = (async () =>
      new Response(chatgpt.body, {
        headers: {
          'content-type': 'application/http-message-signatures-directory+json',
          'content-digest': chatgpt.contentDigest,
          'signature-input': chatgpt.signatureInput,
          signature: chatgpt.signature,
        },
      })) as unknown as typeof fetch;
    const resolver = new FetchingKeyDirectoryResolver({
      allowedOrigins: ['https://chatgpt.com'],
      fetchImpl,
      nowMs: () => CHATGPT_CREATED * 1000,
    });
    const res = await resolver.resolve('https://chatgpt.com');
    if (res.status !== 'ok') throw new Error(`expected ok, got ${JSON.stringify(res)}`);
    expect(res.keys.map((k) => [k.thumbprint, k.proof])).toEqual([[CHATGPT_KEYID, 'valid']]);
  });
});

describe('directory proofs signed over arbitrary member text', () => {
  const AUTHORITY = 'agent.example';
  const NOW = 1_750_000_000;
  let keys: AgentKeyPair;
  let keyid: string;
  let body: string;

  beforeEach(() => {
    keys = generateAgentKeyPair();
    keyid = webBotAuthKeyId(keys.publicKey);
    body = JSON.stringify({ keys: [keys.publicKey.export({ format: 'jwk' })] });
  });

  const sha256 = (data: string): string => `sha-256=:${createHash('sha256').update(data).digest('base64')}:`;
  const sha512 = (data: string): string => `sha-512=:${createHash('sha512').update(data).digest('base64')}:`;

  /**
   * Sign `member` (a Signature-Input member value) the way RFC 9421 says to:
   * one line per covered component in the member's own order, then the member
   * verbatim as @signature-params. `extra` supplies values for components other
   * than the two Appendix B names.
   */
  function signedResponse(opts: {
    member: string;
    contentDigest?: string;
    extra?: Record<string, string>;
  }): ResponseFixture {
    const contentDigest = opts.contentDigest ?? sha256(body);
    const list = opts.member.slice(1, opts.member.indexOf(')'));
    const lines = list.split(' ').map((id) => {
      if (id === '"@authority";req') return `${id}: ${AUTHORITY}`;
      if (id === '"content-digest"') return `${id}: ${contentDigest}`;
      const value = opts.extra?.[id];
      if (value === undefined) throw new Error(`no value for ${id}`);
      return `${id}: ${value}`;
    });
    lines.push(`"@signature-params": ${opts.member}`);
    const sig = nodeSign(null, Buffer.from(lines.join('\n')), keys.privateKey);
    return {
      body,
      contentDigest,
      signatureInput: `proof=${opts.member}`,
      signature: `proof=:${sig.toString('base64')}:`,
    };
  }

  const window = `created=${NOW - 60};expires=${NOW + 3600}`;
  const status = (response: ResponseFixture): KeyProofStatus | undefined =>
    classify(response, { authority: AUTHORITY, now: NOW, keyid });

  it('accepts the template order with no alg (the E.2.3 shape)', () => {
    expect(status(signedResponse({ member: `${COVERED};${window};keyid="${keyid}";tag="${TAG}"` }))).toBe(
      'valid',
    );
  });

  it('accepts alg="ed25519", as chatgpt.com sends it', () => {
    const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}";alg="ed25519"`;
    expect(status(signedResponse({ member }))).toBe('valid');
  });

  it('accepts the parameters in another order', () => {
    const member = `${COVERED};tag="${TAG}";alg="ed25519";keyid="${keyid}";expires=${NOW + 3600};created=${NOW - 60}`;
    expect(status(signedResponse({ member }))).toBe('valid');
  });

  it('accepts parameters it does not read (nonce, an unknown one)', () => {
    const member =
      `${COVERED};${window};nonce="bm9uY2U";keyid="${keyid}";tag="${TAG}";x-unknown=token;flag`;
    expect(status(signedResponse({ member }))).toBe('valid');
  });

  it('keeps a quoted string with ; and , inside it as one member', () => {
    const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}";note="a;b, c=d"`;
    const response = signedResponse({ member });
    expect(status({ ...response, signatureInput: `other=("@authority";req), ${response.signatureInput}` })).toBe(
      'valid',
    );
  });

  it('rejects any alg other than ed25519', () => {
    for (const alg of ['"rsa-pss-sha512"', '"ecdsa-p256-sha256"', '"ED25519"', 'ed25519']) {
      const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}";alg=${alg}`;
      expect(status(signedResponse({ member })), alg).toBe('invalid');
    }
  });

  it('rejects a covered list with a third component, though the signature is good over it', () => {
    const member = `("@authority";req "content-digest" "content-type");${window};keyid="${keyid}";tag="${TAG}"`;
    const response = signedResponse({
      member,
      extra: { '"content-type"': 'application/http-message-signatures-directory+json' },
    });
    expect(status(response)).toBe('invalid');
  });

  it('rejects the two covered components in the other order', () => {
    const member = `("content-digest" "@authority";req);${window};keyid="${keyid}";tag="${TAG}"`;
    expect(status(signedResponse({ member }))).toBe('invalid');
  });

  it('rejects a covered list missing content-digest', () => {
    const member = `("@authority";req);${window};keyid="${keyid}";tag="${TAG}"`;
    expect(status(signedResponse({ member }))).toBe('invalid');
  });

  it('rejects a Content-Digest header that does not match the body, though the proof covers it', () => {
    const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}"`;
    expect(status(signedResponse({ member, contentDigest: sha256('{"keys":[]}') }))).toBe('invalid');
  });

  it('accepts a sha-512-only Content-Digest over the correct body', () => {
    const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}"`;
    expect(status(signedResponse({ member, contentDigest: sha512(body) }))).toBe('valid');
  });

  it('accepts sha-256 and sha-512 together when both match', () => {
    const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}"`;
    expect(status(signedResponse({ member, contentDigest: `${sha256(body)}, ${sha512(body)}` }))).toBe(
      'valid',
    );
  });

  it('rejects a good sha-256 alongside a sha-512 that does not match', () => {
    const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}"`;
    const header = `${sha256(body)}, ${sha512('tampered')}`;
    expect(status(signedResponse({ member, contentDigest: header }))).toBe('invalid');
  });

  it('rejects a Content-Digest carrying no algorithm it can check', () => {
    const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}"`;
    const md5 = `md5=:${createHash('md5').update(body).digest('base64')}:`;
    expect(status(signedResponse({ member, contentDigest: md5 }))).toBe('invalid');
  });

  it('covers the Content-Digest header as sent, not a value recomputed from the body', () => {
    // Same digest bytes, but the header the directory sent carries a second
    // member the signer covered. Re-deriving the value from the body would
    // drop it and break the base, which is what happened with `alg`.
    const member = `${COVERED};${window};keyid="${keyid}";tag="${TAG}"`;
    const header = `${sha256(body)}, ${sha512(body)}`;
    const response = signedResponse({ member, contentDigest: header });
    expect(status(response)).toBe('valid');
    expect(status({ ...response, contentDigest: sha256(body) })).toBe('invalid');
  });

  it('still ignores a proof whose keyid is not in the directory', () => {
    const member = `${COVERED};${window};keyid="not-a-listed-key";tag="${TAG}";alg="rsa-pss-sha512"`;
    expect(status(signedResponse({ member }))).toBe('absent');
  });
});

describe('end to end: a directory whose proof carries alg', () => {
  const ORIGIN = 'https://agent.example';
  const NOW = 1_750_000_000;

  it('verifies a Web Bot Auth request trusted:true with the proof required', async () => {
    const keys = generateAgentKeyPair();
    const keyid = webBotAuthKeyId(keys.publicKey);
    const body = JSON.stringify({ keys: [keys.publicKey.export({ format: 'jwk' })] });
    const contentDigest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
    const member = `${COVERED};created=${NOW - 60};expires=${NOW + 86400};keyid="${keyid}";tag="${TAG}";alg="ed25519"`;
    const base = [
      `"@authority";req: agent.example`,
      `"content-digest": ${contentDigest}`,
      `"@signature-params": ${member}`,
    ].join('\n');
    const sig = nodeSign(null, Buffer.from(base), keys.privateKey).toString('base64');
    const fetchImpl = (async () =>
      new Response(body, {
        headers: {
          'content-type': 'application/http-message-signatures-directory+json',
          'content-digest': contentDigest,
          'signature-input': `sig1=${member}`,
          signature: `sig1=:${sig}:`,
        },
      })) as unknown as typeof fetch;

    const verifier = new WebBotAuthVerifier({
      resolver: new FetchingKeyDirectoryResolver({
        allowedOrigins: [ORIGIN],
        fetchImpl,
        nowMs: () => NOW * 1000,
      }),
      // Grace off for this origin: an absent proof would be dropped, so a
      // trusted result means the alg-bearing proof itself verified.
      proofRequiredOrigins: [ORIGIN],
      now: () => NOW,
    });
    const signed = signWithWebBotAuth({
      method: 'GET',
      url: 'https://shop.example.com/products/tool-1234',
      signatureAgent: ORIGIN,
      privateKey: keys.privateKey,
      created: NOW - 5,
    });
    const result = await verifier.verify({ method: signed.method, url: signed.url, headers: signed.headers });
    expect(result).toMatchObject({ trusted: true, protocol: 'web-bot-auth' });
  });
});
