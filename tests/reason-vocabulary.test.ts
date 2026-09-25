import { beforeEach, describe, expect, it } from 'vitest';
import {
  FetchingKeyDirectoryResolver,
  StaticSignatureAgentKeys,
  WebBotAuthVerifier,
} from '../src/verifier/web-bot-auth.js';
import { JwksUriKeySource, WbaPublishedKeySource } from '../src/verifier/federated-directory.js';
import { classifyKeyDirectoryMediaType } from '@ava-pay/agent/protocol/web-bot-auth';
import { generateAgentKeyPair, signWithWebBotAuth, webBotAuthKeyId } from '../src/sdk/index.js';
import type { AgentKeyPair } from '../src/sdk/index.js';
import type { IncomingRequest } from '../src/types.js';

/**
 * The Web Bot Auth reason vocabulary: each fault arrives under a name that
 * says what the verifier knows, with the outcome REASON_CONCLUSIVE fixes for
 * it. Real Ed25519 signatures from the SDK signer throughout, then edited the
 * way a faulty signer or a tampering hop would.
 *
 * The NV numbers refer to the published negative vector set the names trace
 * to; these tests use our own keys and do not depend on that set.
 */

const FIXED_NOW = 1_750_000_000;
const AGENT_ORIGIN = 'https://agent.example';
const MERCHANT_URL = 'https://shop.example.com/products/tool-1234';
const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';

function toIncoming(signed: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}): IncomingRequest {
  return {
    method: signed.method,
    url: signed.url,
    headers: { ...signed.headers },
    ...(signed.body !== undefined ? { body: signed.body } : {}),
  };
}

describe('Web Bot Auth reason vocabulary', () => {
  let keys: AgentKeyPair;
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
    const resolver = new StaticSignatureAgentKeys();
    resolver.add(AGENT_ORIGIN, { keys: [keys.publicKey.export({ format: 'jwk' })] });
    verifier = new WebBotAuthVerifier({ resolver, now: () => FIXED_NOW });
  });

  it('control: the unedited request verifies', async () => {
    expect((await verifier.verify(toIncoming(sign()))).trusted).toBe(true);
  });

  it('a covered header the request does not carry → covered_component_missing (NV-09)', async () => {
    const request = toIncoming(sign({ body: '{"cart":1}', method: 'POST', components: ['@authority', 'content-digest', 'signature-agent'] }));
    delete request.headers['content-digest'];
    expect(await verifier.verify(request)).toMatchObject({
      trusted: false,
      reason: 'covered_component_missing',
      conclusive: true,
    });
  });

  it('an unreadable Signature-Input → signature_input_malformed (NV-10)', async () => {
    const request = toIncoming(sign());
    // Drop the closing parenthesis of the component list.
    request.headers['signature-input'] = request.headers['signature-input']!.replace(')', '');
    expect(await verifier.verify(request)).toMatchObject({
      trusted: false,
      reason: 'signature_input_malformed',
      conclusive: true,
    });
  });

  it('a non-numeric created → signature_input_malformed', async () => {
    const request = toIncoming(sign());
    request.headers['signature-input'] = request.headers['signature-input']!.replace(
      /created=\d+/,
      'created=soon',
    );
    expect(await verifier.verify(request)).toMatchObject({ reason: 'signature_input_malformed' });
  });

  it('a keyid that is not a JWK thumbprint → signature_input_malformed; a missing one → signature_parameter_missing', async () => {
    const wrongShape = toIncoming(sign());
    wrongShape.headers['signature-input'] = wrongShape.headers['signature-input']!.replace(
      /keyid="[^"]+"/,
      'keyid="agent-key-1"',
    );
    expect(await verifier.verify(wrongShape)).toMatchObject({ reason: 'signature_input_malformed' });

    const absent = toIncoming(sign());
    absent.headers['signature-input'] = absent.headers['signature-input']!.replace(/;keyid="[^"]+"/, '');
    expect(await verifier.verify(absent)).toMatchObject({ reason: 'signature_parameter_missing' });
  });

  it('a Signature with no member for the label → signature_value_malformed (NV-11)', async () => {
    const request = toIncoming(sign());
    request.headers['signature'] = request.headers['signature']!.replace(/^[^=]+=/, 'other=');
    expect(await verifier.verify(request)).toMatchObject({
      trusted: false,
      reason: 'signature_value_malformed',
      conclusive: true,
    });
  });

  it('a Signature value that is not a 64-byte byte sequence → signature_value_malformed', async () => {
    for (const value of [':AAAA:', 'not-a-byte-sequence']) {
      const request = toIncoming(sign());
      request.headers['signature'] = request.headers['signature']!.replace(/=.*$/, `=${value}`);
      expect(await verifier.verify(request)).toMatchObject({ reason: 'signature_value_malformed' });
    }
  });

  it('an unreadable Signature-Agent → signature_agent_malformed (NV-18)', async () => {
    const request = toIncoming(sign());
    request.headers['signature-agent'] = '"https://agent.example';
    expect(await verifier.verify(request)).toMatchObject({
      trusted: false,
      reason: 'signature_agent_malformed',
      conclusive: true,
    });
  });

  it('an unreadable keyed dictionary is signature_agent_malformed, not a missing member (NV-18)', async () => {
    // The keyed lookup fails either way; the name must say the header did not
    // parse, not that it parsed and lacked the member.
    const unreadable = toIncoming(sign({ signatureAgentFormat: 'dictionary' }));
    unreadable.headers['signature-agent'] = unreadable.headers['signature-agent']!.replace(/"$/, '');
    expect(await verifier.verify(unreadable)).toMatchObject({ reason: 'signature_agent_malformed' });

    // A header that parses and simply lacks the covered member (NV-14).
    const lacking = toIncoming(sign({ signatureAgentFormat: 'dictionary' }));
    lacking.headers['signature-agent'] = lacking.headers['signature-agent']!.replace(/^[^=]+=/, 'other=');
    expect(await verifier.verify(lacking)).toMatchObject({ reason: 'signature_agent_member_missing' });
  });

  it('a Signature-Agent carrying credentials → signature_agent_not_origin', async () => {
    const request = toIncoming(sign());
    request.headers['signature-agent'] = '"https://user:pw@agent.example"';
    expect(await verifier.verify(request)).toMatchObject({ reason: 'signature_agent_not_origin' });
  });

  it('a foreign tag is invalid, not unsigned, and never reaches the directory', async () => {
    let resolved = 0;
    const counting = new WebBotAuthVerifier({
      resolver: {
        resolve: async () => {
          resolved++;
          return { status: 'not_allowed' };
        },
      },
      now: () => FIXED_NOW,
    });
    const result = await counting.verify(toIncoming(sign({ tag: 'other-protocol' })));
    expect(result).toMatchObject({ trusted: false, reason: 'foreign_signature_tag', conclusive: true });
    expect(resolved).toBe(0);
  });

  it('keeps invalid_signature for a failed verify: canonicalization and forgery are not told apart', async () => {
    // A signer that disagrees with us about one component's value produces the
    // same observation as a forgery: one Ed25519 verify returning false. We do
    // not claim to know which it was.
    const request = toIncoming(sign({ components: ['@authority', '@path', 'signature-agent'] }));
    request.url = MERCHANT_URL.replace('/products/tool-1234', '/products/tool-1234/');
    expect(await verifier.verify(request)).toMatchObject({
      trusted: false,
      reason: 'invalid_signature',
      conclusive: true,
    });
  });
});

describe('Web Bot Auth Content-Digest over an empty body', () => {
  let keys: AgentKeyPair;
  let verifier: WebBotAuthVerifier;

  beforeEach(() => {
    keys = generateAgentKeyPair();
    const resolver = new StaticSignatureAgentKeys();
    resolver.add(AGENT_ORIGIN, { keys: [keys.publicKey.export({ format: 'jwk' })] });
    verifier = new WebBotAuthVerifier({ resolver, now: () => FIXED_NOW });
  });

  function signPost(body: string) {
    return signWithWebBotAuth({
      method: 'POST',
      url: MERCHANT_URL,
      signatureAgent: AGENT_ORIGIN,
      privateKey: keys.privateKey,
      created: FIXED_NOW - 5,
      body,
      components: ['@authority', '@method', '@path', 'content-digest', 'signature-agent'],
    });
  }

  it('verifies a signature over the empty body that arrived', async () => {
    // Signed afresh for each delivery, or the second would be a replay.
    const withEmpty = toIncoming(signPost(''));
    expect(withEmpty.headers['content-digest']).toBe('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:');
    expect((await verifier.verify({ ...withEmpty, body: '' })).trusted).toBe(true);
    const { body: _dropped, ...noBody } = toIncoming(signPost(''));
    expect((await verifier.verify(noBody)).trusted).toBe(true);
  });

  it('rejects a digest made over a body that did not arrive → content_digest_mismatch', async () => {
    // What the storefront embed does to an agent's signed POST: headers
    // forwarded, body gone. The signature itself still verifies over the
    // headers, which is why the digest has to be held to the empty body.
    const signed = toIncoming(signPost('{"cart":[{"sku":"A","qty":1}]}'));
    for (const body of [undefined, '']) {
      const request: IncomingRequest = {
        method: signed.method,
        url: signed.url,
        headers: signed.headers,
        ...(body !== undefined ? { body } : {}),
      };
      expect(await verifier.verify(request)).toMatchObject({
        trusted: false,
        reason: 'content_digest_mismatch',
        conclusive: true,
      });
    }
  });

  it('still accepts a bodyless request that sends no Content-Digest at all', async () => {
    const request = toIncoming(
      signWithWebBotAuth({
        method: 'GET',
        url: MERCHANT_URL,
        signatureAgent: AGENT_ORIGIN,
        privateKey: keys.privateKey,
        created: FIXED_NOW - 5,
      }),
    );
    expect(request.headers['content-digest']).toBeUndefined();
    expect((await verifier.verify(request)).trusted).toBe(true);
  });
});

describe('key directory media-type gate', () => {
  let keys: AgentKeyPair;
  let jwkSet: string;

  beforeEach(() => {
    keys = generateAgentKeyPair();
    // A real JWK Set holding the very key that signs the request below, so the
    // only thing wrong with each response is the type it was served under.
    jwkSet = JSON.stringify({ keys: [keys.publicKey.export({ format: 'jwk' })] });
  });

  function servedAs(contentType: string | null): typeof fetch {
    return (async () =>
      new Response(jwkSet, contentType === null ? {} : { headers: { 'content-type': contentType } })) as unknown as typeof fetch;
  }

  function resolverFor(contentType: string | null, warnings: string[] = []) {
    const fetchImpl =
      contentType === null
        ? ((async () => {
            const res = new Response(jwkSet);
            res.headers.delete('content-type');
            return res;
          }) as unknown as typeof fetch)
        : servedAs(contentType);
    return new FetchingKeyDirectoryResolver({
      allowedOrigins: [AGENT_ORIGIN],
      fetchImpl,
      onWarning: (m) => warnings.push(m),
    });
  }

  function signedRequest(): IncomingRequest {
    return toIncoming(
      signWithWebBotAuth({
        method: 'GET',
        url: MERCHANT_URL,
        signatureAgent: AGENT_ORIGIN,
        privateKey: keys.privateKey,
        created: FIXED_NOW - 5,
      }),
    );
  }

  it('classifies media types by essence, ignoring parameters and case', () => {
    expect(classifyKeyDirectoryMediaType(`${DIRECTORY_MEDIA_TYPE}; charset=utf-8`)).toBe('directory');
    expect(classifyKeyDirectoryMediaType('Application/JSON')).toBe('json');
    expect(classifyKeyDirectoryMediaType('application/jwk-set+json')).toBe('jwk-set');
    expect(classifyKeyDirectoryMediaType('text/html; charset=utf-8')).toBe('other');
    expect(classifyKeyDirectoryMediaType(null)).toBe('other');
  });

  it('a real JWK Set served as text/html does not verify and does not read as unknown_key', async () => {
    const resolver = resolverFor('text/html; charset=utf-8');
    expect(await resolver.resolve(AGENT_ORIGIN)).toMatchObject({ status: 'unsupported_media_type' });

    const verifier = new WebBotAuthVerifier({ resolver: resolverFor('text/html'), now: () => FIXED_NOW });
    const result = await verifier.verify(signedRequest());
    expect(result).toMatchObject({
      trusted: false,
      reason: 'key_directory_unsupported_media_type',
      conclusive: false,
    });
    if (!result.trusted) expect(result.reason).not.toBe('unknown_key');
  });

  it('refuses a response with no Content-Type at all', async () => {
    const verifier = new WebBotAuthVerifier({ resolver: resolverFor(null), now: () => FIXED_NOW });
    expect(await verifier.verify(signedRequest())).toMatchObject({
      reason: 'key_directory_unsupported_media_type',
      conclusive: false,
    });
  });

  it('accepts the registered type silently', async () => {
    const warnings: string[] = [];
    const verifier = new WebBotAuthVerifier({
      resolver: resolverFor(DIRECTORY_MEDIA_TYPE, warnings),
      now: () => FIXED_NOW,
    });
    expect((await verifier.verify(signedRequest())).trusted).toBe(true);
    expect(warnings).toEqual([]);
  });

  it('accepts plain application/json with a warning', async () => {
    const warnings: string[] = [];
    const verifier = new WebBotAuthVerifier({
      resolver: resolverFor('application/json; charset=utf-8', warnings),
      now: () => FIXED_NOW,
    });
    expect((await verifier.verify(signedRequest())).trusted).toBe(true);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(DIRECTORY_MEDIA_TYPE);
  });

  it('the federated WBA source treats a wrong media type as an outage, not a miss', async () => {
    const source = new WbaPublishedKeySource({
      resolver: resolverFor('text/html'),
      origins: [AGENT_ORIGIN],
      now: () => FIXED_NOW,
    });
    await expect(source.resolve(webBotAuthKeyId(keys.publicKey))).rejects.toThrow(/unavailable/);
  });

  it('a jwks_uri source accepts application/jwk-set+json and refuses text/html as an outage', async () => {
    const thumbprint = webBotAuthKeyId(keys.publicKey);
    const url = 'https://keys.agent.example/jwks.json';
    const good = new JwksUriKeySource({
      urls: [url],
      type: 'jwks_uri',
      fetchImpl: servedAs('application/jwk-set+json'),
      now: () => FIXED_NOW,
    });
    expect(await good.resolve(thumbprint)).toMatchObject({ binding: 'url-only' });

    const html = new JwksUriKeySource({
      urls: [url],
      type: 'jwks_uri',
      fetchImpl: servedAs('text/html'),
      now: () => FIXED_NOW,
    });
    await expect(html.resolve(thumbprint)).rejects.toThrow(/unavailable/);

    const warnings: string[] = [];
    const json = new JwksUriKeySource({
      urls: [url],
      type: 'jwks_uri',
      fetchImpl: servedAs('application/json'),
      now: () => FIXED_NOW,
      onWarning: (m) => warnings.push(m),
    });
    expect(await json.resolve(thumbprint)).toMatchObject({ binding: 'url-only' });
    expect(warnings).toHaveLength(1);
  });
});
