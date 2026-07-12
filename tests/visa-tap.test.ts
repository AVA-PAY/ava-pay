import {
  constants,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  FetchingVisaJwksResolver,
  StaticVisaJwks,
  VisaTapVerifier,
} from '../src/verifier/visa-tap.js';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import {
  parseVisaJwks,
  buildTapObjectSignatureBase,
} from '@ava-pay/agent/protocol/visa-tap';
import { generateAgentKeyPair, signTapObject, signWithVisa, signWithVisaTap } from '../src/sdk/index.js';
import type { AgentKeyPair } from '../src/sdk/index.js';
import type { IncomingRequest, Mandate } from '../src/types.js';

/**
 * Real Visa TAP wire-format tests — real Ed25519 + RSA-PSS + PS256 crypto.
 *
 * The signer replicates the byte format of Visa's sample tap-agent
 * (github.com/visa/trusted-agent-protocol); a format-lock test below pins it.
 * The Consumer Recognition flow simulates Visa's side with a locally
 * generated RSA key served through a static JWKS resolver.
 */

const FIXED_NOW = 1_750_000_000;
const AGENT_ID = 'tap_agent_demo';
const MERCHANT_URL = 'https://shop.example.com/products/tool-1234';

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

/** Compact-JWS PS256 signer standing in for Visa's IdToken issuance. */
function makeIdToken(
  visaKey: KeyObject,
  kid: string,
  claims: Record<string, unknown>,
  headerOverrides: Record<string, unknown> = {},
): string {
  const header = { alg: 'PS256', kid, typ: 'JWT+ext.id_token', ...headerOverrides };
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const c = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig = nodeSign('sha256', Buffer.from(`${h}.${c}`), {
    key: visaKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
  });
  return `${h}.${c}.${sig.toString('base64url')}`;
}

function defaultIdTokenClaims(): Record<string, unknown> {
  return {
    iss: 'https://visa.com',
    sub: 'consumer_opaque_123',
    aud: 'merchant',
    iat: FIXED_NOW - 60,
    exp: FIXED_NOW + 600,
    jti: 'jti-1',
    email_mask: 'a***@e***.com',
    phone_number_mask: '+1******1234',
  };
}

describe('VisaTapVerifier — message signature', () => {
  let agentKeys: AgentKeyPair;
  let strangerKeys: AgentKeyPair;
  let directory: StaticAgentDirectory;
  let verifier: VisaTapVerifier;

  function sign(overrides: Partial<Parameters<typeof signWithVisaTap>[0]> = {}) {
    return signWithVisaTap({
      url: MERCHANT_URL,
      privateKey: agentKeys.privateKey,
      keyid: AGENT_ID,
      created: FIXED_NOW - 5,
      ...overrides,
    });
  }

  beforeEach(() => {
    agentKeys = generateAgentKeyPair();
    strangerKeys = generateAgentKeyPair();
    directory = new StaticAgentDirectory();
    directory.add(AGENT_ID, agentKeys.publicKey);
    directory.add('tap_agent_revoked', strangerKeys.publicKey, true);
    verifier = new VisaTapVerifier({ directory, now: () => FIXED_NOW });
  });

  it('verifies a browse-intent ed25519 request (sample wire format, keyId spelling)', async () => {
    const signed = sign();
    expect(signed.headers['signature-input']).toContain('keyId="tap_agent_demo"');
    expect(signed.headers['signature-input']).toContain('tag="agent-browser-auth"');

    const result = await verifier.verify(toIncoming(signed));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.protocol).toBe('visa-tap');
    expect(result.agent?.id).toBe(AGENT_ID);
    expect(result.tap).toEqual({ intent: 'browse' });
    expect(result.mandate).toBeUndefined();
  });

  it('verifies the spec spelling keyid= as well', async () => {
    const result = await verifier.verify(toIncoming(sign({ keyParamName: 'keyid' })));
    expect(result.trusted).toBe(true);
  });

  it('verifies an rsa-pss-sha256 request (Python MAX_LENGTH salt, like the sample agent)', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    directory.add('tap_agent_rsa', rsa.publicKey);
    const signed = signWithVisaTap({
      url: MERCHANT_URL,
      privateKey: rsa.privateKey,
      keyid: 'tap_agent_rsa',
      created: FIXED_NOW - 5,
    });
    expect(signed.headers['signature-input']).toContain('alg="rsa-pss-sha256"');
    const result = await verifier.verify(toIncoming(signed));
    expect(result.trusted).toBe(true);
  });

  it('marks payer-intent requests as intent=payer', async () => {
    const result = await verifier.verify(toIncoming(sign({ tag: 'agent-payer-auth' })));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.tap?.intent).toBe('payer');
  });

  it('rejects a signature from a key that is not registered → unknown_agent', async () => {
    const signed = sign({ keyid: 'never_registered' });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'unknown_agent',
    });
  });

  it('rejects a revoked key → revoked_agent', async () => {
    const signed = signWithVisaTap({
      url: MERCHANT_URL,
      privateKey: strangerKeys.privateKey,
      keyid: 'tap_agent_revoked',
      created: FIXED_NOW - 5,
    });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'revoked_agent',
    });
  });

  it('rejects a forged signature under a registered keyid → invalid_signature', async () => {
    const signed = sign({ privateKey: strangerKeys.privateKey });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'invalid_signature',
    });
  });

  it('rejects tampering with a covered component → invalid_signature', async () => {
    const signed = sign();
    const tampered = { ...toIncoming(signed), url: 'https://shop.example.com/admin' };
    expect(await verifier.verify(tampered)).toMatchObject({
      trusted: false,
      reason: 'invalid_signature',
    });
  });

  it('enforces the 8-minute spec window regardless of a generous expires', async () => {
    const signed = sign({ created: FIXED_NOW - 600, expires: FIXED_NOW + 86_400 });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'signature_expired',
    });
  });

  it('rejects expired and future-dated signatures → signature_expired', async () => {
    for (const overrides of [
      { created: FIXED_NOW - 1000, expires: FIXED_NOW - 520 },
      { created: FIXED_NOW + 3600, expires: FIXED_NOW + 4080 },
    ]) {
      expect(await verifier.verify(toIncoming(sign(overrides)))).toMatchObject({
        trusted: false,
        reason: 'signature_expired',
      });
    }
  });

  it('rejects unsupported algorithms → unsupported_algorithm', async () => {
    const signed = sign();
    signed.headers['signature-input'] = signed.headers['signature-input']!.replace(
      'alg="ed25519"',
      'alg="es256"',
    );
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'unsupported_algorithm',
    });
  });

  it('requires @authority and @path in the cover set', async () => {
    const signed = sign();
    signed.headers['signature-input'] = signed.headers['signature-input']!.replace(
      '("@authority" "@path")',
      '("@authority")',
    );
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'malformed_signature_header',
    });
  });

  it('blocks a replayed nonce → replay_detected (spec: matching nonce → block)', async () => {
    const signed = toIncoming(sign());
    expect((await verifier.verify(signed)).trusted).toBe(true);
    expect(await verifier.verify(signed)).toMatchObject({
      trusted: false,
      reason: 'replay_detected',
    });
  });

  it('locks the sample-implementation byte format (agent.py template)', () => {
    const signed = sign({ created: 1_735_689_600, expires: 1_735_690_080, nonce: 'nonce-123' });
    expect(signed.headers['signature-input']).toBe(
      'sig2=("@authority" "@path"); created=1735689600; expires=1735690080; ' +
        'keyId="tap_agent_demo"; alg="ed25519"; nonce="nonce-123"; tag="agent-browser-auth"',
    );
    expect(signed.headers['signature']).toMatch(/^sig2=:[A-Za-z0-9+/]+={0,2}:$/);
  });
});

describe('VisaTapVerifier — Consumer Recognition Object + IdToken', () => {
  let agentKeys: AgentKeyPair;
  let visaRsa: { publicKey: KeyObject; privateKey: KeyObject };
  let directory: StaticAgentDirectory;
  let visaJwks: StaticVisaJwks;
  let verifier: VisaTapVerifier;
  const VISA_KID = 'visa-idtoken-key-1';
  let nonceCounter = 0;
  let NONCE = 'session-nonce-1';

  function signedCheckout(consumerOverrides: Record<string, unknown> = {}, opts: { skipObjectSig?: boolean } = {}) {
    // Fresh message nonce per request — the replay guard (rightly) blocks reuse.
    NONCE = `session-nonce-${++nonceCounter}`;
    const idToken =
      (consumerOverrides.IdToken as string | undefined) ??
      makeIdToken(visaRsa.privateKey, VISA_KID, defaultIdTokenClaims());
    const fields = {
      nonce: NONCE,
      IdToken: idToken,
      contextualData: { countryCode: 'US', zip: '94103' },
      kid: AGENT_ID,
      alg: 'ed25519',
      ...consumerOverrides,
    };
    const consumer = opts.skipObjectSig
      ? { ...fields, signature: Buffer.from('junk-signature').toString('base64url') }
      : signTapObject(fields as never, agentKeys.privateKey);
    const body = JSON.stringify({ agenticConsumer: consumer });
    return signWithVisaTap({
      url: 'https://shop.example.com/checkout',
      method: 'POST',
      privateKey: agentKeys.privateKey,
      keyid: AGENT_ID,
      tag: 'agent-payer-auth',
      nonce: NONCE,
      created: FIXED_NOW - 5,
      body,
    });
  }

  beforeEach(() => {
    agentKeys = generateAgentKeyPair();
    visaRsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    directory = new StaticAgentDirectory();
    directory.add(AGENT_ID, agentKeys.publicKey);
    const visaPubJwk = visaRsa.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    visaJwks = new StaticVisaJwks({ keys: [{ ...visaPubJwk, kid: VISA_KID, use: 'sig' }] });
    verifier = new VisaTapVerifier({ directory, visaJwks, now: () => FIXED_NOW });
  });

  it('verifies a full checkout: message sig + object sig + Visa-signed IdToken', async () => {
    const result = await verifier.verify(toIncoming(signedCheckout()));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.tap).toEqual({
      intent: 'payer',
      consumer: {
        sub: 'consumer_opaque_123',
        emailMask: 'a***@e***.com',
        phoneNumberMask: '+1******1234',
      },
    });
    expect(result.mandate).toBeUndefined(); // TAP consumer recognition ≠ AVA mandate
  });

  it('rejects a CRO whose nonce is not linked to the message signature', async () => {
    const signed = signedCheckout({ nonce: 'some-other-nonce' });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'recognition_nonce_mismatch',
    });
  });

  it('rejects a CRO with a broken object signature', async () => {
    const signed = signedCheckout({}, { skipObjectSig: true });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'recognition_signature_invalid',
    });
  });

  it('rejects a CRO whose kid does not match the message keyid', async () => {
    const signed = signedCheckout({ kid: 'someone_else' });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'malformed_recognition_object',
    });
  });

  it('rejects tampering with signed CRO content after signing', async () => {
    const signed = signedCheckout();
    const body = JSON.parse(signed.body!) as { agenticConsumer: Record<string, unknown> };
    body.agenticConsumer.contextualData = { countryCode: 'RU' };
    const tampered = { ...toIncoming(signed), body: JSON.stringify(body) };
    expect(await verifier.verify(tampered)).toMatchObject({
      trusted: false,
      reason: 'recognition_signature_invalid',
    });
  });

  it('rejects IdTokens that are expired, unsigned by Visa, wrong-alg, or unknown-kid', async () => {
    const cases: Array<{ token: string }> = [
      { token: makeIdToken(visaRsa.privateKey, VISA_KID, { ...defaultIdTokenClaims(), exp: FIXED_NOW - 600 }) },
      { token: makeIdToken(generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey, VISA_KID, defaultIdTokenClaims()) },
      { token: makeIdToken(visaRsa.privateKey, VISA_KID, defaultIdTokenClaims(), { alg: 'RS256' }) },
      { token: makeIdToken(visaRsa.privateKey, 'unknown-kid', defaultIdTokenClaims()) },
    ];
    for (const { token } of cases) {
      const signed = signedCheckout({ IdToken: token });
      expect(await verifier.verify(toIncoming(signed))).toMatchObject({
        trusted: false,
        reason: 'id_token_invalid',
      });
    }
  });

  it('rejects an alg:none IdToken outright', async () => {
    const h = Buffer.from(JSON.stringify({ alg: 'none', kid: VISA_KID })).toString('base64url');
    const c = Buffer.from(JSON.stringify(defaultIdTokenClaims())).toString('base64url');
    const signed = signedCheckout({ IdToken: `${h}.${c}.` });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'id_token_invalid',
    });
  });

  it('fails closed when the Visa JWKS is unavailable → key_directory_unavailable', async () => {
    visaJwks.markUnavailable();
    expect(await verifier.verify(toIncoming(signedCheckout()))).toMatchObject({
      trusted: false,
      reason: 'key_directory_unavailable',
    });
  });

  it('fails closed when no Visa JWKS resolver is configured at all', async () => {
    const bare = new VisaTapVerifier({ directory, now: () => FIXED_NOW });
    expect(await bare.verify(toIncoming(signedCheckout()))).toMatchObject({
      trusted: false,
      reason: 'key_directory_unavailable',
    });
  });

  it('rejects malformed CRO shapes and non-JSON bodies → malformed_recognition_object', async () => {
    const noIdToken = signedCheckout({ IdToken: undefined as never });
    // IdToken removed → still signed over remaining fields, so the shape gate fires.
    const noIdTokenBody = JSON.parse(noIdToken.body!) as { agenticConsumer: Record<string, unknown> };
    delete noIdTokenBody.agenticConsumer.IdToken;
    const resigned = signTapObject(
      (() => {
        const { signature: _sig, ...rest } = noIdTokenBody.agenticConsumer;
        return rest as never;
      })(),
      agentKeys.privateKey,
    );
    const signed = signWithVisaTap({
      url: 'https://shop.example.com/checkout',
      method: 'POST',
      privateKey: agentKeys.privateKey,
      keyid: AGENT_ID,
      tag: 'agent-payer-auth',
      nonce: NONCE,
      created: FIXED_NOW - 5,
      body: JSON.stringify({ agenticConsumer: resigned }),
    });
    expect(await verifier.verify(toIncoming(signed))).toMatchObject({
      trusted: false,
      reason: 'malformed_recognition_object',
    });

    const badBody = signWithVisaTap({
      url: 'https://shop.example.com/checkout',
      method: 'POST',
      privateKey: agentKeys.privateKey,
      keyid: AGENT_ID,
      tag: 'agent-payer-auth',
      created: FIXED_NOW - 5,
      body: 'this is not json',
    });
    expect(await verifier.verify(toIncoming(badBody))).toMatchObject({
      trusted: false,
      reason: 'malformed_recognition_object',
    });
  });
});

describe('VisaTapVerifier — Agentic Payment Container', () => {
  let agentKeys: AgentKeyPair;
  let directory: StaticAgentDirectory;
  let verifier: VisaTapVerifier;
  let nonceCounter = 0;
  let NONCE = 'container-nonce-0';

  function signedWithContainer(overrides: Record<string, unknown> = {}, tamper?: (c: Record<string, unknown>) => void) {
    // Fresh message nonce per request — the replay guard (rightly) blocks reuse.
    NONCE = `container-nonce-${++nonceCounter}`;
    const fields = {
      nonce: NONCE,
      paymentCredentialsHash: { hash: 'abc123', alg: 'SHA-256' },
      kid: AGENT_ID,
      alg: 'ed25519',
      ...overrides,
    };
    const container = signTapObject(fields as never, agentKeys.privateKey) as unknown as Record<string, unknown>;
    if (tamper) tamper(container);
    return signWithVisaTap({
      url: 'https://shop.example.com/checkout',
      method: 'POST',
      privateKey: agentKeys.privateKey,
      keyid: AGENT_ID,
      tag: 'agent-payer-auth',
      nonce: NONCE,
      created: FIXED_NOW - 5,
      body: JSON.stringify({ agenticPaymentContainer: container }),
    });
  }

  beforeEach(() => {
    agentKeys = generateAgentKeyPair();
    directory = new StaticAgentDirectory();
    directory.add(AGENT_ID, agentKeys.publicKey);
    verifier = new VisaTapVerifier({ directory, now: () => FIXED_NOW });
  });

  it('verifies a signed payment container and surfaces its shape', async () => {
    const result = await verifier.verify(toIncoming(signedWithContainer()));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.tap?.payment).toEqual({ hasCredentialsHash: true, hasEncryptedPayload: false });
  });

  it('rejects nonce mismatch, tampering, and kid mismatch', async () => {
    expect(
      await verifier.verify(toIncoming(signedWithContainer({ nonce: 'other' }))),
    ).toMatchObject({ trusted: false, reason: 'recognition_nonce_mismatch' });

    expect(
      await verifier.verify(
        toIncoming(
          signedWithContainer({}, (c) => {
            c.paymentCredentialsHash = { hash: 'tampered', alg: 'SHA-256' };
          }),
        ),
      ),
    ).toMatchObject({ trusted: false, reason: 'payment_container_signature_invalid' });

    expect(
      await verifier.verify(toIncoming(signedWithContainer({ kid: 'someone_else' }))),
    ).toMatchObject({ trusted: false, reason: 'malformed_payment_container' });
  });
});

describe('visa-tap protocol primitives', () => {
  it("parses Visa's live JWKS shape (captured 2026-07-12 from mcp.visa.com)", () => {
    // Real key material from https://mcp.visa.com/.well-known/jwks (truncated x5c omitted —
    // chain validation is out of public-spec scope and the parser ignores x5c).
    const live = {
      keys: [
        {
          kty: 'RSA',
          e: 'AQAB',
          kid: '4e31087e-7493-4f17-8417-9d3cbb64db9e',
          n: 'qxlgvVHV2tDq3uyXEEzjmwDdUlO-98Mvo9Vzk_a5QcUPkSK6ALZq6ncoIzvbUuSSpQzs1wzRSM-3uMcMCgZj2Gw7pPDCxyIzT8pbCPN2Jghw_Q4do1NLXRk-T16tlaMg0MLj8Di1ptDQY-s5_GSqXdsxF5pTygcfl_9xiGzD9tdyPywd6PJ8MvWaHncOfIDkhq-G-c2fqbbU6hvKuRqIkKuT-GkWmj4QoswxI7LbuU1Lq1PmjMmrXHqfhkuP5q15WnXM5mnMmvarN-k3tHyS9_3a3R5IqPCsGeILZRykoaAfrFi74Gr7W-0DxKxzuux828wQTzQkCW_pvoT4-7ACEw',
        },
      ],
    };
    const keys = parseVisaJwks(live);
    expect(keys).toHaveLength(1);
    expect(keys[0]?.kid).toBe('4e31087e-7493-4f17-8417-9d3cbb64db9e');
    expect(keys[0]?.key.asymmetricKeyType).toBe('rsa');
  });

  it('drops malformed JWKS entries and rejects non-JWKS documents', () => {
    expect(parseVisaJwks({ keys: [{ kty: 'RSA' }, { kty: 'EC', kid: 'x' }, 'junk'] })).toHaveLength(0);
    expect(() => parseVisaJwks({ nope: true })).toThrow();
  });

  it('object signature base preserves field order and excludes the signature', () => {
    const base = buildTapObjectSignatureBase({
      nonce: 'n1',
      IdToken: 'a.b.c',
      contextualData: { countryCode: 'US' },
      kid: 'k',
      alg: 'ed25519',
      signature: 'SHOULD-NOT-APPEAR',
    });
    expect(base).toBe(
      [
        '"nonce": n1',
        '"IdToken": a.b.c',
        '"contextualData": {"countryCode":"US"}',
        '"kid": k',
        '"alg": ed25519',
      ].join('\n'),
    );
  });
});

describe('FetchingVisaJwksResolver', () => {
  const JWKS_BODY = () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = rsa.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    return JSON.stringify({ keys: [{ ...jwk, kid: 'k1', use: 'sig' }] });
  };

  function fakeFetch(handler: () => Response): { impl: typeof fetch; calls: number[] } {
    const calls: number[] = [];
    const impl = (async () => {
      calls.push(1);
      return handler();
    }) as typeof fetch;
    return { impl, calls };
  }

  it('fetches, parses, and caches the JWKS', async () => {
    const body = JWKS_BODY();
    const { impl, calls } = fakeFetch(() => new Response(body));
    const resolver = new FetchingVisaJwksResolver({ fetchImpl: impl });
    expect(await resolver.resolve('k1')).not.toBeNull();
    expect(await resolver.resolve('k1')).not.toBeNull();
    expect(calls).toHaveLength(1);
    expect(await resolver.resolve('unknown')).toBeNull();
  });

  it('throws (→ fail closed upstream) on HTTP errors and oversized bodies', async () => {
    for (const handler of [
      () => new Response('nope', { status: 500 }),
      () => new Response(JSON.stringify({ keys: [], pad: 'x'.repeat(100_000) })),
    ]) {
      const resolver = new FetchingVisaJwksResolver({ fetchImpl: fakeFetch(handler).impl });
      await expect(resolver.resolve('k1')).rejects.toThrow();
    }
  });

  it('refuses non-https JWKS URLs', () => {
    expect(() => new FetchingVisaJwksResolver({ url: 'http://mcp.visa.com/.well-known/jwks' })).toThrow();
  });
});

describe('MultiProtocolVerifier dispatch with real TAP', () => {
  let agentKeys: AgentKeyPair;
  let multi: MultiProtocolVerifier;

  beforeEach(() => {
    agentKeys = generateAgentKeyPair();
    const directory = new StaticAgentDirectory();
    directory.add(AGENT_ID, agentKeys.publicKey);
    directory.add('agent_demo', agentKeys.publicKey);
    multi = new MultiProtocolVerifier({
      visa: new VisaAgentVerifier({ directory, now: () => FIXED_NOW }),
      visaTap: new VisaTapVerifier({ directory, now: () => FIXED_NOW }),
      ap2: new Ap2AgentVerifier({ directory, now: () => FIXED_NOW }),
      webBotAuth: new WebBotAuthVerifier({
        resolver: new StaticSignatureAgentKeys(),
        now: () => FIXED_NOW,
      }),
    });
  });

  it('routes agent-browser-auth / agent-payer-auth to the real TAP verifier', async () => {
    for (const tag of ['agent-browser-auth', 'agent-payer-auth'] as const) {
      const signed = signWithVisaTap({
        url: MERCHANT_URL,
        privateKey: agentKeys.privateKey,
        keyid: AGENT_ID,
        tag,
        created: FIXED_NOW - 5,
      });
      const result = await multi.verify(toIncoming(signed));
      if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
      expect(result.protocol).toBe('visa-tap');
    }
  });

  it('still routes untagged RFC 9421 to the AVA TAP profile', async () => {
    const mandate: Mandate = {
      id: 'mandate_demo',
      iat: FIXED_NOW - 60,
      exp: FIXED_NOW + 600,
      maxAmountMinor: 50_000,
      currency: 'USD',
      allowedMerchants: ['shop.example.com'],
    };
    const body = JSON.stringify({ items: [{ sku: 'SKU-1', qty: 1 }] });
    const signed = signWithVisa({
      method: 'POST',
      url: 'https://shop.example.com/cart',
      body,
      agentId: 'agent_demo',
      privateKey: agentKeys.privateKey,
      mandate,
      created: FIXED_NOW - 5,
      expires: FIXED_NOW + 60,
    });
    const result = await multi.verify(toIncoming({ ...signed, body }));
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.protocol).toBe('ava-tap');
    expect(result.mandate?.id).toBe('mandate_demo');
  });
});
