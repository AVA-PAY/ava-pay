import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  ACCEPT_SIGNATURE_HEADER,
  ACCEPT_SIGNATURE_VALUE,
  acceptSignatureHeaders,
} from '../shopify-app/app/lib/accept-signature.js';
import { StaticSignatureAgentKeys, WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import { generateAgentKeyPair, signWithWebBotAuth } from '../src/sdk/index.js';

/**
 * The twins' Accept-Signature value (draft-ietf-webbotauth-httpsig-protocol-01
 * Section 5.3, RFC 9421 Section 5): ONE canonical definition in TypeScript,
 * mirrored in PHP. The parity test reads both sources and fails on drift, in
 * the style of check:type-sync; the round-trip test proves a request signed
 * exactly as the value asks verifies trusted, so the header can never ask for
 * a shape the verifier would refuse.
 */

const PHP_MIRROR = new URL(
  '../woocommerce-plugin/includes/core/class-ava-pay-accept-signature.php',
  import.meta.url,
);

const FIXED_NOW = 1_750_000_000;
const AGENT_ORIGIN = 'https://agent.example';

describe('Accept-Signature canonical value', () => {
  it('is mirrored byte for byte in the WooCommerce core class', () => {
    const php = readFileSync(PHP_MIRROR, 'utf8');
    const value = php.match(/const VALUE = '([^']+)';/);
    if (!value) throw new Error('AVA_Pay_Accept_Signature::VALUE not found in the PHP mirror');
    expect(value[1]).toBe(ACCEPT_SIGNATURE_VALUE);
    const header = php.match(/const HEADER = '([^']+)';/);
    expect(header?.[1]).toBe(ACCEPT_SIGNATURE_HEADER);
  });

  it('gates both ways: sent to unverified callers, withheld from trusted ones', () => {
    expect(acceptSignatureHeaders(false)).toEqual({
      'Accept-Signature': ACCEPT_SIGNATURE_VALUE,
    });
    expect(acceptSignatureHeaders(true)).toEqual({});
  });

  it('asks for exactly what the verifier requires of a request to the endpoint', () => {
    // RFC 9421 Section 5.1 member shape: label=(components);parameters.
    const m = ACCEPT_SIGNATURE_VALUE.match(/^([a-z0-9]+)=\(([^)]*)\)(.*)$/);
    if (!m) throw new Error('canonical value is not a single dictionary member');
    const [, label, components, params] = m;
    expect(label).toBe('sig1');
    // The exact covered set: the target binding (@authority), the body
    // binding (content-digest), and the Signature-Agent member keyed to the
    // label (-01 Section 5.2.1 MUST).
    expect(components).toBe('"@authority" "content-digest" "signature-agent";key="sig1"');
    // created/expires requested WITHOUT values (RFC 9421 Section 5.1:
    // "generate and include"); the tag the verifier dispatches on. No keyid,
    // no alg, no nonce: any directory key, either algorithm, no chosen nonce.
    expect(params).toBe(';created;expires;tag="web-bot-auth"');
  });

  it('round-trips: a request signed exactly as the value asks verifies trusted', async () => {
    const m = ACCEPT_SIGNATURE_VALUE.match(/^([a-z0-9]+)=\(([^)]*)\)(.*)$/)!;
    const label = m[1]!;
    // Component names, derived from the constant so drift fails here too
    // (each space-separated identifier is `"name"` possibly followed by
    // parameters such as ;key="sig1").
    const components = m[2]!.split(' ').map((c) => c.match(/^"([^"]+)"/)![1]!);
    expect(components).toEqual(['@authority', 'content-digest', 'signature-agent']);

    const keys = generateAgentKeyPair();
    const resolver = new StaticSignatureAgentKeys();
    resolver.add(AGENT_ORIGIN, {
      keys: [keys.publicKey.export({ format: 'jwk' }) as object],
    });
    const verifier = new WebBotAuthVerifier({ resolver, now: () => FIXED_NOW });

    const signed = signWithWebBotAuth({
      method: 'POST',
      url: 'https://shop.example.com/wp-json/ava-pay/v1/verify-agent',
      body: JSON.stringify({ intent: 'browse' }),
      signatureAgent: AGENT_ORIGIN,
      privateKey: keys.privateKey,
      created: FIXED_NOW - 5,
      label,
      components,
      // The keyed dictionary form the value's "signature-agent";key="sig1"
      // asks for.
      signatureAgentFormat: 'dictionary',
    });
    expect(signed.headers['signature-input']).toContain(`"signature-agent";key="${label}"`);
    expect(signed.headers['signature-input']).toContain('tag="web-bot-auth"');
    expect(signed.headers['content-digest']).toBeDefined();

    const result = await verifier.verify({
      method: 'POST',
      url: 'https://shop.example.com/wp-json/ava-pay/v1/verify-agent',
      headers: signed.headers,
      ...(signed.body !== undefined ? { body: signed.body } : {}),
    });
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.agent?.id).toBe(AGENT_ORIGIN);
  });
});
