import { randomUUID, sign as nodeSign, type KeyObject } from 'node:crypto';
import type { Mandate } from '../types.js';
import { computeContentDigest } from '../protocol/visa/http-signatures.js';

/**
 * Visa Trusted Agent Protocol — agent-side signing.
 *
 * Mirror image of the Visa verifier: same signature base, same Ed25519 alg,
 * same covered-component layout. Build a signed request once, send it
 * either to AVA Pay /verify directly or to a merchant App Proxy.
 */

export function encodeMandate(m: Mandate): string {
  return Buffer.from(JSON.stringify(m), 'utf-8').toString('base64');
}

export interface VisaSignInput {
  method: string;
  url: string;
  /** Headers beyond the ones the SDK adds (Host, Content-Digest, x-ava-mandate, Signature*). */
  extraHeaders?: Record<string, string>;
  body?: string;
  agentId: string;
  privateKey: KeyObject;
  mandate: Mandate;
  /** Defaults to `["@method", "@target-uri", "host", "content-digest", "x-ava-mandate"]`. */
  components?: string[];
  /** Defaults to now (seconds). */
  created?: number;
  /** Defaults to created + 60. */
  expires?: number;
  /** Defaults to "sig1". */
  label?: string;
  /**
   * Single-use nonce for replay protection. Defaults to a random UUID.
   * Verifiers reject a nonce they have already seen within the signature
   * window, so never reuse one across requests.
   */
  nonce?: string;
}

export interface SignedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | undefined;
}

export function signWithVisa(input: VisaSignInput): SignedRequest {
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const expires = input.expires ?? created + 60;
  const label = input.label ?? 'sig1';
  const nonce = input.nonce ?? randomUUID();
  const components = input.components ?? [
    '@method',
    '@target-uri',
    'host',
    'content-digest',
    'x-ava-mandate',
  ];

  const host = new URL(input.url).host;
  const contentDigest = computeContentDigest(input.body);
  const mandateHeader = encodeMandate(input.mandate);

  const headers: Record<string, string> = {
    host,
    'content-digest': contentDigest,
    'x-ava-mandate': mandateHeader,
    ...(input.extraHeaders ?? {}),
  };

  const componentList = components.map((c) => `"${c}"`).join(' ');
  const params = `;created=${created};expires=${expires};keyid="${input.agentId}";alg="ed25519";nonce="${nonce}"`;
  const sigInputValue = `(${componentList})${params}`;
  const signatureInputHeader = `${label}=${sigInputValue}`;

  const lines: string[] = [];
  for (const comp of components) {
    let v: string;
    if (comp === '@method') v = input.method.toUpperCase();
    else if (comp === '@target-uri') v = input.url;
    else if (comp === '@authority') v = host;
    else if (comp.startsWith('@')) {
      throw new Error(`unsupported derived component: ${comp}`);
    } else {
      const headerVal = headers[comp];
      if (headerVal === undefined) throw new Error(`covered component missing: ${comp}`);
      v = headerVal;
    }
    lines.push(`"${comp}": ${v}`);
  }
  lines.push(`"@signature-params": ${sigInputValue}`);
  const signatureBase = lines.join('\n');

  const sig = nodeSign(null, Buffer.from(signatureBase), input.privateKey);
  const signatureHeader = `${label}=:${sig.toString('base64')}:`;

  return {
    method: input.method,
    url: input.url,
    headers: {
      ...headers,
      'signature-input': signatureInputHeader,
      signature: signatureHeader,
    },
    ...(input.body !== undefined ? { body: input.body } : { body: undefined }),
  };
}
