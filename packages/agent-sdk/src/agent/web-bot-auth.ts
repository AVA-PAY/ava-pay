import { createPublicKey, randomBytes, sign as nodeSign, type KeyObject } from 'node:crypto';
import { computeContentDigest } from '../protocol/visa/http-signatures.js';
import {
  ecP256JwkThumbprint,
  ed25519JwkThumbprint,
  KEY_DIRECTORY_PATH,
  WEB_BOT_AUTH_TAG,
} from '../protocol/web-bot-auth/index.js';
import type { SignedRequest } from './visa.js';

/**
 * Web Bot Auth: agent-side signing (IETF
 * draft-ietf-webbotauth-httpsig-protocol-01).
 *
 * Mirror image of the WebBotAuthVerifier: covered components
 * ("@authority" "@method" "@path" "signature-agent"), parameters
 * created/expires/keyid/alg/nonce/tag="web-bot-auth", keyid = RFC 7638 JWK
 * thumbprint of the signing key. Signs with Ed25519 or ECDSA P-256/SHA-256
 * (the key type decides; alg defaults to the matching HTTP Signature
 * Algorithms registry name, and ECDSA signatures are the raw r||s form RFC
 * 9421 Section 3.3.4 requires, never DER).
 *
 * -01 Section 5.2.1 requires signers to send the dictionary Signature-Agent
 * form and to cover the member keyed to their own label, so the default
 * covers `"signature-agent";key="<label>"` and puts that member's value in
 * the base, matching the Appendix E vectors. Members MUST NOT carry
 * parameters, so there is no type parameter. The bare-string 'item' form
 * stays available for reproducing deployed traffic (chatgpt.com still sends
 * it, and -01 Appendix E keeps legacy vectors for it).
 */

export interface WebBotAuthSignInput {
  method: string;
  url: string;
  /**
   * The agent's Signature-Agent value: the https URL of the JWK Set the
   * public key is published at (-01 Section 5.5), e.g.
   * "https://signer.example/.well-known/http-message-signatures-directory".
   * A bare origin is emitted with the well-known directory path appended,
   * the shape -01 intends (WG PR #153), unless `legacyBareOrigin` asks for
   * the deployed bare-origin form.
   */
  signatureAgent: string;
  /**
   * Emit a bare-origin `signatureAgent` exactly as given instead of
   * appending the well-known path. This reproduces what deployed agents
   * send today (chatgpt.com, agent.bot.goog, shopify.com, measured
   * 2026-10-31); verifiers resolve it through their legacy tolerance.
   */
  legacyBareOrigin?: boolean;
  privateKey: KeyObject;
  /** Headers beyond the ones the SDK adds (host, signature-agent, Signature*). */
  extraHeaders?: Record<string, string>;
  body?: string;
  /** Defaults to `["@authority", "@method", "@path", "signature-agent"]` — what real agents cover. */
  components?: string[];
  /** Defaults to now (seconds). */
  created?: number;
  /** Defaults to created + 300. */
  expires?: number | null;
  /**
   * Anti-replay nonce, base64url. Defaults to 64 random bytes. Pass null to
   * omit (some agents may; the verifier then replay-keys on the signature bytes).
   */
  nonce?: string | null;
  /** Defaults to "sig1". */
  label?: string;
  /** Defaults to "web-bot-auth". Pass null to omit (negative testing). */
  tag?: string | null;
  /**
   * Defaults to the signing key's own registry name ("ed25519" or
   * "ecdsa-p256-sha256"). Pass null to omit; verifiers resolve the algorithm
   * from the directory key.
   */
  alg?: string | null;
  /** keyid override. Defaults to the RFC 7638 thumbprint of the signing key's public half. */
  keyid?: string;
  /**
   * Wire form of the Signature-Agent header. "dictionary" (default) is the
   * label-keyed form -01 Section 5.2.1 requires signers to send; "item" is
   * the legacy bare quoted string deployed agents still emit, kept for
   * reproducing that traffic in tests.
   */
  signatureAgentFormat?: 'item' | 'dictionary';
  /**
   * Cover `"signature-agent";key="<label>"` rather than the whole field.
   * Defaults to true for the dictionary form (what -01 Section 5.2.1
   * requires) and false for the bare-string form, which has no members to
   * key. Set false with the dictionary form only to reproduce an older signer.
   */
  keyedSignatureAgentComponent?: boolean;
}

export function signWithWebBotAuth(input: WebBotAuthSignInput): SignedRequest {
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const expires = input.expires === null ? undefined : (input.expires ?? created + 300);
  const label = input.label ?? 'sig1';
  const nonce = input.nonce === null ? undefined : (input.nonce ?? randomBytes(64).toString('base64url'));
  const tag = input.tag === null ? undefined : (input.tag ?? WEB_BOT_AUTH_TAG);
  const keyInfo = signingKeyInfo(input.privateKey);
  const alg = input.alg === null ? undefined : (input.alg ?? keyInfo.alg);
  const keyid = input.keyid ?? keyInfo.thumbprint;
  const components = input.components ?? ['@authority', '@method', '@path', 'signature-agent'];

  const url = new URL(input.url);
  const isDictionary = (input.signatureAgentFormat ?? 'dictionary') === 'dictionary';
  // A bare origin becomes the well-known directory URL, the shape -01
  // intends a Signature-Agent value to have (WG PR #153), unless the caller
  // explicitly wants the deployed legacy form.
  const agentUrl = new URL(input.signatureAgent);
  const signatureAgentValue =
    !input.legacyBareOrigin && agentUrl.pathname === '/' && agentUrl.search === ''
      ? `${input.signatureAgent.replace(/\/$/, '')}${KEY_DIRECTORY_PATH}`
      : input.signatureAgent;
  /** The dictionary member value on its own: what a keyed component covers. */
  const signatureAgentMember = `"${signatureAgentValue}"`;
  const signatureAgentHeader = isDictionary
    ? `${label}=${signatureAgentMember}`
    : signatureAgentMember;
  const keyed = input.keyedSignatureAgentComponent ?? isDictionary;

  const headers: Record<string, string> = {
    host: url.host,
    'signature-agent': signatureAgentHeader,
    ...(input.body !== undefined ? { 'content-digest': computeContentDigest(input.body) } : {}),
    ...(input.extraHeaders ?? {}),
  };

  /** Component identifier as it appears in Signature-Input and in the base. */
  const identifier = (c: string): string =>
    c === 'signature-agent' && keyed ? `"${c}";key="${label}"` : `"${c}"`;
  const componentList = components.map(identifier).join(' ');
  const params = [
    `;created=${created}`,
    expires !== undefined ? `;expires=${expires}` : '',
    `;keyid="${keyid}"`,
    alg !== undefined ? `;alg="${alg}"` : '',
    nonce !== undefined ? `;nonce="${nonce}"` : '',
    tag !== undefined ? `;tag="${tag}"` : '',
  ].join('');
  const sigInputValue = `(${componentList})${params}`;

  const lines: string[] = [];
  for (const comp of components) {
    let v: string;
    if (comp === '@method') v = input.method.toUpperCase();
    else if (comp === '@target-uri') v = input.url;
    else if (comp === '@authority') v = url.host;
    else if (comp === '@path') v = url.pathname;
    else if (comp === '@query') v = url.search === '' ? '?' : url.search;
    else if (comp.startsWith('@')) {
      throw new Error(`unsupported derived component: ${comp}`);
    } else if (comp === 'signature-agent' && keyed) {
      // RFC 9421 Section 2.1: a keyed identifier covers the member's value, not
      // the whole field.
      v = signatureAgentMember;
    } else {
      const headerVal = headers[comp];
      if (headerVal === undefined) throw new Error(`covered component missing: ${comp}`);
      v = headerVal;
    }
    lines.push(`${identifier(comp)}: ${v}`);
  }
  lines.push(`"@signature-params": ${sigInputValue}`);
  const signatureBase = lines.join('\n');

  const sig =
    keyInfo.alg === 'ecdsa-p256-sha256'
      ? nodeSign('sha256', Buffer.from(signatureBase), {
          key: input.privateKey,
          dsaEncoding: 'ieee-p1363',
        })
      : nodeSign(null, Buffer.from(signatureBase), input.privateKey);

  return {
    method: input.method,
    url: input.url,
    headers: {
      ...headers,
      'signature-input': `${label}=${sigInputValue}`,
      signature: `${label}=:${sig.toString('base64')}:`,
    },
    ...(input.body !== undefined ? { body: input.body } : { body: undefined }),
  };
}

/** RFC 7638 thumbprint of a key's public half — the Web Bot Auth keyid. */
export function webBotAuthKeyId(key: KeyObject): string {
  return signingKeyInfo(key).thumbprint;
}

/** Thumbprint + HTTP Signature Algorithms registry name for a signing key. */
function signingKeyInfo(key: KeyObject): { thumbprint: string; alg: 'ed25519' | 'ecdsa-p256-sha256' } {
  const pub = key.type === 'private' ? createPublicKey(key) : key;
  const jwk = pub.export({ format: 'jwk' }) as {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
  };
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') {
    return { thumbprint: ed25519JwkThumbprint(jwk.x), alg: 'ed25519' };
  }
  if (jwk.kty === 'EC' && jwk.crv === 'P-256' && typeof jwk.x === 'string' && typeof jwk.y === 'string') {
    return { thumbprint: ecP256JwkThumbprint(jwk.x, jwk.y), alg: 'ecdsa-p256-sha256' };
  }
  throw new Error('Web Bot Auth signing requires an Ed25519 or EC P-256 key');
}
