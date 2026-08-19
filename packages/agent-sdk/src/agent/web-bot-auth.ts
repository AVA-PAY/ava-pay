import { createPublicKey, randomBytes, sign as nodeSign, type KeyObject } from 'node:crypto';
import { computeContentDigest } from '../protocol/visa/http-signatures.js';
import {
  ed25519JwkThumbprint,
  WEB_BOT_AUTH_TAG,
  type SignatureAgentType,
} from '../protocol/web-bot-auth/index.js';
import type { SignedRequest } from './visa.js';

/**
 * Web Bot Auth — agent-side signing (IETF draft-meunier-webbotauth-httpsig-protocol).
 *
 * Mirror image of the WebBotAuthVerifier and byte-compatible with real
 * deployed traffic (OpenAI's agents): covered components
 * ("@authority" "@method" "@path" "signature-agent"), parameters
 * created/expires/keyid/alg/nonce/tag="web-bot-auth", Ed25519 signature,
 * keyid = RFC 7638 JWK thumbprint of the signing key.
 *
 * Draft -02 Section 5.2.1 requires signers to send the dictionary
 * Signature-Agent form and to cover the member keyed to their own label, so
 * `signatureAgentFormat: "dictionary"` covers `"signature-agent";key="<label>"`
 * and puts that member's value in the base, matching the Appendix E vectors.
 * The bare-string form stays available for reproducing deployed traffic.
 */

export interface WebBotAuthSignInput {
  method: string;
  url: string;
  /**
   * The agent's Signature-Agent origin, e.g. "https://chatgpt.com". The
   * verifier fetches this origin's /.well-known/http-message-signatures-directory
   * to resolve the key, so the public key must be published there.
   */
  signatureAgent: string;
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
  /** Defaults to "ed25519". Pass null to omit — verifiers resolve the alg from the directory key. */
  alg?: string | null;
  /** keyid override. Defaults to the RFC 7638 thumbprint of the signing key's public half. */
  keyid?: string;
  /**
   * Wire form of the Signature-Agent header. "item" (default) is the bare
   * quoted string deployed agents send today; "dictionary" is the
   * label-keyed form of the restructured draft.
   */
  signatureAgentFormat?: 'item' | 'dictionary';
  /**
   * Cover `"signature-agent";key="<label>"` rather than the whole field.
   * Defaults to true for the dictionary form (what -02 requires) and false for
   * the bare-string form, which has no members to key. Set false with the
   * dictionary form only to reproduce a pre--02 signer.
   */
  keyedSignatureAgentComponent?: boolean;
  /**
   * §5.5 discovery type, emitted as a `;type=` parameter on the dictionary
   * member (only meaningful with signatureAgentFormat "dictionary", since a
   * bare string carries no parameters). Omit for the default `directory`.
   */
  signatureAgentType?: SignatureAgentType;
}

export function signWithWebBotAuth(input: WebBotAuthSignInput): SignedRequest {
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const expires = input.expires === null ? undefined : (input.expires ?? created + 300);
  const label = input.label ?? 'sig1';
  const nonce = input.nonce === null ? undefined : (input.nonce ?? randomBytes(64).toString('base64url'));
  const tag = input.tag === null ? undefined : (input.tag ?? WEB_BOT_AUTH_TAG);
  const alg = input.alg === null ? undefined : (input.alg ?? 'ed25519');
  const keyid = input.keyid ?? thumbprintOf(input.privateKey);
  const components = input.components ?? ['@authority', '@method', '@path', 'signature-agent'];

  const url = new URL(input.url);
  const typeParam =
    input.signatureAgentType !== undefined ? `;type=${input.signatureAgentType}` : '';
  const isDictionary = input.signatureAgentFormat === 'dictionary';
  /** The dictionary member value on its own: what a keyed component covers. */
  const signatureAgentMember = `"${input.signatureAgent}"${typeParam}`;
  const signatureAgentHeader = isDictionary
    ? `${label}=${signatureAgentMember}`
    : `"${input.signatureAgent}"`;
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

  const sig = nodeSign(null, Buffer.from(signatureBase), input.privateKey);

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
  return thumbprintOf(key);
}

function thumbprintOf(key: KeyObject): string {
  const pub = key.type === 'private' ? createPublicKey(key) : key;
  const jwk = pub.export({ format: 'jwk' }) as { kty?: string; crv?: string; x?: string };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('Web Bot Auth signing requires an Ed25519 key');
  }
  return ed25519JwkThumbprint(jwk.x);
}
