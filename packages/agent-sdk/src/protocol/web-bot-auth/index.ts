import { createHash } from 'node:crypto';

/**
 * Web Bot Auth protocol primitives.
 *
 * Targets the restructured IETF drafts (2026-06-26):
 *   - draft-meunier-webbotauth-httpsig-protocol-00  (signed requests)
 *   - draft-meunier-webbotauth-httpsig-directory-00 (key discovery)
 *
 * Deployed reality (verified against live traffic, 2026-07): OpenAI's agents
 * still emit the pre-restructure shape — `Signature-Agent: "https://chatgpt.com"`
 * as a bare Structured Field string, covered components
 * ("@authority" "@method" "@path" "signature-agent"), and parameters
 * created/expires/keyid/nonce/tag="web-bot-auth"/alg="ed25519". The new draft
 * moves Signature-Agent to a Dictionary keyed by signature label
 * (`sig1="https://..."`). We accept both forms; everything else is identical.
 *
 * keyid is a base64url JWK SHA-256 Thumbprint (RFC 7638; Ed25519 form per
 * RFC 8037 Appendix A.3) of the signing key, resolved against the agent's
 * key directory at https://{signature-agent}/.well-known/http-message-signatures-directory.
 */

export const WEB_BOT_AUTH_TAG = 'web-bot-auth';
export const KEY_DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
export const KEY_DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';

export class WebBotAuthParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebBotAuthParseError';
  }
}

/** base64url of a 32-byte value is always exactly 43 chars, no padding. */
const B64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;

export interface SignatureAgentValue {
  /** The decoded member value, e.g. "https://chatgpt.com". */
  target: string;
  /** Normalized https origin (lowercase), used for allowlisting + directory fetch. */
  origin: string;
}

/**
 * Parse a Signature-Agent header value.
 *
 * Accepts both wire forms:
 *   - bare SF string (old draft, what OpenAI sends today):  "https://chatgpt.com"
 *   - dictionary keyed by signature label (new draft):      sig1="https://chatgpt.com"
 *
 * Only the default `directory` discovery type is supported; a member carrying
 * an explicit non-directory type parameter (e.g. `;type=jwks_uri`) is rejected
 * rather than misinterpreted — fail closed.
 */
export function parseSignatureAgent(headerValue: string, label?: string): SignatureAgentValue {
  const value = headerValue.trim();
  if (value === '') throw new WebBotAuthParseError('Signature-Agent header is empty');

  let target: string | undefined;
  if (value.startsWith('"')) {
    // Bare sf-string form.
    if (!value.endsWith('"') || value.length < 3 || value.slice(1, -1).includes('"')) {
      throw new WebBotAuthParseError('Signature-Agent is not a valid quoted string');
    }
    target = value.slice(1, -1);
  } else {
    // Dictionary form: member(s) of shape  label="value"[;param...]
    const memberRe = /([a-z][a-z0-9_.*-]*)="([^"]*)"((?:;[^,;=]+(?:=[^,;]+)?)*)/g;
    let m: RegExpExecArray | null;
    let fallback: { target: string; params: string } | undefined;
    let matched: { target: string; params: string } | undefined;
    while ((m = memberRe.exec(value)) !== null) {
      const entry = { target: m[2] as string, params: m[3] ?? '' };
      if (label !== undefined && m[1] === label) {
        matched = entry;
        break;
      }
      fallback = fallback ?? entry;
    }
    const chosen = matched ?? fallback;
    if (!chosen) {
      throw new WebBotAuthParseError('Signature-Agent is neither a quoted string nor a dictionary');
    }
    const typeMatch = chosen.params.match(/;\s*type=([^;]+)/);
    if (typeMatch && typeMatch[1] !== 'directory') {
      throw new WebBotAuthParseError(
        `Signature-Agent discovery type "${typeMatch[1]}" is not supported (only "directory").`,
      );
    }
    target = chosen.target;
  }

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new WebBotAuthParseError(`Signature-Agent value is not a valid URL: ${target}`);
  }
  if (url.protocol !== 'https:') {
    throw new WebBotAuthParseError('Signature-Agent must be an https origin');
  }
  if (url.username !== '' || url.password !== '') {
    throw new WebBotAuthParseError('Signature-Agent must not carry credentials');
  }
  return { target, origin: url.origin.toLowerCase() };
}

/**
 * RFC 7638 JWK SHA-256 thumbprint for an Ed25519 key (RFC 8037 Appendix A.3):
 * base64url(SHA-256 of the canonical JSON {"crv":"Ed25519","kty":"OKP","x":...}).
 * This is what Web Bot Auth mandates as the signature `keyid`.
 */
export function ed25519JwkThumbprint(x: string): string {
  if (!B64URL_32_BYTES.test(x)) {
    throw new WebBotAuthParseError('Ed25519 JWK "x" must be 43 base64url chars (32 bytes)');
  }
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`;
  return createHash('sha256').update(canonical, 'utf-8').digest('base64url');
}

/** One usable key out of an agent's key directory. */
export interface WebBotAuthKey {
  /** Computed RFC 7638 thumbprint — matches the request's keyid. */
  thumbprint: string;
  /** Ed25519 public key, base64url (JWK "x"). */
  x: string;
  /** Optional validity window (unix seconds) copied from the JWK. */
  nbf?: number;
  exp?: number;
}

/**
 * Parse a key directory response body (a JWKS per the directory draft).
 *
 * Fail-closed filtering, per the draft's "a client application SHOULD validate
 * the directory format and reject malformed entries":
 *   - only OKP / Ed25519 keys with a well-formed `x` survive;
 *   - a key whose `kid` is present but does not equal its computed RFC 7638
 *     thumbprint is dropped (the spec REQUIRES kid to be the thumbprint —
 *     a mismatch means a broken or lying directory entry);
 *   - a key declaring `use` other than "sig" or `alg` other than "ed25519" is dropped.
 *
 * Throws only when the overall document shape is wrong.
 */
export function parseKeyDirectory(json: unknown): WebBotAuthKey[] {
  if (typeof json !== 'object' || json === null || !Array.isArray((json as { keys?: unknown }).keys)) {
    throw new WebBotAuthParseError('Key directory must be a JWKS object with a "keys" array');
  }
  const out: WebBotAuthKey[] = [];
  for (const entry of (json as { keys: unknown[] }).keys) {
    if (typeof entry !== 'object' || entry === null) continue;
    const jwk = entry as Record<string, unknown>;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') continue;
    if (typeof jwk.x !== 'string' || !B64URL_32_BYTES.test(jwk.x)) continue;
    if (jwk.use !== undefined && jwk.use !== 'sig') continue;
    // "ed25519" is the HTTP Signature Algorithms registry name; "EdDSA" is the
    // JOSE (RFC 8037) name. Both unambiguously mean Ed25519 on an OKP key.
    if (jwk.alg !== undefined && !['ed25519', 'eddsa'].includes(String(jwk.alg).toLowerCase())) {
      continue;
    }
    const thumbprint = ed25519JwkThumbprint(jwk.x);
    if (jwk.kid !== undefined && jwk.kid !== thumbprint) continue;
    const key: WebBotAuthKey = { thumbprint, x: jwk.x };
    if (typeof jwk.nbf === 'number' && Number.isFinite(jwk.nbf)) key.nbf = jwk.nbf;
    if (typeof jwk.exp === 'number' && Number.isFinite(jwk.exp)) key.exp = jwk.exp;
    out.push(key);
  }
  return out;
}
