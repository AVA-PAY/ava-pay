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

export {
  DIRECTORY_PROOF_TAG,
  buildDirectoryProofBase,
  signDirectoryResponse,
  verifyDirectoryProofs,
  type KeyProofStatus,
  type DirectoryProofSigner,
} from './directory-proof.js';

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

/**
 * §5.5 discovery type. `directory` (the default, and the type of a bare string)
 * binds a domain via the reserved well-known path. `jwks_uri` and `cimd` give
 * key continuity at an arbitrary URL with NO origin association, so a verifier
 * must price them differently (see the `binding` on the verdict).
 */
export type SignatureAgentType = 'directory' | 'jwks_uri' | 'cimd';

const KNOWN_SIGNATURE_AGENT_TYPES: readonly SignatureAgentType[] = ['directory', 'jwks_uri', 'cimd'];

export interface SignatureAgentValue {
  /** The decoded member value, e.g. "https://chatgpt.com". */
  target: string;
  /** Normalized https origin (lowercase), used for allowlisting + directory fetch. */
  origin: string;
  /**
   * Discovery type from the §5.5 `type` parameter. `directory` is the default
   * ONLY when no type parameter is present (and for a bare string). A member
   * carrying an UNRECOGNIZED type is ignored, never upgraded to `directory`;
   * the type is never inferred from the path shape.
   */
  type: SignatureAgentType;
}

/**
 * Parse a Signature-Agent header value.
 *
 * Accepts both wire forms (accept-both tolerance, App E.1.3):
 *   - bare SF string (deployed today, an explicit verifier-MAY): "https://chatgpt.com"
 *   - dictionary keyed by signature label (signers MUST send this): sig1="https://chatgpt.com"
 *
 * The §5.5 `type` parameter is parsed and returned so the caller can price the
 * binding strength. `directory` / `jwks_uri` / `cimd` are all accepted. A
 * member with an unrecognized type is skipped, never treated as `directory`
 * (that would grant domain binding to a member the spec says to ignore): the
 * label-matched member is rejected outright, and an unrecognized-type member
 * is never chosen as the unlabeled fallback.
 */
export function parseSignatureAgent(headerValue: string, label?: string): SignatureAgentValue {
  const value = headerValue.trim();
  if (value === '') throw new WebBotAuthParseError('Signature-Agent header is empty');

  let target: string | undefined;
  let type: SignatureAgentType = 'directory';
  if (value.startsWith('"')) {
    // Bare sf-string form: no parameters, so the discovery type is the default.
    if (!value.endsWith('"') || value.length < 3 || value.slice(1, -1).includes('"')) {
      throw new WebBotAuthParseError('Signature-Agent is not a valid quoted string');
    }
    target = value.slice(1, -1);
  } else {
    // Dictionary form: member(s) of shape  label="value"[;param...]
    const memberRe = /([a-z][a-z0-9_.*-]*)="([^"]*)"((?:;[^,;=]+(?:=[^,;]+)?)*)/g;
    let m: RegExpExecArray | null;
    // The fallback (unlabeled call) only ever holds a member with a recognized
    // type; an unrecognized-type member is never selected as fallback.
    let fallback: { target: string; type: SignatureAgentType } | undefined;
    let matched: { target: string; type: SignatureAgentType | null } | undefined;
    while ((m = memberRe.exec(value)) !== null) {
      const memberType = parseDiscoveryType(m[3] ?? '');
      if (label !== undefined && m[1] === label) {
        // The label-matched member is authoritative for this signature; capture
        // it even if its type is unrecognized (null), and reject below.
        matched = { target: m[2] as string, type: memberType };
        break;
      }
      if (memberType !== null && fallback === undefined) {
        fallback = { target: m[2] as string, type: memberType };
      }
    }
    if (matched) {
      if (matched.type === null) {
        throw new WebBotAuthParseError(
          'Signature-Agent member carries an unrecognized discovery type parameter',
        );
      }
      target = matched.target;
      type = matched.type;
    } else if (fallback) {
      target = fallback.target;
      type = fallback.type;
    } else {
      throw new WebBotAuthParseError(
        'Signature-Agent has no usable member (empty, unparseable, or unrecognized type only)',
      );
    }
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
  return { target, origin: url.origin.toLowerCase(), type };
}

/**
 * Read the §5.5 `type` parameter from a Structured Field member's parameter
 * string. An ABSENT parameter defaults to `directory`. A recognized value is
 * returned as-is. An unrecognized value returns null (the member must be
 * skipped, never upgraded to `directory` and never inferred from the URL path).
 */
function parseDiscoveryType(params: string): SignatureAgentType | null {
  const typeMatch = params.match(/;\s*type=([^;]+)/);
  if (!typeMatch) return 'directory';
  const raw = typeMatch[1]!.trim().replace(/^"|"$/g, '').toLowerCase();
  return (KNOWN_SIGNATURE_AGENT_TYPES as readonly string[]).includes(raw)
    ? (raw as SignatureAgentType)
    : null;
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
 * Parse a key directory response body.
 *
 * Accepts BOTH deployed shapes (accept-both interop tolerance, recorded as a
 * data point for the review reply):
 *   - the canonical JWKS wrapper `{ "keys": [ ...jwk ] }` (draft -01, served by
 *     chatgpt.com), possibly carrying extra metadata like `signature_agent` /
 *     `purpose`, which we ignore;
 *   - a BARE single JWK object (served by www.shopify.com as of 2026-08-09),
 *     which we treat as a one-key directory.
 *
 * Fail-closed filtering, per the draft's "a client application SHOULD validate
 * the directory format and reject malformed entries":
 *   - only OKP / Ed25519 keys with a well-formed `x` survive;
 *   - a key whose `kid` is present but does not equal its computed RFC 7638
 *     thumbprint is dropped (the spec REQUIRES kid to be the thumbprint —
 *     a mismatch means a broken or lying directory entry);
 *   - a key declaring `use` other than "sig" or `alg` other than "ed25519" is dropped.
 *
 * Throws only when the overall document shape is neither a keys array nor a JWK.
 */
export function parseKeyDirectory(json: unknown): WebBotAuthKey[] {
  if (typeof json !== 'object' || json === null) {
    throw new WebBotAuthParseError('Key directory must be a JSON object');
  }
  const obj = json as Record<string, unknown>;
  let entries: unknown[];
  if (Array.isArray(obj.keys)) {
    entries = obj.keys;
  } else if (typeof obj.kty === 'string') {
    // Bare single JWK (no "keys" wrapper). Never infer more than one key here.
    entries = [obj];
  } else {
    throw new WebBotAuthParseError(
      'Key directory must be a JWKS object with a "keys" array or a single JWK',
    );
  }
  const out: WebBotAuthKey[] = [];
  for (const entry of entries) {
    const key = parseDirectoryKey(entry);
    if (key) out.push(key);
  }
  return out;
}

/** Validate + normalize one directory JWK, or null if it must be dropped. */
function parseDirectoryKey(entry: unknown): WebBotAuthKey | null {
  if (typeof entry !== 'object' || entry === null) return null;
  const jwk = entry as Record<string, unknown>;
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return null;
  if (typeof jwk.x !== 'string' || !B64URL_32_BYTES.test(jwk.x)) return null;
  if (jwk.use !== undefined && jwk.use !== 'sig') return null;
  // "ed25519" is the HTTP Signature Algorithms registry name; "EdDSA" is the
  // JOSE (RFC 8037) name. Both unambiguously mean Ed25519 on an OKP key.
  if (jwk.alg !== undefined && !['ed25519', 'eddsa'].includes(String(jwk.alg).toLowerCase())) {
    return null;
  }
  const thumbprint = ed25519JwkThumbprint(jwk.x);
  if (jwk.kid !== undefined && jwk.kid !== thumbprint) return null;
  const key: WebBotAuthKey = { thumbprint, x: jwk.x };
  if (typeof jwk.nbf === 'number' && Number.isFinite(jwk.nbf)) key.nbf = jwk.nbf;
  if (typeof jwk.exp === 'number' && Number.isFinite(jwk.exp)) key.exp = jwk.exp;
  return key;
}
