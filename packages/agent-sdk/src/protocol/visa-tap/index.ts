import { constants, createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto';

/**
 * Visa Trusted Agent Protocol — real wire-format primitives.
 *
 * Built against Visa's public specification (developer.visa.com →
 * Trusted Agent Protocol → Specifications) and cross-checked against the
 * sample implementation at github.com/visa/trusted-agent-protocol
 * (last upstream change 2025-10-28; protocol-watch 2026-07-12 confirms the
 * spec surface is unchanged).
 *
 * Wire shape (what the sample tap-agent actually emits):
 *
 *   Signature-Input: sig2=("@authority" "@path"); created=…; expires=…;
 *                    keyId="…"; alg="rsa-pss-sha256"; nonce="…"; tag="agent-browser-auth"
 *   Signature:       sig2=:…:
 *
 * Notes on deviations we must tolerate:
 *   - the sample spells the key parameter `keyId` (capital I) while the spec
 *     text uses `keyid` — verifiers accept both spellings;
 *   - algorithms seen in the wild: "ed25519" and "rsa-pss-sha256" (Python
 *     PSS MAX_LENGTH salt), spec also names PS256/ES256;
 *   - tags: "agent-browser-auth" (browse) and "agent-payer-auth" (payment intent).
 *
 * Checkout requests may carry two signed body objects:
 *   - agenticConsumer (Consumer Recognition Object): nonce, IdToken (a JWT
 *     signed BY VISA, PS256, typ "JWT+ext.id_token"), contextualData, and an
 *     object signature by the AGENT's key linking it to the message signature;
 *   - agenticPaymentContainer: nonce, payment payloads (credentials hash /
 *     merchant-encrypted payload / card metadata), same object-signature scheme.
 *
 * The public spec defines the object signature base only as "a canonical
 * representation of all fields in the object in the order received except for
 * the signature itself", with no worked example (and the sample repo does not
 * implement it at all). buildTapObjectSignatureBase below is our documented
 * interpretation: one line per field in insertion order, `"name": value`,
 * strings raw and everything else compact JSON, joined by \n — the same style
 * as the message-signature base. If Visa publishes a normative example that
 * differs, only that function changes.
 */

export const TAP_BROWSER_TAG = 'agent-browser-auth';
export const TAP_PAYER_TAG = 'agent-payer-auth';
export const TAP_TAGS = [TAP_BROWSER_TAG, TAP_PAYER_TAG] as const;
export type TapTag = (typeof TAP_TAGS)[number];

/** Visa's public verification JWKS (IdToken signing keys). */
export const VISA_JWKS_URL = 'https://mcp.visa.com/.well-known/jwks';

/** Spec: created/expires "should not be more than 8 minutes apart". */
export const TAP_MAX_WINDOW_SECONDS = 8 * 60;

export const ID_TOKEN_TYP = 'JWT+ext.id_token';

export class VisaTapParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VisaTapParseError';
  }
}

export function isTapTag(tag: string | undefined): tag is TapTag {
  return tag === TAP_BROWSER_TAG || tag === TAP_PAYER_TAG;
}

// ─── Message-signature algorithms ───────────────────────────────────────────

/** Algorithms we verify for the HTTP message signature. */
export const TAP_MESSAGE_ALGS = ['ed25519', 'rsa-pss-sha256', 'ps256'] as const;

export function isSupportedTapMessageAlg(alg: string): boolean {
  return (TAP_MESSAGE_ALGS as readonly string[]).includes(alg.toLowerCase());
}

/**
 * Verify a TAP message/object signature with the declared algorithm.
 *
 * RSA-PSS verification uses AUTO salt length: the sample agent signs with
 * Python's PSS.MAX_LENGTH salt while JOSE PS256 uses digest-length salt —
 * AUTO accepts both (salt length is not security-relevant on verify).
 */
export function verifyTapSignature(
  alg: string,
  publicKey: KeyObject,
  data: Buffer,
  signature: Buffer,
): boolean {
  const lower = alg.toLowerCase();
  if (lower === 'ed25519') {
    if (publicKey.asymmetricKeyType !== 'ed25519' || signature.length !== 64) return false;
    return nodeVerify(null, data, publicKey, signature);
  }
  if (lower === 'rsa-pss-sha256' || lower === 'ps256') {
    if (publicKey.asymmetricKeyType !== 'rsa' && publicKey.asymmetricKeyType !== 'rsa-pss') {
      return false;
    }
    return nodeVerify(
      'sha256',
      data,
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_AUTO,
      },
      signature,
    );
  }
  return false;
}

// ─── Visa JWKS ──────────────────────────────────────────────────────────────

export interface VisaJwk {
  kid: string;
  /** Ready-to-use public key object. */
  key: KeyObject;
  /** Key type, for algorithm gating ("rsa" today). */
  keyType: string;
}

/**
 * Parse Visa's JWKS document. Fail-closed filtering: only RSA signature keys
 * with a kid and well-formed material survive; malformed entries are dropped.
 * (Visa's live JWKS carries RSA keys with x5c chains; we verify against the
 * JWK material itself — x5c chain validation is out of public-spec scope.)
 */
export function parseVisaJwks(json: unknown): VisaJwk[] {
  if (typeof json !== 'object' || json === null || !Array.isArray((json as { keys?: unknown }).keys)) {
    throw new VisaTapParseError('Visa JWKS must be an object with a "keys" array');
  }
  const out: VisaJwk[] = [];
  for (const entry of (json as { keys: unknown[] }).keys) {
    if (typeof entry !== 'object' || entry === null) continue;
    const jwk = entry as Record<string, unknown>;
    if (typeof jwk.kid !== 'string' || jwk.kid === '') continue;
    if (jwk.use !== undefined && jwk.use !== 'sig') continue;
    if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') continue;
    try {
      const key = createPublicKey({
        key: { kty: 'RSA', n: jwk.n, e: jwk.e },
        format: 'jwk',
      });
      out.push({ kid: jwk.kid, key, keyType: 'rsa' });
    } catch {
      continue; // malformed key material → drop
    }
  }
  return out;
}

// ─── IdToken (Visa-signed PS256 JWT) ────────────────────────────────────────

export interface IdTokenHeader {
  alg?: string;
  kid?: string;
  typ?: string;
}

export interface IdTokenClaims {
  iss?: string;
  sub?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  jti?: string;
  email?: string;
  phone_number?: string;
  email_mask?: string;
  phone_number_mask?: string;
  [claim: string]: unknown;
}

export interface ParsedIdToken {
  header: IdTokenHeader;
  claims: IdTokenClaims;
  signingInput: Buffer;
  signature: Buffer;
}

/**
 * Parse a compact-JWS IdToken WITHOUT verifying. Structural gates only:
 * three segments, JSON header/claims, alg PS256 (spec: "PS256 preferred;
 * None not supported" — we accept exactly PS256, fail closed), kid present.
 */
export function parseIdToken(token: string): ParsedIdToken {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new VisaTapParseError('IdToken must be a compact JWS with three segments');
  }
  const [headerB64, claimsB64, sigB64] = parts as [string, string, string];
  let header: IdTokenHeader;
  let claims: IdTokenClaims;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf-8')) as IdTokenHeader;
    claims = JSON.parse(Buffer.from(claimsB64, 'base64url').toString('utf-8')) as IdTokenClaims;
  } catch {
    throw new VisaTapParseError('IdToken segments are not valid base64url JSON');
  }
  if (header.alg !== 'PS256') {
    throw new VisaTapParseError(`IdToken alg must be PS256 (got ${header.alg ?? 'none'})`);
  }
  if (typeof header.kid !== 'string' || header.kid === '') {
    throw new VisaTapParseError('IdToken header must carry the Visa kid');
  }
  return {
    header,
    claims,
    signingInput: Buffer.from(`${headerB64}.${claimsB64}`, 'utf-8'),
    signature: Buffer.from(sigB64, 'base64url'),
  };
}

// ─── Signed body objects (Consumer Recognition / Payment Container) ────────

export interface TapSignedObject {
  nonce: string;
  kid: string;
  alg: string;
  signature: string;
  [field: string]: unknown;
}

export interface TapBodyObjects {
  consumer?: TapSignedObject;
  paymentContainer?: TapSignedObject;
}

/**
 * Extract agenticConsumer / agenticPaymentContainer from a request body.
 * Returns {} when the body is absent or carries neither object. Throws
 * VisaTapParseError when the body is not JSON or an object is malformed.
 */
export function parseTapBodyObjects(body: string | undefined): TapBodyObjects {
  if (body === undefined || body.trim() === '') return {};
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    throw new VisaTapParseError('Request body is not valid JSON');
  }
  if (typeof json !== 'object' || json === null) return {};
  const root = json as Record<string, unknown>;
  const out: TapBodyObjects = {};
  if (root.agenticConsumer !== undefined) {
    out.consumer = validateSignedObject(root.agenticConsumer, 'agenticConsumer');
  }
  if (root.agenticPaymentContainer !== undefined) {
    out.paymentContainer = validateSignedObject(
      root.agenticPaymentContainer,
      'agenticPaymentContainer',
    );
  }
  return out;
}

function validateSignedObject(value: unknown, name: string): TapSignedObject {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VisaTapParseError(`${name} must be a JSON object`);
  }
  const obj = value as Record<string, unknown>;
  for (const field of ['nonce', 'kid', 'alg', 'signature'] as const) {
    if (typeof obj[field] !== 'string' || obj[field] === '') {
      throw new VisaTapParseError(`${name} is missing required field "${field}"`);
    }
  }
  return obj as unknown as TapSignedObject;
}

/**
 * Build the object-signature base for a TAP signed body object.
 *
 * Spec (only normative sentence): "The signature base string is a canonical
 * representation of all fields in the object in the order received except for
 * the signature itself." No worked example exists publicly — this is our
 * documented interpretation, mirroring the message-signature base style:
 * one `"name": value` line per field in insertion order (strings raw,
 * non-strings compact JSON), joined with \n. Signers in this SDK use the
 * same builder, so SDK↔verifier round-trips are exact.
 */
export function buildTapObjectSignatureBase(obj: Record<string, unknown>): string {
  const lines: string[] = [];
  for (const [name, value] of Object.entries(obj)) {
    if (name === 'signature') continue;
    const rendered = typeof value === 'string' ? value : JSON.stringify(value);
    lines.push(`"${name}": ${rendered}`);
  }
  return lines.join('\n');
}
