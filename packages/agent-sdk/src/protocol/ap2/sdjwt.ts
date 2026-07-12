import { createHash, createPublicKey, verify as nodeVerify, type KeyObject } from 'node:crypto';

/**
 * dSD-JWT primitives for AP2 v0.2 mandates.
 *
 * Ported from the reference implementation at
 * github.com/google-agentic-commerce/AP2 v0.2.0 (code/sdk/python/ap2/sdk/sdjwt)
 * — RFC 9901 SD-JWT plus draft-gco-oauth-delegate-sd-jwt-00 delegation:
 *
 *   - a chain is `~~`-joined compact SD-JWTs;
 *   - the root token is issuer-signed (key resolved by kid via the caller's
 *     key provider — AP2's x5c root-of-trust variant is not supported yet and
 *     is rejected, fail closed);
 *   - every subsequent hop is a KB-SD-JWT: its issuer JWT is signed by the
 *     PREVIOUS hop's `cnf.jwk`, carries typ "kb+sd-jwt" (terminal, no cnf) or
 *     "kb+sd-jwt+kb" (intermediate, must have cnf), and binds to the previous
 *     token via exactly one of `sd_hash` / `issuer_jwt_hash`;
 *   - mandate payloads ride in `delegate_payload: [ ... ]`, whose elements
 *     may be inline dicts, RFC 9901 `{"...": digest}` array elements, or bare
 *     digest strings (CMWallet form), each resolved against the token's
 *     disclosures;
 *   - every disclosure attached to a token MUST be referenced by some digest
 *     in it — an unmatched disclosure is rejected.
 *
 * Algorithms: ES256 (P-256, IEEE P1363 signatures) and EdDSA (Ed25519),
 * matching the reference SDK's key types. Signature verification never
 * consults the alg header alone — the resolved key's type must agree.
 */

export class SdJwtError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SdJwtError';
  }
}

const TYP_TERMINAL = ['kb+sd-jwt', 'kb-sd-jwt'];
const TYP_INTERMEDIATE = ['kb+sd-jwt+kb', 'kb-sd-jwt+kb'];

export interface ParsedSdJwt {
  issuerJwt: string;
  disclosures: string[];
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** `<issuerJwt>~<d1>~...~` — the form sd_hash commits to. */
  sdJwt: string;
  /** Effective (disclosure-resolved) delegate payloads; set by verification. */
  delegateItems?: Array<Record<string, unknown>>;
  verifiedPayload?: Record<string, unknown>;
}

export function b64urlJson(segment: string, what: string): Record<string, unknown> {
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(segment, 'base64url').toString('utf-8'));
  } catch {
    throw new SdJwtError(`Cannot parse ${what} as base64url JSON`);
  }
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    throw new SdJwtError(`${what} must decode to a JSON object`);
  }
  return decoded as Record<string, unknown>;
}

/** Parse one compact SD-JWT segment (`jwt~d1~...~[kb]`). AP2 hops carry no trailing KB-JWT. */
export function parseSdJwt(token: string): ParsedSdJwt {
  if (token.startsWith('~')) throw new SdJwtError('Malformed SD-JWT: empty issuer JWT');
  if (!token.includes('~')) throw new SdJwtError('Malformed SD-JWT: missing disclosure separator');
  const parts = token.split('~');
  const issuerJwt = parts[0]!;
  if (!token.endsWith('~')) {
    throw new SdJwtError('Trailing KB-JWTs are not used in AP2 chains');
  }
  const disclosures = parts.slice(1, -1);
  if (disclosures.some((d) => d === '')) {
    throw new SdJwtError('Malformed SD-JWT: empty disclosure segment');
  }
  const jwtParts = issuerJwt.split('.');
  if (jwtParts.length !== 3) {
    throw new SdJwtError('Malformed SD-JWT: issuer JWT must have header.payload.signature');
  }
  const header = b64urlJson(jwtParts[0]!, 'JWT header');
  const payload = b64urlJson(jwtParts[1]!, 'JWT payload');
  const sdJwt = disclosures.length ? `${issuerJwt}~${disclosures.join('~')}~` : `${issuerJwt}~`;
  return { issuerJwt, disclosures, header, payload, sdJwt };
}

// ─── Hashing ────────────────────────────────────────────────────────────────

function hashAlgOf(payload: Record<string, unknown>): string {
  const alg = payload['_sd_alg'];
  if (alg === undefined) return 'sha256';
  if (alg === 'sha-256') return 'sha256';
  if (alg === 'sha-384') return 'sha384';
  if (alg === 'sha-512') return 'sha512';
  throw new SdJwtError(`Unsupported _sd_alg: ${String(alg)}`);
}

export function disclosureDigest(disclosure: string, payload: Record<string, unknown>): string {
  return createHash(hashAlgOf(payload)).update(disclosure, 'ascii').digest('base64url');
}

export function computeSdHash(token: ParsedSdJwt): string {
  return createHash(hashAlgOf(token.payload)).update(token.sdJwt, 'ascii').digest('base64url');
}

export function computeIssuerJwtHash(token: ParsedSdJwt): string {
  return createHash(hashAlgOf(token.payload)).update(token.issuerJwt, 'ascii').digest('base64url');
}

// ─── Signature verification ─────────────────────────────────────────────────

/** Verify a compact JWT's signature with the given key (ES256 / EdDSA only). */
export function verifyJwtSignature(issuerJwt: string, key: KeyObject): boolean {
  const [h, p, s] = issuerJwt.split('.') as [string, string, string];
  const data = Buffer.from(`${h}.${p}`, 'utf-8');
  let sig: Buffer;
  try {
    sig = Buffer.from(s, 'base64url');
  } catch {
    return false;
  }
  try {
    if (key.asymmetricKeyType === 'ed25519') {
      return sig.length === 64 && nodeVerify(null, data, key, sig);
    }
    if (key.asymmetricKeyType === 'ec') {
      return sig.length === 64 && nodeVerify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
    }
    return false;
  } catch {
    return false;
  }
}

/** Build a KeyObject from a JWK-ish cnf.jwk value. Returns null for unusable keys. */
export function keyFromJwk(jwk: unknown): KeyObject | null {
  if (typeof jwk !== 'object' || jwk === null) return null;
  try {
    const key = createPublicKey({ key: jwk as never, format: 'jwk' });
    if (key.asymmetricKeyType !== 'ed25519' && key.asymmetricKeyType !== 'ec') return null;
    return key;
  } catch {
    return null;
  }
}

// ─── Disclosure resolution ──────────────────────────────────────────────────

function decodeDisclosure(disclosure: string): unknown[] {
  let arr: unknown;
  try {
    arr = JSON.parse(Buffer.from(disclosure, 'base64url').toString('utf-8'));
  } catch {
    throw new SdJwtError('Disclosure is not base64url JSON');
  }
  if (!Array.isArray(arr) || arr.length < 2 || arr.length > 3) {
    throw new SdJwtError('Disclosure must be a 2- or 3-element JSON array');
  }
  return arr;
}

/** Every digest slot reachable from the payload: top-level/_nested _sd arrays,
 *  {"...": d} array elements, and bare-string delegate_payload items. */
function collectDigestSlots(node: unknown, out: Set<string>, inDelegatePayload = false): void {
  if (Array.isArray(node)) {
    for (const el of node) {
      if (typeof el === 'string' && inDelegatePayload) out.add(el);
      else collectDigestSlots(el, out, inDelegatePayload);
    }
    return;
  }
  if (typeof node !== 'object' || node === null) return;
  const obj = node as Record<string, unknown>;
  for (const [k, v] of Object.entries(obj)) {
    if (k === '_sd' && Array.isArray(v)) {
      for (const d of v) if (typeof d === 'string') out.add(d);
    } else if (k === '...' && typeof v === 'string') {
      out.add(v);
    } else {
      collectDigestSlots(v, out, inDelegatePayload || k === 'delegate_payload');
    }
  }
}

/**
 * Verify one SD-JWT token: signature under `key`, then resolve disclosures.
 *
 * Fail-closed rules:
 *   - the signature must verify;
 *   - every attached disclosure must be referenced by a digest in the token;
 *   - delegate_payload elements resolve from {"...": digest} / bare digests /
 *    inline dicts; property disclosures resolve `_sd` arrays inside items.
 *
 * Returns the payload with `delegate_payload` fully resolved, and fills
 * `token.delegateItems` / `token.verifiedPayload`.
 */
export function verifySdJwt(token: ParsedSdJwt, key: KeyObject): Record<string, unknown> {
  if (!verifyJwtSignature(token.issuerJwt, key)) {
    throw new SdJwtError('SD-JWT issuer signature did not verify');
  }

  // Reject disclosures the payload never references.
  const slots = new Set<string>();
  collectDigestSlots(token.payload, slots);
  for (const d of token.disclosures) {
    if (!slots.has(disclosureDigest(d, token.payload))) {
      throw new SdJwtError('Disclosure not referenced by any digest in the token');
    }
  }

  const digestToDisclosure = new Map<string, string>();
  for (const d of token.disclosures) {
    digestToDisclosure.set(disclosureDigest(d, token.payload), d);
  }

  const payload = structuredClone(token.payload);
  const dp = payload['delegate_payload'];
  const items: Array<Record<string, unknown>> = [];
  if (Array.isArray(dp)) {
    const resolved: unknown[] = [];
    for (const el of dp) {
      let value: unknown = el;
      if (typeof el === 'string') {
        value = resolveDigest(el, digestToDisclosure) ?? el;
      } else if (
        typeof el === 'object' &&
        el !== null &&
        typeof (el as Record<string, unknown>)['...'] === 'string' &&
        Object.keys(el as object).length === 1
      ) {
        const hit = resolveDigest((el as Record<string, unknown>)['...'] as string, digestToDisclosure);
        if (hit === undefined) {
          throw new SdJwtError('delegate_payload digest has no matching disclosure');
        }
        value = hit;
      }
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        const item = value as Record<string, unknown>;
        inlineSdClaims(item, digestToDisclosure);
        items.push(item);
      }
      resolved.push(value);
    }
    payload['delegate_payload'] = resolved;
  }
  token.delegateItems = items;
  token.verifiedPayload = payload;
  return payload;
}

function resolveDigest(digest: string, map: Map<string, string>): Record<string, unknown> | undefined {
  const disclosure = map.get(digest);
  if (disclosure === undefined) return undefined;
  const arr = decodeDisclosure(disclosure);
  const value = arr.length === 2 ? arr[1] : arr[2];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

/** Resolve `_sd` property digests inside a delegate item, in place. */
function inlineSdClaims(item: Record<string, unknown>, map: Map<string, string>): void {
  const sd = item['_sd'];
  if (!Array.isArray(sd)) return;
  for (const digest of sd) {
    if (typeof digest !== 'string') continue;
    const disclosure = map.get(digest);
    if (disclosure === undefined) continue;
    const arr = decodeDisclosure(disclosure);
    if (arr.length === 3 && typeof arr[1] === 'string') {
      item[arr[1]] = arr[2];
    }
  }
  delete item['_sd'];
}

// ─── cnf walking + binding ──────────────────────────────────────────────────

export function cnfJwkOf(token: ParsedSdJwt): KeyObject | null {
  const holders: Array<Record<string, unknown>> = [
    ...(token.delegateItems ?? []),
    ...(token.verifiedPayload ? [token.verifiedPayload] : []),
  ];
  for (const holder of holders) {
    const cnf = holder['cnf'];
    if (typeof cnf === 'object' && cnf !== null && 'jwk' in (cnf as object)) {
      return keyFromJwk((cnf as Record<string, unknown>)['jwk']);
    }
  }
  return null;
}

function verifyBinding(payload: Record<string, unknown>, prev: ParsedSdJwt): void {
  const hasSd = 'sd_hash' in payload;
  const hasIss = 'issuer_jwt_hash' in payload;
  if (hasSd === hasIss) {
    throw new SdJwtError(
      "KB-SD-JWT must carry exactly one of 'sd_hash' / 'issuer_jwt_hash'",
    );
  }
  const expected = hasSd ? computeSdHash(prev) : computeIssuerJwtHash(prev);
  const actual = payload[hasSd ? 'sd_hash' : 'issuer_jwt_hash'];
  if (actual !== expected) {
    throw new SdJwtError(`${hasSd ? 'sd_hash' : 'issuer_jwt_hash'} mismatch`);
  }
}

// ─── Chain verification ─────────────────────────────────────────────────────

export interface VerifyChainOptions {
  /** Resolve the ROOT token's verification key (by its header kid). Null = unknown. */
  rootKey: (kid: string | undefined, token: ParsedSdJwt) => Promise<KeyObject | null> | KeyObject | null;
  /** Required aud on the terminal hop, when enforcing. */
  expectedAud?: string;
  /** Required nonce on the terminal hop, when enforcing a specific value. */
  expectedNonce?: string;
  clockSkewSeconds?: number;
  now?: () => number;
}

export interface VerifiedChain {
  /** Effective delegate payloads, root-first (one or more per hop). */
  payloads: Array<Record<string, unknown>>;
  /** Parsed, verified tokens. */
  tokens: ParsedSdJwt[];
  /** Terminal hop's aud/nonce/iat claims (for replay + audience policy). */
  terminal: { aud?: string; nonce?: string; iat?: number };
}

/**
 * Verify a `~~`-joined dSD-JWT delegation chain (or a single root SD-JWT).
 * Faithful port of the reference verify_chain; throws SdJwtError on ANY
 * failure — callers translate into typed reasons.
 */
export async function verifyChain(chain: string, opts: VerifyChainOptions): Promise<VerifiedChain> {
  const skew = opts.clockSkewSeconds ?? 300;
  const now = opts.now ? opts.now() : Math.floor(Date.now() / 1000);
  const segments = chain.split('~~').map(restoreTrailingTilde);
  const tokens = segments.map(parseSdJwt);

  const root = tokens[0]!;
  if ('x5c' in root.header) {
    // The reference SDK trusts x5c chains to configured roots; we have no
    // trust anchors configured for that path yet. Reject, never guess.
    throw new SdJwtError('x5c root-of-trust resolution is not supported');
  }
  const rootKid = typeof root.header['kid'] === 'string' ? (root.header['kid'] as string) : undefined;
  const rootKey = await opts.rootKey(rootKid, root);
  if (!rootKey) throw new SdJwtError(`No key for root kid "${rootKid ?? '(missing)'}"`);

  const payloads: Array<Record<string, unknown>> = [];
  const rootPayload = verifySdJwt(root, rootKey);
  checkTime([rootPayload, ...(root.delegateItems ?? [])], now, skew);
  payloads.push(...(root.delegateItems?.length ? root.delegateItems : [rootPayload]));

  let terminal: VerifiedChain['terminal'] = {};
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i]!;
    const prev = tokens[i - 1]!;
    const isLast = i === tokens.length - 1;

    const typ = typeof token.header['typ'] === 'string' ? (token.header['typ'] as string) : undefined;
    if (typ === undefined || ![...TYP_TERMINAL, ...TYP_INTERMEDIATE].includes(typ)) {
      throw new SdJwtError(`Unexpected KB-SD-JWT typ: ${typ ?? '(none)'}`);
    }

    const prevKey = cnfJwkOf(prev);
    if (!prevKey) throw new SdJwtError('Previous hop is missing a usable cnf.jwk');

    const payload = verifySdJwt(token, prevKey);
    verifyBinding(payload, prev);
    if (typeof payload['iat'] !== 'number') {
      throw new SdJwtError('KB-SD-JWT missing required iat claim');
    }
    if (isLast) {
      if (opts.expectedAud !== undefined && payload['aud'] !== opts.expectedAud) {
        throw new SdJwtError(
          `aud mismatch: expected "${opts.expectedAud}", got "${String(payload['aud'])}"`,
        );
      }
      if (opts.expectedNonce !== undefined && payload['nonce'] !== opts.expectedNonce) {
        throw new SdJwtError('nonce mismatch on terminal hop');
      }
      terminal = {
        ...(typeof payload['aud'] === 'string' ? { aud: payload['aud'] as string } : {}),
        ...(typeof payload['nonce'] === 'string' ? { nonce: payload['nonce'] as string } : {}),
        ...(typeof payload['iat'] === 'number' ? { iat: payload['iat'] as number } : {}),
      };
    }

    const hasCnf = (token.delegateItems ?? []).some(
      (item) => typeof item['cnf'] === 'object' && item['cnf'] !== null,
    );
    if (TYP_TERMINAL.includes(typ) && hasCnf) {
      throw new SdJwtError("Terminal KB-SD-JWT must not carry a 'cnf' claim");
    }
    if (TYP_INTERMEDIATE.includes(typ) && !hasCnf) {
      throw new SdJwtError(`Intermediate ${typ} requires a 'cnf' claim`);
    }
    if (!isLast && (token.delegateItems?.length ?? 0) > 1) {
      throw new SdJwtError('Intermediate hop disclosed more than one delegate item');
    }

    checkTime([payload, ...(token.delegateItems ?? [])], now, skew);
    payloads.push(...(token.delegateItems?.length ? token.delegateItems : [payload]));
  }

  if (tokens.length === 1) {
    // Single root token: nothing enforced aud/nonce, so callers requiring a
    // key-bound presentation must check `terminal` themselves.
    terminal = {};
  }

  return { payloads, tokens, terminal };
}

/** Segments lose their trailing `~` when joined with `~~`; restore it. */
function restoreTrailingTilde(segment: string, index: number, all: string[]): string {
  if (index === all.length - 1 || segment.endsWith('~')) return segment;
  const last = segment.split('~').pop() ?? '';
  if (last.split('.').length === 3) return segment;
  return `${segment}~`;
}

function checkTime(payloads: Array<Record<string, unknown>>, now: number, skew: number): void {
  for (const p of payloads) {
    const exp = p['exp'];
    if (exp !== undefined) {
      if (typeof exp !== 'number') throw new SdJwtError('Invalid exp claim type');
      if (now > exp + skew) throw new SdJwtError(`Token expired at ${exp}`);
    }
    const iat = p['iat'];
    if (iat !== undefined) {
      if (typeof iat !== 'number') throw new SdJwtError('Invalid iat claim type');
      if (iat > now + skew) throw new SdJwtError(`Token iat is in the future: ${iat}`);
    }
  }
}
