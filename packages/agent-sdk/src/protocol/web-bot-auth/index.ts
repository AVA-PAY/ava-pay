import { createHash } from 'node:crypto';

/**
 * Web Bot Auth protocol primitives.
 *
 * Targets draft-ietf-webbotauth-httpsig-protocol-01 (published 2026-10-29).
 * -01 redefined what a Signature-Agent value is: a member value is an https
 * URL to a JWK Set, fetched as sent and identified by its normalized form
 * with the query dropped (Section 5.5). The well-known URI registered in
 * Section 8.1 is a special case whose URL additionally names a domain
 * (Section 4.5); any other path gives key continuity at a URL with no origin
 * association, because TLS authenticates the host but not the path.
 *
 * Deployed reality (measured 2026-10-31): chatgpt.com still sends the bare
 * sf-string `"https://chatgpt.com"`, Google sends `g="https://agent.bot.goog"`,
 * Shopify signs with `"https://shopify.com"`, all bare origins, with keys
 * served only at the well-known path. The legacy bare-origin tolerance below
 * keeps resolving those at the well-known path.
 *
 * keyid is a base64url JWK SHA-256 Thumbprint (RFC 7638: the Section 3.2 form
 * for EC keys, the RFC 8037 Appendix A.3 form for Ed25519) of the signing key,
 * resolved against the JWK Set the Signature-Agent URL serves.
 *
 * Algorithms: ed25519 and ecdsa-p256-sha256 (see keys.ts). RSA is a stated
 * non-goal for now, rejected with a reason that says so.
 */

export {
  DIRECTORY_PROOF_TAG,
  buildDirectoryProofBase,
  signDirectoryResponse,
  verifyDirectoryProofs,
  type KeyProofStatus,
  type DirectoryProofSigner,
} from './directory-proof.js';

export {
  directoryKeyAlgorithm,
  directoryKeyJwk,
  verifyWithDirectoryKey,
  type WebBotAuthKeyAlgorithm,
} from './keys.js';

export const WEB_BOT_AUTH_TAG = 'web-bot-auth';
export const KEY_DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
export const KEY_DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';
/** RFC 7517 Section 8.5 media type for a JWK Set, the natural type of a jwks_uri. */
export const JWK_SET_MEDIA_TYPE = 'application/jwk-set+json';

/**
 * Classify a key directory response's Content-Type. Parameters (charset) and
 * case are ignored.
 *   directory  KEY_DIRECTORY_MEDIA_TYPE, what the draft registers
 *   jwk-set    application/jwk-set+json
 *   json       plain application/json, the common generic fallback
 *   other      anything else, including an absent header
 * Callers decide which classes they accept; a fetcher that parsed an `other`
 * body as keys would let a page that merely contains a key set (an HTML error
 * page, a CMS) stand in for a directory.
 */
export type KeyDirectoryMediaClass = 'directory' | 'jwk-set' | 'json' | 'other';

export function classifyKeyDirectoryMediaType(contentType: string | null | undefined): KeyDirectoryMediaClass {
  const essence = (contentType ?? '').split(';')[0]!.trim().toLowerCase();
  if (essence === KEY_DIRECTORY_MEDIA_TYPE) return 'directory';
  if (essence === JWK_SET_MEDIA_TYPE) return 'jwk-set';
  if (essence === 'application/json') return 'json';
  return 'other';
}

/**
 * What a WebBotAuthParseError from parseSignatureAgent is about, so a verifier
 * can name the fault without parsing the message:
 *   malformed      not a readable Structured Field, no usable member, or a
 *                  member that carries parameters (-01 Section 5.2.1 says
 *                  members MUST NOT carry them and a verifier MUST ignore a
 *                  member that does)
 *   ambiguous      several usable members and none keyed to the signature
 *   member_missing the covered (keyed) member is not in the header
 *   not_origin     the value is not an acceptable JWK Set URL: not https,
 *                  carrying credentials or a fragment, or not an absolute URI
 * Errors from the key directory helpers are always `malformed`.
 */
export type WebBotAuthParseErrorCode = 'malformed' | 'ambiguous' | 'member_missing' | 'not_origin';

export class WebBotAuthParseError extends Error {
  readonly code: WebBotAuthParseErrorCode;

  constructor(message: string, code: WebBotAuthParseErrorCode = 'malformed') {
    super(message);
    this.name = 'WebBotAuthParseError';
    this.code = code;
  }
}

/** base64url of a 32-byte value is always exactly 43 chars, no padding. */
const B64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/;

export interface SignatureAgentValue {
  /** The decoded member value exactly as sent, e.g. "https://chatgpt.com". */
  target: string;
  /**
   * The URL -01 §5.5 tells a verifier to GET for this member ("The verifier
   * fetches the member value as sent"), so a query survives here (and only
   * here). For a legacy bare origin this is the origin's well-known
   * directory URL. NOTE: this repo's resolvers deliberately fetch the
   * `identifier` instead of this URL. Under fetch-as-sent, every query
   * spelling shares the one cache entry its identifier names, so a
   * caller-chosen query whose answer differs (an error, or a 200 with a
   * different key set, which §6.10 treats as evidence) would displace the
   * entry every other spelling shares. The field reports what the header
   * said, for consumers that make a different trade-off.
   */
  fetchUrl: string;
  /**
   * The identifier: the fetched URL normalized per RFC 3986 §6.2.2 and §6.2.3
   * with any query dropped (-01 §5.5: "The URL the verifier resolved is the
   * identifier, with any query discarded... Otherwise one key set would yield
   * an identifier per spelling, and an Agent could mint them at will").
   * Allowlists, caches and (URL, key) lookups key on this.
   */
  identifier: string;
  /** Lowercase https origin of the identifier. */
  origin: string;
  /**
   * `domain` when the identifier is the §8.1 well-known URL on its origin,
   * which names the domain (-01 §4.5); `url-only` for any other path, which
   * names nothing but itself ("TLS authenticates the host but not the path",
   * -01 §5.5).
   */
  binding: 'domain' | 'url-only';
  /**
   * True when the member value was a bare origin (empty or "/" path, no
   * query) resolved at the well-known path by the legacy tolerance. -01 does
   * not sanction this shape (WG PR #153 rewrites every example and vector to
   * carry the well-known path explicitly), but chatgpt.com, agent.bot.goog
   * and shopify.com all still send bare origins (measured 2026-10-31), with
   * keys served only at the well-known path. Accept-deployed-reality: the
   * tolerance is on by default and this flag records that it fired.
   */
  legacyBareOrigin: boolean;
}

/**
 * Parse a Signature-Agent header value.
 *
 * Accepts both wire forms:
 *   - bare SF string (deployed today; -01 §5.2.1 lets a verifier accept it as
 *     a dictionary with a single member): "https://chatgpt.com"
 *   - dictionary keyed by signature label (signers MUST send this):
 *     sig1="https://signer.example/.well-known/http-message-signatures-directory"
 *
 * -01 §5.2.1: "Dictionary members MUST NOT carry parameters. A verifier MUST
 * ignore a member that carries parameters." A member with ANY parameter
 * (including the retired -00 `;type=`) is therefore ignored. When that leaves
 * the member the signature covers unusable, the error names the parameter and
 * says what to send instead, because "ignored" would otherwise surface as a
 * baffling member_missing to the operator who sent it.
 *
 * `strict` controls what happens when `label` names no member. Off (default),
 * a single usable member is taken, which is the tolerance the deployed
 * bare-string traffic needs. SEVERAL usable members and no label match is an
 * error either way: nothing says which one signed, so any choice would be
 * attribution by header order. ON, the absence is an error too: a caller that
 * knows the signature covers one NAMED member must resolve that member or
 * nothing, because falling back would attribute the signature to a member it
 * never covered (-01 §5.2.2).
 */
export function parseSignatureAgent(
  headerValue: string,
  label?: string,
  options: { strict?: boolean } = {},
): SignatureAgentValue {
  const value = headerValue.trim();
  if (value === '') throw new WebBotAuthParseError('Signature-Agent header is empty');

  let target: string | undefined;
  if (value.startsWith('"')) {
    // Bare sf-string form: a String Item carries no dictionary parameters.
    if (!value.endsWith('"') || value.length < 3 || value.slice(1, -1).includes('"')) {
      throw new WebBotAuthParseError('Signature-Agent is not a valid quoted string');
    }
    target = value.slice(1, -1);
  } else {
    // Dictionary form: member(s) of shape  label="value"[;param...]
    const memberRe = /([a-z][a-z0-9_.*-]*)="([^"]*)"((?:;[^,;=]+(?:=[^,;]+)?)*)/g;
    let m: RegExpExecArray | null;
    // Members without parameters are the usable candidates. A member carrying
    // ANY parameter is ignored (-01 §5.2.1 MUST); the first such parameter is
    // remembered so the error can name it when ignoring left nothing usable.
    const candidates: string[] = [];
    let matched: { target: string; params: string } | undefined;
    let ignoredParameter: string | undefined;
    while ((m = memberRe.exec(value)) !== null) {
      const params = m[3] ?? '';
      if (label !== undefined && m[1] === label) {
        // The label-matched member is authoritative for this signature; capture
        // it even when it carries parameters, and reject below by name.
        matched = { target: m[2] as string, params };
        break;
      }
      if (params === '') {
        candidates.push(m[2] as string);
      } else {
        ignoredParameter ??= params.slice(1).split(/[;=]/)[0];
      }
    }
    const parameterError = (params: string): WebBotAuthParseError => {
      const name = params.replace(/^;/, '').split(/[;=]/)[0];
      return new WebBotAuthParseError(
        `Signature-Agent member carries a parameter ("${name}"), which `
          + 'draft-ietf-webbotauth-httpsig-protocol-01 Section 5.2.1 forbids: members MUST NOT '
          + 'carry parameters and a verifier MUST ignore a member that does. Send the JWK Set '
          + 'URL as the bare member value instead.',
      );
    };
    if (matched) {
      if (matched.params !== '') throw parameterError(matched.params);
      target = matched.target;
    } else if (options.strict === true) {
      // Name the failure for what it is. A header we could not read as a
      // dictionary at all is malformed; "no member keyed X" is true only of a
      // header that parsed and lacks X. This only chooses the error's name:
      // either way the request is refused.
      throw hasUnparsedResidue(value, memberRe)
        ? new WebBotAuthParseError('Signature-Agent is not a readable Structured Field dictionary')
        : new WebBotAuthParseError(
            `Signature-Agent has no member keyed "${label}", which is the member the signature covers`,
            'member_missing',
          );
    } else if (candidates.length === 1) {
      target = candidates[0]!;
    } else if (candidates.length > 1) {
      // Several usable members and nothing says which one signed. Picking one
      // would attribute the signature to a member chosen by header order, which
      // is precisely the attribution §5.2.2 forbids ("A verifier MUST NOT
      // attribute a signature to a member that signature does not cover").
      throw new WebBotAuthParseError(
        `Signature-Agent carries ${candidates.length} usable members and none is keyed "${label}", so the signature cannot be attributed to one of them`,
        'ambiguous',
      );
    } else if (ignoredParameter !== undefined) {
      // Every member was ignored for carrying parameters: say which parameter
      // did it rather than reporting an empty header.
      throw parameterError(`;${ignoredParameter}`);
    } else {
      throw new WebBotAuthParseError(
        'Signature-Agent has no usable member (empty or unparseable)',
      );
    }
  }

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new WebBotAuthParseError(
      `Signature-Agent value is not an absolute URI: ${target}`,
      'not_origin',
    );
  }
  if (url.protocol !== 'https:') {
    throw new WebBotAuthParseError('Signature-Agent must be an https URL', 'not_origin');
  }
  if (url.username !== '' || url.password !== '') {
    throw new WebBotAuthParseError('Signature-Agent must not carry credentials', 'not_origin');
  }
  if (url.hash !== '') {
    // A fragment is client-side state; it can neither be fetched nor identify
    // a resource, so there is nothing -01 §5.5 could resolve.
    throw new WebBotAuthParseError('Signature-Agent must not carry a fragment', 'not_origin');
  }
  const origin = url.origin.toLowerCase();

  // Legacy bare-origin tolerance, ON by default: a value whose path is empty
  // or "/" with no query resolves at the origin's well-known directory URL.
  // -01 does not sanction this shape (its §5.5 fetches the member value as
  // sent, and WG PR #153 rewrites every example and vector to carry the
  // well-known path explicitly), but every live signer still sends bare
  // origins (chatgpt.com and shopify.com as bare sf-strings,
  // agent.bot.goog as g="https://agent.bot.goog", all measured 2026-10-31)
  // and their keys exist only at the well-known path. Accept-deployed-reality
  // until they migrate.
  if (url.pathname === '/' && url.search === '') {
    const wellKnown = `${origin}${KEY_DIRECTORY_PATH}`;
    return {
      target,
      fetchUrl: wellKnown,
      identifier: wellKnown,
      origin,
      binding: 'domain',
      legacyBareOrigin: true,
    };
  }

  // -01 §5.5: fetch the member value as sent (query kept); the identifier is
  // the normalized URL with the query discarded.
  const identifier = `${origin}${normalizePathPercentEncoding(url.pathname)}`;
  const fetchUrl = `${identifier}${url.search}`;
  return {
    target,
    fetchUrl,
    identifier,
    origin,
    // -01 §4.5: the well-known URL additionally names a domain; any other
    // path names only itself.
    binding: identifier === `${origin}${KEY_DIRECTORY_PATH}` ? 'domain' : 'url-only',
    legacyBareOrigin: false,
  };
}

/**
 * Normalize a Signature-Agent allowlist entry or identifier to the identifier
 * form the parser produces, so allowlists, caches and key lookups all compare
 * the same octets (-01 §5.5: identifiers are compared after RFC 3986 §6.2.2
 * and §6.2.3 normalization).
 *
 * An entry whose path is empty or "/" (an origin) means EXACTLY that origin's
 * well-known directory URL. It never admits other paths on the origin,
 * because a JWK Set at an arbitrary path does not name the host's operator
 * ("TLS authenticates the host but not the path", -01 §5.5). A full https URL
 * means exactly that identifier, query and fragment dropped.
 *
 * CONFIGURATION ENTRIES ONLY. Never apply this to a request-derived
 * identifier: parseSignatureAgent gives the member value "https://host/?x"
 * the identifier "https://host/", and expanding that "/" path here would
 * alias it onto the host's well-known directory entry, which is how a
 * caller-chosen query could poison an allowlisted host's cache entry.
 * Resolvers compare request identifiers verbatim.
 */
export function signatureAgentIdentifier(entry: string): string {
  const url = new URL(entry);
  if (url.protocol !== 'https:') {
    throw new Error(`Signature-Agent identifiers must be https, got: ${entry}`);
  }
  const origin = url.origin.toLowerCase();
  if (url.pathname === '/') return `${origin}${KEY_DIRECTORY_PATH}`;
  return `${origin}${normalizePathPercentEncoding(url.pathname)}`;
}

/**
 * RFC 3986 §6.2.2 percent-encoding normalization over a URL path the WHATWG
 * parser already case- and scheme-normalized (lowercase host, default port
 * dropped, dot-segments removed): decode percent-encoded unreserved
 * characters and uppercase the hex digits of every other escape, so two
 * spellings of one path compare octet for octet.
 */
function normalizePathPercentEncoding(pathname: string): string {
  return pathname.replace(/%([0-9a-fA-F]{2})/g, (escape, hex: string) => {
    const code = parseInt(hex, 16);
    const char = String.fromCharCode(code);
    // RFC 3986 §2.3 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
    if (/[A-Za-z0-9\-._~]/.test(char)) return char;
    return `%${hex.toUpperCase()}`;
  });
}

/**
 * True when something in a dictionary-form header is not a member the member
 * pattern reads, once separating commas and whitespace are set aside. Used only
 * to name an error, never to accept or refuse a header.
 */
function hasUnparsedResidue(value: string, memberRe: RegExp): boolean {
  const pattern = new RegExp(memberRe.source, 'g');
  return value.replace(pattern, '').replace(/[\s,]+/g, '') !== '';
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

/**
 * RFC 7638 Section 3.2 JWK SHA-256 thumbprint for an EC P-256 key:
 * base64url(SHA-256 of the canonical JSON with exactly the required members
 * {crv, kty, x, y} in lexicographic order). -00 Section 5.2 names this form
 * for EC request keyids.
 */
export function ecP256JwkThumbprint(x: string, y: string): string {
  if (!B64URL_32_BYTES.test(x) || !B64URL_32_BYTES.test(y)) {
    throw new WebBotAuthParseError(
      'P-256 JWK "x" and "y" must each be 43 base64url chars (32 bytes)',
    );
  }
  const canonical = `{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`;
  return createHash('sha256').update(canonical, 'utf-8').digest('base64url');
}

/** One usable key out of an agent's key directory. */
export interface WebBotAuthKey {
  /**
   * Computed RFC 7638 thumbprint. This is the key's identity: derived from the
   * material by us, never trusted from a label. -00 Section 5.2 makes it the
   * request keyid.
   */
  thumbprint: string;
  /**
   * The advertised `kid` label exactly as published, when the entry carries a
   * string one. -00 Section 5.5 says a kid, if present, MUST equal the
   * thumbprint, but agent.bot.goog publishes six-char kids (seen 2026-09-29),
   * so a verifier keeps the label as a selector hint and never trusts it as
   * identity. Absent when the entry has no kid or a non-string one.
   */
  kid?: string;
  /**
   * The key's curve, which pins its one signature algorithm (ed25519 for
   * Ed25519, ecdsa-p256-sha256 for P-256; see directoryKeyAlgorithm). Optional
   * so the type stays additive: a key parsed by an older build carries no crv
   * and is Ed25519, and parseDirectoryKey always sets it.
   */
  crv?: 'Ed25519' | 'P-256';
  /** Public key first coordinate, base64url (JWK "x"). */
  x: string;
  /** P-256 keys only: the second coordinate (JWK "y"). Absent on Ed25519. */
  y?: string;
  /** Optional validity window (unix seconds) copied from the JWK. */
  nbf?: number;
  exp?: number;
}

/** One directory entry that was set aside, with why, for truthful reporting. */
export interface DroppedDirectoryEntry {
  /** Position in the published entry list. */
  index: number;
  /** Human-readable reason the entry is unusable. */
  reason: string;
}

/** What a key directory document holds: usable keys plus what was set aside. */
export interface KeyDirectoryContents {
  keys: WebBotAuthKey[];
  dropped: DroppedDirectoryEntry[];
}

/**
 * Ceiling on published entries, matching Cloudflare's implementation cap. A
 * directory over it is unusable as a whole (readKeyDirectory throws) rather
 * than silently truncated: a truncated view could hide the one key a request
 * needs and misreport "unknown key" for a key the directory serves.
 */
export const MAX_DIRECTORY_KEYS = 100;

/**
 * Parse a key directory response body.
 *
 * Accepts BOTH deployed shapes (accept-both interop tolerance, recorded as a
 * data point for the review reply):
 *   - the canonical JWKS wrapper `{ "keys": [ ...jwk ] }` (the §5.5.1 shape,
 *     served by chatgpt.com), possibly carrying extra metadata like
 *     `signature_agent` / `purpose`, which we ignore;
 *   - a BARE single JWK object (served by www.shopify.com as of 2026-08-09),
 *     which we treat as a one-key directory.
 *
 * Fail-closed filtering, per the draft's "a client application SHOULD validate
 * the directory format and reject malformed entries":
 *   - OKP/Ed25519 keys with a well-formed `x`, and EC/P-256 keys with
 *     well-formed `x` and `y`, survive. Everything else is dropped with a
 *     reason: RSA keys (a stated non-goal for now, not an accident), other EC
 *     curves (P-384, ...), other key types, malformed coordinates.
 *   - a key declaring `use` other than "sig" is dropped, as is a key whose
 *     `alg` does not name its own type's algorithm. The editor's copy (WG PR
 *     #139) has a directory JWK `alg` follow RFC 7517 §4.4, so the accepted
 *     spellings are "EdDSA" / "Ed25519" / "ed25519" on an OKP key and "ES256"
 *     on an EC key; a mismatch (ES256 on an Ed25519 key, EdDSA on a P-256 key)
 *     drops the key, because that key cannot have signed what the label says.
 *     alg-absent is accepted (the key type decides) because stock WebCrypto
 *     REJECTS `alg: "ed25519"` on import (Joshua Ashcroft's implementer report
 *     to the list, 2026-08-18), so directories have good reason to omit it.
 *
 * A `kid` that differs from the computed thumbprint NEVER drops the key. -00
 * Section 5.5 says a published kid MUST be the thumbprint, but the identity of
 * a key is its material: the thumbprint is computed here and the advertised
 * label is kept verbatim as a selector hint (WebBotAuthKey.kid). Dropping the
 * key punished the signer for the directory's labelling and made
 * agent.bot.goog (six-char kids, seen 2026-09-29) parse to zero keys.
 *
 * Throws when the overall document shape is neither a keys array nor a JWK, or
 * when it publishes more than MAX_DIRECTORY_KEYS entries (unusable as a whole,
 * never silently truncated).
 */
export function readKeyDirectory(json: unknown): KeyDirectoryContents {
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
  if (entries.length > MAX_DIRECTORY_KEYS) {
    throw new WebBotAuthParseError(
      `Key directory publishes ${entries.length} entries; more than ${MAX_DIRECTORY_KEYS} is unusable`,
    );
  }
  const keys: WebBotAuthKey[] = [];
  const dropped: DroppedDirectoryEntry[] = [];
  entries.forEach((entry, index) => {
    const parsed = parseDirectoryKey(entry);
    if (typeof parsed === 'string') {
      dropped.push({ index, reason: parsed });
    } else {
      keys.push(parsed);
    }
  });
  return { keys, dropped };
}

/** The usable keys of a directory document. See readKeyDirectory for the rules. */
export function parseKeyDirectory(json: unknown): WebBotAuthKey[] {
  return readKeyDirectory(json).keys;
}

/** Validate + normalize one directory JWK; a string is the reason it is unusable. */
function parseDirectoryKey(entry: unknown): WebBotAuthKey | string {
  if (typeof entry !== 'object' || entry === null) return 'not a JSON object';
  const jwk = entry as Record<string, unknown>;

  let key: WebBotAuthKey;
  const alg = jwk.alg !== undefined ? String(jwk.alg).toLowerCase() : undefined;
  if (jwk.kty === 'OKP') {
    if (jwk.crv !== 'Ed25519') {
      return `OKP curve ${JSON.stringify(jwk.crv)} is not supported (Ed25519 only)`;
    }
    if (typeof jwk.x !== 'string' || !B64URL_32_BYTES.test(jwk.x)) {
      return '"x" is not 43 base64url chars';
    }
    // "ed25519" is the HTTP Signature Algorithms registry name; "EdDSA" is the
    // JOSE (RFC 8037) name. Both unambiguously mean Ed25519 on an OKP key.
    // Anything else contradicts the key's own type, so the entry is unusable.
    if (alg !== undefined && !['ed25519', 'eddsa'].includes(alg)) {
      return `"alg" is ${JSON.stringify(jwk.alg)} on an OKP/Ed25519 key (mismatched alg)`;
    }
    key = { thumbprint: ed25519JwkThumbprint(jwk.x), crv: 'Ed25519', x: jwk.x };
  } else if (jwk.kty === 'EC') {
    if (jwk.crv !== 'P-256') {
      return `EC curve ${JSON.stringify(jwk.crv)} is not supported (P-256 only)`;
    }
    if (
      typeof jwk.x !== 'string' || !B64URL_32_BYTES.test(jwk.x)
      || typeof jwk.y !== 'string' || !B64URL_32_BYTES.test(jwk.y)
    ) {
      return '"x" and "y" must each be 43 base64url chars';
    }
    // RFC 7517 §4.4 spelling for ECDSA P-256/SHA-256 (per the editor's copy,
    // WG PR #139). Any other value contradicts the key's own type.
    if (alg !== undefined && alg !== 'es256') {
      return `"alg" is ${JSON.stringify(jwk.alg)} on an EC/P-256 key (mismatched alg; ES256 is its algorithm)`;
    }
    key = { thumbprint: ecP256JwkThumbprint(jwk.x, jwk.y), crv: 'P-256', x: jwk.x, y: jwk.y };
  } else if (jwk.kty === 'RSA') {
    // Deliberate, not an accident: say so, so an RSA directory operator reads
    // a decision rather than a parser gap.
    return 'RSA keys are not supported by this verifier (a stated non-goal; it verifies ed25519 and ecdsa-p256-sha256)';
  } else {
    return `key type ${JSON.stringify(jwk.kty)} is not supported (OKP/Ed25519 or EC/P-256)`;
  }

  if (jwk.use !== undefined && jwk.use !== 'sig') return `"use" is ${JSON.stringify(jwk.use)}, not "sig"`;
  // The advertised label rides along verbatim; only a string can select.
  if (typeof jwk.kid === 'string') key.kid = jwk.kid;
  if (typeof jwk.nbf === 'number' && Number.isFinite(jwk.nbf)) key.nbf = jwk.nbf;
  if (typeof jwk.exp === 'number' && Number.isFinite(jwk.exp)) key.exp = jwk.exp;
  return key;
}
