import { createHash } from 'node:crypto';
import type { AgentVerifier } from './interface.js';
import type { IncomingRequest, VerificationFailureReason, VerificationResult } from '../types.js';
import {
  buildSignatureBase,
  computeContentDigest,
  parseSignature,
  parseSignatureInput,
  SignatureParseError,
  verifyEd25519,
} from './http-signatures.js';
import {
  KEY_DIRECTORY_PATH,
  parseKeyDirectory,
  parseSignatureAgent,
  WEB_BOT_AUTH_TAG,
  WebBotAuthParseError,
  type WebBotAuthKey,
} from '@ava-pay/agent/protocol/web-bot-auth';
import { InMemoryReplayGuard, type ReplayGuard } from './replay.js';

/**
 * WebBotAuthVerifier — verifies IETF Web Bot Auth signed agent traffic
 * (draft-meunier-webbotauth-httpsig-protocol / -httpsig-directory), the
 * scheme real ChatGPT / Claude / Perplexity crawler+agent requests use.
 *
 * Identity, not payment authority: a passing request proves "this really is
 * the agent operated by {Signature-Agent origin}" — nothing about a buyer or
 * a spend mandate. The result therefore carries `agent` but no mandate.
 *
 * Pipeline:
 *   1. Parse Signature-Input / Signature (RFC 9421) + require tag="web-bot-auth".
 *   2. Algorithm gate: the key resolved from the directory pins Ed25519; an
 *      explicit alg param, if present, must agree. (Unlike Visa TAP we do not
 *      require the alg param — deployed agents may omit it and the spec keys
 *      the algorithm off the directory JWK, so there is no confusion window.)
 *   3. Enforce created/expires window with skew + server-side max-age cap.
 *   4. Signature-Agent header: required (it is our key-discovery root), must
 *      be covered by the signature (else an attacker could re-attribute a
 *      captured signature), must parse to an https origin.
 *   5. Covered components must include @authority or @target-uri (binds the
 *      signature to this merchant; spec MUST).
 *   6. Resolve the origin's key directory (allowlist → fetch → JWKS), find
 *      the key whose RFC 7638 thumbprint equals keyid, check its nbf/exp.
 *   7. Verify Ed25519 over the signature base.
 *   8. Replay check (post-signature): keyed on the nonce when present, else
 *      on a digest of the signature bytes — a replayed capture is
 *      byte-identical because every parameter is inside the signed base.
 *
 * Every failure is a typed `trusted:false` reason; the verifier never throws.
 * Fail closed: unreachable directory → key_directory_unavailable, origin not
 * in the trust set → unknown_signature_agent, unknown/expired key → unknown_key.
 */

export type KeyDirectoryResolution =
  | { status: 'ok'; keys: WebBotAuthKey[] }
  | { status: 'not_allowed' }
  | { status: 'unavailable'; detail?: string };

/** Resolves a Signature-Agent origin to its published signing keys. */
export interface SignatureAgentKeyResolver {
  resolve(origin: string): Promise<KeyDirectoryResolution>;
}

export interface WebBotAuthVerifierOptions {
  resolver: SignatureAgentKeyResolver;
  /** Tolerated clock skew on created/expires and key nbf/exp, in seconds. */
  clockSkewSeconds?: number;
  /** Hard server-side cap on signature lifetime from `created`, in seconds. */
  maxAgeSeconds?: number;
  /** Replay guard shared across verifiers (server.ts injects one instance). */
  replayGuard?: ReplayGuard;
  /**
   * When the request has a body, require a covered + matching Content-Digest.
   * Default FALSE — deployed Web Bot Auth agents sign only the request
   * envelope (@authority/@method/@path/signature-agent), so requiring a signed
   * body would reject all real traffic. A Content-Digest that IS present or
   * covered is always validated strictly. This protocol authenticates the
   * agent, not the body; merchants needing signed carts use Visa TAP / AP2.
   */
  requireContentDigest?: boolean;
  /** Override "now" (seconds) for deterministic tests. */
  now?: () => number;
}

const DEFAULT_SKEW = 30;
const DEFAULT_TTL_SECONDS = 60;
const DEFAULT_MAX_AGE_SECONDS = 300;
/** keyid must be a base64url SHA-256 JWK thumbprint — always 43 chars. */
const THUMBPRINT_SHAPE = /^[A-Za-z0-9_-]{43}$/;

export class WebBotAuthVerifier implements AgentVerifier {
  private readonly resolver: SignatureAgentKeyResolver;
  private readonly skew: number;
  private readonly maxAge: number;
  private readonly replayGuard: ReplayGuard;
  private readonly requireContentDigest: boolean;
  private readonly now: () => number;

  constructor(opts: WebBotAuthVerifierOptions) {
    this.resolver = opts.resolver;
    this.skew = opts.clockSkewSeconds ?? DEFAULT_SKEW;
    this.maxAge = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
    this.replayGuard = opts.replayGuard ?? new InMemoryReplayGuard();
    this.requireContentDigest = opts.requireContentDigest ?? false;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async verify(request: IncomingRequest): Promise<VerificationResult> {
    const sigInput = request.headers['signature-input'];
    const sig = request.headers['signature'];
    const sigAgentHeader = request.headers['signature-agent'];

    if (!sigInput || !sig) {
      return fail(
        'missing_agent_credentials',
        'Web Bot Auth requires Signature and Signature-Input headers.',
      );
    }
    if (!sigAgentHeader) {
      return fail(
        'missing_agent_credentials',
        'Web Bot Auth requires a Signature-Agent header for key discovery.',
      );
    }

    // ── 1. Parse signature headers ────────────────────────────────────────
    let parsedInput;
    let signature: Buffer;
    try {
      parsedInput = parseSignatureInput(sigInput);
      signature = parseSignature(sig, parsedInput.label);
    } catch (err) {
      return fail(
        'malformed_signature_header',
        err instanceof SignatureParseError ? err.message : 'Could not parse signature headers.',
      );
    }

    const { created, expires, nonce, keyid, alg, tag } = parsedInput.parameters;

    if (tag !== WEB_BOT_AUTH_TAG) {
      return fail(
        'malformed_signature_header',
        `Signature-Input must carry tag="${WEB_BOT_AUTH_TAG}" (got ${tag === undefined ? 'none' : `"${tag}"`}).`,
      );
    }

    // ── 2. Algorithm gate ─────────────────────────────────────────────────
    // The directory key pins the algorithm (OKP/Ed25519 only survives
    // parseKeyDirectory), so an omitted alg param cannot cause confusion; an
    // explicit one must not contradict it.
    if (alg !== undefined && alg !== 'ed25519') {
      return fail(
        'unsupported_algorithm',
        `Algorithm "${alg}" is not supported (require ed25519).`,
      );
    }

    // ── 3. Time window ────────────────────────────────────────────────────
    const now = this.now();
    if (created === undefined || expires === undefined) {
      return fail(
        'malformed_signature_header',
        'Signature-Input must include created and expires parameters.',
      );
    }
    if (created > now + this.skew) {
      return fail('signature_expired', `Signature created in the future (created=${created}, now=${now}).`);
    }
    const effectiveExpires = Math.min(expires, created + this.maxAge);
    if (effectiveExpires + this.skew < now) {
      return fail(
        'signature_expired',
        `Signature expired at ${effectiveExpires} (now=${now}, max age ${this.maxAge}s).`,
      );
    }

    if (keyid === undefined || !THUMBPRINT_SHAPE.test(keyid)) {
      return fail(
        'malformed_signature_header',
        'Signature-Input keyid must be a base64url JWK SHA-256 thumbprint.',
      );
    }

    // ── 4/5. Covered-component requirements ───────────────────────────────
    if (!parsedInput.components.includes('signature-agent')) {
      return fail(
        'malformed_signature_header',
        'signature-agent must be a covered component when the header is sent.',
      );
    }
    if (
      !parsedInput.components.includes('@authority') &&
      !parsedInput.components.includes('@target-uri')
    ) {
      return fail(
        'malformed_signature_header',
        'Covered components must include @authority or @target-uri.',
      );
    }

    let origin: string;
    try {
      origin = parseSignatureAgent(sigAgentHeader, parsedInput.label).origin;
    } catch (err) {
      return fail(
        'malformed_signature_header',
        err instanceof WebBotAuthParseError ? err.message : 'Could not parse Signature-Agent.',
      );
    }

    // ── Content-Digest (cheap, before any directory I/O) ─────────────────
    const hasBody = request.body !== undefined && request.body !== '';
    const digestHeader = request.headers['content-digest'];
    const digestCovered = parsedInput.components.includes('content-digest');
    if (hasBody && this.requireContentDigest && (!digestHeader || !digestCovered)) {
      return fail(
        'content_digest_mismatch',
        'Request has a body but no covered Content-Digest header.',
      );
    }
    if (hasBody && digestHeader !== undefined && digestHeader.trim() !== computeContentDigest(request.body)) {
      return fail('content_digest_mismatch', 'Content-Digest does not match the body.');
    }

    // ── 6. Key directory resolution ───────────────────────────────────────
    let resolution: KeyDirectoryResolution;
    try {
      resolution = await this.resolver.resolve(origin);
    } catch {
      resolution = { status: 'unavailable' };
    }
    if (resolution.status === 'not_allowed') {
      return fail(
        'unknown_signature_agent',
        `Signature agent "${origin}" is not in this merchant's trust set.`,
      );
    }
    if (resolution.status === 'unavailable') {
      // Fail closed: no key material, no trust.
      return fail(
        'key_directory_unavailable',
        `Key directory for "${origin}" could not be fetched or parsed.`,
      );
    }

    const key = resolution.keys.find((k) => k.thumbprint === keyid);
    if (!key) {
      return fail(
        'unknown_key',
        `keyid "${keyid}" is not published in ${origin}${KEY_DIRECTORY_PATH}.`,
      );
    }
    if (key.nbf !== undefined && key.nbf > now + this.skew) {
      return fail('unknown_key', `Key "${keyid}" is not yet valid (nbf=${key.nbf}).`);
    }
    if (key.exp !== undefined && key.exp + this.skew < now) {
      return fail('unknown_key', `Key "${keyid}" expired at ${key.exp}.`);
    }

    // ── 7. Verify the signature ───────────────────────────────────────────
    let signatureBase: string;
    try {
      signatureBase = buildSignatureBase(parsedInput, {
        method: request.method,
        url: request.url,
        headers: request.headers,
        ...(request.body !== undefined ? { body: request.body } : {}),
      });
    } catch (err) {
      return fail(
        'malformed_signature_header',
        err instanceof SignatureParseError ? err.message : 'Could not build signature base.',
      );
    }

    let signatureOk = false;
    try {
      signatureOk = verifyEd25519({ kty: 'OKP', crv: 'Ed25519', x: key.x }, signatureBase, signature);
    } catch {
      signatureOk = false;
    }
    if (!signatureOk) {
      return fail('invalid_signature', 'Ed25519 verification failed against the directory key.');
    }

    // ── 8. Replay check ───────────────────────────────────────────────────
    // Post-signature so unauthenticated junk can't flood the store. When the
    // agent sent no nonce, the signature bytes are the replay key: every
    // parameter lives inside the signed base, so a replayed capture is
    // byte-identical and anything else fails verification above.
    const replayId = nonce !== undefined && nonce !== ''
      ? `n:${nonce}`
      : `s:${createHash('sha256').update(signature).digest('base64url')}`;
    const fresh = await this.replayGuard.checkAndStore(
      `wba:${origin}:${keyid}:${replayId}`,
      effectiveExpires + this.skew,
    );
    if (!fresh) {
      return fail(
        'replay_detected',
        `Signature from "${origin}" has already been seen within its validity window.`,
      );
    }

    return {
      trusted: true,
      protocol: 'web-bot-auth',
      agent: { id: origin, protocol: 'web-bot-auth', keyThumbprint: keyid },
      ttlSeconds: DEFAULT_TTL_SECONDS,
    };
  }
}

function fail(reason: VerificationFailureReason, message: string): VerificationResult {
  return { trusted: false, reason, message };
}

// ─── Key directory resolvers ────────────────────────────────────────────────

/**
 * Signature-Agent origins we resolve by default. Only origins whose live
 * directory we have verified belong here (checked 2026-07-12: chatgpt.com
 * serves a valid Ed25519 JWKS; claude.ai / perplexity.ai do not publish one
 * yet). Merchants extend the set via WBA_ALLOWED_SIGNATURE_AGENTS.
 */
export const DEFAULT_SIGNATURE_AGENTS = ['https://chatgpt.com'];

/** Static resolver for tests and private allowlists: origin → parsed JWKS. */
export class StaticSignatureAgentKeys implements SignatureAgentKeyResolver {
  private readonly byOrigin = new Map<string, WebBotAuthKey[]>();
  private readonly unavailable = new Set<string>();

  add(origin: string, directoryJson: unknown): void {
    this.byOrigin.set(normalizeOrigin(origin), parseKeyDirectory(directoryJson));
  }

  /** Simulate an unreachable directory for the origin (tests). */
  markUnavailable(origin: string): void {
    this.unavailable.add(normalizeOrigin(origin));
  }

  async resolve(origin: string): Promise<KeyDirectoryResolution> {
    if (this.unavailable.has(origin)) return { status: 'unavailable' };
    const keys = this.byOrigin.get(origin);
    if (!keys) return { status: 'not_allowed' };
    return { status: 'ok', keys };
  }
}

export interface FetchingKeyDirectoryResolverOptions {
  /**
   * Origins we are willing to fetch key material from. Doubles as the SSRF
   * guard: a Signature-Agent outside this set is never dereferenced.
   */
  allowedOrigins: string[];
  /** Directory cache TTL. Default 10 minutes. */
  cacheTtlMs?: number;
  /** How long a fetch failure is remembered before retrying. Default 30s. */
  failureCacheTtlMs?: number;
  /** Per-fetch timeout. Default 5000ms. */
  timeoutMs?: number;
  /** Maximum directory response size. Default 64 KiB. */
  maxResponseBytes?: number;
  /** Injectable fetch for tests. */
  fetchImpl?: typeof fetch;
  /** Override "now" (ms) for deterministic tests. */
  nowMs?: () => number;
}

const TEN_MINUTES_MS = 10 * 60 * 1000;

/**
 * Fetches https://{origin}/.well-known/http-message-signatures-directory,
 * bounded and cached.
 *
 * Fetch discipline (the directory draft leaves these to implementations):
 * https only, redirects are errors, 5s timeout, 64 KiB response cap, and only
 * allowlisted origins are ever contacted. Success and failure are both cached
 * (10 min / 30 s) so a flood of requests cannot turn us into a fetch cannon.
 *
 * Directory responses are trusted on the strength of TLS to an allowlisted
 * origin. The draft's optional per-key response signatures
 * (proof-of-possession) are not validated yet — no live directory publishes
 * them today (checked chatgpt.com 2026-07-12); revisit when they appear.
 */
export class FetchingKeyDirectoryResolver implements SignatureAgentKeyResolver {
  private readonly allowed: Set<string>;
  private readonly cacheTtlMs: number;
  private readonly failureCacheTtlMs: number;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly fetchImpl: typeof fetch;
  private readonly nowMs: () => number;
  private readonly cache = new Map<
    string,
    { until: number; value: KeyDirectoryResolution }
  >();

  constructor(opts: FetchingKeyDirectoryResolverOptions) {
    this.allowed = new Set(opts.allowedOrigins.map(normalizeOrigin));
    this.cacheTtlMs = opts.cacheTtlMs ?? TEN_MINUTES_MS;
    this.failureCacheTtlMs = opts.failureCacheTtlMs ?? 30_000;
    this.timeoutMs = opts.timeoutMs ?? 5_000;
    this.maxBytes = opts.maxResponseBytes ?? 64 * 1024;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.nowMs = opts.nowMs ?? Date.now;
  }

  async resolve(origin: string): Promise<KeyDirectoryResolution> {
    if (!this.allowed.has(origin)) return { status: 'not_allowed' };

    const cached = this.cache.get(origin);
    const now = this.nowMs();
    if (cached && cached.until > now) return cached.value;

    const value = await this.fetchDirectory(origin);
    const ttl = value.status === 'ok' ? this.cacheTtlMs : this.failureCacheTtlMs;
    this.cache.set(origin, { until: now + ttl, value });
    return value;
  }

  private async fetchDirectory(origin: string): Promise<KeyDirectoryResolution> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${origin}${KEY_DIRECTORY_PATH}`, {
        redirect: 'error',
        signal: controller.signal,
        headers: { accept: 'application/http-message-signatures-directory+json, application/json' },
      });
      if (!res.ok) {
        return { status: 'unavailable', detail: `HTTP ${res.status}` };
      }
      const body = await readBounded(res, this.maxBytes);
      const keys = parseKeyDirectory(JSON.parse(body));
      return { status: 'ok', keys };
    } catch (err) {
      return {
        status: 'unavailable',
        detail: err instanceof Error ? err.message : 'fetch failed',
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

async function readBounded(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) {
    const text = await res.text();
    if (Buffer.byteLength(text) > maxBytes) throw new Error('directory response too large');
    return text;
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error('directory response too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf-8');
}

function normalizeOrigin(origin: string): string {
  const url = new URL(origin);
  if (url.protocol !== 'https:') {
    throw new Error(`Signature-Agent origins must be https, got: ${origin}`);
  }
  return url.origin.toLowerCase();
}
