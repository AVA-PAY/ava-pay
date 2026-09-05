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
  verifyDirectoryProofs,
  WEB_BOT_AUTH_TAG,
  WebBotAuthParseError,
  type KeyProofStatus,
  type WebBotAuthKey,
} from '@ava-pay/agent/protocol/web-bot-auth';
import { InMemoryReplayGuard, type ReplayGuard } from './replay.js';

/**
 * WebBotAuthVerifier — verifies IETF Web Bot Auth signed agent traffic
 * (draft-ietf-webbotauth-httpsig-protocol-00, adopted 2026-09-01 and
 * content-identical to draft-meunier-webbotauth-httpsig-protocol-02), the
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

/** A directory key plus its Appendix B proof-of-possession status. */
export interface ResolvedDirectoryKey extends WebBotAuthKey {
  proof: KeyProofStatus;
}

export type KeyDirectoryResolution =
  | { status: 'ok'; keys: ResolvedDirectoryKey[] }
  | { status: 'not_allowed' }
  /**
   * The directory URL answered with a redirect. Separate from `unavailable`
   * because -02 Section 5.5 makes it a configuration fault the operator can
   * fix, not an outage, and the merchant-facing reason says so.
   */
  | { status: 'redirected'; detail?: string }
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
  /**
   * Signature-Agent origins that MUST serve Appendix B directory
   * proof-of-possession (the per-source grace flag is OFF for these). Default:
   * none, so grace is ON everywhere and a key that offers no proof is tolerated.
   * As of 2026-08-09 no live directory serves proofs, so an ON-by-default hard
   * fail would reject all real traffic. A key whose proof is present but
   * INVALID is dropped regardless, at every grace setting.
   */
  proofRequiredOrigins?: string[];
  /** Override "now" (seconds) for deterministic tests. */
  now?: () => number;
}

const DEFAULT_SKEW = 30;
const DEFAULT_TTL_SECONDS = 60;
const DEFAULT_MAX_AGE_SECONDS = 300;
/** Clock skew tolerated on Appendix B proof created/expires, evaluated at fetch. */
const PROOF_SKEW_SECONDS = 300;
/** keyid must be a base64url SHA-256 JWK thumbprint — always 43 chars. */
const THUMBPRINT_SHAPE = /^[A-Za-z0-9_-]{43}$/;

export class WebBotAuthVerifier implements AgentVerifier {
  private readonly resolver: SignatureAgentKeyResolver;
  private readonly skew: number;
  private readonly maxAge: number;
  private readonly replayGuard: ReplayGuard;
  private readonly requireContentDigest: boolean;
  private readonly proofRequired: Set<string>;
  private readonly now: () => number;

  constructor(opts: WebBotAuthVerifierOptions) {
    this.resolver = opts.resolver;
    this.skew = opts.clockSkewSeconds ?? DEFAULT_SKEW;
    this.maxAge = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
    this.proofRequired = new Set((opts.proofRequiredOrigins ?? []).map(normalizeOrigin));
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    // The internally-created guard must share the verifier's clock: with an
    // injected test clock but a wall-clock guard, stored nonce expiries (in
    // the frozen past) clamp to "now" and lapse one real second later —
    // replays were intermittently accepted on slow CI runners.
    this.replayGuard = opts.replayGuard ?? new InMemoryReplayGuard({ now: this.now });
    this.requireContentDigest = opts.requireContentDigest ?? false;
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
      // -02 Section 5.2.1: a signed request MUST carry Signature-Agent. We do
      // not fall back to resolving the bare keyid against every directory we
      // know: that is the (URL, key) confusion Section 5.4 forbids. Conclusive,
      // because nothing about this request is in doubt.
      return fail(
        'missing_signature_agent',
        'Web Bot Auth requires a Signature-Agent header (draft -02 Section 5.2.1); none was sent.',
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
    // -02 Section 5.2.1 requires the Signature-Agent member to be covered. Two
    // shapes reach us:
    //   keyed     ("signature-agent";key="agent2") the -02 form. We resolve THE
    //             MEMBER THE SIGNATURE COVERS, which is the invariant that
    //             matters: Section 5.2.2 forbids attributing a signature to a
    //             member it does not cover. We deliberately do NOT additionally
    //             require key == signature label. Section 5.2.1 says "the
    //             member keyed to the signature label", but the draft's own
    //             Appendix E.1.1 / E.2.1 vectors label the signature sig2 and
    //             key the member agent2, and -02 deleted the -01 sentence that
    //             made matching a RECOMMENDED. Enforcing it would reject the
    //             working group's published vectors while adding no security
    //             over resolving the covered member. Raised for the IETF reply.
    //   unkeyed   the deployed form (chatgpt.com sends the bare sf-string
    //             header with an unkeyed component). Covering the field covers
    //             every member, so the label-matched member is still what the
    //             signer committed to, and Section 5.2.1 explicitly lets a
    //             verifier accept the legacy form.
    const sigAgentComponent = parsedInput.componentIds.find((c) => c.name === 'signature-agent');
    if (!sigAgentComponent) {
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
    // Binding strength (D3) is declarative: it reflects the Signature-Agent
    // discovery type the agent asserted, which is what a merchant prices. A
    // `directory` type binds the key to the origin; jwks_uri/cimd do not.
    let binding: 'domain' | 'url-only';
    try {
      // Keyed: resolve exactly the covered member, strictly (no fallback to
      // another member, which would be the attribution the spec forbids).
      // Unkeyed: the whole field is covered, so the label-matched member with
      // the legacy fallback is sound.
      const parsedAgent =
        sigAgentComponent.key !== undefined
          ? parseSignatureAgent(sigAgentHeader, sigAgentComponent.key, { strict: true })
          : parseSignatureAgent(sigAgentHeader, parsedInput.label);
      origin = parsedAgent.origin;
      binding = parsedAgent.type === 'directory' ? 'domain' : 'url-only';
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
    if (resolution.status === 'redirected') {
      // Could-not-check, so inconclusive and fail closed, exactly like an
      // outage. Kept as its own reason because the operator fix differs and
      // reporting "unreachable" for a directory that answered would be untrue.
      return fail(
        'key_directory_redirected',
        `Key directory for "${origin}" answered with a redirect; draft -02 Section 5.5 requires 200 (OK) and forbids following it.`,
        false,
      );
    }
    if (resolution.status === 'unavailable') {
      // Fail closed: no key material, no trust. Could-not-check, so inconclusive.
      // Reason kept as key_directory_unavailable for backward compatibility; it
      // unifies with directory_unavailable in the v1.0 contract revision.
      return fail(
        'key_directory_unavailable',
        `Key directory for "${origin}" could not be fetched or parsed.`,
        false,
      );
    }

    const key = resolution.keys.find((k) => k.thumbprint === keyid);
    if (!key) {
      return fail(
        'unknown_key',
        `keyid "${keyid}" is not published in ${origin}${KEY_DIRECTORY_PATH}.`,
      );
    }
    // Appendix B proof-of-possession gate (D2). A proof that was offered and
    // FAILED is never tolerated: the directory entry is untrustworthy, so this
    // runs before the entry's own nbf/exp are believed. A proof that is ABSENT
    // is tolerated unless this source has the grace flag off. Both are
    // definitive per-key determinations, so the fail() results are conclusive.
    if (key.proof === 'invalid') {
      return fail(
        'key_proof_invalid',
        `Directory proof-of-possession for key "${keyid}" was offered but failed verification.`,
      );
    }
    if (key.proof === 'absent' && this.proofRequired.has(origin)) {
      return fail(
        'unsigned_key',
        `Directory for "${origin}" served no proof-of-possession for key "${keyid}", and this source requires one.`,
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
      conclusive: true,
      protocol: 'web-bot-auth',
      agent: { id: origin, protocol: 'web-bot-auth', keyThumbprint: keyid, binding },
      ttlSeconds: DEFAULT_TTL_SECONDS,
    };
  }
}

function fail(
  reason: VerificationFailureReason,
  message: string,
  conclusive = true,
): VerificationResult {
  return { trusted: false, reason, message, conclusive };
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
    // A static key list carries no wire response, hence no proof-of-possession:
    // proof is honestly 'absent' (tolerated under grace, dropped without it).
    return { status: 'ok', keys: keys.map((k) => ({ ...k, proof: 'absent' as const })) };
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
 * Fetch discipline: the response MUST be 200 (OK) and redirects are never
 * followed, both required by -02 Section 5.5; https only; 5s timeout; 64 KiB
 * response cap; and only allowlisted origins are ever contacted (the SSRF
 * guard). Success and failure are both cached (10 min / 30 s) so a flood of
 * requests cannot turn us into a fetch cannon.
 *
 * A 3xx resolves to `redirected` rather than `unavailable` so the verifier can
 * tell a merchant which of the two happened: a directory that is up and
 * misconfigured is an operator fix, an unreachable one is an outage.
 *
 * Directory responses are trusted on the strength of TLS to an allowlisted
 * origin, plus Appendix B proof-of-possession when the directory serves it:
 * each key is classified valid/invalid/absent (verifyDirectoryProofs) and the
 * verifier applies the per-source grace flag. No live directory publishes
 * proofs today (checked chatgpt.com and www.shopify.com 2026-08-09), so grace
 * defaults on and absent proofs are tolerated until a source ships them.
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
    const url = `${origin}${KEY_DIRECTORY_PATH}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      // `manual` so a 3xx is observed and refused rather than followed by the
      // fetch implementation. -02 Section 5.5: discovery MUST be served with
      // 200 (OK), and a verifier MUST NOT automatically follow redirects.
      const res = await this.fetchImpl(url, {
        redirect: 'manual',
        signal: controller.signal,
        headers: { accept: 'application/http-message-signatures-directory+json, application/json' },
      });
      if (res.status >= 300 && res.status < 400) {
        // Until -02 we followed up to three https, allowlisted hops, because
        // shopify.com's apex 301 to www was the deployed reality (built
        // 2026-08-11). -02 makes that non-conformant, so the tolerance is
        // gone and accept-deployed-reality yields to a published MUST that we
        // reported the issue for. CONSEQUENCE: the shopify.com APEX directory
        // no longer resolves for identity purposes. Their www host serves the
        // directory directly and is unaffected.
        return { status: 'redirected', detail: `HTTP ${res.status}` };
      }
      if (res.status !== 200) {
        // Exactly 200, not any 2xx: a 204 carries no key set to parse.
        return { status: 'unavailable', detail: `HTTP ${res.status}` };
      }
      const body = await readBounded(res, this.maxBytes);
      const keys = parseKeyDirectory(JSON.parse(body));
      // Appendix B: classify each key by its response proof-of-possession.
      // The request authority is the host we actually fetched (post-redirect),
      // which is what the directory operator signs over (@authority;req).
      const proofByThumbprint = verifyDirectoryProofs({
        authority: new URL(url).host,
        body,
        signatureInput: res.headers.get('signature-input') ?? undefined,
        signature: res.headers.get('signature') ?? undefined,
        now: Math.floor(this.nowMs() / 1000),
        skewSeconds: PROOF_SKEW_SECONDS,
        keys,
      });
      const resolved: ResolvedDirectoryKey[] = keys.map((k) => ({
        ...k,
        proof: proofByThumbprint.get(k.thumbprint) ?? 'absent',
      }));
      return { status: 'ok', keys: resolved };
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

export async function readBounded(res: Response, maxBytes: number): Promise<string> {
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
