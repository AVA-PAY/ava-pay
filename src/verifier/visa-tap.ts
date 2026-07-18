import type { AgentVerifier } from './interface.js';
import type {
  IncomingRequest,
  TapVerificationDetail,
  VerificationFailureReason,
  VerificationResult,
} from '../types.js';
import type { AgentDirectory } from './agent-directory.js';
import {
  buildSignatureBase,
  parseSignatureInput,
  SignatureParseError,
} from './http-signatures.js';
import {
  buildTapObjectSignatureBase,
  isSupportedTapMessageAlg,
  isTapTag,
  parseIdToken,
  parseTapBodyObjects,
  parseVisaJwks,
  TAP_MAX_WINDOW_SECONDS,
  TAP_PAYER_TAG,
  verifyTapSignature,
  VISA_JWKS_URL,
  VisaTapParseError,
  type TapSignedObject,
  type VisaJwk,
} from '@ava-pay/agent/protocol/visa-tap';
import { InMemoryReplayGuard, type ReplayGuard } from './replay.js';
import { createPublicKey, type KeyObject } from 'node:crypto';

/**
 * VisaTapVerifier — Visa's REAL Trusted Agent Protocol wire format
 * (developer.visa.com spec + github.com/visa/trusted-agent-protocol sample).
 *
 * Distinct from VisaAgentVerifier, which implements AVA's TAP-style profile
 * (x-ava-mandate header). MultiProtocolVerifier disambiguates by the
 * spec-mandated tags: agent-browser-auth / agent-payer-auth.
 *
 * Verified layers, to public-spec depth:
 *   1. RFC 9421 message signature over ("@authority" "@path") — binds agent
 *      identity (keyid → agent directory) and intent (tag) to this merchant
 *      and path. Algorithms: ed25519, rsa-pss-sha256/PS256. The 8-minute
 *      spec maximum for created↔expires is enforced on top of skew.
 *   2. Consumer Recognition Object (body `agenticConsumer`), when present:
 *      required fields, nonce linkage to the message signature, kid linkage
 *      to the message keyid, object signature under the agent key, and the
 *      embedded IdToken — a Visa-signed PS256 JWT verified against Visa's
 *      public JWKS (https://mcp.visa.com/.well-known/jwks) with exp/iat and
 *      typ "JWT+ext.id_token" checks.
 *   3. Agentic Payment Container (body `agenticPaymentContainer`), when
 *      present: required fields, nonce/kid linkage, object signature.
 *      paymentCredentialsHash and merchant-encrypted payloads are surfaced,
 *      not interpreted — hash comparison and decryption are merchant-side by
 *      design.
 *
 * The object-signature base is Visa's one under-specified construct (no
 * public worked example); see buildTapObjectSignatureBase in the SDK for the
 * documented interpretation both our signer and this verifier share.
 *
 * Fail-closed: unknown/revoked keyid, unreachable Visa JWKS while an IdToken
 * needs verification, any malformed or unlinked signed object → typed
 * trusted:false. Never throws. Trusted results are identity + validated
 * context (`tap` detail) — never an AVA mandate; merchant policy decides
 * privileges.
 */

export interface VisaJwksResolver {
  /** Resolve Visa's IdToken signing key by kid. Throwing = unavailable. */
  resolve(kid: string): Promise<VisaJwk | null>;
}

export interface VisaTapVerifierOptions {
  /** Resolves the agent's message-signing key by keyid. */
  directory: AgentDirectory;
  /** Resolves Visa's IdToken signing keys. Required to accept Consumer Recognition Objects. */
  visaJwks?: VisaJwksResolver;
  clockSkewSeconds?: number;
  replayGuard?: ReplayGuard;
  /** Override "now" (seconds) for deterministic tests. */
  now?: () => number;
}

const DEFAULT_SKEW = 30;
const DEFAULT_TTL_SECONDS = 60;

export class VisaTapVerifier implements AgentVerifier {
  private readonly directory: AgentDirectory;
  private readonly visaJwks: VisaJwksResolver | undefined;
  private readonly skew: number;
  private readonly replayGuard: ReplayGuard;
  private readonly now: () => number;

  constructor(opts: VisaTapVerifierOptions) {
    this.directory = opts.directory;
    this.visaJwks = opts.visaJwks;
    this.skew = opts.clockSkewSeconds ?? DEFAULT_SKEW;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    // The internally-created guard must share the verifier's clock: with an
    // injected test clock but a wall-clock guard, stored nonce expiries (in
    // the frozen past) clamp to "now" and lapse one real second later —
    // replays were intermittently accepted on slow CI runners.
    this.replayGuard = opts.replayGuard ?? new InMemoryReplayGuard({ now: this.now });
  }

  async verify(request: IncomingRequest): Promise<VerificationResult> {
    const sigInput = request.headers['signature-input'];
    const sig = request.headers['signature'];
    if (!sigInput || !sig) {
      return fail(
        'missing_agent_credentials',
        'Visa TAP requires Signature and Signature-Input headers.',
      );
    }

    // ── 1. Parse + gates ──────────────────────────────────────────────────
    let parsedInput;
    let signature: Buffer;
    try {
      parsedInput = parseSignatureInput(sigInput);
      signature = parseTapSignatureValue(sig, parsedInput.label);
    } catch (err) {
      return fail(
        'malformed_signature_header',
        err instanceof SignatureParseError ? err.message : 'Could not parse signature headers.',
      );
    }

    const { created, expires, nonce, keyid, alg, tag } = parsedInput.parameters;

    if (!isTapTag(tag)) {
      return fail(
        'malformed_signature_header',
        `Signature-Input tag must be agent-browser-auth or agent-payer-auth (got ${tag ?? 'none'}).`,
      );
    }
    if (alg === undefined) {
      // Spec lists alg among the required Signature-Input fields.
      return fail('malformed_signature_header', 'Signature-Input must declare alg.');
    }
    if (!isSupportedTapMessageAlg(alg)) {
      return fail(
        'unsupported_algorithm',
        `Algorithm "${alg}" is not supported (ed25519 or rsa-pss-sha256/PS256).`,
      );
    }

    const now = this.now();
    if (created === undefined || expires === undefined) {
      return fail(
        'malformed_signature_header',
        'Signature-Input must include created and expires.',
      );
    }
    if (created > now + this.skew) {
      return fail('signature_expired', `Signature created in the future (created=${created}, now=${now}).`);
    }
    // Spec: created/expires "should not be more than 8 minutes apart" — the
    // effective window is capped at 8 minutes from created regardless.
    const effectiveExpires = Math.min(expires, created + TAP_MAX_WINDOW_SECONDS);
    if (effectiveExpires + this.skew < now) {
      return fail(
        'signature_expired',
        `Signature expired at ${effectiveExpires} (now=${now}, max window ${TAP_MAX_WINDOW_SECONDS}s).`,
      );
    }
    if (nonce === undefined || nonce === '') {
      return fail('malformed_signature_header', 'Signature-Input must include a nonce.');
    }
    if (!keyid) {
      return fail('missing_agent_credentials', 'Signature-Input missing keyid/keyId parameter.');
    }
    if (!parsedInput.components.includes('@authority') || !parsedInput.components.includes('@path')) {
      return fail(
        'malformed_signature_header',
        'Covered components must include @authority and @path.',
      );
    }

    // ── 2. Resolve the agent key ──────────────────────────────────────────
    let record;
    try {
      record = await this.directory.resolve(keyid, { protocol: 'visa', alg, kid: keyid });
    } catch {
      return fail('unknown_agent', `Agent key lookup for "${keyid}" failed.`);
    }
    if (!record) {
      return fail('unknown_agent', `Agent key "${keyid}" is not registered.`);
    }
    if (record.revoked) {
      return fail('revoked_agent', `Agent key "${keyid}" is revoked.`);
    }
    const agentKey = toKeyObject(record.publicKey);
    if (!agentKey) {
      return fail('unknown_agent', `Agent key "${keyid}" has unusable key material.`);
    }

    // ── 3. Verify the message signature ───────────────────────────────────
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

    let ok = false;
    try {
      ok = verifyTapSignature(alg, agentKey, Buffer.from(signatureBase, 'utf-8'), signature);
    } catch {
      ok = false;
    }
    if (!ok) {
      return fail('invalid_signature', `${alg} verification failed against the registered key.`);
    }

    // ── 4. Replay (post-signature; spec: matching nonce → block) ─────────
    const fresh = await this.replayGuard.checkAndStore(
      `tap:${keyid}:${nonce}`,
      effectiveExpires + this.skew,
    );
    if (!fresh) {
      return fail(
        'replay_detected',
        `Nonce has already been used by agent key "${keyid}" within the signature window.`,
      );
    }

    // ── 5. Signed body objects ────────────────────────────────────────────
    let bodyObjects;
    try {
      bodyObjects = parseTapBodyObjects(request.body);
    } catch (err) {
      return fail(
        'malformed_recognition_object',
        err instanceof VisaTapParseError ? err.message : 'Request body objects are malformed.',
      );
    }

    const detail: TapVerificationDetail = {
      intent: tag === TAP_PAYER_TAG ? 'payer' : 'browse',
    };

    if (bodyObjects.consumer) {
      const outcome = await this.validateConsumer(bodyObjects.consumer, nonce, keyid, alg, agentKey, now);
      if (!outcome.ok) return outcome.failure;
      detail.consumer = outcome.consumer;
    }

    if (bodyObjects.paymentContainer) {
      const outcome = this.validatePaymentContainer(
        bodyObjects.paymentContainer,
        nonce,
        keyid,
        alg,
        agentKey,
      );
      if (!outcome.ok) return outcome.failure;
      detail.payment = outcome.payment;
    }

    return {
      trusted: true,
      protocol: 'visa-tap',
      agent: { id: keyid, protocol: 'visa-tap' },
      tap: detail,
      ttlSeconds: DEFAULT_TTL_SECONDS,
    };
  }

  private async validateConsumer(
    consumer: TapSignedObject,
    messageNonce: string,
    messageKeyid: string,
    messageAlg: string,
    agentKey: KeyObject,
    now: number,
  ): Promise<
    | { ok: true; consumer: NonNullable<TapVerificationDetail['consumer']> }
    | { ok: false; failure: VerificationResult }
  > {
    // Linkage: the object must be bound to THIS message signature.
    if (consumer.nonce !== messageNonce) {
      return failure('recognition_nonce_mismatch', 'agenticConsumer nonce does not match the message signature nonce.');
    }
    if (consumer.kid !== messageKeyid || normAlg(consumer.alg) !== normAlg(messageAlg)) {
      return failure(
        'malformed_recognition_object',
        'agenticConsumer kid/alg must match the message signature keyid/alg.',
      );
    }

    // Object signature under the agent's key.
    if (!this.verifyObjectSignature(consumer, agentKey)) {
      return failure('recognition_signature_invalid', 'agenticConsumer signature failed under the agent key.');
    }

    // IdToken — required, Visa-signed PS256 JWT against Visa's public JWKS.
    if (typeof consumer.IdToken !== 'string' || consumer.IdToken === '') {
      return failure('malformed_recognition_object', 'agenticConsumer must carry an IdToken (compact JWS).');
    }
    let idToken;
    try {
      idToken = parseIdToken(consumer.IdToken);
    } catch (err) {
      return failure(
        'id_token_invalid',
        err instanceof VisaTapParseError ? err.message : 'IdToken is malformed.',
      );
    }
    if (idToken.header.typ !== undefined && idToken.header.typ !== 'JWT+ext.id_token') {
      return failure('id_token_invalid', `IdToken typ must be "JWT+ext.id_token" (got "${idToken.header.typ}").`);
    }

    if (!this.visaJwks) {
      // Fail closed: we cannot vouch for consumer recognition we cannot verify.
      return failure(
        'key_directory_unavailable',
        'No Visa JWKS resolver configured; cannot verify the IdToken.',
      );
    }
    let visaKey: VisaJwk | null;
    try {
      visaKey = await this.visaJwks.resolve(idToken.header.kid as string);
    } catch {
      return failure('key_directory_unavailable', 'Visa JWKS could not be fetched or parsed.');
    }
    if (!visaKey) {
      return failure('id_token_invalid', `IdToken kid "${idToken.header.kid}" is not in Visa's JWKS.`);
    }
    if (!verifyTapSignature('ps256', visaKey.key, idToken.signingInput, idToken.signature)) {
      return failure('id_token_invalid', 'IdToken PS256 signature failed against the Visa key.');
    }
    const { exp, iat } = idToken.claims;
    if (typeof exp !== 'number' || exp + this.skew < now) {
      return failure('id_token_invalid', `IdToken is expired or carries no exp (exp=${exp ?? 'none'}).`);
    }
    if (typeof iat === 'number' && iat > now + this.skew) {
      return failure('id_token_invalid', `IdToken iat is in the future (iat=${iat}).`);
    }

    const out: NonNullable<TapVerificationDetail['consumer']> = {};
    if (typeof idToken.claims.sub === 'string') out.sub = idToken.claims.sub;
    if (typeof idToken.claims.email_mask === 'string') out.emailMask = idToken.claims.email_mask;
    if (typeof idToken.claims.phone_number_mask === 'string') {
      out.phoneNumberMask = idToken.claims.phone_number_mask;
    }
    return { ok: true, consumer: out };
  }

  private validatePaymentContainer(
    container: TapSignedObject,
    messageNonce: string,
    messageKeyid: string,
    messageAlg: string,
    agentKey: KeyObject,
  ):
    | { ok: true; payment: NonNullable<TapVerificationDetail['payment']> }
    | { ok: false; failure: VerificationResult } {
    if (container.nonce !== messageNonce) {
      return failure(
        'recognition_nonce_mismatch',
        'agenticPaymentContainer nonce does not match the message signature nonce.',
      );
    }
    if (container.kid !== messageKeyid || normAlg(container.alg) !== normAlg(messageAlg)) {
      return failure(
        'malformed_payment_container',
        'agenticPaymentContainer kid/alg must match the message signature keyid/alg.',
      );
    }
    if (!this.verifyObjectSignature(container, agentKey)) {
      return failure(
        'payment_container_signature_invalid',
        'agenticPaymentContainer signature failed under the agent key.',
      );
    }
    return {
      ok: true,
      payment: {
        hasCredentialsHash: container.paymentCredentialsHash !== undefined,
        hasEncryptedPayload: container.encryptedPayload !== undefined,
      },
    };
  }

  private verifyObjectSignature(obj: TapSignedObject, agentKey: KeyObject): boolean {
    try {
      const { signature, ...fields } = obj;
      const base = buildTapObjectSignatureBase(fields);
      // Node's base64 decoder accepts both standard and url-safe alphabets.
      const sigBytes = Buffer.from(signature, 'base64');
      if (sigBytes.length === 0) return false;
      return verifyTapSignature(String(obj.alg), agentKey, Buffer.from(base, 'utf-8'), sigBytes);
    } catch {
      return false;
    }
  }
}

// The TAP signature header is identical to the generic RFC 9421 one except
// that RSA-PSS signatures are 256 bytes, so the shared 64-byte Ed25519 check
// in parseSignature doesn't apply. Minimal local parse with the same shape.
function parseTapSignatureValue(headerValue: string, expectedLabel: string): Buffer {
  const value = headerValue.trim();
  const eq = value.indexOf('=');
  if (eq === -1) throw new SignatureParseError('Signature header missing `label=`');
  const label = value.slice(0, eq).trim();
  if (label !== expectedLabel) {
    throw new SignatureParseError(
      `Signature label "${label}" does not match Signature-Input label "${expectedLabel}"`,
    );
  }
  const rest = value.slice(eq + 1).trim();
  if (!(rest.startsWith(':') && rest.endsWith(':')) || rest.length < 3) {
    throw new SignatureParseError('Signature value must be wrapped in colons (byte sequence)');
  }
  const buf = Buffer.from(rest.slice(1, -1), 'base64');
  if (buf.length === 0) throw new SignatureParseError('Signature value is empty or not base64');
  return buf;
}

function toKeyObject(publicKey: unknown): KeyObject | null {
  try {
    if (typeof publicKey === 'string') return createPublicKey(publicKey);
    if (publicKey && typeof publicKey === 'object') {
      if ('asymmetricKeyType' in (publicKey as KeyObject)) return publicKey as KeyObject;
      return createPublicKey({ key: publicKey as never, format: 'jwk' });
    }
    return null;
  } catch {
    return null;
  }
}

function normAlg(alg: unknown): string {
  return String(alg).toLowerCase();
}

function fail(reason: VerificationFailureReason, message: string): VerificationResult {
  return { trusted: false, reason, message };
}

function failure(
  reason: VerificationFailureReason,
  message: string,
): { ok: false; failure: VerificationResult } {
  return { ok: false, failure: fail(reason, message) };
}

// ─── Visa JWKS resolver ─────────────────────────────────────────────────────

export interface FetchingVisaJwksResolverOptions {
  /** JWKS URL. Default: Visa's public endpoint. Must be https. */
  url?: string;
  /** Cache TTL for a successful fetch. Default 10 minutes. */
  cacheTtlMs?: number;
  /** How long a failure is remembered before retrying. Default 30s. */
  failureCacheTtlMs?: number;
  timeoutMs?: number;
  maxResponseBytes?: number;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
}

const TEN_MINUTES_MS = 10 * 60 * 1000;

/**
 * Fetches Visa's verification JWKS with the same discipline as the Web Bot
 * Auth directory resolver: fixed https URL (no request-derived URLs — the
 * SSRF surface is a single configured endpoint), no redirects, 5s timeout,
 * 64 KiB cap, success/failure caching. Fail closed on anything else.
 */
export class FetchingVisaJwksResolver implements VisaJwksResolver {
  private readonly url: string;
  private readonly cacheTtlMs: number;
  private readonly failureCacheTtlMs: number;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly fetchImpl: typeof fetch;
  private readonly nowMs: () => number;
  private cached: { until: number; keys: VisaJwk[] } | null = null;
  private failedUntil = 0;

  constructor(opts: FetchingVisaJwksResolverOptions = {}) {
    const url = opts.url ?? VISA_JWKS_URL;
    if (!url.startsWith('https://')) {
      throw new Error(`Visa JWKS URL must be https, got: ${url}`);
    }
    this.url = url;
    this.cacheTtlMs = opts.cacheTtlMs ?? TEN_MINUTES_MS;
    this.failureCacheTtlMs = opts.failureCacheTtlMs ?? 30_000;
    this.timeoutMs = opts.timeoutMs ?? 5_000;
    this.maxBytes = opts.maxResponseBytes ?? 64 * 1024;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.nowMs = opts.nowMs ?? Date.now;
  }

  async resolve(kid: string): Promise<VisaJwk | null> {
    const keys = await this.getKeys();
    return keys.find((k) => k.kid === kid) ?? null;
  }

  private async getKeys(): Promise<VisaJwk[]> {
    const now = this.nowMs();
    if (this.cached && this.cached.until > now) return this.cached.keys;
    if (this.failedUntil > now) throw new Error('Visa JWKS fetch recently failed (cached failure)');

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(this.url, {
        redirect: 'error',
        signal: controller.signal,
        headers: { accept: 'application/json' },
      });
      if (!res.ok) throw new Error(`Visa JWKS fetch failed: HTTP ${res.status}`);
      const text = await res.text();
      if (Buffer.byteLength(text) > this.maxBytes) {
        throw new Error('Visa JWKS response too large');
      }
      const keys = parseVisaJwks(JSON.parse(text));
      this.cached = { until: now + this.cacheTtlMs, keys };
      return keys;
    } catch (err) {
      this.failedUntil = now + this.failureCacheTtlMs;
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Static resolver for tests / private deployments. */
export class StaticVisaJwks implements VisaJwksResolver {
  private readonly keys: VisaJwk[];
  private unavailable = false;

  constructor(jwks: unknown) {
    this.keys = parseVisaJwks(jwks);
  }

  markUnavailable(): void {
    this.unavailable = true;
  }

  async resolve(kid: string): Promise<VisaJwk | null> {
    if (this.unavailable) throw new Error('Visa JWKS unavailable (test)');
    return this.keys.find((k) => k.kid === kid) ?? null;
  }
}
