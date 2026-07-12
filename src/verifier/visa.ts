import type { AgentVerifier } from './interface.js';
import type {
  BuyerInfo,
  IncomingRequest,
  VerificationFailureReason,
  VerificationResult,
} from '../types.js';
import type { AgentDirectory } from './agent-directory.js';
import {
  buildSignatureBase,
  computeContentDigest,
  parseSignature,
  parseSignatureInput,
  SignatureParseError,
  verifyEd25519,
} from './http-signatures.js';
import { decodeMandate, isMerchantAllowed, MandateParseError, safeHost } from './mandate.js';
import { InMemoryReplayGuard, type ReplayGuard } from './replay.js';

/**
 * VisaAgentVerifier — real Trusted Agent Protocol verification.
 *
 * Drop-in replacement for MockAgentVerifier. Implements the same
 * AgentVerifier interface, so server.ts and the route are unchanged.
 *
 * Pipeline:
 *   1. Parse Signature-Input + Signature headers (RFC 9421).
 *   2. Reject unsupported algorithms (we only accept ed25519).
 *   3. Enforce signature window (created/expires + clock skew).
 *   4. Validate Content-Digest matches the request body, if a body exists.
 *   5. Resolve the agent in the AgentDirectory (cached). 404 → unknown_agent;
 *      revoked flag → revoked_agent.
 *   6. Build the signature base from covered components and verify Ed25519
 *      against the directory's public key.
 *   7. Decode and validate the mandate (expiry, merchant scope).
 *   8. Compose VerificationResult with buyerInfo derived from the mandate.
 *
 * Every failure mode returns a typed `trusted: false` result with one of the
 * VerificationFailureReason codes — never throws. The route's <50ms budget is
 * preserved because all heavy lifting is in-process; the only I/O is the
 * directory lookup, which the cache eliminates after first hit.
 */

export interface VisaAgentVerifierOptions {
  directory: AgentDirectory;
  /** Tolerated clock skew on signature.created / signature.expires, in seconds. */
  clockSkewSeconds?: number;
  /** Require a covered + matching content-digest when the request has a body. */
  requireContentDigest?: boolean;
  /**
   * Hard server-side cap on signature lifetime, in seconds. Applied from
   * `created` regardless of what `expires` the signer volunteered (or omitted).
   */
  maxAgeSeconds?: number;
  /**
   * Replay guard shared across verifiers. Defaults to a per-verifier
   * in-memory guard; production should inject one shared instance.
   */
  replayGuard?: ReplayGuard;
  /** Override "now" (seconds) for deterministic tests. */
  now?: () => number;
}

const DEFAULT_SKEW = 30;
const DEFAULT_TTL_SECONDS = 60;
const DEFAULT_MAX_AGE_SECONDS = 300;

export class VisaAgentVerifier implements AgentVerifier {
  private readonly directory: AgentDirectory;
  private readonly skew: number;
  private readonly requireContentDigest: boolean;
  private readonly maxAge: number;
  private readonly replayGuard: ReplayGuard;
  private readonly now: () => number;

  constructor(opts: VisaAgentVerifierOptions) {
    this.directory = opts.directory;
    this.skew = opts.clockSkewSeconds ?? DEFAULT_SKEW;
    this.requireContentDigest = opts.requireContentDigest ?? true;
    this.maxAge = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
    this.replayGuard = opts.replayGuard ?? new InMemoryReplayGuard();
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async verify(request: IncomingRequest): Promise<VerificationResult> {
    const sigInput = request.headers['signature-input'];
    const sig = request.headers['signature'];
    const mandateRaw = request.headers['x-ava-mandate'];

    if (!sigInput || !sig || !mandateRaw) {
      return fail(
        'missing_agent_credentials',
        'Required headers Signature, Signature-Input, x-ava-mandate are missing.',
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

    // ── 2. Algorithm gate ─────────────────────────────────────────────────
    // `alg` is mandatory: an omitted alg must not silently bypass the gate.
    if (parsedInput.parameters.alg === undefined) {
      return fail(
        'unsupported_algorithm',
        'Signature-Input must declare alg="ed25519" explicitly.',
      );
    }
    if (parsedInput.parameters.alg !== 'ed25519') {
      return fail(
        'unsupported_algorithm',
        `Algorithm "${parsedInput.parameters.alg}" is not supported (require ed25519).`,
      );
    }

    // ── 3. Time window ────────────────────────────────────────────────────
    // `created` is mandatory, and the effective lifetime is capped server-side
    // at maxAge regardless of the `expires` the signer volunteered (or omitted)
    // — a hostile signer must not get an unbounded-lifetime signature.
    const now = this.now();
    const { created, expires, nonce } = parsedInput.parameters;
    if (created === undefined) {
      return fail(
        'malformed_signature_header',
        'Signature-Input must include a created parameter.',
      );
    }
    if (created > now + this.skew) {
      return fail('signature_expired', `Signature created in the future (created=${created}, now=${now}).`);
    }
    const effectiveExpires = Math.min(expires ?? created + this.maxAge, created + this.maxAge);
    if (effectiveExpires + this.skew < now) {
      return fail(
        'signature_expired',
        `Signature expired at ${effectiveExpires} (now=${now}, max age ${this.maxAge}s).`,
      );
    }
    if (nonce === undefined || nonce === '') {
      return fail(
        'malformed_signature_header',
        'Signature-Input must include a nonce parameter for replay protection.',
      );
    }

    const agentId = parsedInput.parameters.keyid;
    if (!agentId) {
      return fail('missing_agent_credentials', 'Signature-Input missing keyid parameter.');
    }

    // ── 4. Content-Digest check ───────────────────────────────────────────
    if (this.requireContentDigest && request.body !== undefined && request.body !== '') {
      const digestHeader = request.headers['content-digest'];
      if (!digestHeader) {
        return fail(
          'content_digest_mismatch',
          'Request has a body but no Content-Digest header.',
        );
      }
      if (!parsedInput.components.includes('content-digest')) {
        return fail(
          'content_digest_mismatch',
          'Content-Digest must appear in the signature cover set when a body is present.',
        );
      }
      const expected = computeContentDigest(request.body);
      if (digestHeader.trim() !== expected) {
        return fail(
          'content_digest_mismatch',
          'Content-Digest does not match the body.',
        );
      }
    }

    // ── 5. Directory lookup ───────────────────────────────────────────────
    let record;
    try {
      record = await this.directory.resolve(agentId);
    } catch {
      // Directory unreachable. Fail closed with unknown_agent — operationally
      // the merchant treats this the same as "not in directory".
      return fail('unknown_agent', `Agent directory lookup for "${agentId}" failed.`);
    }
    if (!record) {
      return fail('unknown_agent', `Agent "${agentId}" is not in the directory.`);
    }
    if (record.revoked) {
      return fail('revoked_agent', `Agent "${agentId}" is revoked.`);
    }

    // ── 6. Verify the signature ───────────────────────────────────────────
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
      signatureOk = verifyEd25519(record.publicKey, signatureBase, signature);
    } catch {
      signatureOk = false;
    }
    if (!signatureOk) {
      return fail('invalid_signature', 'Ed25519 verification failed against directory key.');
    }

    // ── 6b. Replay check ──────────────────────────────────────────────────
    // Runs only after the signature verifies, so unauthenticated junk can't
    // flood the nonce store or burn a legitimate nonce it merely observed.
    const fresh = await this.replayGuard.checkAndStore(
      `visa:${agentId}:${nonce}`,
      effectiveExpires + this.skew,
    );
    if (!fresh) {
      return fail(
        'replay_detected',
        `Nonce has already been used by agent "${agentId}" within the signature window.`,
      );
    }

    // ── 7. Mandate ────────────────────────────────────────────────────────
    let mandate;
    try {
      mandate = decodeMandate(mandateRaw);
    } catch (err) {
      return fail(
        'malformed_mandate',
        err instanceof MandateParseError ? err.message : 'Mandate could not be parsed.',
      );
    }

    if (mandate.exp <= now) {
      return fail('mandate_expired', `Mandate ${mandate.id} expired at ${mandate.exp} (now=${now}).`);
    }

    const merchantHost = safeHost(request.url);
    if (!isMerchantAllowed(mandate, merchantHost)) {
      return fail(
        'mandate_merchant_mismatch',
        `Mandate ${mandate.id} does not authorize purchases on ${merchantHost ?? '(unknown host)'}.`,
      );
    }

    // ── 8. Compose result ─────────────────────────────────────────────────
    const buyerInfo: BuyerInfo = mandate.buyer ?? { buyerId: `buyer_for_${mandate.id}` };

    // Discount handling: Visa TAP doesn't standardize merchant-funded
    // discounts. Agents may include an advisory `x-ava-discount-hint` header
    // (covered by the signature), but the merchant policy in the Shopify
    // plugin is what actually decides + caps it.
    const discountHint = parseDiscountHint(request.headers['x-ava-discount-hint']);

    return {
      trusted: true,
      buyerInfo,
      mandate,
      ...(discountHint !== undefined ? { discount: discountHint } : {}),
      ttlSeconds: DEFAULT_TTL_SECONDS,
    };
  }
}

function fail(reason: VerificationFailureReason, message: string): VerificationResult {
  return { trusted: false, reason, message };
}

function parseDiscountHint(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > 1) return undefined;
  return n;
}
