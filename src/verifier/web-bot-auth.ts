import { createHash } from 'node:crypto';
import type { AgentVerifier } from './interface.js';
import type { IncomingRequest, VerificationFailureReason, VerificationResult } from '../types.js';
import { rejection } from '../types.js';
import {
  buildSignatureBase,
  computeContentDigest,
  parseSignature,
  parseSignatureInput,
  SignatureParseError,
  type SignatureParseErrorCode,
} from './http-signatures.js';
import {
  classifyKeyDirectoryMediaType,
  directoryKeyAlgorithm,
  JWK_SET_MEDIA_TYPE,
  KEY_DIRECTORY_MEDIA_TYPE,
  KEY_DIRECTORY_PATH,
  parseKeyDirectory,
  readKeyDirectory,
  parseSignatureAgent,
  signatureAgentIdentifier,
  verifyDirectoryProofs,
  verifyWithDirectoryKey,
  WEB_BOT_AUTH_TAG,
  WebBotAuthParseError,
  type KeyProofStatus,
  type WebBotAuthKeyAlgorithm,
  type WebBotAuthParseErrorCode,
  type WebBotAuthKey,
} from '@ava-pay/agent/protocol/web-bot-auth';
import { InMemoryReplayGuard, type ReplayGuard } from './replay.js';

/**
 * WebBotAuthVerifier — verifies IETF Web Bot Auth signed agent traffic
 * (draft-ietf-webbotauth-httpsig-protocol-01, published 2026-10-29), the
 * scheme real ChatGPT / Google crawler+agent requests use.
 *
 * Identity, not payment authority: a passing request proves "this really is
 * the agent identified by {Signature-Agent URL}", nothing about a buyer or
 * a spend mandate. The result therefore carries `agent` but no mandate.
 *
 * Pipeline:
 *   1. Parse Signature-Input / Signature (RFC 9421) + require tag="web-bot-auth".
 *   2. Algorithm gate: ed25519 and ecdsa-p256-sha256 are the algorithms we
 *      verify (RSA is a stated non-goal for now, and the message says so). The
 *      key resolved from the directory pins the algorithm; an explicit alg
 *      param, if present, must name one we verify and later agree with the
 *      selected key's type. (Unlike Visa TAP we do not require the alg param:
 *      deployed agents may omit it and the spec keys the algorithm off the
 *      directory JWK, so there is no confusion window.)
 *   3. Enforce created/expires window with skew + server-side max-age cap.
 *   4. Signature-Agent header: required (it is our key-discovery root), must
 *      be covered by the signature (else an attacker could re-attribute a
 *      captured signature), must parse to an https JWK Set URL (-01 §5.5; a
 *      bare origin resolves at the well-known path through the legacy
 *      tolerance). The identifier is the normalized URL with the query
 *      dropped, and everything downstream (allowlist, cache, (URL, key)
 *      lookup per §5.4, replay namespace) keys on it.
 *   5. Covered components must include @authority or @target-uri (binds the
 *      signature to this merchant; spec MUST).
 *   6. Resolve the identifier's JWK Set (allowlist → fetch the identifier,
 *      never a caller-chosen query → parse),
 *      find the key whose RFC 7638 thumbprint equals keyid, falling back to
 *      the advertised kid with a warning (the label is a selector, never the
 *      identity), and check its nbf/exp.
 *   7. Verify the signature over the base with the key's own algorithm
 *      (ECDSA per RFC 9421 §3.3.4: raw r||s bytes, never DER).
 *   8. Replay check (post-signature): keyed on the nonce when present, else
 *      on a digest of the signature bytes — a replayed capture is
 *      byte-identical because every parameter is inside the signed base.
 *
 * Every failure is a typed `trusted:false` reason; the verifier never throws.
 * Fail closed: unreachable directory → key_directory_unavailable, identifier
 * not in the trust set → unknown_signature_agent (a policy refusal: no
 * directory is allowlisted, nothing was fetched), keyid absent from the
 * directory → unknown_key (could-not-check: rotation lag and cache staleness
 * look the same from here), a PUBLISHED key outside its own nbf/exp →
 * key_outside_validity_window (conclusive). Each reason's outcome (invalid or
 * could-not-check) comes from REASON_CONCLUSIVE via rejection(), never from
 * the call site.
 *
 * Open resolution of non-allowlisted URLs is a stated non-goal for now: -01
 * Appendix C.1 treats a verifier-maintained list as origin policy, and
 * adopting open resolution needs the §6.7 address filtering and C.3 fetch
 * coalescing first.
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
   * because -01 Section 5.5 makes it a configuration fault the operator can
   * fix, not an outage, and the merchant-facing reason says so.
   */
  | { status: 'redirected'; detail?: string }
  /**
   * The directory answered 200 with a Content-Type that is not a JSON key
   * directory type, so the body was never parsed. Separate from `unavailable`
   * for the same reason as `redirected`: it is up and misconfigured.
   */
  | { status: 'unsupported_media_type'; detail?: string }
  | { status: 'unavailable'; detail?: string };

/**
 * Resolves a Signature-Agent identifier to the signing keys its JWK Set URL
 * publishes.
 *
 * `identifier` is the normalized Signature-Agent identifier (a full https
 * URL, query dropped; -01 §5.5): what parseSignatureAgent().identifier
 * produces, or signatureAgentIdentifier() applied to a configuration entry.
 * Implementations compare it against their trust set VERBATIM. They must
 * never re-apply the configuration-entry rule that expands a "/" path to the
 * well-known URL: the identifier of the member value "https://host/?x" is
 * "https://host/", and expanding it would alias that caller-chosen value
 * onto the host's genuine directory entry, letting one request poison the
 * cache entry every real request shares. Implementations fetch exactly the
 * identifier, never a caller-supplied variant of it (a deliberate deviation
 * from -01 §5.5's fetch-as-sent; see FetchingKeyDirectoryResolver).
 */
export interface SignatureAgentKeyResolver {
  resolve(identifier: string): Promise<KeyDirectoryResolution>;
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
   * Signature-Agent sources that MUST serve Appendix B directory
   * proof-of-possession (the per-source grace flag is OFF for these). Entries
   * are origins (meaning exactly that origin's well-known directory URL) or
   * full https URLs, like the allowlist. The check applies only to
   * domain-bound identifiers: Appendix B validates the DOMAIN binding, which
   * an arbitrary-path JWK Set URL does not claim (-01 Appendix B). Default:
   * none, so grace is ON everywhere and a key that offers no proof is tolerated.
   * chatgpt.com serves proofs (2026-09-25); www.shopify.com did not when last
   * checked (2026-08-09), so an ON-by-default hard fail would reject real
   * traffic. Only a `valid` proof (the full Appendix B shape) satisfies the
   * requirement: a `possession-only` proof (agent.bot.goog's authority-only
   * covered list) is treated like `absent` here. A key whose proof is present
   * but INVALID is dropped regardless, at every grace setting.
   */
  proofRequiredOrigins?: string[];
  /**
   * Receives operator-facing warnings about requests that verified despite a
   * deviation from -01, today only "key selected by advertised kid instead of
   * thumbprint". Default console.warn; server.ts passes the app logger.
   */
  onWarning?: (message: string) => void;
  /** Override "now" (seconds) for deterministic tests. */
  now?: () => number;
}

const DEFAULT_SKEW = 30;
const DEFAULT_TTL_SECONDS = 60;
/**
 * Server-side cap on signature lifetime from `created`, seconds: a stated
 * policy, not an oversight. -01 Section 5.2 RECOMMENDS an `expires` of up to
 * 24 hours; we cap at 300 s whatever the signature says, because a captured
 * request stays replayable anywhere the nonce store does not reach until its
 * effective expiry, and the replay guard holds every seen signature in memory
 * until then. Merchants that want longer windows set maxAgeSeconds; the
 * signature_expired message tells a long-expires signer that the cap, not
 * their expires, decided.
 */
const DEFAULT_MAX_AGE_SECONDS = 300;
/** The HTTP Signature Algorithms registry names this verifier accepts. */
const SUPPORTED_WIRE_ALGS: readonly WebBotAuthKeyAlgorithm[] = ['ed25519', 'ecdsa-p256-sha256'];
/** Clock skew tolerated on Appendix B proof created/expires, evaluated at fetch. */
const PROOF_SKEW_SECONDS = 300;
/**
 * Sanity bound on the wire keyid: non-empty, visible ASCII, at most 128 chars.
 * -01 Section 5.2 says the keyid MUST be a 43-char JWK thumbprint, but a keyid
 * is a SELECTOR, not an identity: agent.bot.goog signs with its six-char kids
 * (seen 2026-09-29), and failing the request on the label's shape rejected a
 * signer whose key the directory publishes. Anything outside this bound is
 * still signature_input_malformed.
 */
const KEYID_SANITY = /^[\x21-\x7e]{1,128}$/;

export class WebBotAuthVerifier implements AgentVerifier {
  private readonly resolver: SignatureAgentKeyResolver;
  private readonly skew: number;
  private readonly maxAge: number;
  private readonly replayGuard: ReplayGuard;
  private readonly requireContentDigest: boolean;
  private readonly proofRequired: Set<string>;
  private readonly onWarning: (message: string) => void;
  private readonly now: () => number;

  constructor(opts: WebBotAuthVerifierOptions) {
    this.resolver = opts.resolver;
    this.skew = opts.clockSkewSeconds ?? DEFAULT_SKEW;
    this.maxAge = opts.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
    this.proofRequired = new Set((opts.proofRequiredOrigins ?? []).map(signatureAgentIdentifier));
    this.onWarning = opts.onWarning ?? ((message) => console.warn(message));
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
      // draft-ietf-webbotauth-httpsig-protocol-01 Section 5.2.1: a signed
      // request MUST carry Signature-Agent. We do not fall back to resolving
      // the bare keyid against every directory we know: that is the (URL, key)
      // confusion Section 5.4 forbids. Conclusive, because nothing about this
      // request is in doubt.
      return fail(
        'missing_signature_agent',
        'Web Bot Auth requires a Signature-Agent header '
          + '(draft-ietf-webbotauth-httpsig-protocol Section 5.2.1); none was sent.',
      );
    }

    // ── 1. Parse signature headers ────────────────────────────────────────
    // The Signature VALUE is parsed after the tag and algorithm gates below:
    // our wire parse enforces the 64-byte Ed25519 / ECDSA r||s length, and an
    // RSA signer declaring alg="rsa-pss-sha512" (the -01 Appendix E.1
    // vectors) deserves the stated-non-goal message, not "must be 64 bytes".
    let parsedInput;
    try {
      parsedInput = parseSignatureInput(sigInput);
    } catch (err) {
      return err instanceof SignatureParseError
        ? fail(signatureParseReason(err.code), err.message)
        : fail('signature_input_malformed', 'Could not parse signature headers.');
    }

    const { created, expires, nonce, keyid, alg, tag } = parsedInput.parameters;

    if (tag === undefined) {
      return fail(
        'signature_parameter_missing',
        `Signature-Input must carry tag="${WEB_BOT_AUTH_TAG}" (no tag parameter was sent).`,
      );
    }
    if (tag !== WEB_BOT_AUTH_TAG) {
      // A well-formed signature declaring another protocol. RFC 9421 Section
      // 3.2.1 says an application MUST enforce its own requirements and that
      // verification MUST fail when a signature does not conform; the draft's
      // Section 5.4 says an origin MAY instead discard signatures with another
      // tag, which would leave the request unsigned. We take the RFC 9421
      // branch and report invalid. This check always sat here, first after
      // parsing, for pipeline reasons (cheap checks before directory I/O); it
      // now stays here as a deliberate reading, not an accident of ordering.
      // The multi-protocol dispatcher routes known tags to their own verifier
      // before this runs, so reaching here means the tag is unknown to it too
      // or the request also carried a Signature-Agent header.
      return fail(
        'foreign_signature_tag',
        `Signature-Input declares tag="${tag}"; this verifier speaks tag="${WEB_BOT_AUTH_TAG}" only.`,
      );
    }

    // ── 2. Algorithm gate ─────────────────────────────────────────────────
    // The directory key pins the algorithm (only Ed25519 and P-256 keys
    // survive parseKeyDirectory), so an omitted alg param cannot cause
    // confusion; an explicit one must name an algorithm we verify here, and
    // must agree with the selected key's type below.
    if (alg !== undefined && !(SUPPORTED_WIRE_ALGS as readonly string[]).includes(alg)) {
      return fail(
        'unsupported_algorithm',
        `Algorithm "${alg}" is not supported: this verifier accepts ed25519 and `
          + 'ecdsa-p256-sha256. RSA algorithms are a stated non-goal for now.',
      );
    }

    let signature: Buffer;
    try {
      signature = parseSignature(sig, parsedInput.label);
    } catch (err) {
      return err instanceof SignatureParseError
        ? fail(signatureParseReason(err.code), err.message)
        : fail('signature_value_malformed', 'Could not parse the Signature header.');
    }

    // ── 3. Time window ────────────────────────────────────────────────────
    const now = this.now();
    if (created === undefined || expires === undefined) {
      return fail(
        'signature_parameter_missing',
        'Signature-Input must include created and expires parameters.',
      );
    }
    if (created > now + this.skew) {
      return fail(
        'signature_created_in_future',
        `Signature created in the future (created=${created}, now=${now}, skew ${this.skew}s).`,
      );
    }
    const effectiveExpires = Math.min(expires, created + this.maxAge);
    if (effectiveExpires + this.skew < now) {
      // When the signer's own window is still open, the cap decided, and the
      // message must say so: a signer sending the 24 h expires -01 Section 5.2
      // recommends would otherwise read "expired" as a clock bug.
      const cappedWhileStillValid = expires + this.skew >= now;
      return fail(
        'signature_expired',
        `Signature expired at ${effectiveExpires} (now=${now}, max age ${this.maxAge}s).`
          + (cappedWhileStillValid
            ? ` The signature's own expires=${expires} has not passed: this verifier caps`
              + ` signature lifetime at created + ${this.maxAge}s as a replay-window policy`
              + ' (configurable via maxAgeSeconds).'
            : ''),
      );
    }

    if (keyid === undefined) {
      return fail('signature_parameter_missing', 'Signature-Input must include a keyid parameter.');
    }
    if (!KEYID_SANITY.test(keyid)) {
      // A shape no published label could have. The 43-char thumbprint gate
      // that used to sit here failed real signers over the label alone; see
      // KEYID_SANITY.
      return fail(
        'signature_input_malformed',
        'Signature-Input keyid must be printable ASCII of at most 128 chars.',
      );
    }

    // ── 4/5. Covered-component requirements ───────────────────────────────
    // -01 Section 5.2.1 requires the Signature-Agent member keyed to the
    // signature label to be covered. Two shapes reach us:
    //   keyed     ("signature-agent";key="sig2") the -01 form. We resolve THE
    //             MEMBER THE SIGNATURE COVERS, which is the invariant that
    //             matters: Section 5.2.2 forbids attributing a signature to a
    //             member it does not cover. We deliberately do NOT additionally
    //             require key == signature label: the published -00 Appendix
    //             E.2.1 vector keyed the member agent2 under label sig2 (-01
    //             re-keyed it, WG PR #138), and enforcing the match adds no
    //             security over resolving the covered member.
    //   unkeyed   the deployed form (chatgpt.com sends the bare sf-string
    //             header with an unkeyed component). Covering the field covers
    //             every member, so the label-matched member is still what the
    //             signer committed to, and Section 5.2.1 explicitly lets a
    //             verifier accept the legacy form as a dictionary with a
    //             single member keyed to the covering signature's label.
    const sigAgentComponent = parsedInput.componentIds.find((c) => c.name === 'signature-agent');
    if (!sigAgentComponent) {
      return fail(
        'required_component_not_covered',
        'signature-agent must be a covered component when the header is sent.',
      );
    }
    if (
      !parsedInput.components.includes('@authority') &&
      !parsedInput.components.includes('@target-uri')
    ) {
      return fail(
        'required_component_not_covered',
        'Covered components must include @authority or @target-uri.',
      );
    }

    let origin: string;
    let identifier: string;
    // Binding strength (D3) reflects the URL's shape (-01 §4.5): the
    // well-known directory URL names a domain; any other path names only
    // itself, which is what a merchant prices.
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
      identifier = parsedAgent.identifier;
      binding = parsedAgent.binding;
    } catch (err) {
      return err instanceof WebBotAuthParseError
        ? fail(signatureAgentReason(err.code), err.message)
        : fail('signature_agent_malformed', 'Could not parse Signature-Agent.');
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
    // A Content-Digest that is present is checked against the body that
    // arrived, empty or not. An empty body has a digest like any other, so a
    // digest made over a non-empty body does not describe this request. The
    // storefront embed forwards an agent's headers into a bodyless POST, which
    // is exactly the case this closes.
    if (digestHeader !== undefined && digestHeader.trim() !== computeContentDigest(request.body ?? '')) {
      return fail(
        'content_digest_mismatch',
        hasBody
          ? 'Content-Digest does not match the body.'
          : 'Content-Digest does not match the empty body that arrived.',
      );
    }

    // ── 6. Key directory resolution ───────────────────────────────────────
    let resolution: KeyDirectoryResolution;
    try {
      resolution = await this.resolver.resolve(identifier);
    } catch {
      resolution = { status: 'unavailable' };
    }
    if (resolution.status === 'not_allowed') {
      // A policy refusal, not a verdict on the signature: this identifier is
      // not allowlisted, so nothing was fetched and nothing was checked. The
      // message must not read as a bad signature, and the result is
      // could-not-check (conclusive=false via the table). An origin allowlist
      // entry admits only the well-known URL, never other paths on the origin
      // ("TLS authenticates the host but not the path", -01 §5.5), so a
      // request naming an arbitrary path on a trusted origin lands here too.
      return fail(
        'unknown_signature_agent',
        `No key directory is allowlisted for the Signature-Agent URL "${identifier}" on this `
          + 'merchant, so the request was not evaluated and nothing was fetched. Add the URL '
          + 'to the trust set to have it resolved.',
      );
    }
    if (resolution.status === 'redirected') {
      // Could-not-check, so inconclusive and fail closed, exactly like an
      // outage. Kept as its own reason because the operator fix differs and
      // reporting "unreachable" for a directory that answered would be untrue.
      return fail(
        'key_directory_redirected',
        `Key directory "${identifier}" answered with a redirect; `
          + 'draft-ietf-webbotauth-httpsig-protocol-01 Section 5.5 requires 200 (OK) and forbids following it.',
      );
    }
    if (resolution.status === 'unsupported_media_type') {
      // Could-not-check: the body was never read as keys, so this says nothing
      // about the signer and must not read as unknown_key.
      return fail(
        'key_directory_unsupported_media_type',
        `Key directory "${identifier}" was not served under an accepted media type`
          + `${resolution.detail ? ` (${resolution.detail})` : ''}; its body was not parsed.`,
      );
    }
    if (resolution.status === 'unavailable') {
      // Fail closed: no key material, no trust. Could-not-check, so inconclusive.
      // Reason kept as key_directory_unavailable for backward compatibility; it
      // unifies with directory_unavailable in the v1.0 contract revision. The
      // detail carries what the resolver saw, including "entries published but
      // none usable", which is a could-not-check and must never read as a
      // definitive unknown_key.
      return fail(
        'key_directory_unavailable',
        `Key directory "${identifier}" could not be used`
          + `${resolution.detail ? ` (${resolution.detail})` : ''}.`,
      );
    }

    // Select by computed thumbprint first: the thumbprint is the key's
    // identity and what -01 Section 5.2 says the keyid is. Fall back to the
    // advertised kid when it selects exactly one key. At the well-known URL a
    // kid that is not the thumbprint deviates from the -01 §5.5 note and is
    // warned (agent.bot.goog publishes six-char kids, 2026-09-29); at any
    // other URL kid is an operator-chosen label and matching it is simply how
    // §5.5 says selection works there, so no warning.
    let key = resolution.keys.find((k) => k.thumbprint === keyid);
    if (!key) {
      const byKid = resolution.keys.filter((k) => k.kid === keyid);
      if (byKid.length === 1) {
        key = byKid[0];
        if (binding === 'domain') {
          this.onWarning(
            `Web Bot Auth keyid "${keyid}" from "${identifier}" matched a directory key by its advertised kid, `
              + `not by thumbprint (${key!.thumbprint}); the draft-ietf-webbotauth-httpsig-protocol-01 `
              + 'Section 5.5 note requires a kid at the well-known URL to be the JWK thumbprint.',
          );
        }
      } else if (byKid.length > 1) {
        return fail(
          'unknown_key',
          `keyid "${keyid}" matched none of the ${resolution.keys.length} keys published at `
            + `${identifier} by thumbprint, and its advertised kid appears on `
            + `${byKid.length} keys, so it selects none of them.`,
        );
      }
    }
    if (!key) {
      // Could-not-check (conclusive=false via the table): an absent key may be
      // a signer to refuse, but it may equally be mid-rotation or behind a
      // cached directory copy, and the response cannot tell us which.
      return fail(
        'unknown_key',
        `keyid "${keyid}" matched none of the ${resolution.keys.length} keys published at `
          + `${identifier} by thumbprint or by advertised kid. The key may `
          + 'be mid-rotation or behind a cached directory copy, so this is not a definitive '
          + 'rejection.',
      );
    }
    // The wire alg, when present, must agree with the selected key's type: an
    // Ed25519 key cannot have made an ecdsa-p256-sha256 signature, and
    // verifying with the key's own algorithm regardless of the label would
    // accept a signature whose declared algorithm is a lie.
    const keyAlg = directoryKeyAlgorithm(key);
    if (alg !== undefined && alg !== keyAlg) {
      return fail(
        'unsupported_algorithm',
        `Signature alg "${alg}" does not match the directory key selected by keyid "${keyid}", `
          + `whose algorithm is ${keyAlg}.`,
      );
    }
    // Appendix B proof-of-possession gate (D2). A proof that was offered and
    // FAILED is never tolerated: the directory entry is untrustworthy, so this
    // runs before the entry's own nbf/exp are believed. A proof that is ABSENT
    // or POSSESSION-ONLY (verifies, but covers no content-digest, so the body
    // is unbound) is tolerated unless this source has the grace flag off: a
    // strict operator asked for the Appendix B proof, and only `valid` is one.
    // All are definitive per-key determinations, so the fail() results are
    // conclusive.
    if (key.proof === 'invalid') {
      return fail(
        'key_proof_invalid',
        `Directory proof-of-possession for key "${keyid}" was offered but failed verification.`,
      );
    }
    // Proof-required applies only to domain-bound identifiers: Appendix B
    // validates the DOMAIN binding, which an arbitrary-path URL never claims.
    if (key.proof !== 'valid' && binding === 'domain' && this.proofRequired.has(identifier)) {
      return fail(
        'unsigned_key',
        key.proof === 'possession-only'
          ? `Directory "${identifier}" served only a possession proof for key "${keyid}" `
            + '(no content-digest coverage), and this source requires the full Appendix B proof.'
          : `Directory "${identifier}" served no proof-of-possession for key "${keyid}", and this source requires one.`,
      );
    }
    // A key the directory publishes whose own window excludes now is a
    // definitive answer about that key, so its reason is conclusive, unlike
    // an absent key, which may just be rotation or cache lag.
    if (key.nbf !== undefined && key.nbf > now + this.skew) {
      return fail(
        'key_outside_validity_window',
        `Key "${keyid}" is published but not yet valid (nbf=${key.nbf}, now=${now}).`,
      );
    }
    if (key.exp !== undefined && key.exp + this.skew < now) {
      return fail(
        'key_outside_validity_window',
        `Key "${keyid}" is published but expired at ${key.exp} (now=${now}).`,
      );
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
      return err instanceof SignatureParseError
        ? fail(signatureParseReason(err.code), err.message)
        : fail('malformed_signature_header', 'Could not build signature base.');
    }

    let signatureOk = false;
    try {
      signatureOk = verifyWithDirectoryKey(key, signatureBase, signature);
    } catch {
      signatureOk = false;
    }
    if (!signatureOk) {
      // One verify returning false covers both a forgery and a signer that
      // canonicalized a component differently (an empty @path where the rule
      // requires "/"). We cannot tell the two apart from here, so there is no
      // canonicalization reason: a name we cannot honestly emit would be worse
      // than this coarse one.
      return fail(
        'invalid_signature',
        keyAlg === 'ecdsa-p256-sha256'
          ? 'ECDSA P-256 verification failed against the directory key '
            + '(signature bytes must be raw r||s per RFC 9421 Section 3.3.4, never DER).'
          : 'Ed25519 verification failed against the directory key.',
      );
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
      `wba:${identifier}:${keyid}:${replayId}`,
      effectiveExpires + this.skew,
    );
    if (!fresh) {
      return fail(
        'replay_detected',
        `Signature from "${identifier}" has already been seen within its validity window.`,
      );
    }

    return {
      trusted: true,
      conclusive: true,
      protocol: 'web-bot-auth',
      // agent.id: the origin for a domain-bound identifier (the well-known
      // URL names that domain, -01 §4.5, and the twins, mandates and admin
      // views key on it), the identifier URL itself for url-only, which
      // names nothing but itself. keyThumbprint is always the COMPUTED
      // thumbprint, never the wire keyid: when the key was selected by
      // advertised kid the two differ, and the identity reported downstream,
      // plus the (URL, key) keying of Section 5.4, must stay derived from
      // the material.
      agent: {
        id: binding === 'domain' ? origin : identifier,
        protocol: 'web-bot-auth',
        keyThumbprint: key.thumbprint,
        binding,
        signatureAgentUrl: identifier,
      },
      ttlSeconds: DEFAULT_TTL_SECONDS,
    };
  }
}

function fail(reason: VerificationFailureReason, message: string): VerificationResult {
  return rejection(reason, message);
}

/** Name an RFC 9421 parse or base-construction fault by what it is about. */
function signatureParseReason(code: SignatureParseErrorCode): VerificationFailureReason {
  switch (code) {
    case 'input':
      return 'signature_input_malformed';
    case 'value':
      return 'signature_value_malformed';
    case 'duplicate_component':
      return 'duplicate_covered_component';
    case 'component_missing':
      return 'covered_component_missing';
    case 'base_unbuildable':
      // A derived component we do not implement, or a request URL that does
      // not parse. Neither is a fault in the signer's headers we can name, so
      // it keeps the coarse name.
      return 'malformed_signature_header';
  }
}

/** Name a Signature-Agent fault by what the operator must fix in that header. */
function signatureAgentReason(code: WebBotAuthParseErrorCode): VerificationFailureReason {
  switch (code) {
    case 'malformed':
      return 'signature_agent_malformed';
    case 'ambiguous':
      return 'signature_agent_ambiguous';
    case 'member_missing':
      return 'signature_agent_member_missing';
    case 'not_origin':
      return 'signature_agent_not_origin';
  }
}

// ─── Key directory resolvers ────────────────────────────────────────────────

/**
 * Signature-Agent sources we resolve by default. Entries are origins, which
 * mean EXACTLY that origin's well-known directory URL (a full https URL is
 * also accepted and means exactly that identifier). Only sources whose live
 * directory we have verified belong here. Merchants extend the set via
 * WBA_ALLOWED_SIGNATURE_AGENTS or WBA_EXTRA_SIGNATURE_AGENTS.
 *
 * - chatgpt.com: checked 2026-07-12, valid Ed25519 JWKS; a real ChatGPT
 *   page visit verified on a live WooCommerce store on 2026-09-29.
 * - agent.bot.goog: checked 2026-09-29, five Ed25519 keys served as
 *   application/http-message-signatures-directory+json with a signed
 *   response; Google's crawler guide names it as the Signature-Agent for
 *   its (self-described experimental) signed requests. Its kids are not
 *   thumbprints, which is why kid is a selector hint (see the parser notes).
 * - claude.ai / perplexity.ai: no directory published when last checked.
 */
export const DEFAULT_SIGNATURE_AGENTS = ['https://chatgpt.com', 'https://agent.bot.goog'];

/** Static resolver for tests and private allowlists: identifier → parsed JWKS. */
export class StaticSignatureAgentKeys implements SignatureAgentKeyResolver {
  private readonly byIdentifier = new Map<string, WebBotAuthKey[]>();
  private readonly unavailable = new Set<string>();

  /** `entry` is an origin (= its well-known URL) or a full https URL. */
  add(entry: string, directoryJson: unknown): void {
    this.byIdentifier.set(signatureAgentIdentifier(entry), parseKeyDirectory(directoryJson));
  }

  /** Simulate an unreachable directory for the entry (tests). */
  markUnavailable(entry: string): void {
    this.unavailable.add(signatureAgentIdentifier(entry));
  }

  async resolve(identifier: string): Promise<KeyDirectoryResolution> {
    // Entries were normalized at add(); the request identifier is compared
    // VERBATIM. Re-normalizing here with the entry rule would expand the "/"
    // path, aliasing the identifier of "https://host/?x" onto the host's
    // well-known entry (the resolver-interface contract).
    if (this.unavailable.has(identifier)) return { status: 'unavailable' };
    const keys = this.byIdentifier.get(identifier);
    if (!keys) return { status: 'not_allowed' };
    // A static key list carries no wire response, hence no proof-of-possession:
    // proof is honestly 'absent' (tolerated under grace, dropped without it).
    return { status: 'ok', keys: keys.map((k) => ({ ...k, proof: 'absent' as const })) };
  }
}

export interface FetchingKeyDirectoryResolverOptions {
  /**
   * What we are willing to fetch key material from. An entry that is an
   * origin means EXACTLY that origin's well-known directory URL. It never
   * admits other paths on the origin, because a JWK Set at an arbitrary path
   * does not name the host's operator ("TLS authenticates the host but not
   * the path", -01 §5.5). An entry that is a full https URL means exactly
   * that identifier. Doubles as the SSRF guard: a Signature-Agent outside
   * this set is never dereferenced.
   */
  allowedOrigins: string[];
  /**
   * Directory cache TTL ceiling. Default 10 minutes. A response that carries
   * Cache-Control max-age caps the entry at min(this, max-age - Age).
   */
  cacheTtlMs?: number;
  /** How long a fetch failure is remembered before retrying. Default 30s. */
  failureCacheTtlMs?: number;
  /**
   * -01 §6.10 stale-on-error window: how long the last successfully resolved
   * key set keeps serving while refreshes FAIL (network, TLS, timeout,
   * non-200, redirect, media type, parse), measured from that last good
   * fetch. Default 1 hour. A refresh that RESOLVES, including one whose
   * entries are all unusable, is evidence and replaces the entry at once.
   */
  staleIfErrorMs?: number;
  /** Per-fetch timeout. Default 5000ms. */
  timeoutMs?: number;
  /** Maximum directory response size. Default 64 KiB. */
  maxResponseBytes?: number;
  /** Injectable fetch for tests. */
  fetchImpl?: typeof fetch;
  /** Override "now" (ms) for deterministic tests. */
  nowMs?: () => number;
  /**
   * Receives operator-facing warnings: a directory served as plain
   * application/json, kid labels that are not thumbprints, and Appendix B
   * proof deviations. Default console.warn; server.ts passes the app logger.
   */
  onWarning?: (message: string) => void;
}

const TEN_MINUTES_MS = 10 * 60 * 1000;
const ONE_HOUR_MS = 60 * 60 * 1000;

/**
 * Fetches a Signature-Agent identifier's JWK Set URL, bounded and cached.
 *
 * Keying is by identifier (-01 §5.4: key lookup MUST be keyed on the
 * (URL, key) pair): the allowlist, the cache, the stale-on-error state AND
 * the network request all use the normalized identifier. Fetching the
 * identifier rather than the member value as sent is a deliberate deviation
 * from -01 §5.5. Under fetch-as-sent, every query spelling shares the one
 * cache entry its identifier names, so any spelling that makes the directory
 * host answer differently (an error, a WAF page, or a 200 with a different
 * key set, which §6.10 treats as evidence) would displace the entry every
 * other spelling shares: one request carrying a chosen query could evict the
 * canonical key set for the whole failure window. §5.5's own rationale is
 * that the query is not identity, and §6.7 says to constrain what is
 * dereferenced, so a member value's query is accepted, dropped from the
 * identifier, and never sent.
 *
 * Fetch discipline: the response MUST be 200 (OK) and redirects are never
 * followed, both required by -01 Section 5.5; https only; 5s timeout; 64 KiB
 * response cap; and only allowlisted identifiers are ever contacted (the SSRF
 * guard). Success and failure are both cached (10 min / 30 s; -01 Appendix
 * C.5 caps negative caching at five minutes) so a flood of requests cannot
 * turn us into a fetch cannon.
 *
 * The success cache honours the response's own freshness (Appendix C.4 says to
 * use normal HTTP caching semantics): when the response carries Cache-Control
 * max-age, the entry expires after min(cacheTtlMs, (max-age - Age)), so a key
 * the operator removes stops verifying within the directory's own cache
 * lifetime (§5.5.2) even when an edge served us an already-aged copy. Without
 * max-age the configured TTL applies unchanged.
 *
 * Stale on error (-01 §6.10 MUST): a directory that fails to resolve is not
 * evidence and never evicts the last good key set: an operator's outage
 * must not revoke its keys here. While refreshes fail, the last good set
 * keeps serving for up to staleIfErrorMs from the fetch that produced it
 * (warned once per identifier), with the failure cached for
 * failureCacheTtlMs between retries. A refresh that RESOLVES (a 200 that
 * parses, with or without the key, including one whose entries are all
 * unusable) is evidence and replaces the entry immediately.
 *
 * A 3xx resolves to `redirected` rather than `unavailable` so the verifier can
 * tell a merchant which of the two happened: a directory that is up and
 * misconfigured is an operator fix, an unreachable one is an outage.
 *
 * Media type: at the well-known URL the body is parsed only when Content-Type
 * is the registered KEY_DIRECTORY_MEDIA_TYPE (a -01 §5.5.1 MUST for that URL)
 * or plain application/json (accepted with a warning, because it is a common
 * server default). At any other URL application/jwk-set+json is also
 * accepted: that is the natural media type of a JWK Set resource (RFC 7517
 * §8.5.1). Anything else, including no Content-Type, resolves to
 * `unsupported_media_type` without parsing, so a JWK Set that happens to
 * appear in an HTML page never stands in for a directory.
 *
 * Directory responses are trusted on the strength of TLS to an allowlisted
 * identifier, plus Appendix B proof-of-possession when the directory serves
 * it: each key is classified valid/invalid/absent/possession-only
 * (verifyDirectoryProofs) and the verifier applies the per-source grace flag.
 * chatgpt.com serves proofs (seen 2026-09-25, with an `alg="ed25519"`
 * parameter); www.shopify.com did not when last checked (2026-08-09), so
 * grace defaults on and absent proofs are tolerated until every source ships
 * them.
 */
export class FetchingKeyDirectoryResolver implements SignatureAgentKeyResolver {
  private readonly allowed: Set<string>;
  private readonly cacheTtlMs: number;
  private readonly failureCacheTtlMs: number;
  private readonly staleIfErrorMs: number;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly fetchImpl: typeof fetch;
  private readonly nowMs: () => number;
  private readonly onWarning: (message: string) => void;
  private readonly cache = new Map<
    string,
    { until: number; value: KeyDirectoryResolution }
  >();
  /** Last successfully RESOLVED ok value per identifier, for §6.10. */
  private readonly lastGood = new Map<
    string,
    { value: KeyDirectoryResolution; fetchedAtMs: number; staleWarned: boolean }
  >();

  constructor(opts: FetchingKeyDirectoryResolverOptions) {
    this.allowed = new Set(opts.allowedOrigins.map(signatureAgentIdentifier));
    this.cacheTtlMs = opts.cacheTtlMs ?? TEN_MINUTES_MS;
    this.failureCacheTtlMs = opts.failureCacheTtlMs ?? 30_000;
    this.staleIfErrorMs = opts.staleIfErrorMs ?? ONE_HOUR_MS;
    this.timeoutMs = opts.timeoutMs ?? 5_000;
    this.maxBytes = opts.maxResponseBytes ?? 64 * 1024;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.nowMs = opts.nowMs ?? Date.now;
    this.onWarning = opts.onWarning ?? ((message) => console.warn(message));
  }

  async resolve(identifier: string): Promise<KeyDirectoryResolution> {
    // Allowlist entries were normalized at construction; the request
    // identifier is compared VERBATIM. Re-normalizing here with the entry
    // rule would expand a "/" path to the well-known URL, so the identifier
    // of "https://host/?x" (which is "https://host/") would pass the
    // allowlist of an allowlisted host, the caller-chosen query would be
    // fetched, and its answer cached under the host's genuine identifier
    // (the resolver-interface contract; office finding 2026-11-03).
    const id = identifier;
    if (!this.allowed.has(id)) return { status: 'not_allowed' };

    const cached = this.cache.get(id);
    const now = this.nowMs();
    if (cached && cached.until > now) return cached.value;

    // Fetch exactly the identifier (the §5.5 deviation in the class doc).
    const { value, freshForMs, resolved } = await this.fetchDirectory(id);
    if (value.status === 'ok') {
      this.lastGood.set(id, { value, fetchedAtMs: now, staleWarned: false });
      const ttl = Math.min(this.cacheTtlMs, freshForMs ?? Number.POSITIVE_INFINITY);
      this.cache.set(id, { until: now + ttl, value });
      return value;
    }
    if (resolved) {
      // The directory answered and we read it: that is evidence (-01 §6.10),
      // so it replaces whatever we held, including the stale-on-error copy.
      this.lastGood.delete(id);
      this.cache.set(id, { until: now + this.failureCacheTtlMs, value });
      return value;
    }
    // A failure to resolve is NOT evidence (-01 §6.10 MUST NOT evict). Serve
    // the last good set inside the stale window; cache that decision for the
    // failure TTL so the retry cadence stays bounded either way.
    const good = this.lastGood.get(id);
    if (good && now < good.fetchedAtMs + this.staleIfErrorMs) {
      if (!good.staleWarned) {
        good.staleWarned = true;
        this.onWarning(
          `Key directory ${id} failed to refresh`
            + `${value.status === 'unavailable' && value.detail ? ` (${value.detail})` : ''}; `
            + `serving the key set fetched ${Math.round((now - good.fetchedAtMs) / 1000)}s ago `
            + `for up to ${Math.round(this.staleIfErrorMs / 1000)}s from that fetch `
            + '(draft-ietf-webbotauth-httpsig-protocol-01 Section 6.10: a failed fetch is not evidence).',
        );
      }
      this.cache.set(id, { until: now + this.failureCacheTtlMs, value: good.value });
      return good.value;
    }
    this.cache.set(id, { until: now + this.failureCacheTtlMs, value });
    return value;
  }

  private async fetchDirectory(
    url: string,
  ): Promise<{ value: KeyDirectoryResolution; freshForMs?: number; resolved: boolean }> {
    // -01 §5.5.1: the registered directory media type is a MUST at the
    // well-known URL; elsewhere a JWK Set may serve other consumers under its
    // own media type.
    const wellKnown = isWellKnownDirectoryUrl(url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      // `manual` so a 3xx is observed and refused rather than followed by the
      // fetch implementation. -01 Section 5.5: discovery MUST be served with
      // 200 (OK), and a verifier MUST NOT automatically follow redirects.
      const res = await this.fetchImpl(url, {
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          accept: wellKnown
            ? 'application/http-message-signatures-directory+json, application/json'
            : 'application/http-message-signatures-directory+json, application/jwk-set+json, application/json',
        },
      });
      if (res.status >= 300 && res.status < 400) {
        // Until -02 (now -01's §5.5) we followed up to three https,
        // allowlisted hops, because shopify.com's apex 301 to www was the
        // deployed reality (built 2026-08-11). The published MUST made that
        // non-conformant, so the tolerance is gone. CONSEQUENCE: the
        // shopify.com APEX directory does not resolve for identity purposes.
        // Their www host serves the directory directly and is unaffected.
        return { value: { status: 'redirected', detail: `HTTP ${res.status}` }, resolved: false };
      }
      if (res.status !== 200) {
        // Exactly 200, not any 2xx: a 204 carries no key set to parse.
        return { value: { status: 'unavailable', detail: `HTTP ${res.status}` }, resolved: false };
      }
      const contentType = res.headers.get('content-type');
      const mediaClass = classifyKeyDirectoryMediaType(contentType);
      const accepted = wellKnown
        ? mediaClass === 'directory' || mediaClass === 'json'
        : mediaClass === 'directory' || mediaClass === 'jwk-set' || mediaClass === 'json';
      if (!accepted) {
        await res.body?.cancel().catch(() => {});
        return {
          value: {
            status: 'unsupported_media_type',
            detail: contentType ? `Content-Type ${contentType}` : 'no Content-Type',
          },
          resolved: false,
        };
      }
      if (mediaClass === 'json') {
        this.onWarning(
          `Key directory ${url} is served as application/json; `
            + `the expected media type is ${wellKnown ? KEY_DIRECTORY_MEDIA_TYPE : JWK_SET_MEDIA_TYPE}.`,
        );
      }
      const body = await readBounded(res, this.maxBytes);
      const { keys, dropped } = readKeyDirectory(JSON.parse(body));
      if (keys.length === 0 && dropped.length > 0) {
        // Entries were published and none is usable to us. That says nothing
        // definitive about any signer, so it is could-not-check (the verifier
        // maps it to key_directory_unavailable), never a key-not-published
        // negative. The detail records what was seen and why each entry was
        // set aside. It RESOLVED, though: the answer is evidence and replaces
        // a cached entry (-01 §6.10).
        const why = dropped.map((d) => `#${d.index}: ${d.reason}`).join('; ');
        return {
          value: {
            status: 'unavailable',
            detail: `directory publishes ${dropped.length} entries, none usable: ${why}`,
          },
          resolved: true,
        };
      }
      const mislabelled = keys.filter((k) => k.kid !== undefined && k.kid !== k.thumbprint);
      if (wellKnown && mislabelled.length > 0) {
        // Once per fetch (the result is cached), not per request. Only at the
        // well-known URL: the -01 §5.5 note scopes the thumbprint MUST to it,
        // and at any other URL kid is an operator-chosen label.
        this.onWarning(
          `Key directory ${url} advertises kid labels that are not JWK thumbprints on `
            + `${mislabelled.length} of ${keys.length} keys (e.g. kid "${mislabelled[0]!.kid}"); `
            + 'the draft-ietf-webbotauth-httpsig-protocol-01 Section 5.5 note requires a kid at '
            + 'the well-known URL to be the thumbprint. '
            + 'Keys are kept and identified by their computed thumbprints.',
        );
      }
      // Appendix B: classify each key by its response proof-of-possession.
      // The request authority is the host we actually fetched, which is what
      // the directory operator signs over (@authority;req).
      const proofByThumbprint = verifyDirectoryProofs({
        authority: new URL(url).host,
        body,
        contentDigest: res.headers.get('content-digest') ?? undefined,
        signatureInput: res.headers.get('signature-input') ?? undefined,
        signature: res.headers.get('signature') ?? undefined,
        now: Math.floor(this.nowMs() / 1000),
        skewSeconds: PROOF_SKEW_SECONDS,
        keys,
        onWarning: this.onWarning,
      });
      const resolvedKeys: ResolvedDirectoryKey[] = keys.map((k) => ({
        ...k,
        proof: proofByThumbprint.get(k.thumbprint) ?? 'absent',
      }));
      const freshForMs = responseFreshnessMs(res.headers);
      return {
        value: { status: 'ok', keys: resolvedKeys },
        ...(freshForMs !== undefined ? { freshForMs } : {}),
        resolved: true,
      };
    } catch (err) {
      return {
        value: {
          status: 'unavailable',
          detail: err instanceof Error ? err.message : 'fetch failed',
        },
        resolved: false,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

/** True when the identifier is an origin's §8.1 well-known directory URL. */
function isWellKnownDirectoryUrl(identifier: string): boolean {
  try {
    const url = new URL(identifier);
    return url.pathname === KEY_DIRECTORY_PATH && url.search === '';
  } catch {
    return false;
  }
}

/**
 * Remaining freshness of a response per its own caching headers, in ms:
 * Cache-Control max-age minus the Age an intermediary reports, floored at 0.
 * Undefined when the response carries no max-age, in which case the caller's
 * configured TTL stands alone.
 */
function responseFreshnessMs(headers: Headers): number | undefined {
  const cacheControl = headers.get('cache-control');
  const maxAgeMatch = cacheControl?.match(/(?:^|[,\s])max-age\s*=\s*("?)(\d{1,10})\1(?=$|[,\s;])/i);
  if (!maxAgeMatch) return undefined;
  const ageHeader = Number(headers.get('age') ?? '');
  const age = Number.isFinite(ageHeader) && ageHeader > 0 ? Math.floor(ageHeader) : 0;
  return Math.max(0, Number(maxAgeMatch[2]) - age) * 1000;
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
