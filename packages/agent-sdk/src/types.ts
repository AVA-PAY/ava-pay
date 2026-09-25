/**
 * AVA Pay — shared types for the /verify endpoint.
 *
 * These types form the contract between merchant integrations (Shopify plugin,
 * WooCommerce hook, raw HTTP) and our verification engine. The shape is
 * intentionally aligned with the Visa Trusted Agent Protocol + Google AP2
 * mandate concepts so we can swap MockAgentVerifier for a real implementation
 * without changing callers.
 */

/**
 * Full HTTP snapshot the merchant forwards to /verify.
 *
 * We intentionally do not parse signed headers ourselves at this layer —
 * the verifier owns that. Merchants just hand us everything they received.
 */
export interface IncomingRequest {
  /** HTTP method on the merchant checkout request, e.g. "POST". */
  method: string;
  /** Full request URL the agent hit on the merchant, e.g. "https://shop.example.com/cart". */
  url: string;
  /** Lower-cased header map. Multi-value headers should be joined with ", ". */
  headers: Record<string, string>;
  /**
   * Raw request body as a string (already-decoded JSON, form-encoded, etc.).
   * Verification needs the exact bytes that were signed, so callers should
   * forward the body before any reserialization.
   */
  body?: string;
}

/** Information about the human buyer the agent is acting on behalf of. */
export interface BuyerInfo {
  /** Stable opaque buyer ID (e.g. an AVA Pass account hash). Never PII. */
  buyerId: string;
  /** ISO country code derived from the mandate, used for tax/discount logic. */
  country?: string;
  /** Optional display name the merchant may show ("Order placed for: Alex"). */
  displayName?: string;
}

/** A purchase mandate: what the agent is allowed to buy on the buyer's behalf. */
export interface Mandate {
  /** Mandate identifier signed by the buyer / AVA Pass issuer. */
  id: string;
  /** Issued-at unix timestamp (seconds). */
  iat: number;
  /** Expiry unix timestamp (seconds). */
  exp: number;
  /** Maximum spend authorized by this mandate, in minor currency units. */
  maxAmountMinor: number;
  /** ISO 4217 currency, e.g. "USD". */
  currency: string;
  /** Allowed merchant domains (exact-match or "*" for any). */
  allowedMerchants: string[];
  /**
   * Optional buyer info embedded in the signed mandate. Real Visa TAP mandates
   * carry this; older/simpler mandates don't, in which case the verifier
   * synthesizes a buyerId from the mandate id.
   */
  buyer?: BuyerInfo;
}

/**
 * Reasons we may reject a verification request.
 *
 * Every member has a fixed outcome, recorded in REASON_CONCLUSIVE below: either
 * invalid (the verifier checked and the request failed, conclusive) or
 * unverified (the verifier could not complete its checks, not conclusive). A
 * name says what the verifier KNOWS, not how it found out.
 */
export type VerificationFailureReason =
  // Generic
  | 'missing_agent_credentials'
  // Signature-layer (RFC 9421 / Visa TAP)
  // malformed_signature_header is the coarse name the Visa, Visa TAP and AP2
  // verifiers still use for any unparseable or incomplete signature. Web Bot
  // Auth reports the finer names below and uses this one only for a signature
  // base it cannot build for a reason none of them describes (a derived
  // component it does not implement, or an unusable request URL).
  | 'malformed_signature_header'
  // Signature-Input cannot be parsed, or one of its parameter values cannot be
  // read (a non-numeric created, a keyid that is not a JWK thumbprint).
  | 'signature_input_malformed'
  // Signature cannot be parsed: no member for the Signature-Input label, not a
  // byte sequence, or not a 64-byte Ed25519 value.
  | 'signature_value_malformed'
  // Signature-Input parses but omits a parameter the protocol requires
  // (created, expires, keyid, tag).
  | 'signature_parameter_missing'
  // A well-formed signature whose tag declares a protocol other than the one
  // the verifier speaks. The header is not garbage; it is someone else's.
  | 'foreign_signature_tag'
  // The covered component list repeats one identifier (name plus parameters),
  // which RFC 9421 Section 2.5 forbids.
  | 'duplicate_covered_component'
  // The signature does not cover a component the protocol requires it to
  // (the request target, or the Signature-Agent member).
  | 'required_component_not_covered'
  // The signature covers a component the request does not carry, so the base
  // the signer signed cannot be rebuilt from what arrived.
  | 'covered_component_missing'
  | 'unsupported_algorithm'
  | 'invalid_signature'
  // Actual expiry only: the signature's window, or the server-side cap on its
  // lifetime, ended before the request arrived.
  | 'signature_expired'
  // created is ahead of the verifier clock by more than the tolerated skew.
  // Split out of signature_expired, which told a signer the opposite of what
  // was wrong.
  | 'signature_created_in_future'
  | 'content_digest_mismatch'
  | 'replay_detected'
  // Directory / agent-state
  | 'unknown_agent'
  | 'revoked_agent'
  // An agent directory could not be reached or parsed, so the verifier could
  // not complete its checks. Distinct from unknown_agent, which is a reachable
  // directory that does not list the agent. Pairs with conclusive=false, and
  // trusted stays false (fail closed). Note that web-bot-auth and the Visa JWKS
  // paths report the same could-not-check condition as key_directory_unavailable
  // for backward compatibility, and the two names unify in the v1.0 contract
  // revision, which also promotes conclusive to the full ternary (D4).
  | 'directory_unavailable'
  // Mandate
  | 'malformed_mandate'
  | 'mandate_expired'
  | 'mandate_merchant_mismatch'
  | 'mandate_amount_exceeded'
  // AP2 (Google Agent Payments Protocol, v0.2 dSD-JWT mandate chains)
  | 'malformed_jws'
  | 'jws_unsupported_algorithm'
  | 'jws_signature_invalid'
  | 'mandate_chain_mismatch'
  | 'mandate_constraint_violation'
  | 'checkout_hash_mismatch'
  | 'unsupported_protocol_version'
  // Web Bot Auth (IETF draft-ietf-webbotauth-httpsig-protocol-00, formerly
  // draft-meunier-webbotauth-httpsig-protocol-02)
  | 'unknown_signature_agent'
  | 'key_directory_unavailable'
  // The Signature-Agent URL answered with a redirect. Section 5.5 of -02
  // requires discovery to be served with 200 (OK) and forbids a verifier from
  // following redirects, so there is no key material to check and no identity
  // to attribute. Kept distinct from key_directory_unavailable because the
  // operator fix is different and a merchant deserves the specific story: the
  // directory is reachable and misconfigured, not down. Pairs with
  // conclusive=false (we could not check), and never reported as unknown_agent.
  | 'key_directory_redirected'
  // The key directory answered 200 with a Content-Type that is not a JSON key
  // directory type, so its body was never parsed. Could-not-check: nothing was
  // learned about the signer, and a key set served as text/html must not read
  // as unknown_key. Operator fix: serve the directory with its media type.
  | 'key_directory_unsupported_media_type'
  | 'unknown_key'
  // Signature-Agent header names, each for what the operator must fix in that
  // header. All conclusive: the header arrived and says something definite.
  // The header is not a readable Structured Field (bad quoting, no usable
  // member, a value that is not a URL, or only members of unknown type).
  | 'signature_agent_malformed'
  // Several usable members, none keyed to the signature, so nothing says which
  // one signed. Attributing by header order is what Section 5.2.2 forbids.
  | 'signature_agent_ambiguous'
  // The signature covers a keyed member the header does not contain.
  | 'signature_agent_member_missing'
  // The member value is not an acceptable origin: not https, carrying
  // credentials, or (directory type) carrying a path, query or fragment.
  | 'signature_agent_not_origin'
  // A signed request that carried no Signature-Agent header. Required on every
  // signed request by Section 5.2.1 of -02, so this is a definitive rejection
  // rather than a prompt to guess an identity from keyid alone. Distinct from
  // missing_agent_credentials, which means no signature was offered at all.
  | 'missing_signature_agent'
  // Appendix B directory proof-of-possession. Distinct observations that behave
  // differently: unsigned_key is "no proof offered" (the directory served no
  // response signature for this key), tolerated when the per-source grace flag
  // is on and dropped when it is off. key_proof_invalid is "proof offered and
  // failed verification", never tolerated at any grace setting. Both are
  // definitive per-key determinations, so a result rejecting on them is
  // conclusive; only a directory-level fetch failure is inconclusive.
  | 'unsigned_key'
  | 'key_proof_invalid'
  // Visa Trusted Agent Protocol (real wire format) — signed body objects
  | 'malformed_recognition_object'
  | 'recognition_nonce_mismatch'
  | 'recognition_signature_invalid'
  | 'id_token_invalid'
  | 'malformed_payment_container'
  | 'payment_container_signature_invalid'
  // Multi-protocol
  | 'ambiguous_protocol';

/**
 * The outcome every failure reason carries, and the only place it is decided.
 *
 * true: invalid. The verifier completed its checks and the request failed
 * them (Appendix C.1 `invalid` in the Web Bot Auth draft).
 * false: unverified. The verifier could not complete its checks, so the result
 * says nothing about the signer (C.1 `unverified`). trusted stays false there
 * too, so fail-closed behavior does not depend on this flag.
 *
 * Enforced three ways, so a new could-not-check reason cannot silently inherit
 * the conclusive default:
 *   - `satisfies Record<VerificationFailureReason, boolean>` fails the build
 *     if a reason is added to the union without an entry here, or an entry
 *     names a reason the union does not have;
 *   - every verifier builds its failures through rejection() below, which
 *     reads the flag from this table instead of taking it as an argument;
 *   - check:type-sync reads this table from the source and fails unless it
 *     lists every union member exactly once and matches the Shopify mirror.
 */
export const REASON_CONCLUSIVE = {
  missing_agent_credentials: true,
  malformed_signature_header: true,
  signature_input_malformed: true,
  signature_value_malformed: true,
  signature_parameter_missing: true,
  foreign_signature_tag: true,
  duplicate_covered_component: true,
  required_component_not_covered: true,
  covered_component_missing: true,
  unsupported_algorithm: true,
  invalid_signature: true,
  signature_expired: true,
  signature_created_in_future: true,
  content_digest_mismatch: true,
  replay_detected: true,
  unknown_agent: true,
  revoked_agent: true,
  directory_unavailable: false,
  malformed_mandate: true,
  mandate_expired: true,
  mandate_merchant_mismatch: true,
  mandate_amount_exceeded: true,
  malformed_jws: true,
  jws_unsupported_algorithm: true,
  jws_signature_invalid: true,
  mandate_chain_mismatch: true,
  mandate_constraint_violation: true,
  checkout_hash_mismatch: true,
  unsupported_protocol_version: true,
  unknown_signature_agent: true,
  key_directory_unavailable: false,
  key_directory_redirected: false,
  key_directory_unsupported_media_type: false,
  unknown_key: true,
  signature_agent_malformed: true,
  signature_agent_ambiguous: true,
  signature_agent_member_missing: true,
  signature_agent_not_origin: true,
  missing_signature_agent: true,
  unsigned_key: true,
  key_proof_invalid: true,
  malformed_recognition_object: true,
  recognition_nonce_mismatch: true,
  recognition_signature_invalid: true,
  id_token_invalid: true,
  malformed_payment_container: true,
  payment_container_signature_invalid: true,
  ambiguous_protocol: true,
} as const satisfies Record<VerificationFailureReason, boolean>;

/** The reasons whose outcome is unverified (could not check), in table order. */
export const COULD_NOT_CHECK_REASONS: readonly VerificationFailureReason[] = (
  Object.keys(REASON_CONCLUSIVE) as VerificationFailureReason[]
).filter((reason) => !REASON_CONCLUSIVE[reason]);

/**
 * Build a failure result whose `conclusive` flag comes from REASON_CONCLUSIVE.
 * There is no parameter for the flag on purpose: a caller cannot emit a reason
 * with the other outcome, so the pairing holds at every call site by
 * construction rather than by review.
 */
export function rejection(
  reason: VerificationFailureReason,
  message: string,
): Extract<VerificationResult, { trusted: false }> {
  // Untyped JavaScript callers can pass a string the table does not know. That
  // is not a reason we can classify, so it is never reported as a definite
  // rejection; trusted is false either way.
  const conclusive = Object.hasOwn(REASON_CONCLUSIVE, reason) ? REASON_CONCLUSIVE[reason] : false;
  return { trusted: false, reason, message, conclusive };
}

/**
 * Protocol that authenticated a trusted request.
 * 'visa-tap' is Visa's real Trusted Agent Protocol wire format;
 * 'ava-tap' is AVA's TAP-style profile (x-ava-mandate header).
 */
export type VerifiedProtocol = 'visa-tap' | 'ava-tap' | 'ap2' | 'web-bot-auth';

/** What a real Visa TAP verification established, beyond agent identity. */
export interface TapVerificationDetail {
  /** browse = agent-browser-auth; payer = agent-payer-auth (payment intent). */
  intent: 'browse' | 'payer';
  /** Present when a Consumer Recognition Object validated (incl. its Visa-signed IdToken). */
  consumer?: {
    /** Opaque subject from the Visa IdToken. Never PII in the clear. */
    sub?: string;
    emailMask?: string;
    phoneNumberMask?: string;
  };
  /** Present when an Agentic Payment Container validated. */
  payment?: {
    hasCredentialsHash: boolean;
    /** Merchant-encrypted payload present (only the merchant can decrypt it). */
    hasEncryptedPayload: boolean;
  };
}

/**
 * The agent identity a signature actually proved.
 *
 * For Web Bot Auth this is the Signature-Agent origin (e.g.
 * "https://chatgpt.com") whose published key directory verified the request.
 * Identity is NOT payment authority: a Web Bot Auth result carries no mandate
 * and authorizes nothing beyond "this request really came from this agent."
 */
export interface VerifiedAgentIdentity {
  /** Canonical agent identifier — for Web Bot Auth, the https origin. */
  id: string;
  protocol: VerifiedProtocol;
  /** RFC 7638 JWK thumbprint of the key that verified, when applicable. */
  keyThumbprint?: string;
  /**
   * Web Bot Auth only: how strongly the identity is bound (§5.5). `domain` when
   * the key was discovered through the reserved well-known directory path (the
   * `directory` type), which ties the key to the origin. `url-only` when the
   * Signature-Agent declared a `jwks_uri`/`cimd` type, which proves key
   * continuity at an arbitrary URL with no origin association. Merchants can
   * price the difference. Absent for protocols where the distinction does not
   * apply.
   */
  binding?: 'domain' | 'url-only';
}

/**
 * Accountability provenance for a verified agent origin: who operates it and
 * where that claim came from.
 *
 * This answers a DIFFERENT question from key resolution. A resolved key proves
 * "this request came from this origin"; an OperatorRecord says "and here is who
 * is accountable for that origin, per a registry". The two must never shadow
 * each other, so this is attached to an already-verified result as provenance
 * and NEVER contributes to `trusted`, `conclusive`, or `reason`. Absent on
 * every failed or inconclusive result, and absent on a verified result when no
 * operator source is configured or the source could not answer.
 *
 * Produced by an OperatorSource (src/verifier/operator-source.ts). See
 * docs/RESOLVER-SOURCES.md.
 */
export interface OperatorRecord {
  /** The https origin this record describes, e.g. "https://www.shopify.com". */
  origin: string;
  /** Operator name as the registry reports it. Not a trust claim on its own. */
  operator: string;
  /** Abuse contact published for the origin, when the registry publishes one. */
  abuseContact?: string;
  /** Which registry answered, e.g. an RDAP service name. Provenance, not authority. */
  registry: string;
  /**
   * DNSSEC validation state of the key-to-name binding the source checked.
   * `unchecked` means the source did not attempt validation; it is NOT a pass.
   */
  dnssec: 'valid' | 'invalid' | 'absent' | 'unchecked';
  /** ISO 8601 timestamp of when the source made this observation. */
  observedAt: string;
}

/**
 * Result returned to the merchant.
 *
 * The shape is a discriminated union on `trusted` so merchants can do:
 *   if (result.trusted) { applyDiscount(result.discount) }
 *   else { showHumanCaptcha(result.reason) }
 */
export type VerificationResult =
  | {
      trusted: true;
      /**
       * Whether the verifier completed its checks. A successful verification is
       * always conclusive, so this is true. Present on both branches so callers
       * can read `result.conclusive` without first narrowing on `trusted`.
       */
      conclusive?: boolean;
      /** Which protocol verified the request. Set by newer verifiers; absent on older results. */
      protocol?: VerifiedProtocol;
      /** The agent identity the signature proved (always set for web-bot-auth). */
      agent?: VerifiedAgentIdentity;
      /**
       * Buyer + mandate are present only for payment protocols (Visa TAP, AP2).
       * Identity-only protocols (Web Bot Auth) verify who the agent is, not
       * what it may buy — merchants MUST NOT treat their absence as spend
       * authorization.
       */
      buyerInfo?: BuyerInfo;
      mandate?: Mandate;
      /** Real Visa TAP only: intent + validated consumer/payment context. */
      tap?: TapVerificationDetail;
      /**
       * Accountability provenance for the verified origin, attached AFTER
       * verification by an optional OperatorSource. Advisory only: it never
       * changed `trusted` or `conclusive`, and its absence means "not looked
       * up or not answered", never "not accountable".
       */
      operator?: OperatorRecord;
      /** Optional merchant-funded discount, expressed as a fraction 0..1 (e.g. 0.1 = 10%). */
      discount?: number;
      /** How long this decision is valid, in seconds. Merchant can cache. */
      ttlSeconds: number;
    }
  | {
      trusted: false;
      reason: VerificationFailureReason;
      /** Human-readable detail. Safe to log; never includes secrets. */
      message: string;
      /**
       * Whether the verifier completed its checks. Fixed per reason by
       * REASON_CONCLUSIVE, which is the source of truth: false for exactly the
       * could-not-check reasons it lists (today directory_unavailable,
       * key_directory_unavailable, key_directory_redirected and
       * key_directory_unsupported_media_type, also exported as
       * COULD_NOT_CHECK_REASONS), true for every other reason, where the
       * request was definitively rejected. trusted stays false either way, so
       * fail-closed behavior never depends on this flag.
       *
       * AVA's engine always sets it, because every failure is built by
       * rejection(), which reads the table. It stays optional on the type so a
       * reader of results from an older API build still type-checks; read an
       * absent value as conclusive. The full ternary lands in the v1.0
       * contract (D4).
       */
      conclusive?: boolean;
    };
