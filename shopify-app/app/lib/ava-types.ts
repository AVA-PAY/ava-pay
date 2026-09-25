/**
 * Mirror of the AVA Pay API contract.
 * Keep in sync with `<repo>/AVA Pay/src/types.ts` until we extract a shared package.
 */

export interface IncomingRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface BuyerInfo {
  buyerId: string;
  country?: string;
  displayName?: string;
}

export interface Mandate {
  id: string;
  iat: number;
  exp: number;
  maxAmountMinor: number;
  currency: string;
  allowedMerchants: string[];
}

export type VerificationFailureReason =
  // Generic
  | 'missing_agent_credentials'
  // Signature-layer (RFC 9421 / Visa TAP). malformed_signature_header is the
  // coarse name the Visa, Visa TAP and AP2 verifiers still use; Web Bot Auth
  // reports the finer names that follow it.
  | 'malformed_signature_header'
  | 'signature_input_malformed'
  | 'signature_value_malformed'
  | 'signature_parameter_missing'
  // Well-formed, but the tag declares another protocol.
  | 'foreign_signature_tag'
  | 'duplicate_covered_component'
  | 'required_component_not_covered'
  | 'covered_component_missing'
  | 'unsupported_algorithm'
  | 'invalid_signature'
  // Actual expiry only. Clock-ahead is signature_created_in_future.
  | 'signature_expired'
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
  // requires discovery to be served with 200 (OK) and forbids following
  // redirects, so there is no key material and no identity to attribute. Kept
  // distinct from key_directory_unavailable: reachable and misconfigured, not
  // down. Could-not-check, so conclusive=false, and never unknown_agent.
  | 'key_directory_redirected'
  // The directory answered 200 with a Content-Type that is not a JSON key
  // directory type, so it was never parsed. Could-not-check, conclusive=false,
  // and never unknown_key.
  | 'key_directory_unsupported_media_type'
  | 'unknown_key'
  // What is wrong with the Signature-Agent header itself. All conclusive.
  | 'signature_agent_malformed'
  | 'signature_agent_ambiguous'
  | 'signature_agent_member_missing'
  | 'signature_agent_not_origin'
  // A signed request that carried no Signature-Agent header, required on every
  // signed request by Section 5.2.1 of -02. Definitive rejection, not a prompt
  // to guess identity from keyid. Distinct from missing_agent_credentials,
  // which means no signature was offered at all.
  | 'missing_signature_agent'
  // Appendix B directory proof-of-possession. unsigned_key is "no proof
  // offered" (tolerated under the per-source grace flag, dropped when it is
  // off); key_proof_invalid is "proof offered and failed verification", never
  // tolerated. Both are definitive per-key determinations (conclusive), unlike
  // a directory-level fetch failure.
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
 * Mirror of REASON_CONCLUSIVE in packages/agent-sdk/src/types.ts, the table
 * that fixes each reason's outcome: true is a definite rejection, false is
 * could-not-check. check:type-sync fails if this table and the SDK's differ in
 * any key or value, or if either does not list its union exactly once. The
 * plugin still splits on the `conclusive` flag the API sends (verify-flow.ts),
 * never on this table; the table is the contract that flag honours.
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

export type VerifiedProtocol = 'visa-tap' | 'ava-tap' | 'ap2' | 'web-bot-auth';

export interface TapVerificationDetail {
  intent: 'browse' | 'payer';
  consumer?: {
    sub?: string;
    emailMask?: string;
    phoneNumberMask?: string;
  };
  payment?: {
    hasCredentialsHash: boolean;
    hasEncryptedPayload: boolean;
  };
}

export interface VerifiedAgentIdentity {
  /** Canonical agent identifier — for Web Bot Auth, the https origin (e.g. "https://chatgpt.com"). */
  id: string;
  protocol: VerifiedProtocol;
  keyThumbprint?: string;
  /**
   * Web Bot Auth only: how strongly the identity is bound (§5.5). `domain` when
   * discovered via the reserved well-known directory path; `url-only` when the
   * Signature-Agent declared a `jwks_uri`/`cimd` type (key continuity at an
   * arbitrary URL, no origin association). Merchants can price the difference.
   */
  binding?: 'domain' | 'url-only';
}

/**
 * Accountability provenance for a verified agent origin (who operates it and
 * which registry said so). Attached AFTER verification by an optional operator
 * source on the API side; advisory only. It never affects `trusted`,
 * `conclusive`, or `reason`, and its absence means "not looked up or not
 * answered", never "not accountable".
 */
export interface OperatorRecord {
  origin: string;
  operator: string;
  abuseContact?: string;
  registry: string;
  dnssec: 'valid' | 'invalid' | 'absent' | 'unchecked';
  /** ISO 8601 timestamp of when the source made this observation. */
  observedAt: string;
}

export type VerificationResult =
  | {
      trusted: true;
      /**
       * Whether the verifier completed its checks. A successful verification is
       * always conclusive, so this is true. Present on both branches so callers
       * can read `result.conclusive` without first narrowing on `trusted`.
       */
      conclusive?: boolean;
      protocol?: VerifiedProtocol;
      /** The agent identity the signature proved (always set for web-bot-auth). */
      agent?: VerifiedAgentIdentity;
      /**
       * Present only for payment protocols (Visa TAP, AP2). Identity-only
       * protocols (Web Bot Auth) prove who the agent is, not what it may buy.
       */
      buyerInfo?: BuyerInfo;
      mandate?: Mandate;
      /** Real Visa TAP only: intent + validated consumer/payment context. */
      tap?: TapVerificationDetail;
      /** Accountability provenance for the verified origin. Advisory only. */
      operator?: OperatorRecord;
      discount?: number;
      ttlSeconds: number;
    }
  | {
      trusted: false;
      reason: VerificationFailureReason;
      message: string;
      /**
       * Whether the verifier completed its checks. Fixed per reason by
       * REASON_CONCLUSIVE above (mirrored from the SDK), which is the source of
       * truth: false for exactly its could-not-check reasons (today
       * directory_unavailable, key_directory_unavailable,
       * key_directory_redirected and key_directory_unsupported_media_type),
       * true for every other reason. trusted stays false either way, so
       * fail-closed behavior never depends on this flag. The API always sets
       * it; an absent value, from an older API build, reads as conclusive. The
       * full ternary lands in the v1.0 contract (D4).
       */
      conclusive?: boolean;
    };
