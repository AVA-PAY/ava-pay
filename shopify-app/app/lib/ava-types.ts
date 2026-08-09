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
  // Signature-layer (RFC 9421 / Visa TAP)
  | 'malformed_signature_header'
  | 'unsupported_algorithm'
  | 'invalid_signature'
  | 'signature_expired'
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
  // Web Bot Auth (IETF draft-meunier-webbotauth-httpsig-protocol)
  | 'unknown_signature_agent'
  | 'key_directory_unavailable'
  | 'unknown_key'
  // Visa Trusted Agent Protocol (real wire format) — signed body objects
  | 'malformed_recognition_object'
  | 'recognition_nonce_mismatch'
  | 'recognition_signature_invalid'
  | 'id_token_invalid'
  | 'malformed_payment_container'
  | 'payment_container_signature_invalid'
  // Multi-protocol
  | 'ambiguous_protocol';

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
      discount?: number;
      ttlSeconds: number;
    }
  | {
      trusted: false;
      reason: VerificationFailureReason;
      message: string;
      /**
       * Whether the verifier completed its checks. false ONLY on could-not-check
       * paths, where a trust root was unreachable (reason directory_unavailable
       * or key_directory_unavailable); trusted stays false there too, so
       * fail-closed behavior is unchanged. true means the request was
       * definitively rejected. Additive and non-breaking: AVA's engine always
       * sets this, and an absent value should be read as conclusive for forward
       * compatibility. The full ternary lands in the v1.0 contract (D4).
       */
      conclusive?: boolean;
    };
