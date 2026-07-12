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

/** Reasons we may reject a verification request. */
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
    };
