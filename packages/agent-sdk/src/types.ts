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
  // AP2 (Google Agent Payments Protocol)
  | 'malformed_jws'
  | 'jws_unsupported_algorithm'
  | 'jws_signature_invalid'
  | 'cart_intent_mismatch'
  | 'cart_exceeds_intent_limit'
  | 'mandate_chain_mismatch'
  // Multi-protocol
  | 'ambiguous_protocol';

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
      buyerInfo: BuyerInfo;
      mandate: Mandate;
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
