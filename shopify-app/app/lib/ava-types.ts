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

export type VerificationResult =
  | {
      trusted: true;
      buyerInfo: BuyerInfo;
      mandate: Mandate;
      discount?: number;
      ttlSeconds: number;
    }
  | {
      trusted: false;
      reason: VerificationFailureReason;
      message: string;
    };
