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
  // Web Bot Auth (IETF draft-meunier-webbotauth-httpsig-protocol)
  | 'unknown_signature_agent'
  | 'key_directory_unavailable'
  | 'unknown_key'
  // Multi-protocol
  | 'ambiguous_protocol';

export type VerifiedProtocol = 'visa-tap' | 'ap2' | 'web-bot-auth';

export interface VerifiedAgentIdentity {
  /** Canonical agent identifier — for Web Bot Auth, the https origin (e.g. "https://chatgpt.com"). */
  id: string;
  protocol: VerifiedProtocol;
  keyThumbprint?: string;
}

export type VerificationResult =
  | {
      trusted: true;
      protocol?: VerifiedProtocol;
      /** The agent identity the signature proved (always set for web-bot-auth). */
      agent?: VerifiedAgentIdentity;
      /**
       * Present only for payment protocols (Visa TAP, AP2). Identity-only
       * protocols (Web Bot Auth) prove who the agent is, not what it may buy.
       */
      buyerInfo?: BuyerInfo;
      mandate?: Mandate;
      discount?: number;
      ttlSeconds: number;
    }
  | {
      trusted: false;
      reason: VerificationFailureReason;
      message: string;
    };
