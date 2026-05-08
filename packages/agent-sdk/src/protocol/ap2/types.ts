/**
 * AP2 — Google Agent Payments Protocol — type definitions.
 *
 * On-the-wire structure:
 *   Ap2-Attestation:    <compact JWS for the intent mandate>
 *   Ap2-Cart-Mandate:   <compact JWS for the cart mandate>
 *
 * Intent mandate is the long-lived authorization ("user authorizes agent X
 * to spend up to $Y at merchant Z"). Cart mandate is the short-lived
 * "right now, here's exactly what I'm buying." Both signed with the same
 * agent key; cart's `intent_ref` must match intent's `jti`.
 */

export interface JwsHeader {
  alg: 'EdDSA' | 'ES256';
  typ?: string;
  /** Key ID — must match the agent registered in the AgentDirectory. */
  kid: string;
}

interface BaseClaims {
  /** Issuer — agent ID. Same as the kid used to verify the JWS. */
  iss: string;
  iat: number;
  exp: number;
  jti: string;
}

export interface IntentMandateClaims extends BaseClaims {
  ap2: {
    type: 'intent';
    /** Buyer / wallet identifier. Opaque, never PII. */
    sub: string;
    spend_limit: { value: number; currency: string };
    allowed_merchants: string[];
    user_attestation?: {
      format: string;
      attestation: string;
    };
  };
}

export interface CartMandateClaims extends BaseClaims {
  ap2: {
    type: 'cart';
    /** jti of the intent mandate this cart is realizing. */
    intent_ref: string;
    merchant: string;
    items: ReadonlyArray<{
      sku: string;
      qty: number;
      price: number;
    }>;
    total: { value: number; currency: string };
  };
}

export type Ap2FailureReason =
  | 'malformed_jws'
  | 'jws_unsupported_algorithm'
  | 'jws_signature_invalid'
  | 'cart_intent_mismatch'
  | 'cart_exceeds_intent_limit'
  | 'mandate_chain_mismatch';
