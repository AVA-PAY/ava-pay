/**
 * AP2 — Agent Payments Protocol — shared protocol types.
 *
 * v0.2 (clean break from the v0.1 Intent/Cart shapes): mandates are dSD-JWT
 * verifiable credentials — see ./mandates.js for the Checkout / Payment
 * mandate shapes and ./sdjwt.js for the chain primitives. The compact-JWS
 * helpers in ./jws.js remain for standalone JWS use.
 */

export interface JwsHeader {
  alg: 'EdDSA' | 'ES256';
  typ?: string;
  /** Key ID — must match the agent registered in the AgentDirectory. */
  kid: string;
}

export type Ap2FailureReason =
  | 'malformed_jws'
  | 'jws_unsupported_algorithm'
  | 'jws_signature_invalid'
  | 'mandate_chain_mismatch'
  | 'mandate_constraint_violation'
  | 'checkout_hash_mismatch';
