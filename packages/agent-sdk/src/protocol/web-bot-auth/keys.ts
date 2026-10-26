import { verifyEcdsaP256Sha256, verifyEd25519 } from '../visa/http-signatures.js';
import type { WebBotAuthKey } from './index.js';

/**
 * Algorithm agility for Web Bot Auth directory keys, in one place.
 *
 * -00 Section 5.2 defines the request keyid as the RFC 7638 JWK thumbprint
 * "for RSA and EC" and the RFC 8037 Appendix A.3 form for ed25519, and its
 * signature `alg` parameter draws from the HTTP Signature Algorithms registry.
 * The editor's copy (WG PR #139, merged 2026-10-09) has a directory JWK's
 * `alg` member follow RFC 7517 Section 4.4 instead, so `ES256` in a directory
 * is conformant while the wire parameter stays `ecdsa-p256-sha256`.
 *
 * This implementation verifies ed25519 and ecdsa-p256-sha256 (the UCP
 * signatures spec recommends ES256, and Shopify ships UCP). RSA is a stated
 * non-goal for now: RSA keys and rsa-* algorithms are rejected with a message
 * that says what we do verify, never dropped silently.
 */

/** HTTP Signature Algorithms registry names this implementation verifies. */
export type WebBotAuthKeyAlgorithm = 'ed25519' | 'ecdsa-p256-sha256';

/**
 * The one signature algorithm a directory key can verify, derived from its
 * curve. A parsed key with no `crv` predates the EC support and is Ed25519.
 */
export function directoryKeyAlgorithm(key: Pick<WebBotAuthKey, 'crv'>): WebBotAuthKeyAlgorithm {
  return key.crv === 'P-256' ? 'ecdsa-p256-sha256' : 'ed25519';
}

/** The key's JWK, rebuilt from the parsed material (never the raw entry). */
export function directoryKeyJwk(key: WebBotAuthKey): Record<string, string> {
  return key.crv === 'P-256'
    ? { kty: 'EC', crv: 'P-256', x: key.x, y: key.y ?? '' }
    : { kty: 'OKP', crv: 'Ed25519', x: key.x };
}

/**
 * Verify an RFC 9421 signature base against a directory key with the key's
 * own algorithm. ECDSA signature bytes are the raw 64-byte r||s concatenation
 * RFC 9421 Section 3.3.4 requires, never DER.
 */
export function verifyWithDirectoryKey(
  key: WebBotAuthKey,
  signatureBase: string,
  signature: Buffer,
): boolean {
  return directoryKeyAlgorithm(key) === 'ecdsa-p256-sha256'
    ? verifyEcdsaP256Sha256(directoryKeyJwk(key), signatureBase, signature)
    : verifyEd25519(directoryKeyJwk(key), signatureBase, signature);
}
