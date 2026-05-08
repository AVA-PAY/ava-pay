import type { AgentVerifier } from './interface.js';
import type {
  BuyerInfo,
  IncomingRequest,
  Mandate,
  VerificationFailureReason,
  VerificationResult,
} from '../types.js';
import type { AgentDirectory } from './agent-directory.js';
import {
  JwsParseError,
  parseJws,
  verifyJws,
  type ParsedJws,
} from '../protocol/ap2/jws.js';
import type {
  CartMandateClaims,
  IntentMandateClaims,
} from '../protocol/ap2/types.js';
import { safeHost } from './mandate.js';

/**
 * Ap2AgentVerifier — Google Agent Payments Protocol verification.
 *
 * Same `AgentVerifier` interface as VisaAgentVerifier so the route, the
 * AgentDirectory, and the Shopify plugin don't know which protocol they're
 * dealing with.
 *
 * Pipeline:
 *   1. Read `Ap2-Attestation` (intent JWS) and `Ap2-Cart-Mandate` (cart JWS)
 *      from the request headers. Either missing → missing_agent_credentials.
 *   2. Parse both JWSes (header.payload.signature, base64url).
 *   3. Resolve the agent in the directory by the JWS header's `kid`. The cart
 *      mandate's `kid` MUST match the intent mandate's. If different agents
 *      signed the two halves, the chain is broken.
 *   4. Verify both signatures against the directory's public key.
 *   5. Validate claim freshness (iat/exp), spend limit (cart total ≤ intent
 *      spend_limit), merchant scope (cart.merchant ∈ intent.allowed_merchants).
 *   6. Project into the existing VerificationResult shape so downstream
 *      callers (the route, the Shopify plugin) work without changes.
 *
 * Returns the same `Mandate` shape as the Visa path so the response is
 * protocol-agnostic. Future iterations could expose AP2-native fields
 * separately, but unifying the surface is the whole point of this layer.
 */

export interface Ap2AgentVerifierOptions {
  directory: AgentDirectory;
  /** Tolerated clock skew on iat/exp, in seconds. */
  clockSkewSeconds?: number;
  now?: () => number;
}

const DEFAULT_SKEW = 30;
const DEFAULT_TTL_SECONDS = 60;

export class Ap2AgentVerifier implements AgentVerifier {
  private readonly directory: AgentDirectory;
  private readonly skew: number;
  private readonly now: () => number;

  constructor(opts: Ap2AgentVerifierOptions) {
    this.directory = opts.directory;
    this.skew = opts.clockSkewSeconds ?? DEFAULT_SKEW;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async verify(request: IncomingRequest): Promise<VerificationResult> {
    const intentToken = request.headers['ap2-attestation'];
    const cartToken = request.headers['ap2-cart-mandate'];

    if (!intentToken || !cartToken) {
      return fail(
        'missing_agent_credentials',
        'AP2 requires Ap2-Attestation and Ap2-Cart-Mandate headers.',
      );
    }

    let intent: ParsedJws<IntentMandateClaims>;
    let cart: ParsedJws<CartMandateClaims>;
    try {
      intent = parseJws<IntentMandateClaims>(intentToken);
      cart = parseJws<CartMandateClaims>(cartToken);
    } catch (err) {
      if (err instanceof JwsParseError && /Unsupported alg/.test(err.message)) {
        return fail('jws_unsupported_algorithm', err.message);
      }
      return fail(
        'malformed_jws',
        err instanceof Error ? err.message : 'JWS could not be parsed.',
      );
    }

    // Both halves must have been signed by the same agent.
    if (intent.header.kid !== cart.header.kid) {
      return fail(
        'mandate_chain_mismatch',
        `Intent kid "${intent.header.kid}" does not match cart kid "${cart.header.kid}".`,
      );
    }
    if (intent.payload.iss !== cart.payload.iss) {
      return fail(
        'mandate_chain_mismatch',
        `Intent issuer "${intent.payload.iss}" does not match cart issuer "${cart.payload.iss}".`,
      );
    }
    if (cart.payload.ap2.intent_ref !== intent.payload.jti) {
      return fail(
        'cart_intent_mismatch',
        `Cart intent_ref "${cart.payload.ap2.intent_ref}" does not match intent jti "${intent.payload.jti}".`,
      );
    }

    const agentId = intent.header.kid;
    let record;
    try {
      record = await this.directory.resolve(agentId);
    } catch {
      return fail('unknown_agent', `Agent directory lookup for "${agentId}" failed.`);
    }
    if (!record) return fail('unknown_agent', `Agent "${agentId}" is not in the directory.`);
    if (record.revoked) return fail('revoked_agent', `Agent "${agentId}" is revoked.`);

    if (!verifyJws(intent, record.publicKey)) {
      return fail('jws_signature_invalid', 'Intent mandate signature did not verify.');
    }
    if (!verifyJws(cart, record.publicKey)) {
      return fail('jws_signature_invalid', 'Cart mandate signature did not verify.');
    }

    const now = this.now();
    if (intent.payload.exp + this.skew < now) {
      return fail('mandate_expired', `Intent mandate expired at ${intent.payload.exp}.`);
    }
    if (cart.payload.exp + this.skew < now) {
      return fail('mandate_expired', `Cart mandate expired at ${cart.payload.exp}.`);
    }
    if (intent.payload.iat > now + this.skew) {
      return fail('mandate_expired', `Intent mandate issued in the future (iat=${intent.payload.iat}).`);
    }
    if (cart.payload.iat > now + this.skew) {
      return fail('mandate_expired', `Cart mandate issued in the future (iat=${cart.payload.iat}).`);
    }

    // Spend limit
    if (cart.payload.ap2.total.currency !== intent.payload.ap2.spend_limit.currency) {
      return fail(
        'cart_exceeds_intent_limit',
        `Currency mismatch: cart=${cart.payload.ap2.total.currency}, intent=${intent.payload.ap2.spend_limit.currency}.`,
      );
    }
    if (cart.payload.ap2.total.value > intent.payload.ap2.spend_limit.value) {
      return fail(
        'cart_exceeds_intent_limit',
        `Cart total ${cart.payload.ap2.total.value} exceeds intent limit ${intent.payload.ap2.spend_limit.value}.`,
      );
    }

    // Merchant scope: take from cart, validate against intent's allowed list AND
    // the request URL's host (defense in depth: even a valid cart shouldn't be
    // re-used at a different merchant).
    const requestHost = safeHost(request.url);
    const allowed = intent.payload.ap2.allowed_merchants;
    const cartMerchant = cart.payload.ap2.merchant;
    const merchantOk =
      allowed.includes('*') || allowed.includes(cartMerchant);
    if (!merchantOk) {
      return fail(
        'mandate_merchant_mismatch',
        `Cart merchant "${cartMerchant}" not in intent allowed_merchants.`,
      );
    }
    if (requestHost !== null && requestHost !== cartMerchant) {
      return fail(
        'mandate_merchant_mismatch',
        `Cart merchant "${cartMerchant}" does not match request host "${requestHost}".`,
      );
    }

    // Project AP2 into the unified VerificationResult shape.
    const buyerInfo: BuyerInfo = { buyerId: intent.payload.ap2.sub };

    const projectedMandate: Mandate = {
      id: intent.payload.jti,
      iat: intent.payload.iat,
      exp: intent.payload.exp,
      maxAmountMinor: intent.payload.ap2.spend_limit.value,
      currency: intent.payload.ap2.spend_limit.currency,
      allowedMerchants: intent.payload.ap2.allowed_merchants,
      buyer: buyerInfo,
    };

    return {
      trusted: true,
      buyerInfo,
      mandate: projectedMandate,
      ttlSeconds: DEFAULT_TTL_SECONDS,
    };
  }
}

function fail(reason: VerificationFailureReason, message: string): VerificationResult {
  return { trusted: false, reason, message };
}
