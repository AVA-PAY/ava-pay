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
  asCheckoutMandate,
  asOpenCheckoutMandate,
  asOpenPaymentMandate,
  asPaymentMandate,
  checkCheckoutConstraints,
  checkPaymentConstraints,
  computeCheckoutHash,
  DEFAULT_CHECKOUT_EVALUATORS,
  DEFAULT_PAYMENT_EVALUATORS,
  parseCheckoutJwt,
  SdJwtError,
  verifyChain,
  type Checkout,
  type CheckoutConstraintEvaluator,
  type CheckoutMandate,
  type OpenCheckoutMandate,
  type PaymentConstraintEvaluator,
  type PaymentMandate,
  type VerifiedChain,
} from '@ava-pay/agent/protocol/ap2';
import { safeHost } from './mandate.js';
import { InMemoryReplayGuard, type ReplayGuard } from './replay.js';

/**
 * Ap2AgentVerifier — AP2 v0.2 (dSD-JWT mandate chains).
 *
 * CLEAN BREAK from v0.1: the Intent/Cart JWS-pair wire format
 * (Ap2-Attestation / Ap2-Cart-Mandate) is no longer verified — such requests
 * get a typed `unsupported_protocol_version` so old agents receive an
 * actionable answer, not a confusing parse error.
 *
 * v0.2 wire binding (AVA's HTTP binding of AP2, which itself specifies A2A
 * message transport, not HTTP headers):
 *
 *   Ap2-Checkout-Mandate: <open>~~<closed>    dSD-JWT chain (required)
 *   Ap2-Payment-Mandate:  <open>~~<closed>    dSD-JWT chain (optional)
 *
 * Pipeline per chain:
 *   1. Verify the delegation chain (root SD-JWT signed by a directory-resolved
 *      kid; each KB hop signed by the previous hop's cnf.jwk; sd_hash binding;
 *      typ discipline; iat/exp windows) — all in the SDK's verifyChain port of
 *      the reference implementation.
 *   2. Checkout chain: open mandate (vct mandate.checkout.open.1) + closed
 *      mandate (vct mandate.checkout.1); checkout_hash must equal the hash of
 *      the embedded merchant-signed checkout_jwt; the open mandate's
 *      constraints are evaluated against the Checkout payload via a PLUGGABLE
 *      evaluator registry (unknown constraint type = violation, fail closed).
 *   3. Payment chain (when present): open payment mandate + closed payment
 *      mandate; transaction_id must equal the checkout chain's checkout_hash;
 *      payment constraints evaluated via their own pluggable registry.
 *   4. Terminal-hop binding: aud must equal this merchant's origin, the nonce
 *      is required and single-use (shared ReplayGuard) — our stateless
 *      substitute for a verifier-issued challenge.
 *
 * The merchant-signed checkout_jwt is validated structurally and by hash
 * linkage; verifying the merchant's own signature requires the merchant's key
 * and is exposed as the pluggable `checkoutJwtValidator` hook.
 */

export interface Ap2AgentVerifierOptions {
  directory: AgentDirectory;
  clockSkewSeconds?: number;
  replayGuard?: ReplayGuard;
  now?: () => number;
  /** Pluggable checkout-constraint evaluators (defaults: allowed_merchants, line_items). */
  checkoutEvaluators?: ReadonlyMap<string, CheckoutConstraintEvaluator>;
  /** Pluggable payment-constraint evaluators (defaults: amount_range, allowed_payees, reference). */
  paymentEvaluators?: ReadonlyMap<string, PaymentConstraintEvaluator>;
  /**
   * Optional hook to verify the merchant-signed checkout_jwt (signature,
   * issuer). Default: structural + hash-linkage validation only, since the
   * merchant's signing key is deployment-specific. Return violations.
   */
  checkoutJwtValidator?: (checkoutJwt: string, checkout: Checkout) => string[];
}

const DEFAULT_SKEW = 30;
const DEFAULT_TTL_SECONDS = 60;

export class Ap2AgentVerifier implements AgentVerifier {
  private readonly directory: AgentDirectory;
  private readonly skew: number;
  private readonly replayGuard: ReplayGuard;
  private readonly now: () => number;
  private readonly checkoutEvaluators: ReadonlyMap<string, CheckoutConstraintEvaluator>;
  private readonly paymentEvaluators: ReadonlyMap<string, PaymentConstraintEvaluator>;
  private readonly checkoutJwtValidator: ((jwt: string, checkout: Checkout) => string[]) | undefined;

  constructor(opts: Ap2AgentVerifierOptions) {
    this.directory = opts.directory;
    this.skew = opts.clockSkewSeconds ?? DEFAULT_SKEW;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    // The internally-created guard must share the verifier's clock: with an
    // injected test clock but a wall-clock guard, stored nonce expiries (in
    // the frozen past) clamp to "now" and lapse one real second later —
    // replays were intermittently accepted on slow CI runners.
    this.replayGuard = opts.replayGuard ?? new InMemoryReplayGuard({ now: this.now });
    this.checkoutEvaluators = opts.checkoutEvaluators ?? DEFAULT_CHECKOUT_EVALUATORS;
    this.paymentEvaluators = opts.paymentEvaluators ?? DEFAULT_PAYMENT_EVALUATORS;
    this.checkoutJwtValidator = opts.checkoutJwtValidator;
  }

  async verify(request: IncomingRequest): Promise<VerificationResult> {
    // v0.1 traffic gets an actionable, typed answer.
    if (request.headers['ap2-attestation'] !== undefined) {
      return fail(
        'unsupported_protocol_version',
        'AP2 v0.1 (Ap2-Attestation / Ap2-Cart-Mandate) is no longer supported. Send an AP2 v0.2 Ap2-Checkout-Mandate dSD-JWT chain.',
      );
    }

    const checkoutChainToken = request.headers['ap2-checkout-mandate'];
    if (!checkoutChainToken) {
      return fail(
        'missing_agent_credentials',
        'AP2 v0.2 requires an Ap2-Checkout-Mandate header carrying a dSD-JWT chain.',
      );
    }

    const merchantHost = safeHost(request.url);
    if (!merchantHost) {
      return fail('malformed_jws', `Request URL has no valid host: ${request.url}`);
    }
    const expectedAud = `https://${merchantHost}`;

    // ── 1+2. Checkout mandate chain ───────────────────────────────────────
    const checkoutOutcome = await this.verifyMandateChain(checkoutChainToken, expectedAud);
    if (!checkoutOutcome.ok) return checkoutOutcome.failure;

    const { chain, rootKid } = checkoutOutcome;
    let open: OpenCheckoutMandate;
    let closed: CheckoutMandate;
    try {
      if (chain.payloads.length !== 2) {
        throw new SdJwtError(
          `Checkout mandate chain requires exactly 2 payloads, got ${chain.payloads.length}`,
        );
      }
      open = asOpenCheckoutMandate(chain.payloads[0]!);
      closed = asCheckoutMandate(chain.payloads[1]!);
    } catch (err) {
      return fail('malformed_jws', err instanceof Error ? err.message : 'Malformed mandate chain.');
    }

    // Hash linkage: the closed mandate commits to exactly this checkout.
    if (computeCheckoutHash(closed.checkout_jwt) !== closed.checkout_hash) {
      return fail(
        'checkout_hash_mismatch',
        'checkout_hash does not match the hash of the embedded checkout_jwt.',
      );
    }

    let checkout: Checkout;
    try {
      checkout = parseCheckoutJwt(closed.checkout_jwt);
    } catch (err) {
      return fail('malformed_jws', err instanceof Error ? err.message : 'Malformed checkout_jwt.');
    }

    // The checkout must belong to THIS merchant.
    const checkoutMerchantUrl = checkout.merchant?.url;
    if (typeof checkoutMerchantUrl === 'string' && safeHost(checkoutMerchantUrl) !== merchantHost) {
      return fail(
        'mandate_merchant_mismatch',
        `Checkout is for ${safeHost(checkoutMerchantUrl) ?? '(unknown)'}; request hit ${merchantHost}.`,
      );
    }

    // Open-mandate constraints (pluggable; unknown constraint = violation).
    const violations = checkCheckoutConstraints(open, checkout, this.checkoutEvaluators);
    if (this.checkoutJwtValidator) {
      violations.push(...this.checkoutJwtValidator(closed.checkout_jwt, checkout));
    }
    if (violations.length > 0) {
      return fail('mandate_constraint_violation', violations.join(' | '));
    }

    // ── 4. Terminal binding: single-use nonce ─────────────────────────────
    const nonce = chain.terminal.nonce;
    if (!nonce) {
      return fail('mandate_chain_mismatch', 'Terminal hop must carry a nonce.');
    }
    const closedExp = typeof closed.exp === 'number' ? closed.exp : this.now() + 600;
    const fresh = await this.replayGuard.checkAndStore(
      `ap2:${rootKid}:${nonce}`,
      closedExp + this.skew,
    );
    if (!fresh) {
      return fail('replay_detected', 'This mandate presentation nonce has already been used.');
    }

    // ── 3. Payment mandate chain (optional) ───────────────────────────────
    let payment: PaymentMandate | undefined;
    const paymentChainToken = request.headers['ap2-payment-mandate'];
    if (paymentChainToken) {
      const paymentOutcome = await this.verifyMandateChain(paymentChainToken, expectedAud);
      if (!paymentOutcome.ok) return paymentOutcome.failure;
      try {
        if (paymentOutcome.chain.payloads.length !== 2) {
          throw new SdJwtError(
            `Payment mandate chain requires exactly 2 payloads, got ${paymentOutcome.chain.payloads.length}`,
          );
        }
        const openPayment = asOpenPaymentMandate(paymentOutcome.chain.payloads[0]!);
        payment = asPaymentMandate(paymentOutcome.chain.payloads[1]!);
        if (payment.transaction_id !== closed.checkout_hash) {
          return fail(
            'checkout_hash_mismatch',
            'Payment mandate transaction_id does not reference this checkout.',
          );
        }
        const paymentViolations = checkPaymentConstraints(
          openPayment,
          payment,
          { openCheckoutHash: closed.checkout_hash },
          this.paymentEvaluators,
        );
        if (paymentViolations.length > 0) {
          return fail('mandate_constraint_violation', paymentViolations.join(' | '));
        }
      } catch (err) {
        if (err instanceof SdJwtError) return fail('malformed_jws', err.message);
        throw err;
      }
    }

    // ── Compose ───────────────────────────────────────────────────────────
    const totalEntry = checkout.totals.find((t) => t.type === 'total') ?? checkout.totals[0];
    const amountMinor = payment?.payment_amount.amount ?? totalEntry?.amount ?? 0;
    const currency = payment?.payment_amount.currency ?? checkout.currency;

    const buyerInfo: BuyerInfo = {
      buyerId:
        typeof checkout.buyer === 'object' && checkout.buyer !== null && 'id' in checkout.buyer
          ? String((checkout.buyer as Record<string, unknown>)['id'])
          : `buyer_for_${closed.checkout_hash.slice(0, 12)}`,
    };
    const mandate: Mandate = {
      id: closed.checkout_hash,
      iat: typeof closed.iat === 'number' ? closed.iat : this.now(),
      exp: closedExp,
      maxAmountMinor: amountMinor,
      currency,
      allowedMerchants: [merchantHost],
      buyer: buyerInfo,
    };

    return {
      trusted: true,
      protocol: 'ap2',
      agent: { id: rootKid, protocol: 'ap2' },
      buyerInfo,
      mandate,
      ttlSeconds: DEFAULT_TTL_SECONDS,
    };
  }

  /** Verify one dSD-JWT chain with directory-resolved root key + aud enforcement. */
  private async verifyMandateChain(
    token: string,
    expectedAud: string,
  ): Promise<
    | { ok: true; chain: VerifiedChain; rootKid: string }
    | { ok: false; failure: VerificationResult }
  > {
    let rootKid = '';
    let unknownRoot = false;
    let revokedRoot = false;
    let chain: VerifiedChain;
    try {
      chain = await verifyChain(token, {
        rootKey: async (kid) => {
          rootKid = kid ?? '';
          if (!kid) return null;
          let record;
          try {
            record = await this.directory.resolve(kid, { protocol: 'ap2' });
          } catch {
            unknownRoot = true;
            return null;
          }
          if (!record) {
            unknownRoot = true;
            return null;
          }
          if (record.revoked) {
            revokedRoot = true;
            return null;
          }
          return record.publicKey;
        },
        expectedAud,
        clockSkewSeconds: this.skew,
        now: this.now,
      });
    } catch (err) {
      if (revokedRoot) {
        return { ok: false, failure: fail('revoked_agent', `Root key "${rootKid}" is revoked.`) };
      }
      if (unknownRoot) {
        return {
          ok: false,
          failure: fail('unknown_agent', `Root kid "${rootKid}" is not resolvable.`),
        };
      }
      const message = err instanceof Error ? err.message : 'Mandate chain verification failed.';
      const reason: VerificationFailureReason = /signature did not verify/.test(message)
        ? 'jws_signature_invalid'
        : /expired|iat is in the future/.test(message)
          ? 'mandate_expired'
          : /aud mismatch/.test(message)
            ? 'mandate_merchant_mismatch'
            : /sd_hash|issuer_jwt_hash|cnf|typ|aud|nonce|delegate/.test(message)
              ? 'mandate_chain_mismatch'
              : 'malformed_jws';
      return { ok: false, failure: fail(reason, message) };
    }
    if (chain.tokens.length < 2) {
      return {
        ok: false,
        failure: fail(
          'mandate_chain_mismatch',
          'A mandate presentation must be a delegation chain (open ~~ closed), not a bare root token.',
        ),
      };
    }
    return { ok: true, chain, rootKid };
  }
}

function fail(reason: VerificationFailureReason, message: string): VerificationResult {
  return { trusted: false, reason, message };
}
