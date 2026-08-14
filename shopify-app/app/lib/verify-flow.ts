/**
 * The verify orchestration: the trust boundary, minus I/O.
 *
 * Given the merchant settings, the outcome of the AVA Pay /verify call, and the
 * incoming request headers, this decides (a) the VerificationEvent row to
 * record, (b) the JSON body to send the storefront, and (c) the discount
 * percentage to mint a code for. `routes/proxy.verify.tsx` does the I/O around
 * it; every decision lives here so each path is unit-testable without Shopify
 * auth or a database. The WooCommerce plugin's AVA_Pay_Verify_Flow is the twin
 * of this module, and the two are meant to stay in step.
 *
 * Fail closed everywhere: if AVA Pay is unreachable, or the agent fails
 * verification, or the verifier could not complete its checks, the answer is
 * `allow: false`. Storefront JS treats any of those as "no discount, proceed
 * normally" and never blocks the customer.
 */

import type { AvaCallResult } from './ava.server.js';
import type { VerificationResult } from './ava-types.js';
import { applyMerchantPolicy, type MerchantPolicyInput } from './policy.js';
import { extractAgentIdHint, sniffProtocolHint } from './request-hints.js';

/**
 * What a VerificationEvent row can say happened.
 *
 * `unverifiable` is the honest middle: the verifier could not complete its
 * checks (a trust root was unreachable), so nothing was proved either way. It
 * fails closed exactly like `failed`, but it is NOT a rejection and must never
 * be counted or displayed as one. See isConclusive().
 */
export type VerificationOutcome =
  | 'verified'
  | 'failed'
  | 'unverifiable'
  | 'policy_blocked'
  | 'error';

/** Storefront reason for a verdict the verifier could not complete. */
export const REASON_UNVERIFIABLE = 'verification_unavailable';

export interface ProxyResponseBody {
  allow: boolean;
  discount?: {
    code: string;
    percentage: number;
  };
  reason: string;
}

/** The VerificationEvent row, minus the fields only the route knows (shop, discountCode). */
export interface VerificationEventDraft {
  platform: string | null;
  protocol: string | null;
  outcome: VerificationOutcome;
  reason: string | null;
  identityOnly?: boolean;
  discountPct?: number;
}

export interface VerifyDecision {
  event: VerificationEventDraft;
  response: ProxyResponseBody;
  /** Percentage to mint a discount code for. 0 means no code. */
  mintDiscountPct: number;
}

/**
 * Did the verifier complete its checks?
 *
 * `conclusive` is additive on the API's VerificationResult: false ONLY on
 * could-not-check paths, where a trust root was unreachable (reason
 * `directory_unavailable` or `key_directory_unavailable`); true when the
 * request was definitively rejected. An absent value reads as true, matching
 * the API's own forward-compatibility rule, so verdicts from an older API build
 * (or cached before the field existed) keep their meaning instead of silently
 * becoming "could not check". A present but non-boolean value is malformed
 * rather than a signal, and is read the same way as absent.
 *
 * Either way the caller still fails closed. This only decides what we say.
 */
export function isConclusive(result: VerificationResult): boolean {
  return typeof result.conclusive === 'boolean' ? result.conclusive : true;
}

export function decideVerification(
  settings: MerchantPolicyInput,
  call: AvaCallResult,
  headers: Record<string, string>,
): VerifyDecision {
  const platformHint = extractAgentIdHint(headers);
  // What the request was attempting. A rejected or unverifiable verdict carries
  // no protocol of its own, so without this a non-verified row cannot be told
  // apart from any other.
  const protocolHint = sniffProtocolHint(headers);

  if (!call.ok) {
    const reason = `ava_${call.error}`;
    return {
      event: { platform: platformHint, protocol: protocolHint, outcome: 'error', reason },
      response: { allow: false, reason },
      mintDiscountPct: 0,
    };
  }

  const result = call.result;

  if (!result.trusted) {
    // An untrusted verdict is either "we checked and rejected it" or "we never
    // managed to check", and telling a merchant we blocked an agent when we
    // could not reach a trust root is a claim we cannot support. Both stay
    // allow:false; only the story changes.
    //
    // A separate outcome value rather than an overloaded 'failed' with a
    // distinguishing reason: the reason column already carries the typed API
    // reason (which is what makes the row diagnosable), and the vocabulary of
    // could-not-check reasons will grow, so any later reader counting real
    // rejections would have to know the full list. The outcome answers it
    // directly.
    const conclusive = isConclusive(result);
    return {
      event: {
        platform: platformHint,
        protocol: protocolHint,
        outcome: conclusive ? 'failed' : 'unverifiable',
        reason: result.reason,
      },
      response: {
        allow: false,
        reason: conclusive ? 'agent_blocked' : REASON_UNVERIFIABLE,
      },
      mintDiscountPct: 0,
    };
  }

  const platform = result.agent?.id ?? platformHint;
  const protocol = result.protocol ?? result.agent?.protocol ?? protocolHint;
  const identityOnly = !result.mandate;

  const decision = applyMerchantPolicy(settings, result, platform);

  if (!decision.allow) {
    return {
      event: {
        platform,
        protocol,
        outcome: 'policy_blocked',
        reason: decision.reason,
        identityOnly,
      },
      response: { allow: false, reason: decision.reason },
      mintDiscountPct: 0,
    };
  }

  return {
    event: {
      platform,
      protocol,
      outcome: 'verified',
      reason: null,
      identityOnly,
      discountPct: decision.discountPct,
    },
    response: { allow: true, reason: 'verified' },
    mintDiscountPct: decision.discountPct,
  };
}
