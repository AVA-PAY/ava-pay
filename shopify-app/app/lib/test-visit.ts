/**
 * "Send test agent visit": prove a store's AVA Pay setup works without waiting
 * for a real AI shopping agent to turn up.
 *
 * The merchant presses a button in Settings; we sign a Visa Trusted Agent
 * Protocol request server side with AVA Pay's public demo credential, put it
 * through the same `/verify` call and the same `decideVerification()` the App
 * Proxy path uses, and record the same VerificationEvent row. Nothing about the
 * verdict is simulated: the signature is real, the hosted verifier checks it
 * against the directory, and merchant policy decides the outcome.
 *
 * Two deliberate differences from a proxy-delivered request, both recorded
 * rather than papered over:
 *
 *   1. The request never touches the storefront. Development stores cannot
 *      switch their storefront password off, so routing a test through
 *      https://{shop}/apps/... would make the button depend on a password the
 *      merchant would have to type. We call the verify path server side, and
 *      the signed URL still names what the agent signed against, which is what
 *      the verifier needs.
 *   2. No discount code is minted. A button in Settings must not write real
 *      discount objects into a merchant's store, so the result reports the
 *      percentage the policy WOULD apply, with no code attached. Real agent
 *      traffic still mints codes exactly as before.
 *
 * The row carries source='test' so the Traffic page can label it, and so a
 * merchant-initiated request is never presented as organic agent traffic.
 *
 * Three modules, split by what can run where:
 *   test-visit.ts          this file. The verdict shaping and the sentence the
 *                          merchant reads. No node builtins, so the Settings
 *                          component can import it into the browser bundle.
 *   test-visit-request.ts  signing, via node:crypto and @ava-pay/agent.
 *   test-visit.server.ts   the I/O: settings, the verify call, the event write.
 */

import type { AvaCallResult } from './ava.server.js';
import type { IncomingRequest } from './ava-types.js';
import type { MerchantPolicyInput } from './policy.js';
import {
  decideVerification,
  type VerificationEventDraft,
  type VerificationOutcome,
} from './verify-flow.js';

/** What the merchant is told, and what the recorded row says. */
export interface TestVisitResult {
  outcome: VerificationOutcome;
  /** Typed failure/policy reason. Null when verified. */
  reason: string | null;
  protocol: string | null;
  platform: string | null;
  /**
   * Percentage the merchant's policy would apply to this agent. No code is
   * minted for a test visit, so this is what a real visit would have received.
   */
  discountPct: number;
}

export interface TestVisitDecision {
  /** The VerificationEvent row to write, minus shop. */
  event: VerificationEventDraft & { source: 'test' };
  result: TestVisitResult;
}

/**
 * Turn the verify call into the row and the merchant-facing verdict.
 *
 * Every branch goes through decideVerification, so a test visit cannot report
 * something the real proxy path would not have said. The one thing we drop is
 * the minted discount: mintDiscountPct becomes the reported percentage instead
 * of an instruction to create a code.
 */
export function decideTestVisit(
  settings: MerchantPolicyInput,
  call: AvaCallResult,
  request: IncomingRequest,
): TestVisitDecision {
  const { event, mintDiscountPct } = decideVerification(settings, call, request.headers);
  return {
    event: { ...event, source: 'test' },
    result: {
      outcome: event.outcome,
      reason: event.reason,
      protocol: event.protocol,
      platform: event.platform,
      discountPct: mintDiscountPct,
    },
  };
}

/**
 * The merchant-facing sentence for a verdict.
 *
 * Same vocabulary the Traffic page and the storefront use: a verdict we could
 * not reach is never reported as a rejection, and an unreachable API is never
 * reported as a verdict at all.
 */
export function describeTestVisit(result: TestVisitResult): {
  tone: 'success' | 'warning' | 'critical';
  title: string;
  body: string;
} {
  switch (result.outcome) {
    case 'verified':
      return {
        tone: 'success',
        title: 'Verified',
        body:
          result.discountPct > 0
            ? `The test agent verified over ${result.protocol ?? 'its signed protocol'} and your policy would apply a ${result.discountPct}% discount. The visit now appears on the Traffic page, labelled as a test. No discount code was created.`
            : `The test agent verified over ${result.protocol ?? 'its signed protocol'}. Your policy admits it without a discount. The visit now appears on the Traffic page, labelled as a test.`,
      };
    case 'policy_blocked':
      return {
        tone: 'warning',
        title: 'Verified, then blocked by your settings',
        body: `The signature checked out, but your current policy turned the agent away (${result.reason ?? 'policy'}). The visit appears on the Traffic page, labelled as a test.`,
      };
    case 'failed':
      return {
        tone: 'critical',
        title: 'Not verified',
        body: `The verifier rejected the test credential (${result.reason ?? 'unknown reason'}). The visit appears on the Traffic page, labelled as a test.`,
      };
    case 'unverifiable':
      return {
        tone: 'warning',
        title: 'Could not check',
        body: `The verifier could not complete its checks (${result.reason ?? 'a trust root was unreachable'}), so nothing was proved either way. This is not a rejection. Try again shortly.`,
      };
    default:
      return {
        tone: 'warning',
        title: 'Could not reach AVA Pay',
        body: `The verification service did not answer (${result.reason ?? 'unknown error'}), so the test visit could not be checked. Your storefront is unaffected: real agent requests fail closed and customers are never blocked.`,
      };
  }
}
