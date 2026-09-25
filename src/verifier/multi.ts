import type { AgentVerifier } from './interface.js';
import { annotateWithOperator, type OperatorSource } from './operator-source.js';
import type { IncomingRequest, VerificationResult } from '../types.js';
import { rejection } from '../types.js';

/**
 * MultiProtocolVerifier — sniffs the incoming request to decide which
 * underlying verifier to call.
 *
 * The whole point of AVA Pay's positioning is "merchants install once, every
 * agent works." This dispatcher is what makes that true — the merchant's
 * Shopify plugin doesn't know whether the agent spoke Visa TAP, Google AP2,
 * or IETF Web Bot Auth; it just calls /verify and gets the same
 * VerificationResult shape back.
 *
 * Detection rules:
 *   - `signature-input` + `signature` headers → an RFC 9421 protocol, split
 *     by the spec-mandated tag:
 *       - tag="web-bot-auth", or a Signature-Agent header → Web Bot Auth
 *         (ChatGPT/Claude/Perplexity agent traffic)
 *       - tag="agent-browser-auth" | "agent-payer-auth" → real Visa TAP
 *       - no tag → AVA's TAP-style profile (x-ava-mandate)
 *   - `ap2-attestation` header → AP2
 *   - RFC 9421 + AP2 together → ambiguous_protocol (signal to the agent: pick one)
 *   - Neither → missing_agent_credentials
 *
 * The protocol-specific verifiers are passed in by name. New protocols are
 * added by registering them in server.ts and adding a sniff rule here.
 *
 * An optional OperatorSource hangs off the same seam. It runs after whichever
 * verifier answered, only for a verified result, and only ever adds
 * `result.operator` provenance. Dispatch is the right place for it precisely
 * because it is protocol-agnostic: accountability for an origin does not depend
 * on which protocol proved the request came from there. See
 * docs/RESOLVER-SOURCES.md.
 */

export interface MultiProtocolVerifierOptions {
  /** AVA's TAP-style profile (x-ava-mandate). */
  visa: AgentVerifier;
  /** Visa's real Trusted Agent Protocol wire format. */
  visaTap: AgentVerifier;
  ap2: AgentVerifier;
  webBotAuth: AgentVerifier;
  /**
   * Optional accountability provenance for verified origins. Default none, in
   * which case results are byte-for-byte what the verifiers returned.
   */
  operator?: OperatorSource;
}

export class MultiProtocolVerifier implements AgentVerifier {
  constructor(private readonly impls: MultiProtocolVerifierOptions) {}

  async verify(request: IncomingRequest): Promise<VerificationResult> {
    const sigInput = request.headers['signature-input'];
    const hasHttpSig = sigInput !== undefined && 'signature' in request.headers;
    // All RFC 9421 protocols share the same two headers; the spec-mandated
    // tag disambiguates (plus Signature-Agent, which only WBA sends).
    const hasWba =
      hasHttpSig && (/[;\s]tag="web-bot-auth"/.test(sigInput) || 'signature-agent' in request.headers);
    const hasVisaTap =
      hasHttpSig && !hasWba && /[;\s]tag="(agent-browser-auth|agent-payer-auth)"/.test(sigInput);
    const hasVisa = hasHttpSig && !hasWba && !hasVisaTap;
    // v0.2 chains (ap2-checkout-mandate) and legacy v0.1 (ap2-attestation,
    // which the AP2 verifier answers with unsupported_protocol_version).
    const hasAp2 =
      'ap2-checkout-mandate' in request.headers || 'ap2-attestation' in request.headers;

    if (hasHttpSig && hasAp2) {
      return rejection(
        'ambiguous_protocol',
        'Request includes both an RFC 9421 signature and AP2 credentials. Send exactly one protocol per request.',
      );
    }
    if (hasWba) return this.annotate(await this.impls.webBotAuth.verify(request));
    if (hasVisaTap) return this.annotate(await this.impls.visaTap.verify(request));
    if (hasVisa) return this.annotate(await this.impls.visa.verify(request));
    if (hasAp2) return this.annotate(await this.impls.ap2.verify(request));

    return rejection(
      'missing_agent_credentials',
      'No supported protocol detected. Send Visa TAP (Signature + Signature-Input), Web Bot Auth (Signature + Signature-Input + Signature-Agent, tag="web-bot-auth"), or AP2 v0.2 (Ap2-Checkout-Mandate dSD-JWT chain).',
    );
  }

  /**
   * Attach operator provenance to a verified result. Failed and inconclusive
   * results never reach the source: annotateWithOperator re-checks that itself,
   * so the invariant holds even if this call site changes.
   */
  private annotate(result: VerificationResult): Promise<VerificationResult> {
    return annotateWithOperator(result, this.impls.operator, originOf(result));
  }
}

/**
 * The https origin a verified result is about, or undefined when there is none
 * to ask about. Web Bot Auth identities ARE origins; other protocols may
 * identify an agent by an opaque id, and an opaque id is not a name a registry
 * can be asked about, so we do not guess one.
 */
function originOf(result: VerificationResult): string | undefined {
  if (!result.trusted) return undefined;
  const id = result.agent?.id;
  if (!id) return undefined;
  let url: URL;
  try {
    url = new URL(id);
  } catch {
    return undefined;
  }
  return url.protocol === 'https:' ? url.origin : undefined;
}
