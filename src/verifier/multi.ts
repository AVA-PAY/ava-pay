import type { AgentVerifier } from './interface.js';
import type { IncomingRequest, VerificationResult } from '../types.js';

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
 */

export interface MultiProtocolVerifierOptions {
  /** AVA's TAP-style profile (x-ava-mandate). */
  visa: AgentVerifier;
  /** Visa's real Trusted Agent Protocol wire format. */
  visaTap: AgentVerifier;
  ap2: AgentVerifier;
  webBotAuth: AgentVerifier;
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
    const hasAp2 = 'ap2-attestation' in request.headers;

    if (hasHttpSig && hasAp2) {
      return {
        trusted: false,
        reason: 'ambiguous_protocol',
        message:
          'Request includes both an RFC 9421 signature and AP2 credentials. Send exactly one protocol per request.',
      };
    }
    if (hasWba) return this.impls.webBotAuth.verify(request);
    if (hasVisaTap) return this.impls.visaTap.verify(request);
    if (hasVisa) return this.impls.visa.verify(request);
    if (hasAp2) return this.impls.ap2.verify(request);

    return {
      trusted: false,
      reason: 'missing_agent_credentials',
      message:
        'No supported protocol detected. Send Visa TAP (Signature + Signature-Input), Web Bot Auth (Signature + Signature-Input + Signature-Agent, tag="web-bot-auth"), or AP2 (Ap2-Attestation + Ap2-Cart-Mandate).',
    };
  }
}
