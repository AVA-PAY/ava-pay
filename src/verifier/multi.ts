import type { AgentVerifier } from './interface.js';
import type { IncomingRequest, VerificationResult } from '../types.js';

/**
 * MultiProtocolVerifier — sniffs the incoming request to decide which
 * underlying verifier to call.
 *
 * The whole point of AVA Pay's positioning is "merchants install once, every
 * agent works." This dispatcher is what makes that true — the merchant's
 * Shopify plugin doesn't know whether the agent spoke Visa TAP or Google AP2;
 * it just calls /verify and gets the same VerificationResult shape back.
 *
 * Detection rules:
 *   - `signature-input` header → Visa TAP (RFC 9421)
 *   - `ap2-attestation` header → AP2
 *   - Both → ambiguous_protocol (signal to the agent: pick one)
 *   - Neither → missing_agent_credentials
 *
 * The protocol-specific verifiers are passed in by name. New protocols are
 * added by registering them in server.ts; this file doesn't change.
 */

export interface MultiProtocolVerifierOptions {
  visa: AgentVerifier;
  ap2: AgentVerifier;
}

export class MultiProtocolVerifier implements AgentVerifier {
  constructor(private readonly impls: MultiProtocolVerifierOptions) {}

  async verify(request: IncomingRequest): Promise<VerificationResult> {
    const hasVisa = 'signature-input' in request.headers && 'signature' in request.headers;
    const hasAp2 = 'ap2-attestation' in request.headers;

    if (hasVisa && hasAp2) {
      return {
        trusted: false,
        reason: 'ambiguous_protocol',
        message:
          'Request includes both Visa TAP and AP2 credentials. Send exactly one protocol per request.',
      };
    }
    if (hasVisa) return this.impls.visa.verify(request);
    if (hasAp2) return this.impls.ap2.verify(request);

    return {
      trusted: false,
      reason: 'missing_agent_credentials',
      message:
        'No supported protocol detected. Send Visa TAP (Signature + Signature-Input) or AP2 (Ap2-Attestation + Ap2-Cart-Mandate).',
    };
  }
}
