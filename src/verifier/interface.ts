import type { IncomingRequest, VerificationResult } from '../types.js';

/**
 * The single seam between the /verify route and the cryptographic engine.
 *
 * MockAgentVerifier (used today) and a future VisaTrustedAgentVerifier both
 * implement this interface. Routes never import a concrete verifier directly —
 * they take an AgentVerifier in their factory function. That makes swapping
 * implementations a one-line change in src/server.ts.
 */
export interface AgentVerifier {
  verify(request: IncomingRequest): Promise<VerificationResult>;
}
