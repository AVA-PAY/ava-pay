import type { AgentVerifier } from './interface.js';
import type { IncomingRequest, VerificationResult } from '../types.js';
import { rejection } from '../types.js';
import type { AgentDirectory } from './agent-directory.js';
import { decodeMandate, isMerchantAllowed, MandateParseError, safeHost } from './mandate.js';

/**
 * MockAgentVerifier — non-cryptographic stand-in.
 *
 * Useful for testing route + framework wiring without setting up real
 * Ed25519 keypairs. Reads a tiny header set:
 *
 *   x-ava-agent-id        agent identifier (must exist + not be revoked in directory)
 *   x-ava-signature       any value except "bad" passes; "bad" → invalid_signature
 *   x-ava-mandate         base64-encoded JSON mandate
 *   x-ava-mock-discount   optional fraction (e.g. "0.1") that overrides any default
 *
 * The verifier shares the same AgentDirectory abstraction as VisaAgentVerifier,
 * so test fixtures can register/revoke agents the same way for both code paths.
 *
 * BuyerInfo source: the optional `buyer` field on the mandate, falling back to
 * a synthesized id. (The old mock had a parallel buyer store; the directory
 * isn't responsible for buyer identity, the mandate is.)
 */
export class MockAgentVerifier implements AgentVerifier {
  constructor(
    private readonly directory: AgentDirectory,
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  async verify(request: IncomingRequest): Promise<VerificationResult> {
    const agentId = request.headers['x-ava-agent-id'];
    const signature = request.headers['x-ava-signature'];
    const mandateRaw = request.headers['x-ava-mandate'];

    if (!agentId || !signature || !mandateRaw) {
      return rejection(
        'missing_agent_credentials',
        'Required headers x-ava-agent-id, x-ava-signature, x-ava-mandate are missing.',
      );
    }

    const record = await this.directory.resolve(agentId);
    if (!record) {
      return rejection(
        'unknown_agent',
        `Agent "${agentId}" is not registered.`,
      );
    }
    if (record.revoked) {
      return rejection(
        'revoked_agent',
        `Agent "${agentId}" has been revoked.`,
      );
    }

    if (signature === 'bad') {
      return rejection(
        'invalid_signature',
        'Cryptographic signature did not verify against the registered key.',
      );
    }

    let mandate;
    try {
      mandate = decodeMandate(mandateRaw);
    } catch (err) {
      return rejection(
        'malformed_mandate',
        err instanceof MandateParseError ? err.message : 'Mandate could not be parsed.',
      );
    }

    const now = this.now();
    if (mandate.exp <= now) {
      return rejection(
        'mandate_expired',
        `Mandate ${mandate.id} expired at ${mandate.exp} (now=${now}).`,
      );
    }

    const merchantHost = safeHost(request.url);
    if (!isMerchantAllowed(mandate, merchantHost)) {
      return rejection(
        'mandate_merchant_mismatch',
        `Mandate ${mandate.id} does not authorize purchases on ${merchantHost ?? '(unknown host)'}.`,
      );
    }

    const buyerInfo = mandate.buyer ?? { buyerId: `buyer_for_${mandate.id}` };

    const discount =
      parseDiscount(request.headers['x-ava-mock-discount']) ?? defaultDiscount(agentId);

    return {
      trusted: true,
      conclusive: true,
      buyerInfo,
      mandate,
      ...(discount !== undefined ? { discount } : {}),
      ttlSeconds: 60,
    };
  }
}

function parseDiscount(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > 1) return undefined;
  return n;
}

function defaultDiscount(agentId: string): number | undefined {
  if (agentId === 'agent_demo') return 0.1;
  return undefined;
}
