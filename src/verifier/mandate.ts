import type { Mandate } from '../types.js';

/**
 * Mandate parsing + scope validation, shared by MockAgentVerifier and
 * VisaAgentVerifier.
 *
 * In the real Visa Trusted Agent Protocol, the mandate is itself a JWS signed
 * by the buyer's wallet (e.g. AVA Pass). The verifier *should* validate that
 * inner signature too. We don't yet — the AVA Pass mandate-signing key
 * infrastructure isn't built. For now, we treat the mandate header as a JSON
 * payload whose authenticity is implicitly tied to the agent's signature
 * (since the mandate is in the cover set of the HTTP signature).
 */

export class MandateParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MandateParseError';
  }
}

/** Decode a base64-encoded JSON mandate from the `x-ava-mandate` header. */
export function decodeMandate(raw: string): Mandate {
  let json: string;
  try {
    json = Buffer.from(raw, 'base64').toString('utf-8');
  } catch {
    throw new MandateParseError('Mandate header is not valid base64.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new MandateParseError('Mandate payload is not valid JSON.');
  }
  if (!isMandate(parsed)) {
    throw new MandateParseError('Mandate JSON is missing required fields.');
  }
  return parsed;
}

function isMandate(value: unknown): value is Mandate {
  if (typeof value !== 'object' || value === null) return false;
  const m = value as Record<string, unknown>;
  return (
    typeof m.id === 'string' &&
    typeof m.iat === 'number' &&
    typeof m.exp === 'number' &&
    typeof m.maxAmountMinor === 'number' &&
    typeof m.currency === 'string' &&
    Array.isArray(m.allowedMerchants) &&
    m.allowedMerchants.every((x) => typeof x === 'string')
  );
}

export function safeHost(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

export function isMerchantAllowed(mandate: Mandate, host: string | null): boolean {
  if (mandate.allowedMerchants.includes('*')) return true;
  if (host === null) return false;
  return mandate.allowedMerchants.includes(host);
}
