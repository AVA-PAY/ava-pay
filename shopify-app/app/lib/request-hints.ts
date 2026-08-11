/**
 * Best-effort labels read off an incoming agent request, for the Traffic
 * dashboard. Telemetry only: the AVA Pay verifier on the API side is the
 * authority on what a request actually is, and these are what we can say about
 * a request that never got that far.
 *
 * They matter most on failures. A trusted verdict carries its own protocol and
 * identity, but a rejected one carries neither, so without these a failed row
 * reads "something was refused" with no way to tell a malformed Web Bot Auth
 * request from an expired Visa TAP one.
 */

/** Protocols the dispatcher can route to, as the verdict spells them. */
export type ProtocolHint = 'web-bot-auth' | 'visa-tap' | 'ava-tap' | 'ap2';

/**
 * Which protocol the request was *attempting*, mirroring the sniff rules in
 * the API's MultiProtocolVerifier. Null when nothing recognisable was sent, or
 * when the request carries two protocols at once, which the verifier rejects as
 * ambiguous rather than picking one.
 */
export function sniffProtocolHint(headers: Record<string, string>): ProtocolHint | null {
  const sigInput = headers['signature-input'];
  const hasHttpSig = sigInput !== undefined && 'signature' in headers;
  const hasAp2 = 'ap2-checkout-mandate' in headers || 'ap2-attestation' in headers;

  if (hasHttpSig && hasAp2) return null;
  if (hasHttpSig) {
    if (/[;\s]tag="web-bot-auth"/.test(sigInput) || 'signature-agent' in headers) {
      return 'web-bot-auth';
    }
    if (/[;\s]tag="(agent-browser-auth|agent-payer-auth)"/.test(sigInput)) return 'visa-tap';
    // No tag and no Signature-Agent: AVA's own TAP-style profile.
    return 'ava-tap';
  }
  if (hasAp2) return 'ap2';
  return null;
}

/**
 * A dashboard label for who sent this.
 *
 * Web Bot Auth requests carry the agent operator's origin in Signature-Agent
 * (e.g. "https://chatgpt.com"), a far better label for a merchant than the key
 * thumbprint in keyid, which rotates and means nothing to them. TAP requests
 * have no Signature-Agent, so they fall back to keyid, which is the agent id.
 */
export function extractAgentIdHint(headers: Record<string, string>): string | null {
  const sigAgent = headers['signature-agent'];
  if (sigAgent) {
    // Matches both wire forms: "https://origin" and sig1="https://origin".
    const m = sigAgent.match(/"(https:\/\/[^"]+)"/);
    if (m?.[1]) {
      try {
        return new URL(m[1]).origin.toLowerCase();
      } catch {
        // Not a usable URL; fall through to keyid.
      }
    }
  }
  const sigInput = headers['signature-input'];
  if (!sigInput) return null;
  return sigInput.match(/keyid="([^"]+)"/)?.[1] ?? null;
}
