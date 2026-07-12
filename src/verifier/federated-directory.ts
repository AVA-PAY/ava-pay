import { createPublicKey, type KeyObject } from 'node:crypto';
import type { AgentDirectory, AgentRecord, ResolveHints } from './agent-directory.js';
import type { VisaJwksResolver } from './visa-tap.js';
import type { SignatureAgentKeyResolver } from './web-bot-auth.js';

/**
 * FederatedAgentDirectory — resolve a wire key identifier against a chain of
 * roots of trust instead of a single directory.
 *
 * This is the strategic pivot made concrete: AVA's hosted directory stops
 * being "the" registry and becomes one source in a chain. Default order
 * (server.ts):
 *
 *   1. Visa's Agentic Directory (partner-gated remote, when configured)
 *   2. Visa's public JWKS (mcp.visa.com)
 *   3. Web Bot Auth key directories of allowlisted signature agents
 *      ("agent cards" — keys the agent operator publishes at their origin)
 *   4. The hosted AVA directory / private allowlist
 *
 * Semantics:
 *   - The first source that KNOWS the identifier wins — including a revoked
 *     record; revocation in a higher-priority root is definitive and is
 *     never shadowed by a lower source still listing the key.
 *   - A source that ERRORS (outage, timeout) is skipped: each source is an
 *     independently trusted root, so a hit in any remaining root stands on
 *     its own. The residual risk — a revocation unreadable during an outage
 *     while a lower source still lists the key — is accepted and documented;
 *     the alternative (fail the whole chain on any outage) couples every
 *     protocol's availability to every root's uptime.
 *   - Sources answer null for identifiers that aren't theirs (wrong shape,
 *     wrong algorithm family) so an accidental kid collision in one root
 *     can't shadow the right key in another.
 */

export interface FederatedSource {
  /** Short provenance label, e.g. "visa-jwks", "wba:https://chatgpt.com". */
  name: string;
  resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null>;
}

export class FederatedAgentDirectory implements AgentDirectory {
  constructor(private readonly sources: FederatedSource[]) {
    if (sources.length === 0) {
      throw new Error('FederatedAgentDirectory needs at least one source.');
    }
  }

  async resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null> {
    for (const source of this.sources) {
      let record: AgentRecord | null;
      try {
        record = await source.resolve(agentId, hints);
      } catch {
        continue; // source outage → try the next root of trust
      }
      if (record) {
        return { ...record, source: record.source ?? source.name };
      }
    }
    return null;
  }
}

/** Wrap any AgentDirectory as a named chain source. */
export function asSource(name: string, directory: AgentDirectory): FederatedSource {
  return {
    name,
    resolve: (agentId, hints) => directory.resolve(agentId, hints),
  };
}

// ─── Visa JWKS as a source ──────────────────────────────────────────────────

/**
 * Keys Visa publishes at its public JWKS, addressed by kid. Only answers for
 * algorithm hints an RSA key can actually satisfy — an ed25519-signed request
 * whose keyid happens to collide with a Visa kid must fall through, not stop
 * the chain with a key that can never verify.
 */
export class VisaJwksKeySource implements FederatedSource {
  readonly name = 'visa-jwks';

  constructor(private readonly resolver: VisaJwksResolver) {}

  async resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null> {
    if (hints?.alg && !isRsaAlg(hints.alg)) return null;
    const key = await this.resolver.resolve(agentId);
    if (!key) return null;
    return { agentId, publicKey: key.key, revoked: false, source: this.name };
  }
}

function isRsaAlg(alg: string): boolean {
  const lower = alg.toLowerCase();
  return lower === 'ps256' || lower === 'rsa-pss-sha256' || lower === 'rs256';
}

// ─── Web Bot Auth published keys as a source ────────────────────────────────

/**
 * Keys that allowlisted Signature-Agent operators publish at their
 * /.well-known/http-message-signatures-directory, addressed by RFC 7638
 * thumbprint. This lets an agent that already publishes a WBA key card use
 * that SAME key for Visa TAP / AP2 requests: publish once, verified
 * everywhere — the "one API" story.
 *
 * Only answers for 43-char base64url identifiers (thumbprint shape) and
 * ed25519-compatible algorithm hints; honors the published key's nbf/exp.
 * Origins are consulted in configured order.
 */
export interface WbaPublishedKeySourceOptions {
  resolver: SignatureAgentKeyResolver;
  /** Signature-agent origins to search, e.g. ["https://chatgpt.com"]. */
  origins: string[];
  /** Override "now" (seconds) for deterministic tests. */
  now?: () => number;
  /** Skew for nbf/exp checks, seconds. Default 30. */
  clockSkewSeconds?: number;
}

const THUMBPRINT_SHAPE = /^[A-Za-z0-9_-]{43}$/;

export class WbaPublishedKeySource implements FederatedSource {
  readonly name = 'wba-directory';
  private readonly resolver: SignatureAgentKeyResolver;
  private readonly origins: string[];
  private readonly now: () => number;
  private readonly skew: number;

  constructor(opts: WbaPublishedKeySourceOptions) {
    this.resolver = opts.resolver;
    this.origins = opts.origins;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.skew = opts.clockSkewSeconds ?? 30;
  }

  async resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null> {
    if (!THUMBPRINT_SHAPE.test(agentId)) return null;
    if (hints?.alg && !isEd25519Alg(hints.alg)) return null;

    const now = this.now();
    let sawOutage = false;
    for (const origin of this.origins) {
      let resolution;
      try {
        resolution = await this.resolver.resolve(origin);
      } catch {
        sawOutage = true;
        continue;
      }
      if (resolution.status === 'unavailable') {
        sawOutage = true;
        continue;
      }
      if (resolution.status !== 'ok') continue;
      const key = resolution.keys.find((k) => k.thumbprint === agentId);
      if (!key) continue;
      if (key.nbf !== undefined && key.nbf > now + this.skew) continue;
      if (key.exp !== undefined && key.exp + this.skew < now) continue;
      let publicKey: KeyObject;
      try {
        publicKey = createPublicKey({
          key: { kty: 'OKP', crv: 'Ed25519', x: key.x } as never,
          format: 'jwk',
        });
      } catch {
        continue;
      }
      return { agentId, publicKey, revoked: false, source: `wba:${origin}` };
    }
    // If every origin that could have answered was down, surface it as an
    // outage (skipped by the chain) rather than a definitive miss.
    if (sawOutage) throw new Error('all WBA key directories unavailable');
    return null;
  }
}

function isEd25519Alg(alg: string): boolean {
  const lower = alg.toLowerCase();
  return lower === 'ed25519' || lower === 'eddsa';
}
