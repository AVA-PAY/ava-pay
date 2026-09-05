import { createPublicKey, type KeyObject } from 'node:crypto';
import { parseKeyDirectory, type WebBotAuthKey } from '@ava-pay/agent/protocol/web-bot-auth';
import type { AgentDirectory, AgentRecord, ResolveHints } from './agent-directory.js';
import type { VisaJwksResolver } from './visa-tap.js';
import { readBounded, type SignatureAgentKeyResolver } from './web-bot-auth.js';

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
 *      ("agent cards" — keys the agent operator publishes at their origin).
 *      Web Bot Auth rules cited below as "-02 Section N" are
 *      draft-ietf-webbotauth-httpsig-protocol-00 (formerly
 *      draft-meunier-webbotauth-httpsig-protocol-02); the sections did not
 *      move on adoption.
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

/**
 * One append-only observation of a (key, domain) pair. This is the raw material
 * for a future key-continuity / substitution check (D6, watch-only): the log is
 * only ever appended to, so a continuity check becomes a serializer over the
 * history rather than a rebuild.
 */
export interface KeyObservation {
  /** Wire key identifier (kid / RFC 7638 thumbprint). */
  keyId: string;
  /** Domain or URL the key was observed at ((key, domain) pair, D1). */
  domain?: string;
  /** Provenance label of the resolving source. */
  source: string;
  /** Binding strength of the resolving source. */
  binding?: 'domain' | 'url-only';
  /** Whether the resolved record was revoked. */
  revoked: boolean;
  /** Unix seconds when observed. */
  observedAt: number;
}

/** Append-only sink for key observations. Records are added, never mutated. */
export interface KeyObservationLog {
  record(observation: KeyObservation): void;
  /** The full history, oldest first. Read-only view for a later continuity check. */
  all(): readonly KeyObservation[];
}

/** In-memory append-only observation log (dev/test; swap for a durable store). */
export class InMemoryKeyObservationLog implements KeyObservationLog {
  private readonly entries: KeyObservation[] = [];
  record(observation: KeyObservation): void {
    this.entries.push({ ...observation });
  }
  all(): readonly KeyObservation[] {
    return this.entries;
  }
}

export interface FederatedAgentDirectoryOptions {
  /** Append-only sink recording every resolved (key, domain) pair (D6). */
  observations?: KeyObservationLog;
  /** Override "now" (seconds) for deterministic observation timestamps. */
  now?: () => number;
}

export class FederatedAgentDirectory implements AgentDirectory {
  private readonly observations: KeyObservationLog | undefined;
  private readonly now: () => number;

  constructor(
    private readonly sources: FederatedSource[],
    opts: FederatedAgentDirectoryOptions = {},
  ) {
    if (sources.length === 0) {
      throw new Error('FederatedAgentDirectory needs at least one source.');
    }
    this.observations = opts.observations;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
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
        const resolved = { ...record, source: record.source ?? source.name };
        this.observations?.record({
          keyId: agentId,
          domain: resolved.domain,
          source: resolved.source ?? source.name,
          binding: resolved.binding,
          revoked: resolved.revoked,
          observedAt: this.now(),
        });
        return resolved;
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
    // Visa's JWKS is an origin-bound root of trust: domain binding.
    return { agentId, publicKey: key.key, revoked: false, source: this.name, binding: 'domain' };
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
      if (resolution.status === 'unavailable' || resolution.status === 'redirected') {
        // A redirected directory is as unresolvable as a down one for this
        // chain's purposes (-02 Section 5.5), so it skips rather than counting
        // as a definitive miss that would let a later root be shadowed.
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
      // Discovered through the origin's well-known directory path: the (key,
      // domain) pair is (thumbprint, origin) and the binding is domain-bound.
      return {
        agentId,
        publicKey,
        revoked: false,
        source: `wba:${origin}`,
        domain: origin,
        binding: 'domain',
      };
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

// ─── Typed jwks_uri / cimd source (url-only binding) ─────────────────────────

export interface JwksUriKeySourceOptions {
  /** Allowlisted https URLs to fetch a JWKS from. Doubles as the SSRF guard. */
  urls: string[];
  /** The §5.5 discovery type these URLs represent. */
  type: 'jwks_uri' | 'cimd';
  /** Injectable fetch for tests. */
  fetchImpl?: typeof fetch;
  /** Override "now" (seconds) for deterministic tests. */
  now?: () => number;
  /** Skew for nbf/exp checks, seconds. Default 30. */
  clockSkewSeconds?: number;
  /** Per-fetch timeout. Default 5000ms. */
  timeoutMs?: number;
  /** Maximum response size. Default 64 KiB. */
  maxResponseBytes?: number;
}

/**
 * Resolves an Ed25519 key by RFC 7638 thumbprint from a typed jwks_uri / cimd
 * URL (§5.5). Unlike a well-known directory, these give key continuity at an
 * ARBITRARY URL with no origin association, so a hit records url-only binding
 * and the (key, domain) pair records the URL itself. Discipline mirrors the WBA
 * directory fetcher: https only, allowlisted URLs, a redirect is an error (-02
 * Section 5.5 forbids following one), bounded, honoring the published key window.
 */
export class JwksUriKeySource implements FederatedSource {
  readonly name: string;
  private readonly urls: string[];
  private readonly type: 'jwks_uri' | 'cimd';
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly skew: number;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;

  constructor(opts: JwksUriKeySourceOptions) {
    for (const url of opts.urls) {
      if (new URL(url).protocol !== 'https:') {
        throw new Error(`JwksUriKeySource URLs must be https, got: ${url}`);
      }
    }
    this.type = opts.type;
    this.name = opts.type;
    this.urls = opts.urls;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.skew = opts.clockSkewSeconds ?? 30;
    this.timeoutMs = opts.timeoutMs ?? 5_000;
    this.maxBytes = opts.maxResponseBytes ?? 64 * 1024;
  }

  async resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null> {
    if (!THUMBPRINT_SHAPE.test(agentId)) return null;
    if (hints?.alg && !isEd25519Alg(hints.alg)) return null;

    const now = this.now();
    let sawOutage = false;
    for (const url of this.urls) {
      let keys: WebBotAuthKey[];
      try {
        keys = await this.fetchJwks(url);
      } catch {
        sawOutage = true;
        continue;
      }
      const key = keys.find((k) => k.thumbprint === agentId);
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
      return {
        agentId,
        publicKey,
        revoked: false,
        source: `${this.type}:${url}`,
        domain: url,
        binding: 'url-only',
      };
    }
    // Every URL that could have answered was down: surface as an outage so the
    // chain skips to the next root rather than concluding a definitive miss.
    if (sawOutage) throw new Error('all jwks_uri sources unavailable');
    return null;
  }

  private async fetchJwks(url: string): Promise<WebBotAuthKey[]> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        redirect: 'error',
        signal: controller.signal,
        headers: { accept: 'application/jwk-set+json, application/json' },
      });
      // -02 Section 5.5: discovery MUST be served with 200 (OK). `redirect:
      // 'error'` above already refuses a hop; this refuses every other status,
      // including a 2xx that carries no key set.
      if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
      const body = await readBounded(res, this.maxBytes);
      return parseKeyDirectory(JSON.parse(body));
    } finally {
      clearTimeout(timer);
    }
  }
}
