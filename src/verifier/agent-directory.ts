import { createPublicKey, type KeyObject } from 'node:crypto';

/**
 * Minimal JWK shape — Node's `createPublicKey({ format: 'jwk' })` accepts this
 * structurally. We define our own alias because `JsonWebKey` is in lib.dom,
 * which we don't pull in for a server-only build.
 */
type JsonWebKeyLike = {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
  [k: string]: unknown;
};

/**
 * AgentDirectory — resolves an agent's public key + revocation status by ID.
 *
 * In production this points at Visa's Agent Directory: a JWKS-style HTTPS
 * endpoint that returns `{ agentId, publicKey: JWK, revoked }` for any
 * registered agent. As of today (May 2026) Visa's directory access is
 * partner-gated — see README → "Real Visa Protocol — getting credentials".
 *
 * In tests/dev we use `StaticAgentDirectory`. The `CachingAgentDirectory`
 * wrapper applies a 5-minute TTL regardless of the underlying implementation.
 */

export interface AgentRecord {
  agentId: string;
  publicKey: KeyObject;
  revoked: boolean;
  /** Which root of trust produced this record (federated resolution provenance). */
  source?: string;
  /**
   * The domain or URL the key was observed at. Reputation and events key on the
   * (key, domain) pair, not the key alone (D1): the same key seen at two
   * origins is two observations. For a well-known directory this is the origin;
   * for a jwks_uri/cimd source it is the URL.
   */
  domain?: string;
  /**
   * Binding strength of the source that resolved this key (§5.5 / D3).
   * `domain` = discovered through an origin-bound path (well-known directory,
   * Visa root); `url-only` = key continuity at an arbitrary URL with no origin
   * association (jwks_uri/cimd).
   */
  binding?: 'domain' | 'url-only';
}

/**
 * Optional context a verifier can pass so multi-key records and federated
 * sources resolve the RIGHT key instead of the first one.
 */
export interface ResolveHints {
  /** Protocol family of the incoming request (directory keys are scoped to these). */
  protocol?: 'visa' | 'ap2';
  /** Wire algorithm, e.g. "ed25519", "rsa-pss-sha256", "ES256". */
  alg?: string;
  /** Explicit key id, when the wire distinguishes it from the agent id. */
  kid?: string;
}

export interface AgentDirectory {
  resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null>;
}

/**
 * In-memory directory used by tests and local dev. Accepts JWK objects or
 * PEM-encoded SPKI strings.
 */
export class StaticAgentDirectory implements AgentDirectory {
  private records = new Map<string, AgentRecord>();

  add(agentId: string, key: KeyObject | object | string, revoked = false): void {
    const publicKey: KeyObject =
      key instanceof Object && 'asymmetricKeyType' in (key as KeyObject)
        ? (key as KeyObject)
        : typeof key === 'string'
          ? createPublicKey(key)
          : createPublicKey({ key: key as JsonWebKeyLike, format: 'jwk' });
    this.records.set(agentId, { agentId, publicKey, revoked });
  }

  revoke(agentId: string): void {
    const r = this.records.get(agentId);
    if (r) r.revoked = true;
  }

  async resolve(agentId: string): Promise<AgentRecord | null> {
    return this.records.get(agentId) ?? null;
  }
}

/**
 * HTTP client for Visa's Agent Directory. The exact endpoint shape is locked
 * in once Visa Partners credentials are provisioned; this is the placeholder
 * that knows how to GET `{baseUrl}/agents/{id}` with bearer auth, and parse a
 * JWK out of the response.
 *
 * Wrap this in CachingAgentDirectory in production — every cache miss is a
 * round-trip to Visa.
 */
export interface RemoteAgentDirectoryOptions {
  baseUrl: string;
  apiKey?: string;
  /** Override fetch (tests). */
  fetcher?: typeof fetch;
  /** Hard timeout per directory call. */
  timeoutMs?: number;
}

export class RemoteAgentDirectory implements AgentDirectory {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly fetcher: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: RemoteAgentDirectoryOptions) {
    if (!opts.baseUrl) {
      throw new Error('RemoteAgentDirectory requires baseUrl (set VISA_AGENT_DIRECTORY_URL).');
    }
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.apiKey = opts.apiKey;
    this.fetcher = opts.fetcher ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 1_500;
  }

  async resolve(agentId: string): Promise<AgentRecord | null> {
    const url = `${this.baseUrl}/agents/${encodeURIComponent(agentId)}`;
    const headers: Record<string, string> = { accept: 'application/json' };
    if (this.apiKey) headers.authorization = `Bearer ${this.apiKey}`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);

    try {
      const res = await this.fetcher(url, { headers, signal: ctrl.signal });
      if (res.status === 404) return null;
      if (!res.ok) {
        throw new Error(`Visa Agent Directory returned ${res.status}`);
      }
      const body = (await res.json()) as {
        agentId: string;
        publicKey: object;
        revoked?: boolean;
      };
      const publicKey = createPublicKey({ key: body.publicKey as JsonWebKeyLike, format: 'jwk' });
      return { agentId: body.agentId, publicKey, revoked: body.revoked ?? false };
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface CachingAgentDirectoryOptions {
  ttlMs: number;
  now?: () => number;
}

/**
 * In-memory TTL cache. Caches both hits AND misses (a 404 from Visa stays a
 * 404 for the TTL — useful so we don't hammer the directory for unknown
 * agents). Use `invalidate(agentId)` if you need to force a refresh, e.g. on
 * a webhook signaling key rotation.
 */
export class CachingAgentDirectory implements AgentDirectory {
  private readonly inner: AgentDirectory;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private cache = new Map<string, { record: AgentRecord | null; expiresAt: number }>();

  constructor(inner: AgentDirectory, opts: CachingAgentDirectoryOptions) {
    this.inner = inner;
    this.ttlMs = opts.ttlMs;
    this.now = opts.now ?? (() => Date.now());
  }

  async resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null> {
    // Hints change which key a lookup resolves to, so they are part of the
    // cache identity — a visa-hinted hit must not answer an ap2-hinted call.
    const key = cacheKey(agentId, hints);
    const hit = this.cache.get(key);
    if (hit && hit.expiresAt > this.now()) return hit.record;

    const record = await this.inner.resolve(agentId, hints);
    this.cache.set(key, { record, expiresAt: this.now() + this.ttlMs });
    return record;
  }

  invalidate(agentId: string): void {
    const prefix = `${agentId}\u0000`;
    for (const k of this.cache.keys()) {
      if (k === agentId || k.startsWith(prefix)) this.cache.delete(k);
    }
  }

  /** Test helper. */
  size(): number {
    return this.cache.size;
  }
}

function cacheKey(agentId: string, hints?: ResolveHints): string {
  if (!hints) return agentId;
  return `${agentId}\u0000${hints.protocol ?? ''}\u0000${(hints.alg ?? '').toLowerCase()}\u0000${hints.kid ?? ''}`;
}

export const FIVE_MINUTES_MS = 5 * 60 * 1000;
