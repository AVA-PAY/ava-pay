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
}

export interface AgentDirectory {
  resolve(agentId: string): Promise<AgentRecord | null>;
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

  async resolve(agentId: string): Promise<AgentRecord | null> {
    const hit = this.cache.get(agentId);
    if (hit && hit.expiresAt > this.now()) return hit.record;

    const record = await this.inner.resolve(agentId);
    this.cache.set(agentId, { record, expiresAt: this.now() + this.ttlMs });
    return record;
  }

  invalidate(agentId: string): void {
    this.cache.delete(agentId);
  }

  /** Test helper. */
  size(): number {
    return this.cache.size;
  }
}

export const FIVE_MINUTES_MS = 5 * 60 * 1000;
