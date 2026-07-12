/**
 * Replay protection.
 *
 * A ReplayGuard remembers identifiers (signature nonces, mandate jtis) until
 * their signature/mandate window closes. Seeing the same identifier twice
 * inside the window means a captured request is being replayed.
 *
 * The interface is async so the in-memory implementation can be swapped for
 * a Redis-backed one (SET key NX EX ttl) without touching the verifiers.
 */
export interface ReplayGuard {
  /**
   * Atomically check-and-record an identifier.
   *
   * @param key          Namespaced identifier, e.g. `visa:{agentId}:{nonce}`.
   * @param expiresAtSec Unix time (seconds) after which the identifier can be
   *                     forgotten — the end of its signature window plus skew.
   * @returns true if the identifier was fresh (now recorded), false if it was
   *          already seen (replay).
   */
  checkAndStore(key: string, expiresAtSec: number): Promise<boolean>;
}

export interface InMemoryReplayGuardOptions {
  /**
   * Hard cap on remembered identifiers, protecting memory under flood.
   * When full, the soonest-expiring entries are evicted first.
   */
  maxEntries?: number;
  /** Override "now" (seconds) for deterministic tests. */
  now?: () => number;
}

const DEFAULT_MAX_ENTRIES = 100_000;
const SWEEP_INTERVAL_SECONDS = 60;

/**
 * Single-process replay guard. Suitable for one API instance; multi-instance
 * deployments need the Redis implementation so all instances share the set.
 */
export class InMemoryReplayGuard implements ReplayGuard {
  /** key → expiry (unix seconds). Map preserves insertion order for eviction. */
  private readonly seen = new Map<string, number>();
  private readonly maxEntries: number;
  private readonly now: () => number;
  private lastSweep = 0;

  constructor(opts: InMemoryReplayGuardOptions = {}) {
    this.maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  async checkAndStore(key: string, expiresAtSec: number): Promise<boolean> {
    const now = this.now();
    this.maybeSweep(now);

    const existing = this.seen.get(key);
    if (existing !== undefined && existing >= now) {
      return false; // replay
    }

    if (this.seen.size >= this.maxEntries) {
      this.evict(now);
    }
    this.seen.set(key, Math.max(expiresAtSec, now));
    return true;
  }

  /** Number of identifiers currently remembered (visible for tests/metrics). */
  get size(): number {
    return this.seen.size;
  }

  private maybeSweep(now: number): void {
    if (now - this.lastSweep < SWEEP_INTERVAL_SECONDS) return;
    this.lastSweep = now;
    for (const [k, exp] of this.seen) {
      if (exp < now) this.seen.delete(k);
    }
  }

  private evict(now: number): void {
    // Drop expired entries first; if still full, drop the soonest-expiring
    // 10% so a flood degrades replay-window length instead of availability.
    for (const [k, exp] of this.seen) {
      if (exp < now) this.seen.delete(k);
    }
    if (this.seen.size < this.maxEntries) return;
    const entries = [...this.seen.entries()].sort((a, b) => a[1] - b[1]);
    const dropCount = Math.max(1, Math.floor(this.maxEntries / 10));
    for (let i = 0; i < dropCount && i < entries.length; i++) {
      const entry = entries[i];
      if (entry) this.seen.delete(entry[0]);
    }
  }
}
