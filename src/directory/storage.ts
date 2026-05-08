import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import type { DirectoryAgentRecord } from './types.js';

/**
 * Pluggable backing store for the hosted directory.
 *
 * `FileDirectoryStorage` writes JSON to disk so registrations survive
 * restarts. `InMemoryDirectoryStorage` is for tests. Production will swap in
 * a Postgres-backed implementation; the interface stays the same.
 *
 * One JSON file (`data.json`) holds the full keyed-by-agentId map. Cheap and
 * obvious; we'll partition once we have enough agents to care.
 */

export interface DirectoryStorage {
  list(): Promise<DirectoryAgentRecord[]>;
  get(agentId: string): Promise<DirectoryAgentRecord | null>;
  put(record: DirectoryAgentRecord): Promise<void>;
  delete(agentId: string): Promise<boolean>;
}

export class InMemoryDirectoryStorage implements DirectoryStorage {
  private records = new Map<string, DirectoryAgentRecord>();

  async list(): Promise<DirectoryAgentRecord[]> {
    return Array.from(this.records.values());
  }
  async get(agentId: string): Promise<DirectoryAgentRecord | null> {
    return this.records.get(agentId) ?? null;
  }
  async put(record: DirectoryAgentRecord): Promise<void> {
    this.records.set(record.agentId, record);
  }
  async delete(agentId: string): Promise<boolean> {
    return this.records.delete(agentId);
  }
}

export class FileDirectoryStorage implements DirectoryStorage {
  private readonly path: string;
  private cache: Map<string, DirectoryAgentRecord> | null = null;

  constructor(path: string) {
    this.path = path;
  }

  private ensureLoaded(): Map<string, DirectoryAgentRecord> {
    if (this.cache) return this.cache;
    if (!existsSync(this.path)) {
      this.cache = new Map();
      return this.cache;
    }
    const raw = readFileSync(this.path, 'utf-8');
    let parsed: { records: DirectoryAgentRecord[] };
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`Directory storage at ${this.path} is not valid JSON.`);
    }
    this.cache = new Map((parsed.records ?? []).map((r) => [r.agentId, r]));
    return this.cache;
  }

  private flush(): void {
    if (!this.cache) return;
    mkdirSync(dirname(this.path), { recursive: true });
    const records = Array.from(this.cache.values());
    writeFileSync(this.path, JSON.stringify({ records }, null, 2), 'utf-8');
  }

  async list(): Promise<DirectoryAgentRecord[]> {
    return Array.from(this.ensureLoaded().values());
  }
  async get(agentId: string): Promise<DirectoryAgentRecord | null> {
    return this.ensureLoaded().get(agentId) ?? null;
  }
  async put(record: DirectoryAgentRecord): Promise<void> {
    this.ensureLoaded().set(record.agentId, record);
    this.flush();
  }
  async delete(agentId: string): Promise<boolean> {
    const map = this.ensureLoaded();
    const had = map.delete(agentId);
    if (had) this.flush();
    return had;
  }
}
