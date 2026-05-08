import { describe, expect, it } from 'vitest';
import { createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import {
  CachingAgentDirectory,
  StaticAgentDirectory,
  type AgentDirectory,
  type AgentRecord,
} from '../src/verifier/agent-directory.js';

function devKey(): KeyObject {
  const pem = generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' });
  return createPublicKey(pem as string);
}

class CountingDirectory implements AgentDirectory {
  calls = 0;
  constructor(private readonly inner: AgentDirectory) {}
  async resolve(agentId: string): Promise<AgentRecord | null> {
    this.calls++;
    return this.inner.resolve(agentId);
  }
}

describe('CachingAgentDirectory', () => {
  it('caches a hit and reuses it within TTL', async () => {
    const inner = new StaticAgentDirectory();
    inner.add('agent_demo', devKey());
    const counter = new CountingDirectory(inner);

    let now = 1_000_000;
    const cache = new CachingAgentDirectory(counter, {
      ttlMs: 5 * 60 * 1000,
      now: () => now,
    });

    const a = await cache.resolve('agent_demo');
    const b = await cache.resolve('agent_demo');
    expect(a?.agentId).toBe('agent_demo');
    expect(b?.agentId).toBe('agent_demo');
    expect(counter.calls).toBe(1);
  });

  it('caches misses too, so the directory is not hit twice for unknown ids', async () => {
    const counter = new CountingDirectory(new StaticAgentDirectory());

    let now = 1_000_000;
    const cache = new CachingAgentDirectory(counter, { ttlMs: 60_000, now: () => now });

    expect(await cache.resolve('nope')).toBeNull();
    expect(await cache.resolve('nope')).toBeNull();
    expect(counter.calls).toBe(1);
  });

  it('refetches after TTL expires', async () => {
    const inner = new StaticAgentDirectory();
    inner.add('agent_demo', devKey());
    const counter = new CountingDirectory(inner);

    let now = 1_000_000;
    const cache = new CachingAgentDirectory(counter, {
      ttlMs: 60_000,
      now: () => now,
    });

    await cache.resolve('agent_demo');
    now += 30_000;
    await cache.resolve('agent_demo');
    expect(counter.calls).toBe(1); // still within TTL

    now += 60_001;
    await cache.resolve('agent_demo');
    expect(counter.calls).toBe(2); // refetched
  });

  it('invalidate() forces the next resolve to hit the inner directory', async () => {
    const inner = new StaticAgentDirectory();
    inner.add('agent_demo', devKey());
    const counter = new CountingDirectory(inner);

    const cache = new CachingAgentDirectory(counter, { ttlMs: 5 * 60 * 1000 });

    await cache.resolve('agent_demo');
    cache.invalidate('agent_demo');
    await cache.resolve('agent_demo');
    expect(counter.calls).toBe(2);
  });
});
