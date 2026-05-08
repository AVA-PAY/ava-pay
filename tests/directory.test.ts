import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  FileDirectoryStorage,
  InMemoryDirectoryStorage,
} from '../src/directory/storage.js';
import { directoryRoutes } from '../src/directory/routes.js';
import { StorageBackedAgentDirectory } from '../src/directory/storage-directory.js';
import { generateAgentKeyPair } from '../src/sdk/index.js';

function jwkOf(key: ReturnType<typeof generateAgentKeyPair>['publicKey']): object {
  return key.export({ format: 'jwk' }) as object;
}

async function buildDirApp(opts: {
  storage: InMemoryDirectoryStorage | FileDirectoryStorage;
  registrationToken?: string;
}): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(directoryRoutes, opts);
  await app.ready();
  return app;
}

describe('Hosted Agent Directory', () => {
  describe('discovery + registration + lookup', () => {
    let app: FastifyInstance;
    let storage: InMemoryDirectoryStorage;
    const TOKEN = 'test_token_xyz';

    beforeAll(async () => {
      storage = new InMemoryDirectoryStorage();
      app = await buildDirApp({ storage, registrationToken: TOKEN });
    });

    afterAll(async () => {
      await app.close();
    });

    it('exposes a .well-known discovery doc', async () => {
      const res = await app.inject({ method: 'GET', url: '/.well-known/ava-agent-directory' });
      expect(res.statusCode).toBe(200);
      const body = res.json() as { service: string; version: number };
      expect(body.service).toBe('ava-agent-directory');
      expect(body.version).toBe(1);
    });

    it('rejects registration without a bearer token', async () => {
      const keys = generateAgentKeyPair();
      const res = await app.inject({
        method: 'POST',
        url: '/directory/agents',
        payload: {
          agentId: 'agent_anthropic',
          issuer: 'Anthropic',
          keys: [{ alg: 'ed25519', jwk: jwkOf(keys.publicKey), protocols: ['visa', 'ap2'] }],
        },
      });
      expect(res.statusCode).toBe(401);
    });

    it('accepts registration with the right bearer token', async () => {
      const keys = generateAgentKeyPair();
      const res = await app.inject({
        method: 'POST',
        url: '/directory/agents',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: {
          agentId: 'agent_openai',
          issuer: 'OpenAI',
          keys: [{ alg: 'ed25519', jwk: jwkOf(keys.publicKey), protocols: ['visa', 'ap2'] }],
        },
      });
      expect(res.statusCode).toBe(201);
      const body = res.json() as { agentId: string; revoked: boolean };
      expect(body.agentId).toBe('agent_openai');
      expect(body.revoked).toBe(false);
    });

    it('updates an existing registration on second POST (200, not 201)', async () => {
      const keys = generateAgentKeyPair();
      await app.inject({
        method: 'POST',
        url: '/directory/agents',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: {
          agentId: 'agent_repeated',
          issuer: 'X',
          keys: [{ alg: 'ed25519', jwk: jwkOf(keys.publicKey), protocols: ['visa'] }],
        },
      });
      const second = await app.inject({
        method: 'POST',
        url: '/directory/agents',
        headers: { authorization: `Bearer ${TOKEN}` },
        payload: {
          agentId: 'agent_repeated',
          issuer: 'X (updated)',
          keys: [{ alg: 'ed25519', jwk: jwkOf(keys.publicKey), protocols: ['visa', 'ap2'] }],
        },
      });
      expect(second.statusCode).toBe(200);
    });

    it('lookup returns 404 for unknown agents', async () => {
      const res = await app.inject({ method: 'GET', url: '/directory/agents/nope' });
      expect(res.statusCode).toBe(404);
    });

    it('lookup returns the registered record for known agents', async () => {
      const res = await app.inject({ method: 'GET', url: '/directory/agents/agent_openai' });
      expect(res.statusCode).toBe(200);
      const body = res.json() as { issuer: string; revoked: boolean };
      expect(body.issuer).toBe('OpenAI');
      expect(body.revoked).toBe(false);
    });

    it('revoke flips the flag and is reflected in lookup', async () => {
      const revoke = await app.inject({
        method: 'POST',
        url: '/directory/agents/agent_openai/revoke',
        headers: { authorization: `Bearer ${TOKEN}` },
      });
      expect(revoke.statusCode).toBe(200);
      const lookup = await app.inject({ method: 'GET', url: '/directory/agents/agent_openai' });
      const body = lookup.json() as { revoked: boolean };
      expect(body.revoked).toBe(true);
    });

    it('public list excludes revoked agents', async () => {
      const list = await app.inject({ method: 'GET', url: '/directory/agents' });
      const body = list.json() as { agents: Array<{ agentId: string }> };
      const ids = body.agents.map((a) => a.agentId);
      expect(ids).not.toContain('agent_openai'); // we revoked it above
    });
  });

  describe('FileDirectoryStorage persistence', () => {
    let dir: string;
    afterEach(() => {
      if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
    });

    it('persists registrations across instances', async () => {
      dir = mkdtempSync(join(tmpdir(), 'ava-pay-dir-'));
      const path = join(dir, 'data.json');

      const keys = generateAgentKeyPair();
      const a = new FileDirectoryStorage(path);
      await a.put({
        agentId: 'persist_me',
        issuer: 'Test',
        keys: [{ alg: 'ed25519', jwk: jwkOf(keys.publicKey) as any, protocols: ['visa'] }],
        revoked: false,
        registeredAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const b = new FileDirectoryStorage(path);
      const back = await b.get('persist_me');
      expect(back?.issuer).toBe('Test');
    });
  });

  describe('StorageBackedAgentDirectory', () => {
    it('verifier-shaped resolve() works against a registered agent', async () => {
      const storage = new InMemoryDirectoryStorage();
      const keys = generateAgentKeyPair();
      await storage.put({
        agentId: 'verifier_target',
        issuer: 'Test',
        keys: [{ alg: 'ed25519', jwk: jwkOf(keys.publicKey) as any, protocols: ['visa', 'ap2'] }],
        revoked: false,
        registeredAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });
      const dir = new StorageBackedAgentDirectory(storage);
      const r = await dir.resolve('verifier_target');
      expect(r?.agentId).toBe('verifier_target');
      expect(r?.revoked).toBe(false);
      expect(r?.publicKey.asymmetricKeyType).toBe('ed25519');
    });

    it('returns null for unknown agents', async () => {
      const dir = new StorageBackedAgentDirectory(new InMemoryDirectoryStorage());
      expect(await dir.resolve('nope')).toBeNull();
    });
  });
});
