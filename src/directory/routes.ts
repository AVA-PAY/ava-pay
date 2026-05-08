import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { DirectoryStorage } from './storage.js';
import type { DirectoryAgentRecord, DirectoryListing } from './types.js';

/**
 * Hosted Agent Directory HTTP surface.
 *
 *   GET  /.well-known/ava-agent-directory   → discovery (service identity + count)
 *   GET  /directory/agents                  → public list (revoked entries hidden)
 *   GET  /directory/agents/:id              → public lookup
 *   POST /directory/agents                  → register (bearer-token auth)
 *   POST /directory/agents/:id/revoke       → revoke (bearer-token auth)
 *
 * Authentication: a static bearer token from `DIRECTORY_REGISTRATION_TOKEN`.
 * That's deliberately simple for the V1 — the real model is "agent issuers
 * authenticate with their own DPoP-style proof of key possession" and we'll
 * upgrade to that once we have more than a handful of issuers. This keeps
 * the V1 unblockable.
 */

interface DirectoryRouteOptions {
  storage: DirectoryStorage;
  /** If set, registration/revocation requires this bearer token. If unset, all writes are open. */
  registrationToken?: string;
}

const registerBodySchema = {
  type: 'object',
  required: ['agentId', 'issuer', 'keys'],
  additionalProperties: false,
  properties: {
    agentId: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[a-zA-Z0-9_.\\-]+$' },
    issuer: { type: 'string', minLength: 1, maxLength: 256 },
    url: { type: 'string', maxLength: 512 },
    keys: {
      type: 'array',
      minItems: 1,
      maxItems: 4,
      items: {
        type: 'object',
        required: ['alg', 'jwk', 'protocols'],
        additionalProperties: false,
        properties: {
          alg: { type: 'string', enum: ['ed25519', 'es256'] },
          jwk: { type: 'object' },
          protocols: {
            type: 'array',
            minItems: 1,
            items: { type: 'string', enum: ['visa', 'ap2'] },
          },
        },
      },
    },
  },
} as const;

export const directoryRoutes: FastifyPluginAsync<DirectoryRouteOptions> = async (
  fastify: FastifyInstance,
  opts,
) => {
  const { storage, registrationToken } = opts;

  fastify.get('/.well-known/ava-agent-directory', async () => {
    const all = await storage.list();
    const listing: DirectoryListing = {
      service: 'ava-agent-directory',
      version: 1,
      generatedAt: new Date().toISOString(),
      count: all.length,
    };
    return listing;
  });

  fastify.get('/directory/agents', async () => {
    const all = await storage.list();
    return {
      agents: all
        .filter((r) => !r.revoked)
        .map((r) => ({ agentId: r.agentId, issuer: r.issuer, url: r.url, keys: r.keys })),
    };
  });

  fastify.get<{ Params: { id: string } }>(
    '/directory/agents/:id',
    async (req, reply) => {
      const record = await storage.get(req.params.id);
      if (!record) return reply.status(404).send({ error: 'not_found' });
      // Public lookup includes revoked status so verifiers can act on it.
      return record;
    },
  );

  fastify.post(
    '/directory/agents',
    { schema: { body: registerBodySchema } },
    async (req, reply) => {
      if (!authorize(req.headers.authorization, registrationToken)) {
        return reply.status(401).send({ error: 'unauthorized' });
      }
      const body = req.body as Omit<DirectoryAgentRecord, 'revoked' | 'registeredAt' | 'updatedAt'>;
      const now = new Date().toISOString();
      const existing = await storage.get(body.agentId);
      const record: DirectoryAgentRecord = {
        agentId: body.agentId,
        issuer: body.issuer,
        ...(body.url !== undefined ? { url: body.url } : {}),
        keys: body.keys,
        revoked: existing?.revoked ?? false,
        registeredAt: existing?.registeredAt ?? now,
        updatedAt: now,
      };
      await storage.put(record);
      return reply.status(existing ? 200 : 201).send(record);
    },
  );

  fastify.post<{ Params: { id: string } }>(
    '/directory/agents/:id/revoke',
    async (req, reply) => {
      if (!authorize(req.headers.authorization, registrationToken)) {
        return reply.status(401).send({ error: 'unauthorized' });
      }
      const record = await storage.get(req.params.id);
      if (!record) return reply.status(404).send({ error: 'not_found' });
      record.revoked = true;
      record.updatedAt = new Date().toISOString();
      await storage.put(record);
      return record;
    },
  );
};

function authorize(headerValue: string | undefined, expectedToken: string | undefined): boolean {
  if (!expectedToken) return true; // no token configured → open writes (dev mode)
  if (!headerValue) return false;
  if (!headerValue.startsWith('Bearer ')) return false;
  return headerValue.slice('Bearer '.length).trim() === expectedToken;
}
