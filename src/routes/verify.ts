import { createHash } from 'node:crypto';
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import type { AgentVerifier } from '../verifier/interface.js';
import type { IncomingRequest } from '../types.js';

interface VerifyRouteOptions {
  verifier: AgentVerifier;
}

/**
 * JSON schema for the request body. Fastify uses this for fast validation
 * (faster than ajv-on-the-fly because schemas get compiled at boot).
 */
const verifyBodySchema = {
  type: 'object',
  required: ['method', 'url', 'headers'],
  additionalProperties: false,
  properties: {
    method: { type: 'string', minLength: 1 },
    url: { type: 'string', minLength: 1 },
    headers: {
      type: 'object',
      additionalProperties: { type: 'string' },
    },
    body: { type: 'string' },
  },
} as const;

export const verifyRoute: FastifyPluginAsync<VerifyRouteOptions> = async (
  fastify: FastifyInstance,
  opts,
) => {
  const { verifier } = opts;

  fastify.post(
    '/verify',
    {
      schema: { body: verifyBodySchema },
    },
    async (req, reply) => {
      const payload = req.body as IncomingRequest;

      // Normalize headers to lower-case so verifier code can rely on it.
      const normalizedHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(payload.headers ?? {})) {
        normalizedHeaders[k.toLowerCase()] = v;
      }

      const incoming: IncomingRequest = {
        method: payload.method,
        url: payload.url,
        headers: normalizedHeaders,
        ...(payload.body !== undefined ? { body: payload.body } : {}),
      };

      const started = process.hrtime.bigint();
      const result = await verifier.verify(incoming);
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1_000_000;

      reply.header('x-ava-verify-ms', elapsedMs.toFixed(2));
      reply.header('cache-control', 'no-store');

      // Structured per-verification log. Pino (Fastify's built-in logger)
      // emits JSON in production. Agent IDs are hashed so we can correlate
      // without storing raw IDs in long-term log retention.
      const agentIdHint = extractAgentIdHint(incoming.headers);
      req.log.info(
        {
          ava_event: 'verify',
          outcome: result.trusted ? 'trusted' : 'blocked',
          reason: result.trusted ? 'verified' : result.reason,
          agent_hash: agentIdHint ? hashAgentId(agentIdHint) : null,
          elapsed_ms: Number(elapsedMs.toFixed(3)),
          merchant_host: safeHost(incoming.url),
        },
        'verify',
      );

      const status = result.trusted ? 200 : 403;
      return reply.status(status).send(result);
    },
  );
};

/**
 * Best-effort agent ID extraction for telemetry. The verifier itself trusts
 * only the keyid that the signature actually validated under — we read this
 * for log correlation, not authorization.
 */
function extractAgentIdHint(headers: Record<string, string>): string | null {
  const fromHeader = headers['x-ava-agent-id'];
  if (fromHeader) return fromHeader;
  const sigInput = headers['signature-input'];
  if (!sigInput) return null;
  const m = sigInput.match(/keyid="([^"]+)"/);
  return m?.[1] ?? null;
}

/** Stable, non-reversible 8-byte hash for log correlation. */
function hashAgentId(id: string): string {
  return createHash('sha256').update(id).digest('base64url').slice(0, 11);
}

function safeHost(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}
