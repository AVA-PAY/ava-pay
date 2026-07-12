import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import Fastify, { type FastifyInstance } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyRateLimit from '@fastify/rate-limit';
import { verifyRoute } from './routes/verify.js';
import type { AgentVerifier } from './verifier/interface.js';
import { VisaAgentVerifier } from './verifier/visa.js';
import { Ap2AgentVerifier } from './verifier/ap2.js';
import { MultiProtocolVerifier } from './verifier/multi.js';
import {
  CachingAgentDirectory,
  FIVE_MINUTES_MS,
  RemoteAgentDirectory,
  StaticAgentDirectory,
  type AgentDirectory,
} from './verifier/agent-directory.js';
import { directoryRoutes } from './directory/routes.js';
import {
  FileDirectoryStorage,
  InMemoryDirectoryStorage,
  type DirectoryStorage,
} from './directory/storage.js';
import { StorageBackedAgentDirectory } from './directory/storage-directory.js';
import { seedDemoAgent } from './directory/seed-demo.js';
import { InMemoryReplayGuard } from './verifier/replay.js';

export interface BuildServerOptions {
  /** Override the verifier (e.g. swap in MockAgentVerifier for non-crypto tests). */
  verifier?: AgentVerifier;
  /** Override the directory used by the default multi-protocol verifier. */
  directory?: AgentDirectory;
  /**
   * Mount the hosted Agent Directory routes (`/directory/...` and `/.well-known/...`).
   * Defaults to true when no `verifier` override is supplied. Tests pass false to
   * keep route surface minimal.
   */
  mountDirectory?: boolean;
  /** Storage backend for the hosted directory. Default: file-backed at $AVA_DIRECTORY_DATA or /tmp. */
  directoryStorage?: DirectoryStorage;
  /** Bearer token gating directory writes. Defaults to $DIRECTORY_REGISTRATION_TOKEN. */
  registrationToken?: string;
  /**
   * Allow tokenless directory writes (local development only). Defaults to
   * $AVA_ALLOW_OPEN_DIRECTORY_WRITES === '1'. Without a token and without
   * this flag, directory write routes are disabled — fail closed.
   */
  allowOpenDirectoryWrites?: boolean;
  /** Register the global rate limiter. Defaults to true; tests may pass false. */
  rateLimit?: boolean;
  /** Serve the public/ landing page. Defaults to true if the dir exists. */
  servePublic?: boolean;
  /** Pass false in tests to silence Fastify's default logger. */
  logger?: boolean;
}

/**
 * Compose the Fastify app.
 *
 * Default wiring:
 *   - MultiProtocolVerifier { visa: VisaAgentVerifier, ap2: Ap2AgentVerifier }
 *   - directory = CachingAgentDirectory(inner, 5min TTL)
 *   - inner = RemoteAgentDirectory if VISA_AGENT_DIRECTORY_URL is set,
 *             else StorageBackedAgentDirectory if hosting the directory,
 *             else an empty StaticAgentDirectory.
 *   - hosted directory routes mounted by default (turn off with mountDirectory:false)
 */
export async function buildServer(opts: BuildServerOptions = {}): Promise<FastifyInstance> {
  const loggerOpt = opts.logger ?? { level: process.env.LOG_LEVEL ?? 'info' };
  const app = Fastify({ logger: loggerOpt });

  const mountDirectory = opts.mountDirectory ?? !opts.verifier;
  const directoryStorage = opts.directoryStorage ?? buildDefaultDirectoryStorage();

  // Global rate limit — /verify does an Ed25519 verification per request and
  // must not be a free unauthenticated CPU sink.
  if (opts.rateLimit ?? true) {
    await app.register(fastifyRateLimit, {
      max: Number(process.env.RATE_LIMIT_MAX ?? 300),
      timeWindow: '1 minute',
    });
  }

  // Verifier selection. One replay guard shared across protocols so a nonce
  // seen on one path can't be replayed on another.
  let verifier = opts.verifier;
  if (!verifier) {
    const directory = opts.directory ?? buildDefaultDirectory(directoryStorage);
    const replayGuard = new InMemoryReplayGuard();
    const visa = new VisaAgentVerifier({ directory, replayGuard });
    const ap2 = new Ap2AgentVerifier({ directory, replayGuard });
    verifier = new MultiProtocolVerifier({ visa, ap2 });
  }

  await app.register(verifyRoute, { verifier });

  // Hosted Agent Directory. Writes fail closed: enabled only with a token,
  // or with an explicit local-dev opt-in flag.
  if (mountDirectory) {
    const registrationToken = opts.registrationToken ?? process.env.DIRECTORY_REGISTRATION_TOKEN;
    const allowOpenWrites =
      opts.allowOpenDirectoryWrites ?? process.env.AVA_ALLOW_OPEN_DIRECTORY_WRITES === '1';
    await app.register(directoryRoutes, {
      storage: directoryStorage,
      ...(registrationToken ? { registrationToken } : {}),
      allowOpenWrites,
    });
  }

  app.get('/healthz', async () => ({ ok: true }));

  // Serve the public landing page if a `public/` directory exists. Resolves
  // both from compiled-output location (`dist/src/server.js` → ../../public)
  // and from tsx run (`src/server.ts` → ../public).
  const publicDir = resolvePublicDir();
  const servingPublic = publicDir !== null && (opts.servePublic ?? true);
  if (servingPublic) {
    await app.register(fastifyStatic, { root: publicDir!, prefix: '/', decorateReply: false });
  }

  // If we're serving the public landing page AND mounting the directory,
  // pre-seed the public demo agent so visitors can sign + verify without
  // self-registering (which is gated by DIRECTORY_REGISTRATION_TOKEN in prod).
  // Idempotent: existing record is updated, not duplicated.
  if (servingPublic && mountDirectory) {
    await seedDemoAgent(directoryStorage);
  }

  return app;
}

function resolvePublicDir(): string | null {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(here, '../public'),     // tsx: src/server.ts → ../public
    resolve(here, '../../public'),  // compiled: dist/src/server.js → ../../public
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

function buildDefaultDirectoryStorage(): DirectoryStorage {
  const path = process.env.AVA_DIRECTORY_DATA;
  if (path) return new FileDirectoryStorage(path);
  return new InMemoryDirectoryStorage();
}

function buildDefaultDirectory(hostedStorage: DirectoryStorage): AgentDirectory {
  const remoteUrl = process.env.VISA_AGENT_DIRECTORY_URL;
  if (remoteUrl) {
    const apiKey = process.env.VISA_API_KEY;
    const remote = new RemoteAgentDirectory({
      baseUrl: remoteUrl,
      ...(apiKey ? { apiKey } : {}),
    });
    return new CachingAgentDirectory(remote, { ttlMs: FIVE_MINUTES_MS });
  }
  // No remote directory configured — use our own hosted storage as the source
  // of truth. Registrations made via /directory/agents become resolvable
  // immediately by the verifier.
  return new CachingAgentDirectory(new StorageBackedAgentDirectory(hostedStorage), {
    ttlMs: FIVE_MINUTES_MS,
  });
}
