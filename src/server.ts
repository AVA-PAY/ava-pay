import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import Fastify, { type FastifyInstance } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyRateLimit from '@fastify/rate-limit';
import { verifyRoute } from './routes/verify.js';
import type { AgentVerifier } from './verifier/interface.js';
import { VisaAgentVerifier } from './verifier/visa.js';
import { FetchingVisaJwksResolver, VisaTapVerifier } from './verifier/visa-tap.js';
import { Ap2AgentVerifier } from './verifier/ap2.js';
import {
  DEFAULT_SIGNATURE_AGENTS,
  FetchingKeyDirectoryResolver,
  WebBotAuthVerifier,
} from './verifier/web-bot-auth.js';
import { MultiProtocolVerifier } from './verifier/multi.js';
import {
  CachingAgentDirectory,
  FIVE_MINUTES_MS,
  RemoteAgentDirectory,
  StaticAgentDirectory,
  type AgentDirectory,
} from './verifier/agent-directory.js';
import {
  asSource,
  FederatedAgentDirectory,
  VisaJwksKeySource,
  WbaPublishedKeySource,
  type FederatedSource,
} from './verifier/federated-directory.js';
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
  // seen on one path can't be replayed on another. The fetching resolvers are
  // shared between verifiers and the federated directory so their caches are
  // shared too.
  let verifier = opts.verifier;
  if (!verifier) {
    // Visa's public verification JWKS (IdToken signing keys + a federated
    // root of trust). Override with VISA_JWKS_URL, e.g. to pin a sandbox.
    const visaJwks = new FetchingVisaJwksResolver(
      process.env.VISA_JWKS_URL ? { url: process.env.VISA_JWKS_URL } : {},
    );
    const wbaOrigins = wbaAllowedOrigins();
    const wbaKeys = new FetchingKeyDirectoryResolver({ allowedOrigins: wbaOrigins });

    const directory =
      opts.directory ?? buildDefaultDirectory(directoryStorage, visaJwks, wbaKeys, wbaOrigins);
    const replayGuard = new InMemoryReplayGuard();
    const visa = new VisaAgentVerifier({ directory, replayGuard });
    const visaTap = new VisaTapVerifier({ directory, replayGuard, visaJwks });
    const ap2 = new Ap2AgentVerifier({ directory, replayGuard });
    const webBotAuth = new WebBotAuthVerifier({ resolver: wbaKeys, replayGuard });
    verifier = new MultiProtocolVerifier({ visa, visaTap, ap2, webBotAuth });
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

/**
 * Signature-Agent origins the Web Bot Auth verifier will resolve keys for.
 * WBA_ALLOWED_SIGNATURE_AGENTS (comma-separated https origins) replaces the
 * built-in default set; it does not extend it.
 */
function wbaAllowedOrigins(): string[] {
  const env = process.env.WBA_ALLOWED_SIGNATURE_AGENTS;
  if (!env) return DEFAULT_SIGNATURE_AGENTS;
  return env
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
}

function buildDefaultDirectoryStorage(): DirectoryStorage {
  const path = process.env.AVA_DIRECTORY_DATA;
  if (path) return new FileDirectoryStorage(path);
  return new InMemoryDirectoryStorage();
}

/**
 * The federated resolution chain (roadmap Phase 1 §3). Order matters:
 * Visa's partner directory (when credentialed) → Visa's public JWKS →
 * Web Bot Auth key directories of allowlisted agents → our hosted
 * directory / private allowlist. First root that knows the key wins; a
 * root that is down is skipped. The whole chain sits behind one 5-minute
 * cache keyed by (id, hints).
 */
function buildDefaultDirectory(
  hostedStorage: DirectoryStorage,
  visaJwks: FetchingVisaJwksResolver,
  wbaKeys: FetchingKeyDirectoryResolver,
  wbaOrigins: string[],
): AgentDirectory {
  const sources: FederatedSource[] = [];

  const remoteUrl = process.env.VISA_AGENT_DIRECTORY_URL;
  if (remoteUrl) {
    const apiKey = process.env.VISA_API_KEY;
    sources.push(
      asSource(
        'visa-agent-directory',
        new RemoteAgentDirectory({ baseUrl: remoteUrl, ...(apiKey ? { apiKey } : {}) }),
      ),
    );
  }
  sources.push(new VisaJwksKeySource(visaJwks));
  sources.push(new WbaPublishedKeySource({ resolver: wbaKeys, origins: wbaOrigins }));
  // Hosted storage last: registrations made via /directory/agents become
  // resolvable immediately, but never shadow the public roots of trust.
  sources.push(asSource('hosted-directory', new StorageBackedAgentDirectory(hostedStorage)));

  return new CachingAgentDirectory(new FederatedAgentDirectory(sources), {
    ttlMs: FIVE_MINUTES_MS,
  });
}
