import { generateKeyPairSync } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  asSource,
  FederatedAgentDirectory,
  VisaJwksKeySource,
  WbaPublishedKeySource,
} from '../src/verifier/federated-directory.js';
import {
  CachingAgentDirectory,
  StaticAgentDirectory,
  type AgentDirectory,
  type AgentRecord,
  type ResolveHints,
} from '../src/verifier/agent-directory.js';
import { StaticVisaJwks, VisaTapVerifier } from '../src/verifier/visa-tap.js';
import { StaticSignatureAgentKeys } from '../src/verifier/web-bot-auth.js';
import { StorageBackedAgentDirectory } from '../src/directory/storage-directory.js';
import { InMemoryDirectoryStorage } from '../src/directory/storage.js';
import { buildServer } from '../src/server.js';
import {
  generateAgentKeyPair,
  signWithVisaTap,
  webBotAuthKeyId,
  type AgentKeyPair,
} from '../src/sdk/index.js';
import type { DirectoryAgentRecord } from '../src/directory/types.js';

/**
 * Federated directory resolver tests — the chain that replaced single-source
 * (and keys[0]) resolution: Visa JWKS → WBA published keys → hosted/private
 * allowlist, kid- and protocol-aware end to end.
 */

const FIXED_NOW = 1_750_000_000;
const WBA_ORIGIN = 'https://agent.example';

function jwkOf(keys: AgentKeyPair): Record<string, unknown> {
  return keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
}

describe('FederatedAgentDirectory chain', () => {
  let ed: AgentKeyPair;
  let hosted: StaticAgentDirectory;

  beforeEach(() => {
    ed = generateAgentKeyPair();
    hosted = new StaticAgentDirectory();
  });

  it('takes the first root of trust that knows the key and records provenance', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaJwk = rsa.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const visaJwks = new StaticVisaJwks({ keys: [{ ...rsaJwk, kid: 'shared-kid', use: 'sig' }] });
    hosted.add('shared-kid', ed.publicKey); // same id, different key, lower priority

    const federated = new FederatedAgentDirectory([
      new VisaJwksKeySource(visaJwks),
      asSource('hosted-directory', hosted),
    ]);

    const viaVisa = await federated.resolve('shared-kid', { alg: 'ps256' });
    expect(viaVisa?.source).toBe('visa-jwks');
    expect(viaVisa?.publicKey.asymmetricKeyType).toBe('rsa');
  });

  it('algorithm-gates the Visa JWKS so an ed25519 keyid collision falls through', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaJwk = rsa.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const visaJwks = new StaticVisaJwks({ keys: [{ ...rsaJwk, kid: 'shared-kid', use: 'sig' }] });
    hosted.add('shared-kid', ed.publicKey);

    const federated = new FederatedAgentDirectory([
      new VisaJwksKeySource(visaJwks),
      asSource('hosted-directory', hosted),
    ]);

    const viaHosted = await federated.resolve('shared-kid', { alg: 'ed25519' });
    expect(viaHosted?.source).toBe('hosted-directory');
    expect(viaHosted?.publicKey.asymmetricKeyType).toBe('ed25519');
  });

  it('skips a root that is down and resolves from the next one', async () => {
    const down: AgentDirectory = {
      resolve: async () => {
        throw new Error('outage');
      },
    };
    hosted.add('agent_x', ed.publicKey);
    const federated = new FederatedAgentDirectory([
      asSource('down-root', down),
      asSource('hosted-directory', hosted),
    ]);
    expect((await federated.resolve('agent_x'))?.source).toBe('hosted-directory');
  });

  it('a revocation in a higher root is definitive — never shadowed by a lower listing', async () => {
    const upper = new StaticAgentDirectory();
    upper.add('agent_x', ed.publicKey, true); // revoked here
    hosted.add('agent_x', ed.publicKey); // still listed here
    const federated = new FederatedAgentDirectory([
      asSource('upper', upper),
      asSource('hosted-directory', hosted),
    ]);
    const record = await federated.resolve('agent_x');
    expect(record?.revoked).toBe(true);
    expect(record?.source).toBe('upper');
  });

  it('returns null when no root knows the key', async () => {
    const federated = new FederatedAgentDirectory([asSource('hosted-directory', hosted)]);
    expect(await federated.resolve('nobody')).toBeNull();
  });
});

describe('WbaPublishedKeySource', () => {
  let ed: AgentKeyPair;
  let thumbprint: string;
  let resolver: StaticSignatureAgentKeys;

  beforeEach(() => {
    ed = generateAgentKeyPair();
    thumbprint = webBotAuthKeyId(ed.publicKey);
    resolver = new StaticSignatureAgentKeys();
    resolver.add(WBA_ORIGIN, { keys: [jwkOf(ed)] });
  });

  it('resolves a published key by RFC 7638 thumbprint', async () => {
    const source = new WbaPublishedKeySource({
      resolver,
      origins: [WBA_ORIGIN],
      now: () => FIXED_NOW,
    });
    const record = await source.resolve(thumbprint, { alg: 'ed25519' });
    expect(record?.source).toBe(`wba:${WBA_ORIGIN}`);
    expect(record?.publicKey.asymmetricKeyType).toBe('ed25519');
  });

  it('ignores non-thumbprint ids and non-ed25519 algorithm hints', async () => {
    const source = new WbaPublishedKeySource({
      resolver,
      origins: [WBA_ORIGIN],
      now: () => FIXED_NOW,
    });
    expect(await source.resolve('agent_demo')).toBeNull();
    expect(await source.resolve(thumbprint, { alg: 'ps256' })).toBeNull();
  });

  it('honors the published key validity window', async () => {
    const expired = new StaticSignatureAgentKeys();
    expired.add(WBA_ORIGIN, { keys: [{ ...jwkOf(ed), exp: FIXED_NOW - 3600 }] });
    const source = new WbaPublishedKeySource({
      resolver: expired,
      origins: [WBA_ORIGIN],
      now: () => FIXED_NOW,
    });
    expect(await source.resolve(thumbprint)).toBeNull();
  });

  it('reports an outage (throws) so the chain skips rather than concluding a miss', async () => {
    resolver.markUnavailable(WBA_ORIGIN);
    const source = new WbaPublishedKeySource({
      resolver,
      origins: [WBA_ORIGIN],
      now: () => FIXED_NOW,
    });
    await expect(source.resolve(thumbprint)).rejects.toThrow();
  });
});

describe('StorageBackedAgentDirectory — kid/protocol/alg-aware (keys[0] is gone)', () => {
  let storage: InMemoryDirectoryStorage;
  let directory: StorageBackedAgentDirectory;
  let ed: AgentKeyPair;
  let ec: { publicKey: import('node:crypto').KeyObject };

  beforeEach(async () => {
    storage = new InMemoryDirectoryStorage();
    directory = new StorageBackedAgentDirectory(storage);
    ed = generateAgentKeyPair();
    ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const record: DirectoryAgentRecord = {
      agentId: 'multi_key_agent',
      issuer: 'Test Issuer',
      keys: [
        {
          alg: 'ed25519',
          jwk: jwkOf(ed) as DirectoryAgentRecord['keys'][number]['jwk'],
          protocols: ['visa'],
          kid: 'kid-visa-ed',
        },
        {
          alg: 'es256',
          jwk: ec.publicKey.export({ format: 'jwk' }) as DirectoryAgentRecord['keys'][number]['jwk'],
          protocols: ['ap2'],
          kid: 'kid-ap2-ec',
        },
      ],
      revoked: false,
      registeredAt: new Date(0).toISOString(),
      updatedAt: new Date(0).toISOString(),
    };
    await storage.put(record);
  });

  it('picks the key matching the protocol hint (second key, not keys[0])', async () => {
    const forAp2 = await directory.resolve('multi_key_agent', { protocol: 'ap2', alg: 'ES256' });
    expect(forAp2?.publicKey.asymmetricKeyType).toBe('ec');

    const forVisa = await directory.resolve('multi_key_agent', { protocol: 'visa', alg: 'ed25519' });
    expect(forVisa?.publicKey.asymmetricKeyType).toBe('ed25519');
  });

  it('picks the exact key on a kid hint and misses definitively on a wrong kid', async () => {
    const exact = await directory.resolve('multi_key_agent', { kid: 'kid-ap2-ec' });
    expect(exact?.publicKey.asymmetricKeyType).toBe('ec');

    expect(await directory.resolve('multi_key_agent', { kid: 'no-such-kid' })).toBeNull();
  });

  it('fails closed when no key satisfies the hints', async () => {
    expect(
      await directory.resolve('multi_key_agent', { protocol: 'visa', alg: 'ps256' }),
    ).toBeNull();
  });

  it('lets kid hints fall through on legacy records that predate kids', async () => {
    await storage.put({
      agentId: 'legacy_agent',
      issuer: 'Legacy',
      keys: [{ alg: 'ed25519', jwk: jwkOf(ed) as never, protocols: ['visa'] }],
      revoked: false,
      registeredAt: new Date(0).toISOString(),
      updatedAt: new Date(0).toISOString(),
    });
    const record = await directory.resolve('legacy_agent', { kid: 'legacy_agent', protocol: 'visa' });
    expect(record?.publicKey.asymmetricKeyType).toBe('ed25519');
  });
});

describe('CachingAgentDirectory — hint-aware cache identity', () => {
  it('does not let a visa-hinted hit answer an ap2-hinted lookup', async () => {
    const calls: Array<ResolveHints | undefined> = [];
    const ed = generateAgentKeyPair();
    const inner: AgentDirectory = {
      resolve: async (_id, hints): Promise<AgentRecord> => {
        calls.push(hints);
        return { agentId: 'a', publicKey: ed.publicKey, revoked: false };
      },
    };
    const caching = new CachingAgentDirectory(inner, { ttlMs: 60_000 });
    await caching.resolve('a', { protocol: 'visa' });
    await caching.resolve('a', { protocol: 'ap2' });
    await caching.resolve('a', { protocol: 'visa' }); // cached
    expect(calls).toHaveLength(2);

    caching.invalidate('a');
    await caching.resolve('a', { protocol: 'visa' });
    expect(calls).toHaveLength(3); // invalidate cleared hinted entries too
  });
});

describe('end-to-end: TAP requests resolved through the federated chain', () => {
  it('verifies a TAP request signed with a key published only as a WBA agent card', async () => {
    // The "publish once, verified everywhere" story: the agent operator
    // publishes an Ed25519 key at their WBA well-known directory; a Visa TAP
    // request signed with that key (keyid = RFC 7638 thumbprint) verifies
    // with no separate TAP registration.
    const ed = generateAgentKeyPair();
    const thumbprint = webBotAuthKeyId(ed.publicKey);
    const wba = new StaticSignatureAgentKeys();
    wba.add(WBA_ORIGIN, { keys: [jwkOf(ed)] });

    const federated = new FederatedAgentDirectory([
      new WbaPublishedKeySource({ resolver: wba, origins: [WBA_ORIGIN], now: () => FIXED_NOW }),
      asSource('hosted-directory', new StaticAgentDirectory()),
    ]);
    const verifier = new VisaTapVerifier({ directory: federated, now: () => FIXED_NOW });

    const signed = signWithVisaTap({
      url: 'https://shop.example.com/products/tool-1234',
      privateKey: ed.privateKey,
      keyid: thumbprint,
      created: FIXED_NOW - 5,
    });
    const result = await verifier.verify({
      method: signed.method,
      url: signed.url,
      headers: signed.headers,
    });
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.agent?.id).toBe(thumbprint);
  });

  it('verifies an rsa-pss TAP request whose keyid lives in the Visa JWKS', async () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaJwk = rsa.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
    const visaJwks = new StaticVisaJwks({ keys: [{ ...rsaJwk, kid: 'visa-agent-1', use: 'sig' }] });

    const federated = new FederatedAgentDirectory([
      new VisaJwksKeySource(visaJwks),
      asSource('hosted-directory', new StaticAgentDirectory()),
    ]);
    const verifier = new VisaTapVerifier({ directory: federated, now: () => FIXED_NOW });

    const signed = signWithVisaTap({
      url: 'https://shop.example.com/products/tool-1234',
      privateKey: rsa.privateKey,
      keyid: 'visa-agent-1',
      created: FIXED_NOW - 5,
    });
    const result = await verifier.verify({
      method: signed.method,
      url: signed.url,
      headers: signed.headers,
    });
    expect(result.trusted).toBe(true);
  });
});

describe('directory registration accepts kid + ps256 keys', () => {
  it('registers a key with an explicit kid and ps256 alg', async () => {
    const app = await buildServer({
      allowOpenDirectoryWrites: true,
      rateLimit: false,
      logger: false,
      servePublic: false,
    });
    await app.ready();
    try {
      const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
      const res = await app.inject({
        method: 'POST',
        url: '/directory/agents',
        payload: {
          agentId: 'agent_with_kid',
          issuer: 'Kid Tester',
          keys: [
            {
              alg: 'ps256',
              jwk: rsa.publicKey.export({ format: 'jwk' }),
              protocols: ['visa'],
              kid: 'my-key-1',
            },
          ],
        },
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().keys[0].kid).toBe('my-key-1');
    } finally {
      await app.close();
    }
  });
});
