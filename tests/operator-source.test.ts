import { beforeEach, describe, expect, it } from 'vitest';
import { MultiProtocolVerifier } from '../src/verifier/multi.js';
import {
  StaticSignatureAgentKeys,
  WebBotAuthVerifier,
  type SignatureAgentKeyResolver,
} from '../src/verifier/web-bot-auth.js';
import { VisaAgentVerifier } from '../src/verifier/visa.js';
import { VisaTapVerifier } from '../src/verifier/visa-tap.js';
import { Ap2AgentVerifier } from '../src/verifier/ap2.js';
import { StaticAgentDirectory } from '../src/verifier/agent-directory.js';
import type { OperatorRecord, OperatorSource } from '../src/verifier/operator-source.js';
import { generateAgentKeyPair, signWithWebBotAuth } from '../src/sdk/index.js';
import type { AgentKeyPair } from '../src/sdk/index.js';
import type { IncomingRequest } from '../src/types.js';

/**
 * OperatorSource: accountability provenance attached after key resolution.
 *
 * The whole point of the second interface is that it can never move the trust
 * decision, so these tests pin the four ways it must stay out of the way:
 * it annotates a verified result, never runs on a failed or inconclusive one,
 * and neither a throwing source nor a null answer may perturb the result.
 * Real Ed25519 signatures throughout, per repo convention.
 */

const FIXED_NOW = 1_750_000_000;
const AGENT_ORIGIN = 'https://agent.example';
const MERCHANT_URL = 'https://shop.example.com/products/tool-1234';

const RECORD: OperatorRecord = {
  origin: AGENT_ORIGIN,
  operator: 'Example Agent Co',
  abuseContact: 'abuse@agent.example',
  registry: 'example-registry',
  dnssec: 'valid',
  observedAt: '2026-09-24T00:00:00Z',
};

function jwksFor(...keys: AgentKeyPair[]): { keys: object[] } {
  return { keys: keys.map((k) => k.publicKey.export({ format: 'jwk' }) as object) };
}

function toIncoming(signed: {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}): IncomingRequest {
  return {
    method: signed.method,
    url: signed.url,
    headers: signed.headers,
    ...(signed.body !== undefined ? { body: signed.body } : {}),
  };
}

describe('OperatorSource composition', () => {
  let wbaKeys: AgentKeyPair;
  let resolver: StaticSignatureAgentKeys;
  let calls: string[];

  beforeEach(() => {
    wbaKeys = generateAgentKeyPair();
    resolver = new StaticSignatureAgentKeys();
    resolver.add(AGENT_ORIGIN, jwksFor(wbaKeys));
    calls = [];
  });

  function build(operator?: OperatorSource): MultiProtocolVerifier {
    const directory = new StaticAgentDirectory();
    const now = () => FIXED_NOW;
    return new MultiProtocolVerifier({
      visa: new VisaAgentVerifier({ directory, now }),
      visaTap: new VisaTapVerifier({ directory, now }),
      ap2: new Ap2AgentVerifier({ directory, now }),
      webBotAuth: new WebBotAuthVerifier({ resolver, now }),
      ...(operator ? { operator } : {}),
    });
  }

  const recording = (impl: OperatorSource['describe']): OperatorSource => ({
    name: 'test-operator',
    describe: async (origin) => {
      calls.push(origin);
      return impl(origin);
    },
  });

  function signedRequest(keys: AgentKeyPair = wbaKeys): IncomingRequest {
    return toIncoming(
      signWithWebBotAuth({
        method: 'GET',
        url: MERCHANT_URL,
        signatureAgent: AGENT_ORIGIN,
        privateKey: keys.privateKey,
        created: FIXED_NOW - 5,
      }),
    );
  }

  it('annotates a verified result with the operator record', async () => {
    const multi = build(recording(async () => RECORD));
    const result = await multi.verify(signedRequest());

    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(calls).toEqual([AGENT_ORIGIN]);
    expect(result.operator).toEqual(RECORD);
    // Provenance only: the trust decision is untouched.
    expect(result.trusted).toBe(true);
    expect(result.conclusive).toBe(true);
    expect(result.agent?.id).toBe(AGENT_ORIGIN);
  });

  it('leaves a verified result untouched when no source is configured', async () => {
    const result = await build().verify(signedRequest());
    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(result.operator).toBeUndefined();
    expect('operator' in result).toBe(false);
  });

  it('never runs on a failed result', async () => {
    const multi = build(recording(async () => RECORD));
    // Signed with a key the directory does not publish: definitive rejection.
    const stranger = generateAgentKeyPair();
    const result = await multi.verify(signedRequest(stranger));

    expect(result).toMatchObject({ trusted: false, conclusive: true });
    if (result.trusted) throw new Error('expected rejection');
    expect(result.reason).toBe('unknown_key');
    expect(calls).toEqual([]);
    expect('operator' in result).toBe(false);
  });

  it('never runs on an inconclusive result', async () => {
    // A directory that throws is the could-not-check path: trusted false,
    // conclusive false. Accountability has nothing to say about a request we
    // could not check, and must not imply it does.
    const outage: SignatureAgentKeyResolver = {
      resolve: async () => ({ status: 'unavailable', detail: 'simulated outage' }),
    };
    const directory = new StaticAgentDirectory();
    const now = () => FIXED_NOW;
    const multi = new MultiProtocolVerifier({
      visa: new VisaAgentVerifier({ directory, now }),
      visaTap: new VisaTapVerifier({ directory, now }),
      ap2: new Ap2AgentVerifier({ directory, now }),
      webBotAuth: new WebBotAuthVerifier({ resolver: outage, now }),
      operator: recording(async () => RECORD),
    });

    const result = await multi.verify(signedRequest());
    expect(result).toMatchObject({
      trusted: false,
      reason: 'key_directory_unavailable',
      conclusive: false,
    });
    expect(calls).toEqual([]);
  });

  it('leaves the result intact when the source throws', async () => {
    const plain = await build().verify(signedRequest());
    const multi = build(
      recording(async () => {
        throw new Error('RDAP timeout');
      }),
    );
    const result = await multi.verify(signedRequest());

    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(calls).toEqual([AGENT_ORIGIN]);
    expect(result.operator).toBeUndefined();
    expect(result).toEqual(plain);
  });

  it('leaves the result intact when the source answers null', async () => {
    const plain = await build().verify(signedRequest());
    const multi = build(recording(async () => null));
    const result = await multi.verify(signedRequest());

    if (!result.trusted) throw new Error(`expected trusted, got ${JSON.stringify(result)}`);
    expect(calls).toEqual([AGENT_ORIGIN]);
    expect(result.operator).toBeUndefined();
    expect(result).toEqual(plain);
  });
});
