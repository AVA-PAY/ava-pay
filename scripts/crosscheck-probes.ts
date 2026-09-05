/**
 * Two questions the 17 vectors cannot answer on their own, both needed for the
 * issue #11 reply. Companion to crosscheck-negative-vectors.ts.
 *
 * PROBE A: NV-17 with the origin in the trust set.
 *   NV-17 (Signature-Agent "https://signature-agent.test/keys", a directory-type
 *   value carrying a path) carries no directory block, because a verifier
 *   obeying the §5.5 "a verifier MUST ignore a member carrying anything else"
 *   never fetches one. Run as shipped, our verifier rejects it as
 *   unknown_signature_agent, which looks like agreement on the rejection and is
 *   not: the rejection comes from the allowlist, not from the path. Seeding the
 *   origin's directory asks what we do when the origin IS one we resolve.
 *
 * PROBE B: a foreign `tag`.
 *   COVERAGE.md omits this as un-vectorable (id 02): draft §5.2 makes
 *   tag="web-bot-auth" a signer MUST, RFC 9421 §3.2.1 says an application MUST
 *   enforce its own requirements, and draft §5.4 says the origin MAY discard a
 *   signature whose tag is not web-bot-auth. Two conformant answers, so no
 *   expected outcome can be stated. Our behavior is a third datapoint for the
 *   group, not a resolution.
 *
 *   npx tsx scripts/crosscheck-probes.ts --vectors <path-to-clone>
 */
import { readFileSync } from 'node:fs';
import { createPrivateKey, sign as cryptoSign } from 'node:crypto';
import { resolve as resolvePath } from 'node:path';
import { WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import type {
  KeyDirectoryResolution,
  SignatureAgentKeyResolver,
} from '../src/verifier/web-bot-auth.js';
import { parseKeyDirectory } from '@ava-pay/agent/protocol/web-bot-auth';
import { InMemoryReplayGuard } from '../src/verifier/replay.js';

const argv = process.argv.slice(2);
const i = argv.indexOf('--vectors');
const vectorsRoot = i === -1 ? undefined : argv[i + 1];
if (!vectorsRoot) {
  console.error('usage: tsx scripts/crosscheck-probes.ts --vectors <path-to-clone>');
  process.exit(2);
}

// RFC 9421 Appendix B.1.4 "test-key-ed25519". Both halves are published in the
// RFC, which is why the set can use it and why we can sign our own probes.
const PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`;
const KEY_ID = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';
const PUBLIC_X = 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs';
const DIRECTORY_BODY = JSON.stringify({
  keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KEY_ID, x: PUBLIC_X, use: 'sig' }],
});

const set = JSON.parse(
  readFileSync(resolvePath(vectorsRoot, 'web-bot-auth-negative-vectors.json'), 'utf8'),
) as { testGroups: { tests: any[] }[] };
const vectors: any[] = set.testGroups.flatMap((g) => g.tests);
const byId = (id: string) => vectors.find((v) => v.id === id);

/** Serves one directory body for one origin. */
class OneOrigin implements SignatureAgentKeyResolver {
  constructor(private readonly origin: string) {}
  async resolve(origin: string): Promise<KeyDirectoryResolution> {
    if (origin !== this.origin) return { status: 'not_allowed' };
    return {
      status: 'ok',
      keys: parseKeyDirectory(JSON.parse(DIRECTORY_BODY)).map((k) => ({
        ...k,
        proof: 'absent' as const,
      })),
    };
  }
}

const describe = (r: Awaited<ReturnType<WebBotAuthVerifier['verify']>>) =>
  r.trusted
    ? `verified   trusted=true conclusive=${r.conclusive} agent=${r.agent?.id} binding=${r.agent?.binding}`
    : `${r.conclusive === false ? 'unverified' : 'invalid   '} reason=${r.reason}\n              message=${r.message}`;

const verify = async (req: any, now: number, origin: string) => {
  const verifier = new WebBotAuthVerifier({
    resolver: new OneOrigin(origin),
    now: () => now,
    replayGuard: new InMemoryReplayGuard({ now: () => now }),
  });
  return verifier.verify({
    method: req.method,
    url: req.url,
    headers: Object.fromEntries(
      Object.entries(req.headers as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]),
    ),
    ...(req.body !== undefined ? { body: req.body } : {}),
  });
};

// ── Probe A ────────────────────────────────────────────────────────────────
const nv17 = byId('NV-17');
console.log('PROBE A: NV-17 (directory-type Signature-Agent carrying a path)');
console.log(`  Signature-Agent: ${nv17.request.headers['Signature-Agent']}`);
console.log(`  his expected:    ${nv17.expected.outcome} / ${nv17.expected.reason}`);
console.log(`  §5.5: "${nv17.basis.requirement}"`);
console.log();
console.log('  as shipped (origin not in the trust set, no directory in the vector):');
console.log(`    -> ${describe(await verify(nv17.request, nv17.now, 'https://nothing.test'))}`);
console.log();
console.log('  with https://signature-agent.test in the trust set, serving the B.1.4 key:');
console.log(`    -> ${describe(await verify(nv17.request, nv17.now, 'https://signature-agent.test'))}`);

// ── Probe B ────────────────────────────────────────────────────────────────
// Sign a request that is correct in every way except that `tag` names another
// protocol. Signed fresh because tag lives inside @signature-params, so it
// cannot be edited into an existing vector.
const now = 1735689660;
const created = 1735689600;
const expires = created + 120;
const buildAndSign = (tag: string) => {
  const params = `("@authority" "signature-agent";key="sig1");created=${created};keyid="${KEY_ID}";alg="ed25519";expires=${expires};tag="${tag}"`;
  const agentHeader = 'sig1="https://signature-agent.test"';
  const base = [
    '"@authority": example.com',
    `"signature-agent";key="sig1": "https://signature-agent.test"`,
    `"@signature-params": ${params}`,
  ].join('\n');
  const sig = cryptoSign(null, Buffer.from(base), createPrivateKey(PRIVATE_PEM));
  return {
    method: 'GET',
    url: 'https://example.com/',
    headers: {
      'Signature-Agent': agentHeader,
      'Signature-Input': `sig1=${params}`,
      Signature: `sig1=:${sig.toString('base64')}:`,
    },
  };
};

console.log('\n\nPROBE B: foreign tag (COVERAGE.md id 02, omitted as un-vectorable)');
for (const tag of ['web-bot-auth', 'other-protocol']) {
  const r = await verify(buildAndSign(tag), now, 'https://signature-agent.test');
  console.log(`  tag="${tag}"`);
  console.log(`    -> ${describe(r)}`);
}
