/**
 * Two questions the 17 vectors cannot answer on their own, both needed for the
 * issue #11 reply. Companion to crosscheck-negative-vectors.ts.
 *
 * PROBE A: NV-17 with the origin, and then the exact URL, in the trust set.
 *   NV-17 (Signature-Agent "https://signature-agent.test/keys") was written
 *   against -00, where a directory value carrying a path was refused at the
 *   parse. -01 §5.5 makes the member value a URL to a JWK Set, so the parse
 *   now succeeds and the decision moves to the allowlist: with the ORIGIN
 *   trusted the URL is still not fetched (an origin entry admits only the
 *   well-known URL; "TLS authenticates the host but not the path") and the
 *   verdict is unknown_signature_agent; with that EXACT URL trusted it
 *   resolves with binding url-only.
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
import { parseKeyDirectory, signatureAgentIdentifier } from '@ava-pay/agent/protocol/web-bot-auth';
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

/** Serves one directory body for one allowlist entry (origin or full URL). */
class OneOrigin implements SignatureAgentKeyResolver {
  constructor(private readonly entry: string) {}
  async resolve(identifier: string): Promise<KeyDirectoryResolution> {
    // Entry normalized (config rule); request identifier compared VERBATIM
    // per the resolver contract (never expand a "/" path).
    if (identifier !== signatureAgentIdentifier(this.entry)) {
      return { status: 'not_allowed' };
    }
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

// Fresh signatures for both probes (tag lives inside @signature-params and
// the probe-A shape was withdrawn from the set, so neither can be replayed
// from an existing vector).
const now = 1735689660;
const created = 1735689600;
const expires = created + 120;
const buildAndSignAgent = (agentValue: string, tag = 'web-bot-auth') => {
  const params = `("@authority" "signature-agent";key="sig1");created=${created};keyid="${KEY_ID}";alg="ed25519";expires=${expires};tag="${tag}"`;
  const base = [
    '"@authority": example.com',
    `"signature-agent";key="sig1": "${agentValue}"`,
    `"@signature-params": ${params}`,
  ].join('\n');
  const sig = cryptoSign(null, Buffer.from(base), createPrivateKey(PRIVATE_PEM));
  return {
    method: 'GET',
    url: 'https://example.com/',
    headers: {
      'Signature-Agent': `sig1="${agentValue}"`,
      'Signature-Input': `sig1=${params}`,
      Signature: `sig1=:${sig.toString('base64')}:`,
    },
  };
};

// ── Probe A ────────────────────────────────────────────────────────────────
// NV-17 was WITHDRAWN from the set when it followed the document to -01
// (ParallaxGrain commit eb51afe): -01 §5.5 makes a Signature-Agent value a
// URL to a JWK Set, so a path stopped being a parse fault. The probe keeps
// asking the question the vector asked, with the request synthesized here
// (same B.1.4 key, same /keys shape), because the answer now comes from the
// allowlist rather than the parse. The set may still carry the id in prose,
// so the probe reports whether a test by that id exists.
const nv17 = byId('NV-17');
const probeA = buildAndSignAgent('https://signature-agent.test/keys');
console.log('PROBE A: the withdrawn NV-17 shape (Signature-Agent carrying a path), under -01');
console.log(`  NV-17 in the current set: ${nv17 ? 'present' : 'withdrawn (eb51afe)'}`);
console.log('  Signature-Agent: sig1="https://signature-agent.test/keys"');
console.log();
console.log('  as shipped (nothing relevant in the trust set):');
console.log(`    -> ${describe(await verify(probeA, now, 'https://nothing.test'))}`);
console.log();
console.log('  with https://signature-agent.test in the trust set, serving the B.1.4 key:');
console.log('  (an origin entry admits only the well-known URL, -01 §5.5, so /keys is not fetched)');
console.log(`    -> ${describe(await verify(probeA, now, 'https://signature-agent.test'))}`);
console.log();
console.log('  with the exact URL https://signature-agent.test/keys in the trust set:');
console.log(`    -> ${describe(await verify(probeA, now, 'https://signature-agent.test/keys'))}`);

// ── Probe B ────────────────────────────────────────────────────────────────
// A request that is correct in every way except that `tag` names another
// protocol.
console.log('\n\nPROBE B: foreign tag (COVERAGE.md id 02, omitted as un-vectorable)');
for (const tag of ['web-bot-auth', 'other-protocol']) {
  const r = await verify(buildAndSignAgent('https://signature-agent.test', tag), now, 'https://signature-agent.test');
  console.log(`  tag="${tag}"`);
  console.log(`    -> ${describe(r)}`);
}
