/**
 * Cross-check runner for ParallaxGrain's Web Bot Auth negative vectors against
 * OUR verifier.
 *
 * https://github.com/ParallaxGrain/webbotauth-negative-vectors, 17 requests
 * that must not verify, one fault each, signed with the RFC 9421 Appendix
 * B.1.4 key. Each states an Appendix C.1 outcome (normative) and a suggested
 * reason name (proposed).
 *
 * Nothing is vendored: point --vectors at a clone. The set is offered on
 * thibmeu/http-message-signatures-directory issue #11 and may still change, so
 * pinning a copy into tests/ is a separate decision.
 *
 *   npx tsx scripts/crosscheck-negative-vectors.ts --vectors <path-to-clone>
 *   npx tsx scripts/crosscheck-negative-vectors.ts --vectors <path> --json
 *
 * Mapping our result onto Appendix C.1, which is the whole point of the
 * exercise and is stated here rather than buried:
 *   trusted:true                      -> verified
 *   trusted:false, conclusive !== false -> invalid     (checked, and it failed)
 *   trusted:false, conclusive === false -> unverified  (could not check)
 */
import { readFileSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';
import { WebBotAuthVerifier } from '../src/verifier/web-bot-auth.js';
import type {
  KeyDirectoryResolution,
  SignatureAgentKeyResolver,
  ResolvedDirectoryKey,
} from '../src/verifier/web-bot-auth.js';
import { parseKeyDirectory } from '@ava-pay/agent/protocol/web-bot-auth';
import { InMemoryReplayGuard } from '../src/verifier/replay.js';

type Outcome = 'verified' | 'invalid' | 'unverified';

interface Vector {
  id: string;
  title: string;
  enforcement: string;
  expected: { outcome: Outcome; reason: string };
  basis: { section: string; requirement: string; note?: string };
  note: string;
  now: number;
  request: { method: string; url: string; headers: Record<string, string>; body?: string };
  directory?: { url: string; status: number; headers: Record<string, string>; body: string };
}

const argv = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
};
const vectorsRoot = flag('--vectors');
if (!vectorsRoot) {
  console.error('usage: tsx scripts/crosscheck-negative-vectors.ts --vectors <path-to-clone> [--json]');
  process.exit(2);
}
const asJson = argv.includes('--json');

const setPath = resolvePath(vectorsRoot, 'web-bot-auth-negative-vectors.json');
const set = JSON.parse(readFileSync(setPath, 'utf8')) as {
  document: string;
  testGroups: { tests: Vector[] }[];
};
const vectors: Vector[] = set.testGroups.flatMap((g) => g.tests);

/**
 * Serves exactly the directory response the vector carries, keyed to the
 * origin that vector names. A vector with no directory block gets `not_allowed`
 * for every origin, which is what our verifier sees when it reaches for a
 * directory the set says a conforming verifier never fetches.
 */
class VectorDirectoryResolver implements SignatureAgentKeyResolver {
  constructor(private readonly vector: Vector, private readonly forceOrigin?: string) {}

  async resolve(origin: string): Promise<KeyDirectoryResolution> {
    const dir = this.vector.directory;
    if (!dir) return { status: 'not_allowed' };
    const dirOrigin = this.forceOrigin ?? new URL(dir.url).origin;
    if (origin !== dirOrigin) return { status: 'not_allowed' };
    if (dir.status !== 200) return { status: 'unavailable' };
    let keys;
    try {
      keys = parseKeyDirectory(JSON.parse(dir.body));
    } catch {
      return { status: 'unavailable' };
    }
    // The set publishes no Appendix B possession proofs (no live directory
    // serves them), so 'absent' is the honest status and our default grace
    // tolerates it. Same posture as production.
    return {
      status: 'ok',
      keys: keys.map((k): ResolvedDirectoryKey => ({ ...k, proof: 'absent' })),
    };
  }
}

const lower = (h: Record<string, string>): Record<string, string> =>
  Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));

async function run(
  vector: Vector,
  opts: { forceOrigin?: string } = {},
): Promise<{ outcome: Outcome; reason: string | null; message: string | null }> {
  const verifier = new WebBotAuthVerifier({
    resolver: new VectorDirectoryResolver(vector, opts.forceOrigin),
    now: () => vector.now,
    // A guard per vector: replay is not what any of these test, and a shared
    // one would make the run order-dependent.
    replayGuard: new InMemoryReplayGuard({ now: () => vector.now }),
  });
  const result = await verifier.verify({
    method: vector.request.method,
    url: vector.request.url,
    headers: lower(vector.request.headers),
    ...(vector.request.body !== undefined ? { body: vector.request.body } : {}),
  });
  if (result.trusted) return { outcome: 'verified', reason: null, message: null };
  return {
    outcome: result.conclusive === false ? 'unverified' : 'invalid',
    reason: result.reason,
    message: result.message,
  };
}

const rows: {
  id: string;
  title: string;
  enforcement: string;
  expectedOutcome: Outcome;
  expectedReason: string;
  ourOutcome: Outcome;
  ourReason: string | null;
  ourMessage: string | null;
  agree: boolean;
}[] = [];

for (const vector of vectors) {
  const got = await run(vector);
  rows.push({
    id: vector.id,
    title: vector.title,
    enforcement: vector.enforcement,
    expectedOutcome: vector.expected.outcome,
    expectedReason: vector.expected.reason,
    ourOutcome: got.outcome,
    ourReason: got.reason,
    ourMessage: got.message,
    agree: got.outcome === vector.expected.outcome,
  });
}

if (asJson) {
  console.log(JSON.stringify({ document: set.document, rows }, null, 2));
} else {
  const pad = (s: string, n: number) => s.padEnd(n);
  console.log(`document: ${set.document}`);
  console.log(`vectors:  ${rows.length}\n`);
  console.log(
    `${pad('id', 7)}${pad('expected', 12)}${pad('ours', 12)}${pad('agree', 7)}${pad('his reason', 34)}our reason`,
  );
  console.log('-'.repeat(120));
  for (const r of rows) {
    console.log(
      `${pad(r.id, 7)}${pad(r.expectedOutcome, 12)}${pad(r.ourOutcome, 12)}${pad(r.agree ? 'yes' : 'NO', 7)}${pad(r.expectedReason, 34)}${r.ourReason ?? '-'}`,
    );
  }
  const disagreements = rows.filter((r) => !r.agree);
  console.log(`\nagree: ${rows.length - disagreements.length}/${rows.length}`);
  for (const r of disagreements) {
    console.log(`\n  ${r.id} ${r.title}`);
    console.log(`    enforcement: ${r.enforcement}`);
    console.log(`    expected:    ${r.expectedOutcome} / ${r.expectedReason}`);
    console.log(`    ours:        ${r.ourOutcome} / ${r.ourReason ?? '(verified)'}`);
    if (r.ourMessage) console.log(`    message:     ${r.ourMessage}`);
  }
}
