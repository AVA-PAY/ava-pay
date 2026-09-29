/**
 * Worked example: real operator provenance from the Whisper graph.
 *
 *   npx tsx examples/whisper-operator.ts                    (keyless, network required)
 *   WHISPER_API_KEY=... npx tsx examples/whisper-operator.ts (same answers; the key is forwarded)
 *
 * This is the counterpart to examples/operator-composition.ts, whose step 4 uses a deliberately fake
 * source so that composition can be demonstrated without a registry. Here every field is a live
 * answer from a real registry-derived dataset, so the two examples are worth reading together: that
 * one shows the SHAPE of the contract, this one shows the CONTENT.
 *
 * Five steps:
 *
 *   1. The first describe() returns null. That is not a failure and not "no such operator": the
 *      source is cache-first by design, because describe() is called inside a verification and may
 *      not add a network round trip to it. The name is queued instead.
 *   2. The resolution runs in the background. We wait for it here; a merchant's process simply
 *      serves the next request and the answer is there for the one after it.
 *   3. The second describe() returns the record, from three synchronous map reads.
 *   4. The record is composed onto a verified result with the repo's own annotateWithOperator, and
 *      onto a REJECTED one, to show that provenance never rescues a failed signature.
 *   5. Counters, which is what an operator running this in production would watch.
 *
 * No API key is required for ANY field. That is a deliberate property of the source and not a trial.
 * When a key IS supplied it is forwarded and changes no answer; this example makes no claim about what
 * else it might buy, because that is the endpoint's behaviour to state rather than this file's to guess.
 */

import { annotateWithOperator, type OperatorRecord } from '../src/verifier/operator-source.js';
import {
  WhisperOperatorSource,
  hostnameForOrigin,
  type WhisperOperatorRecord,
} from '../src/verifier/whisper-operator-source.js';

/**
 * The origin to describe, canonicalised the way the verifier hands one over.
 *
 * `originOf` in multi.ts always passes `new URL(id).origin`, so production only ever supplies a
 * canonical origin. An argument typed by a person does not: a browser address bar and `new URL(x).href`
 * both give you a trailing slash, and the source refuses that, correctly, because the record echoes
 * `origin` back verbatim and only a canonical input may become output.
 *
 * Without this the example printed "the name is now queued" for a name it had refused, then waited out
 * the settle deadline blaming a resolution that never started. An example is the first thing a reader
 * runs, so it has to be right about its own behaviour.
 */
function canonicalOrigin(raw: string): string {
  try {
    return new URL(raw).origin;
  } catch {
    return raw; // let the check below report it, rather than throwing a stack at the reader
  }
}

const ORIGIN = canonicalOrigin(process.argv[2] ?? 'https://www.shopify.com');

function heading(n: number, title: string): void {
  console.log(`\n${'='.repeat(72)}\n${n}. ${title}\n${'='.repeat(72)}`);
}

/** Wait for the background resolution, bounded, without a fixed sleep. */
async function settle(source: WhisperOperatorSource, deadlineMs = 30_000): Promise<void> {
  const started = Date.now();
  for (;;) {
    const s = source.stats();
    if (s.resolutionsStarted > 0 && s.queueDepth === 0 && s.inflight === 0) return;
    if (Date.now() - started > deadlineMs) {
      // notOurShape is REPORTED here rather than thrown on above. main() already refuses an origin this
      // source does not describe, with a better message and without querying, so a separate branch for it
      // in this loop could never execute - and an unreachable branch that looks like a safety net is worse
      // than none. Reporting the counter keeps the diagnosis if that pre-gate ever moves.
      throw new Error(`no resolution settled within ${deadlineMs}ms (started`
        + ` ${s.resolutionsStarted}, completed ${s.resolutionsCompleted},`
        + ` failed ${s.resolutionsFailed}, queue ${s.queueDepth}, notOurShape ${s.notOurShape})`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

async function main(): Promise<void> {
  if (hostnameForOrigin(ORIGIN) === null) {
    console.error(`${ORIGIN} is not a shape this source describes.`);
    console.error('It wants an https origin naming a real DNS host: no port, no path, no userinfo, and');
    console.error('not an IP literal or a special-use name. Nothing was queried.');
    process.exitCode = 1;
    return;
  }
  const apiKey = process.env['WHISPER_API_KEY'];
  console.log(`origin:  ${ORIGIN}`);
  console.log(`api key: ${apiKey ? 'present (forwarded; changes no answer)' : 'ABSENT (keyless)'}`);

  const warnings: string[] = [];
  const source = new WhisperOperatorSource({
    ...(apiKey ? { apiKey } : {}),
    onWarning: (m) => warnings.push(m),
  });

  heading(1, 'describe() on a cold cache');
  const first = await source.describe(ORIGIN);
  console.log(`returned: ${JSON.stringify(first)}`);
  console.log('null, because nothing is known YET. The name is now queued.');
  console.log(`queueDepth=${source.stats().queueDepth} missEnqueued=${source.stats().missEnqueued}`);

  heading(2, 'the background resolution');
  await settle(source);
  const s2 = source.stats();
  console.log(`graph calls:   ${s2.graphCallsTotal}`);
  console.log(`started/done:  ${s2.resolutionsStarted}/${s2.resolutionsCompleted}`);
  console.log(`failed:        ${s2.resolutionsFailed}`);

  heading(3, 'describe() again, served from cache');
  const record = (await source.describe(ORIGIN)) as WhisperOperatorRecord | null;
  if (!record) {
    // A null is TWO different outcomes and the difference is the whole point of this source, so the
    // example must not flatten them. An earlier version printed "a resolved ABSENCE, not an error" for
    // both, which is false for the gated case.
    //
    // The measurable example is `https://checkout.shopify.com`: it is GATED, while its registrable parent
    // `shopify.com` publishes `Shopify Inc.` - so the parent's answer exists and this client declined to
    // attribute it to the subdomain. (`https://www.bombas.com` is also gated, but do not use it to make
    // this point: `bombas.com` publishes NO operator either, because the 12-row WHOIS window it reads is
    // all privacy-proxy values. An earlier version of this comment claimed a corroborated "Bombas" at the
    // parent, which is false and which this file's own comment on `Identity Protection Service` already
    // contradicted.)
    //
    // Calling a refusal an absence of record tells a reader the opposite of what happened, in the one
    // output they run first.
    if (source.stats().gatedNoHostRow > 0) {
      console.log('still null: this source DECLINED to attribute the registrable parent\'s registrant');
      console.log('to this name, because the graph holds no announced-prefix observation for it.');
      console.log('That is a REFUSAL, not an absence of record: the parent may well have a publishable');
      console.log('operator. Nothing was cached, so a later call will ask again. Warnings:', warnings);
    } else {
      console.log('still null: the graph holds no publishable operator for this name.');
      console.log('That is a resolved ABSENCE, not an error. Warnings:', warnings);
    }
    return;
  }
  console.log(JSON.stringify(record, null, 2));
  console.log('');
  console.log(`operator:      ${record.operator}     <- the accountable party (WHOIS registrant)`);
  console.log(`network org:   ${record.network?.organization ?? '(none)'}     <- who runs the ADDRESS, NOT the operator`);
  if (record.queriedName) {
    console.log(`fold:          asked ${record.queriedName}, answered about ${record.resolvedName}`);
  }
  console.log(`observedAt:    ${record.observedAt}  <- when the SNAPSHOT was taken`);
  console.log(`retrievedAt:   ${record.retrievedAt}  <- when WE read it`);

  heading(4, 'composed onto a verified result, and onto a rejected one');
  const verified: { trusted: true; protocol: 'web-bot-auth'; operator?: OperatorRecord } = {
    trusted: true, protocol: 'web-bot-auth',
  };
  const annotated = await annotateWithOperator(verified, source, ORIGIN);
  console.log(`trusted stays: ${annotated.trusted}`);
  console.log(`operator:      ${annotated.operator?.operator}`);

  const rejected = { trusted: false as const, reason: 'unknown_key' as const };
  const untouched = await annotateWithOperator(rejected, source, ORIGIN);
  console.log(`rejected result annotated: ${'operator' in untouched}  <- provenance never rescues a failed signature`);

  heading(5, 'counters an operator would watch');
  const s = source.stats();
  for (const key of ['describeCalls', 'hitFresh', 'missEnqueued', 'coalesced', 'resolutionsStarted',
    'resolutionsCompleted', 'resolutionsFailed', 'graphCallsTotal', 'graphUnreachable',
    'keyless', 'fqdnEntries', 'zoneEntries', 'outageEntries'] as const) {
    console.log(`  ${key.padEnd(22)} ${String(s[key])}`);
  }
  if (warnings.length > 0) {
    console.log('\nwarnings emitted:');
    for (const w of warnings) console.log(`  - ${w}`);
  }
}

main().catch((err: unknown) => {
  // This example has exactly ONE expected failure, and it is not a bug: the source throws when it could
  // not check a name at all, to stop a caller reading an outage as "no operator". Printing a raw stack
  // with absolute paths for that - in the first thing a reader runs - makes a normal upstream condition
  // look like our defect, and buries the one sentence that explains it.
  //
  // Reproduce it on demand with `timeoutMs: 1`, a real option forwarded to the graph client. Unaided it
  // needs the graph to miss its 5 s per-call budget, shed a 429, or fail transport. All three arrive as
  // this message, but NOT with three different words: the 429 carries `(http429)`, while a budget miss
  // and a transport failure BOTH carry `(transport)`, because the client cannot tell its own deadline
  // from a refused connection - one `catch` covers DNS, TLS, a refusal, a redirect and the timeout. So
  // forcing `timeoutMs: 1` prints `(transport)`, which is the budget rather than a network fault.
  //
  // No rate is quoted here on purpose: five consecutive live runs resolved all four lanes in
  // 341-562 ms, so the budget has roughly an order of magnitude of headroom, and an earlier version of
  // this comment claimed a frequency a reader could contradict by running the example twice.
  const message = err instanceof Error ? err.message : String(err);
  if (message.startsWith('whisper-graph: could not check')) {
    console.error('');
    console.error(message);
    console.error('');
    console.error('That is the source declining to guess, and it is the behaviour you want: a verifier');
    console.error('that answered "no operator" here would be reporting an absence it never established.');
    console.error('No ANSWER was cached, so nothing wrong is stuck in the cache. The OUTAGE itself is');
    console.error('remembered for about a minute, and a call inside that window throws again without');
    console.error('re-querying, so an immediate retry is not the same as asking again. The word in');
    console.error('parentheses above names the failure CLASS, not the exact cause: (transport) covers');
    console.error('the deadline as well as DNS, TLS and a refused connection.');
    process.exitCode = 1;
    return;
  }
  // Anything else is unexpected and keeps its stack, because then the trace is the useful part.
  console.error(err);
  process.exitCode = 1;
});
