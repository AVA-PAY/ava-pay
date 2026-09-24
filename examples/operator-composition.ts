/**
 * Worked example: key resolution and operator provenance, composed.
 *
 *   npx tsx examples/operator-composition.ts        (network required)
 *
 * Four steps against the LIVE Shopify Web Bot Auth deployment:
 *
 *   1. Fetch https://www.shopify.com/.well-known/http-message-signatures-directory
 *      and report what it actually serves (a bare JWK, not a JWK Set).
 *   2. Fetch the apex https://shopify.com/... with redirects disabled and show
 *      the 301. draft-ietf-webbotauth-httpsig-protocol-00 Section 5.5 requires
 *      discovery to be served with 200 (OK) and forbids a verifier from
 *      following the redirect, so our resolver reports `redirected`, which is
 *      a definite fact about a misconfiguration, not an outage.
 *   3. Resolve the published key through the real chain (WbaPublishedKeySource
 *      inside FederatedAgentDirectory) and print the AgentRecord.
 *   4. Run a STUB OperatorSource over the composed result. The stub is a
 *      stand-in for the registry-anchored source (RDAP + DNSSEC-validated
 *      key-to-name binding) that is not built yet; every field it returns says
 *      "example" where a real registry value belongs. Nothing here is real
 *      registry data and nothing here should be read as one.
 *
 * Nothing in step 4 can change anything in steps 1 to 3. That separation is
 * the point of the example.
 */

import { ed25519JwkThumbprint, parseKeyDirectory } from '@ava-pay/agent/protocol/web-bot-auth';
import {
  FederatedAgentDirectory,
  InMemoryKeyObservationLog,
  WbaPublishedKeySource,
} from '../src/verifier/federated-directory.js';
import { FetchingKeyDirectoryResolver } from '../src/verifier/web-bot-auth.js';
import { annotateWithOperator, type OperatorRecord, type OperatorSource } from '../src/verifier/operator-source.js';

const WWW = 'https://www.shopify.com';
const APEX = 'https://shopify.com';
const WELL_KNOWN = '/.well-known/http-message-signatures-directory';

function heading(n: number, title: string): void {
  console.log(`\n${'='.repeat(72)}\n${n}. ${title}\n${'='.repeat(72)}`);
}

/**
 * A stand-in for the registry-anchored operator source. It performs NO lookup:
 * it returns a fixed record whose every value is the literal word "example"
 * where a real RDAP or DNSSEC answer belongs, and it reports dnssec as
 * 'unchecked' because it checked nothing. Replacing this with a real adapter is
 * the entire remaining work; see docs/RESOLVER-SOURCES.md.
 */
class StubOperatorSource implements OperatorSource {
  readonly name = 'stub-operator (NOT a registry)';

  async describe(origin: string): Promise<OperatorRecord | null> {
    if (origin !== WWW) return null; // sources answer null outside their shape
    return {
      origin: WWW,
      operator: 'example-operator-name',
      abuseContact: 'example-abuse-contact',
      registry: 'example-registry (stub, no RDAP lookup performed)',
      dnssec: 'unchecked',
      observedAt: new Date().toISOString(),
    };
  }
}

async function step1(): Promise<string> {
  heading(1, `GET ${WWW}${WELL_KNOWN}`);
  const res = await fetch(`${WWW}${WELL_KNOWN}`, {
    headers: { accept: 'application/http-message-signatures-directory+json, application/json' },
  });
  const body = await res.text();
  const parsed: unknown = JSON.parse(body);
  const isSet = typeof parsed === 'object' && parsed !== null && Array.isArray((parsed as { keys?: unknown }).keys);

  console.log(`status:        ${res.status}`);
  console.log(`content-type:  ${res.headers.get('content-type')}`);
  console.log(`body shape:    ${isSet ? 'JWK Set ({ keys: [...] })' : 'bare single JWK (no keys wrapper)'}`);

  // parseKeyDirectory accepts both shapes, which is why a bare JWK is not a
  // deployment we have to special-case downstream.
  const keys = parseKeyDirectory(parsed);
  const publishedKid = isSet
    ? ((parsed as { keys: Array<{ kid?: string }> }).keys[0]?.kid ?? '(none)')
    : ((parsed as { kid?: string }).kid ?? '(none)');
  for (const key of keys) {
    const computed = ed25519JwkThumbprint(key.x);
    console.log(`  published kid:     ${publishedKid}`);
    console.log(`  RFC 7638 thumb:    ${computed}`);
    console.log(`  kid == thumbprint: ${publishedKid === computed}`);
    console.log(`  nbf/exp:           ${key.nbf ?? '(none)'} / ${key.exp ?? '(none)'}`);
  }
  return keys[0]?.thumbprint ?? '';
}

async function step2(): Promise<void> {
  heading(2, `GET ${APEX}${WELL_KNOWN} (redirects disabled)`);
  const res = await fetch(`${APEX}${WELL_KNOWN}`, { redirect: 'manual' });
  console.log(`status:    ${res.status}`);
  console.log(`location:  ${res.headers.get('location')}`);
  console.log(
    'Section 5.5 of draft-ietf-webbotauth-httpsig-protocol-00 requires discovery\n' +
      'to be served with 200 (OK) and a verifier MUST NOT follow this redirect.\n' +
      'Our resolver reports status "redirected" (an operator misconfiguration a\n' +
      'merchant can be told about), not "unavailable" (an outage).',
  );

  const resolver = new FetchingKeyDirectoryResolver({ allowedOrigins: [APEX] });
  const resolution = await resolver.resolve(APEX);
  console.log(`FetchingKeyDirectoryResolver.resolve("${APEX}") -> ${resolution.status}`);
}

async function step3(thumbprint: string): Promise<void> {
  heading(3, 'Resolve that key through the federated chain');
  const observations = new InMemoryKeyObservationLog();
  const chain = new FederatedAgentDirectory(
    [
      new WbaPublishedKeySource({
        resolver: new FetchingKeyDirectoryResolver({ allowedOrigins: [WWW] }),
        origins: [WWW],
      }),
    ],
    { observations },
  );

  const record = await chain.resolve(thumbprint, { alg: 'ed25519' });
  if (!record) {
    console.log(`no chain source resolved ${thumbprint}`);
    return;
  }
  console.log(`agentId:    ${record.agentId}`);
  console.log(`publicKey:  ${record.publicKey.asymmetricKeyType} (KeyObject)`);
  console.log(`revoked:    ${record.revoked}`);
  console.log(`source:     ${record.source}`);
  console.log(`domain:     ${record.domain}`);
  console.log(`binding:    ${record.binding}`);
  console.log(`observation log: ${JSON.stringify(observations.all()[0])}`);
}

async function step4(thumbprint: string): Promise<void> {
  heading(4, 'Compose: verified result + stub operator provenance');

  // Stand-in for what the WBA verifier returns once the signature checks out.
  // Composition is what this step demonstrates; the signature path has its own
  // tests and its own demo (npm run demo:wba).
  const verified = {
    trusted: true as const,
    conclusive: true,
    protocol: 'web-bot-auth' as const,
    agent: { id: WWW, protocol: 'web-bot-auth' as const, keyThumbprint: thumbprint, binding: 'domain' as const },
    ttlSeconds: 60,
  };

  const source = new StubOperatorSource();
  const annotated = await annotateWithOperator(verified, source, WWW);
  console.log('composed result:');
  console.log(JSON.stringify(annotated, null, 2));

  console.log('\nSame source, a result that did NOT verify:');
  const rejected = { trusted: false as const, reason: 'unknown_key' as const, message: 'no such key', conclusive: true };
  const untouched = await annotateWithOperator(rejected, source, WWW);
  console.log(JSON.stringify(untouched));
  console.log(`operator attached: ${'operator' in untouched}  (accountability never rescues a failed signature)`);
}

async function main(): Promise<void> {
  const thumbprint = await step1();
  await step2();
  if (thumbprint) await step3(thumbprint);
  await step4(thumbprint);
  console.log(
    '\nReminder: step 4 used a STUB. No registry was contacted and no field above\n' +
      'is real registry data. See docs/RESOLVER-SOURCES.md, "What a real operator\n' +
      'source owes its caller".',
  );
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
