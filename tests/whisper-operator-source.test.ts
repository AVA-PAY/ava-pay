/**
 * Tests for the Whisper OperatorSource.
 *
 * Hermetic: every test drives an injected fetch over recorded shapes, so the suite needs no API key
 * and no network. An end-to-end run against the live graph is a separate example
 * (examples/whisper-operator.ts) and is deliberately not part of `vitest run`.
 *
 * The shape of this file follows the contract's two halves. First the pure helpers, where a bad input
 * must be rejected before it can become output. Then the source, where the thing being tested is
 * usually a NEGATIVE: that describe() does not await, does not publish a network organisation as an
 * operator, and does not answer "no record" when it means "I could not check".
 */

import { describe, expect, it, vi } from 'vitest';
import {
  WhisperOperatorSource,
  hostnameForOrigin,
  isSameOrSubdomainOf,
  isPublishableOperator,
  isRepeatedPhrase,
  snapshotToIso,
  type WhisperOperatorRecord,
} from '../src/verifier/whisper-operator-source.js';
import { annotateWithOperator, type OperatorRecord } from '../src/verifier/operator-source.js';

/* ------------------------------------------------------------------ fixtures */

/** A sentinel planted in every fixture's network organisation. It must never reach `operator`. */
const NETORG = 'NETORG-SENTINEL-MUST-NOT-BECOME-OPERATOR';

interface Canned {
  /** No rows at all: no HOSTNAME node, which is the cheap early refusal, not the fold gate's trigger. */
  prefixRows?: Record<string, unknown>[];
  asn?: Record<string, unknown>;
  zone?: Record<string, unknown>;
  whois?: Record<string, unknown>;
  advisories?: Record<string, unknown>[];
}

const PREFIX_COLUMNS = ['subject', 'prefixes', 'netAbuseEmails', 'rirs', 'rpkiStatuses',
  'roaAsns', 'roaMaxLengths', 'anycasts', 'moases'] as const;
const ASN_COLUMNS = ['asns', 'asNames', 'netOrgNames'] as const;
const ZONE_COLUMNS = ['subject', 'dnssecAlgorithms', 'companyName'] as const;
const WHOIS_COLUMNS = ['registrants', 'registrars', 'queryTimes', 'nameServerSets',
  'createDates'] as const;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * A fetch that answers each lane from a canned map.
 *
 * It dispatches on a distinctive token in the query text rather than on call order, because the
 * lane order is an implementation detail and a test that encodes it breaks on a refactor that
 * changed nothing observable.
 */
function cannedFetch(canned: Canned, onCall?: (query: string) => void): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? '{}')) as { query?: string };
    const q = body.query ?? '';
    onCall?.(q);
    if (q.includes('RESOLVES_TO')) {
      return jsonResponse({ columns: PREFIX_COLUMNS, rows: canned.prefixRows ?? [] });
    }
    if (q.includes('ROUTES')) {
      return jsonResponse({ columns: ASN_COLUMNS, rows: canned.asn ? [canned.asn] : [] });
    }
    if (q.includes('whisper.history.whois')) {
      return jsonResponse({
        columns: WHOIS_COLUMNS,
        rows: canned.whois ? [canned.whois] : [],
        ...(canned.advisories ? { advisories: canned.advisories } : {}),
      });
    }
    if (q.includes('SIGNED_WITH')) {
      return jsonResponse({ columns: ZONE_COLUMNS, rows: canned.zone ? [canned.zone] : [] });
    }
    return jsonResponse({ columns: [], rows: [] });
  }) as unknown as typeof fetch;
}

/** www.shopify.com as production actually answers it, with the sentinel planted. */
const SHOPIFY: Canned = {
  prefixRows: [{
    subject: 'www.shopify.com',
    // TWO prefixes, which is what production returns, so no single `prefix` scalar is legitimate.
    prefixes: ['172.64.145.0/24', '104.18.42.0/24'],
    netAbuseEmails: ['abuse@cloudflare.example'],
    rirs: ['ARIN'],
    rpkiStatuses: ['valid'],
    roaAsns: [13335],
    roaMaxLengths: [24],
    anycasts: [false],
    moases: [false],
  }],
  asn: {
    asns: ['AS13335'],
    asNames: ['CLOUDFLARENET-AS'],
    netOrgNames: [NETORG],
  },
  zone: { subject: 'shopify.com', dnssecAlgorithms: [], companyName: 'Shopify Inc.' },
  whois: {
    registrants: ['Shopify Inc.'],
    registrars: ['MarkMonitor Inc.'],
    queryTimes: ['2025-03-19 15:44:35'],
    nameServerSets: ['ns1.shopify.com|ns2.shopify.com'],
    createDates: ['2005-03-11'],
  },
  advisories: [{
    kind: 'whois-parent-fold',
    message: 'WHOIS shown for registrable parent shopify.com (queried www.shopify.com)',
    queried: 'www.shopify.com',
    resolved: 'shopify.com',
  }],
};

/** Drive one origin all the way through: miss, resolve, then the served record. */
async function resolved(
  origin: string,
  canned: Canned,
  opts: Record<string, unknown> = {},
): Promise<WhisperOperatorRecord | null> {
  const src = new WhisperOperatorSource({
    apiKey: 'test-key',
    fetchImpl: cannedFetch(canned),
    onWarning: () => undefined,
    ...opts,
  });
  expect(await src.describe(origin)).toBeNull(); // a cold miss is null, and enqueues
  await vi.waitFor(() => expect(src.stats().resolutionsStarted).toBeGreaterThan(0));
  await vi.waitFor(() => expect(src.stats().inflight + src.stats().queueDepth).toBe(0));
  return (await src.describe(origin)) as WhisperOperatorRecord | null;
}

describe('what comes back off the socket is bounded and shaped', () => {
  // The two checks with the longest justifications in the file and, until now, no test at all. Both are
  // asserted through the real pipeline, so what is proven is the PUBLISHED outcome, not a helper.

  it('cancels an endless body at the cap and calls it an outage, never "no operator"', async () => {
    // A chunked body with no content-length that never ends. `await res.text()` would admit it until the
    // heap gave out; the cap is enforced per chunk and the body cancelled.
    let cancelled = false;
    let delivered = 0;
    const endless = (): Response => {
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          delivered += 8192;
          controller.enqueue(new Uint8Array(8192).fill(0x20));
        },
        cancel() { cancelled = true; },
      });
      return new Response(stream, { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const warnings: string[] = [];
    const src = new WhisperOperatorSource({
      fetchImpl: (() => Promise.resolve(endless())) as unknown as typeof fetch,
      maxResponseBytes: 64 * 1024,
      onWarning: (w) => warnings.push(String(w)),
    });
    expect(await src.describe('https://shopify.com')).toBeNull();
    await vi.waitFor(() => expect(src.stats().resolutionsStarted).toBeGreaterThan(0));
    await vi.waitFor(() => expect(src.stats().inflight + src.stats().queueDepth).toBe(0));

    expect(cancelled).toBe(true);                       // the stream was cancelled, not drained
    expect(delivered).toBeLessThan(1_000_000);          // bounded near the cap, not unbounded
    // And the outcome is an OUTAGE, stated as one. The second describe() THROWS rather than returning a
    // null a caller could read as "checked, no operator" - which is the distinction this source exists to
    // keep, and it is stronger than returning null would be.
    await expect(src.describe('https://shopify.com')).rejects.toThrow(/outage on our side, not an absence/);
    expect(warnings.join(' ')).toMatch(/malformed/);
  });

  it('refuses a body that passes EVERY other check, purely because the type is not JSON', async () => {
    // The content-type gate has to be tested against the only input that isolates it. An HTML error page
    // is NOT that input: it also fails `JSON.parse`, so a test built from one passes with the gate deleted
    // (measured - it did). What only the gate can catch is a response whose BODY would satisfy every
    // downstream check, delivered with a type that says it is not our document. That is the shape of an
    // interstitial that echoes an API envelope, and of any proxy that rewrites a body but not its type.
    const canned = cannedFetch(SHOPIFY);
    const mistyped = (async (url: string | URL | Request, init?: RequestInit) => {
      const real = await (canned as unknown as (u: unknown, i?: RequestInit) => Promise<Response>)(url, init);
      return new Response(await real.text(), {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
      });
    }) as unknown as typeof fetch;

    const src = new WhisperOperatorSource({ fetchImpl: mistyped, onWarning: () => undefined });
    expect(await src.describe('https://www.shopify.com')).toBeNull();
    await vi.waitFor(() => expect(src.stats().resolutionsStarted).toBeGreaterThan(0));
    await vi.waitFor(() => expect(src.stats().inflight + src.stats().queueDepth).toBe(0));

    // Named as an outage, not returned as an absence, and above all NOT published: the identical body
    // served as application/json publishes a full record (the suite asserts that elsewhere), so the type
    // is the only difference between these two outcomes.
    await expect(src.describe('https://www.shopify.com')).rejects.toThrow(/outage on our side, not an absence/);
    expect(src.stats().resolutionsFailed).toBeGreaterThan(0);
  });
});

describe('every reason a record is withheld is OBSERVABLE, not just counted internally', () => {
  // The README promises "stats() returns raw counters, including each reason a record was withheld".
  // Three of the four reasons had a counter and no assertion, and the fourth - the COMMONEST, every
  // unpublishable registrant - was incremented into a field that appeared in neither the exported
  // interface nor the object stats() builds, so no caller could ever read it. A counter nothing can
  // read is not a counter, and the promise stayed false while looking fixed. These assert the promise
  // through stats(), which is the only surface a host actually sees.

  it('counts an unpublishable registrant, and exposes it through stats()', async () => {
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch({
        ...SHOPIFY,
        // Every history row a non-answer: a redaction string, an EPP status token and a bare date.
        whois: { ...SHOPIFY.whois, registrants: ['REDACTED FOR PRIVACY', 'serverTransferProhibited', '2005-03-11'] },
      }),
      onWarning: () => undefined,
    });
    expect(await src.describe('https://shopify.com')).toBeNull();
    await vi.waitFor(() => expect(src.stats().resolutionsStarted).toBeGreaterThan(0));
    await vi.waitFor(() => expect(src.stats().inflight + src.stats().queueDepth).toBe(0));

    // Nothing published, and the reason is legible from the outside.
    expect(await src.describe('https://shopify.com')).toBeNull();
    expect(src.stats().unpublishableRegistrant).toBe(3);
  });

  it('counts a registrar bleed and an uncorroborated name through stats() too', async () => {
    const bleed = new WhisperOperatorSource({
      // The registrant IS the registrar's own name, in a different spelling.
      fetchImpl: cannedFetch({
        ...SHOPIFY,
        whois: { ...SHOPIFY.whois, registrants: ['MarkMonitor Inc.'], registrars: ['MarkMonitor, Inc.'] },
      }),
      onWarning: () => undefined,
    });
    expect(await bleed.describe('https://shopify.com')).toBeNull();
    await vi.waitFor(() => expect(bleed.stats().inflight + bleed.stats().queueDepth).toBe(0));
    expect(bleed.stats().registrarBleed).toBeGreaterThan(0);

    const uncorroborated = new WhisperOperatorSource({
      // A real-looking company that nothing outside WHOIS agrees names this business.
      fetchImpl: cannedFetch({
        ...SHOPIFY,
        zone: { ...SHOPIFY.zone, companyName: 'Something Else Entirely BV' },
        whois: { ...SHOPIFY.whois, registrants: ['Unrelated Holdings LLC'] },
      }),
      onWarning: () => undefined,
    });
    expect(await uncorroborated.describe('https://shopify.com')).toBeNull();
    await vi.waitFor(() => expect(uncorroborated.stats().inflight + uncorroborated.stats().queueDepth).toBe(0));
    expect(uncorroborated.stats().uncorroborated).toBeGreaterThan(0);
  });

  it('counts an undateable snapshot, which is the one absence that is never published', async () => {
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch({
        ...SHOPIFY,
        whois: { ...SHOPIFY.whois, queryTimes: ['not a timestamp at all'] },
      }),
      onWarning: () => undefined,
    });
    expect(await src.describe('https://shopify.com')).toBeNull();
    await vi.waitFor(() => expect(src.stats().inflight + src.stats().queueDepth).toBe(0));
    expect(await src.describe('https://shopify.com')).toBeNull();
    expect(src.stats().undateable).toBeGreaterThan(0);
  });
});

describe('exactly one credential leaves the process, and only when asked', () => {
  // The README makes a quotable security claim: no request content, no buyer data and no signing-key
  // material goes to the endpoint, and the ONLY credential that ever leaves is the merchant's own API
  // key, sent as a header, only if they supply one. Until now nothing tested it - every fixture read
  // `init.body` and none read `init.headers` - so a refactor that moved the key into the body, or added a
  // second header, would have left the claim standing and false. A security sentence in a public README
  // with no test behind it is a promise nobody is keeping.

  /** Captures the headers and body of every request the source makes. */
  function capturing(canned: Canned): { fetchImpl: typeof fetch; calls: Array<{ headers: Record<string, string>; body: string }> } {
    const inner = cannedFetch(canned);
    const calls: Array<{ headers: Record<string, string>; body: string }> = [];
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
        headers[k.toLowerCase()] = v;
      }
      calls.push({ headers, body: String(init?.body ?? '') });
      return (inner as unknown as (u: unknown, i?: RequestInit) => Promise<Response>)(url, init);
    }) as unknown as typeof fetch;
    return { fetchImpl, calls };
  }

  async function drive(opts: Record<string, unknown>): Promise<Array<{ headers: Record<string, string>; body: string }>> {
    const { fetchImpl, calls } = capturing(SHOPIFY);
    const src = new WhisperOperatorSource({ fetchImpl, onWarning: () => undefined, ...opts });
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().resolutionsStarted).toBeGreaterThan(0));
    await vi.waitFor(() => expect(src.stats().inflight + src.stats().queueDepth).toBe(0));
    expect(calls.length).toBeGreaterThan(0);
    return calls;
  }

  it('sends NO credential header at all when no key is configured', async () => {
    const calls = await drive({});
    for (const c of calls) {
      expect(Object.keys(c.headers).sort()).toEqual(['accept', 'content-type']);
      expect(JSON.stringify(c.headers)).not.toMatch(/key|auth|token|cookie/i);
    }
  });

  it('sends the key as x-api-key, on every request, and nowhere else', async () => {
    const KEY = 'test-key-for-the-header-assertion';
    const calls = await drive({ apiKey: KEY });
    for (const c of calls) {
      expect(c.headers['x-api-key']).toBe(KEY);
      // Exactly these three headers: no cookie, no Authorization, no second credential.
      expect(Object.keys(c.headers).sort()).toEqual(['accept', 'content-type', 'x-api-key']);
      // And the key is NOT in the body, which is the half the README promises about content.
      expect(c.body).not.toContain(KEY);
    }
  });

  it('sends only the query and its bindings as the body, never anything about the buyer', async () => {
    const calls = await drive({});
    for (const c of calls) {
      const parsed = JSON.parse(c.body) as Record<string, unknown>;
      expect(Object.keys(parsed).sort()).toEqual(['parameters', 'query']);
      // Every binding is a string or a bounded list of strings: a hostname, its registrable parent, or
      // prefixes the graph itself returned. Nothing else can ride along.
      for (const v of Object.values(parsed['parameters'] as Record<string, unknown>)) {
        const ok = typeof v === 'string' || (Array.isArray(v) && v.every((x) => typeof x === 'string'));
        expect(ok).toBe(true);
      }
    }
  });
});

describe('a bounded list is sorted BEFORE it is capped', () => {
  // The cap ships at 8 and `collect()` order is unspecified, so capping during collection makes the
  // published subset a function of arrival order. Both list builders had that defect; one was fixed and
  // one was not, and nothing in the suite noticed. One assertion per builder, with the input REVERSED so
  // arrival order and sorted order disagree.

  it('publishes the sorted-first nameservers whatever order they arrive in (boundedHostnames)', async () => {
    const twelve = Array.from({ length: 12 }, (_v, i) => `ns${String(11 - i).padStart(2, '0')}.example.com`);
    const rec = await resolved('https://shopify.com', {
      ...SHOPIFY,
      whois: { ...SHOPIFY.whois, nameServerSets: [twelve.join('|')] },
    });
    expect(rec?.nameservers).toEqual([
      'ns00.example.com', 'ns01.example.com', 'ns02.example.com', 'ns03.example.com',
      'ns04.example.com', 'ns05.example.com', 'ns06.example.com', 'ns07.example.com',
    ]);
  });

  it('publishes a deterministic set of prefixes that KEEPS BOTH FAMILIES (boundedList)', async () => {
    // 11 prefixes, 3 of them IPv6, arriving v6-FIRST and descending within each family. The arrival order
    // is what makes this fixture useful: cap-during-collect would keep all three v6 prefixes here by pure
    // luck of arrival, and a lexicographic sort-then-cap would drop all three by rule, because v4 sorts
    // first and there are 8 of them. Neither is acceptable - one is arrival-dependent and the other tells
    // a merchant a dual-stack origin is IPv4-only - so the cap is taken proportionally per family.
    const arriving = [
      '2606:4700:9f::/48', '2606:4700:10::/48', '2606:4700::/44',
      '104.21.9.0/24', '104.21.8.0/24', '104.21.7.0/24', '104.21.6.0/24',
      '104.21.5.0/24', '104.21.4.0/24', '104.21.3.0/24', '104.21.2.0/24',
    ];
    const rec = await resolved('https://shopify.com', {
      ...SHOPIFY,
      prefixRows: [{ ...(SHOPIFY.prefixRows ?? [])[0], prefixes: arriving }],
    });
    const got = rec?.network?.prefixes ?? [];
    expect(got).toHaveLength(8);
    // Published order is a pure function of the values, so the same name yields the same list.
    expect([...got]).toEqual([...got].sort());
    // BOTH families survive the cap. This is the assertion the whole fix exists for.
    expect(got.filter((p) => p.includes(':'))).toHaveLength(3);
    expect(got.filter((p) => !p.includes(':'))).toHaveLength(5);
    // And each family's slice is the head of its OWN sorted family, not an arbitrary subset.
    expect(got.filter((p) => !p.includes(':'))).toEqual(
      arriving.filter((p) => !p.includes(':')).sort().slice(0, 5),
    );
    // Order-independence: the reversed input publishes exactly the same list.
    const reversedRec = await resolved('https://shopify.com', {
      ...SHOPIFY,
      prefixRows: [{ ...(SHOPIFY.prefixRows ?? [])[0], prefixes: [...arriving].reverse() }],
    });
    expect(reversedRec?.network?.prefixes).toEqual(got);
  });

  it('degrades to a plain head-slice when there is only one family to be fair between', async () => {
    // Through `asNames`, which shares the SAME bounded-list function as `prefixes`. An earlier version of
    // this test used nameservers, which go through `boundedHostnames` instead - so it asserted nothing
    // about the function whose behaviour it claimed to cover. Colon-free values put every entry in one
    // group, and the per-family split must then be exactly the old head-slice.
    const eleven = Array.from({ length: 11 }, (_v, i) => `AS-NAME-${String(10 - i).padStart(2, '0')}`);
    const rec = await resolved('https://shopify.com', {
      ...SHOPIFY,
      asn: { ...SHOPIFY.asn, asNames: eleven },
    });
    expect(rec?.network?.asNames).toEqual([...eleven].sort().slice(0, 8));
    // And the same through a field that is never an address at all.
    const nine = Array.from({ length: 9 }, (_v, i) => `ALG${String(9 - i)}`);
    const zoneRec = await resolved('https://shopify.com', {
      ...SHOPIFY,
      zone: { ...SHOPIFY.zone, dnssecAlgorithms: nine },
    });
    const algs = zoneRec?.dnssecAlgorithms;   // `dnssec` is the verdict enum; the list is its own field
    expect(algs).toBeDefined();       // not vacuous: the field must actually be published
    expect(algs).toHaveLength(8);
    expect(algs).toEqual([...nine].sort().slice(0, 8));
  });
});

/* --------------------------------------------------------- the origin is hostile */

describe('hostnameForOrigin', () => {
  it('accepts the canonical https origins production actually sends', () => {
    expect(hostnameForOrigin('https://www.shopify.com')).toBe('www.shopify.com');
    expect(hostnameForOrigin('https://shopify.com')).toBe('shopify.com');
    expect(hostnameForOrigin('https://xn--hopify-hvf.com')).toBe('xn--hopify-hvf.com');
  });

  it.each([
    ['not https', 'http://shopify.com'],
    ['an opaque id', 'urn:uuid:4f9c'],
    ['empty', ''],
    ['userinfo, which canonicalises to a DIFFERENT host', 'https://evil@shopify.com'],
    ['an escaped slash in userinfo', 'https://shopify.com%2F@evil.example'],
    ['a port', 'https://shopify.com:8443'],
    ['a v4 literal', 'https://192.0.2.1'],
    ['a v6 literal', 'https://[2001:db8::1]'],
    ['a decimal-packed v4', 'https://0x7f.1'],
    ['an RFC 6761 special name', 'https://printer.local'],
    ['an onion', 'https://relay.onion'],
    ['a single label', 'https://localhost'],
    ['an empty label', 'https://a..com'],
    ['a hyphen-edged label', 'https://-a.com'],
  ])('rejects %s', (_why, origin) => {
    expect(hostnameForOrigin(origin)).toBeNull();
  });

  it('rejects an absurd origin on LENGTH, before the URL parser is asked', () => {
    // A 1 MB hostname parses successfully and costs real synchronous time in the URL constructor
    // alone, on the merchant's event loop. The length check is what keeps that off the path.
    //
    // Asserted structurally rather than by duration: the bound is smaller than any origin that could
    // be legal, so nothing downstream of it can be reached by an oversized input. An instrumented
    // URL constructor proves the parser is never asked, which is the actual property, and unlike a
    // millisecond ceiling it does not depend on how loaded the machine is.
    const huge = `https://${'a'.repeat(1_000_000)}.com`;
    const RealUrl = globalThis.URL;
    let parses = 0;
    class CountingUrl extends RealUrl {
      constructor(input: string | URL, base?: string | URL) {
        parses += 1;
        super(input, base);
      }
    }
    globalThis.URL = CountingUrl as unknown as typeof URL;
    try {
      expect(hostnameForOrigin(huge)).toBeNull();
      expect(parses).toBe(0); // refused on length; the parser was never handed the string
      expect(hostnameForOrigin('https://www.shopify.com')).toBe('www.shopify.com');
      expect(parses).toBe(1); // and a legitimate origin still reaches it exactly once
    } finally {
      globalThis.URL = RealUrl;
    }
  });

  it('folds a trailing dot, which WHATWG keeps and the graph does not know', () => {
    expect(hostnameForOrigin('https://www.shopify.com.')).toBe('www.shopify.com');
  });

  it('is idempotent: whatever it accepts, re-parsing yields the same origin', () => {
    for (const o of ['https://www.shopify.com', 'https://a-b.example.com']) {
      expect(new URL(o).origin).toBe(o);
    }
  });
});

/* ------------------------------------------------- what we refuse to publish */

describe('isPublishableOperator', () => {
  it('accepts the real company names production returns', () => {
    for (const n of ['Shopify Inc.', 'Chewy, Inc.', 'Wal-Mart Stores, Inc.', 'Inter IKEA Systems B.V.']) {
      expect(isPublishableOperator(n)).toBe(true);
    }
  });

  it.each([
    [''],
    ['   '],
    ['REDACTED FOR PRIVACY'],
    ['DATA REDACTED'],
    ['Data Protected'],
    ['Not Disclosed'],
    ['Not Disclosed Not Disclosed'],
    ['Domains By Proxy, LLC'],
    ['Whois Privacy Corp.'],
    ['Perfect Privacy, LLC'],
    ['serverTransferProhibited'],
    ['Clickverge LLC Clickverge LLC Clickverge LLC'],
    ['Audible, Inc. Audible Inc.'],
  ])('refuses %j, because it is a non-answer wearing a company\'s grammar', (value) => {
    expect(isPublishableOperator(value)).toBe(false);
  });

  it('refuses bidi, control characters and separators without containing them', () => {
    expect(isPublishableOperator(`Shopify Inc.${String.fromCodePoint(0x202e)}`)).toBe(false);
    expect(isPublishableOperator(`Shopify${String.fromCodePoint(0x2028)}Inc.`)).toBe(false);
    expect(isPublishableOperator(`Shopify${String.fromCodePoint(0x0000)}`)).toBe(false);
  });

  it('refuses a value too long to be a name', () => {
    expect(isPublishableOperator('A'.repeat(60_000))).toBe(false);
  });

  it('recognises repetition, including the comma variants an exact compare misses', () => {
    expect(isRepeatedPhrase('Clickverge LLC Clickverge LLC Clickverge LLC')).toBe(true);
    expect(isRepeatedPhrase('Audible, Inc. Audible Inc.')).toBe(true);
    expect(isRepeatedPhrase('Shopify Inc.')).toBe(false);
    expect(isRepeatedPhrase('Wal-Mart Stores, Inc.')).toBe(false);
  });
});

/* --------------------------------------------------------- observedAt is a claim */

describe('snapshotToIso', () => {
  it('converts the graph\'s zoneless form to an ISO instant in UTC', () => {
    expect(snapshotToIso('2025-03-19 15:44:35')).toBe('2025-03-19T15:44:35.000Z');
  });

  it.each(['UTC', 'Pacific/Niue', 'Pacific/Kiritimati', 'Asia/Kolkata'])(
    'is the same instant under TZ=%s, because new Date() on a zoneless string is not',
    (tz) => {
      const prev = process.env.TZ;
      process.env.TZ = tz;
      try {
        expect(snapshotToIso('2025-03-19 15:44:35')).toBe('2025-03-19T15:44:35.000Z');
      } finally {
        process.env.TZ = prev;
      }
    },
  );

  it('never double-stamps a value that already ends in Z', () => {
    const out = snapshotToIso('2025-03-19T15:44:35Z');
    expect(out).toBe('2025-03-19T15:44:35.000Z');
    expect(Number.isNaN(Date.parse(out ?? 'x'))).toBe(false);
  });

  it.each([['garbage'], ['2025-13-45 99:99:99'], ['2026-02-31 00:00:00'], [''], [null], [42]])(
    'returns null for %j rather than inventing a date',
    (value) => {
      expect(snapshotToIso(value)).toBeNull();
    },
  );
});

/* ============================================================== the source */

/**
 * A clock the test owns. Every TTL decision in the source reads this, so expiry is asserted by
 * advancing a number rather than by sleeping - the suite has no timing-dependent test in it.
 */
function testClock(startMs = 1_700_000_000_000): { now: () => number; advance: (ms: number) => void } {
  let t = startMs;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

/** A fetch that counts calls and never resolves. Anything that awaits it hangs and fails on timeout. */
function neverResolvingFetch(): { fetchImpl: typeof fetch; calls: () => number } {
  let calls = 0;
  const fetchImpl = (() => { calls += 1; return new Promise<Response>(() => undefined); }) as unknown as typeof fetch;
  return { fetchImpl, calls: () => calls };
}

describe('describe() is off the request path', () => {
  it('returns without awaiting the network, even on a cold miss', async () => {
    // The assertion is the ABSENCE of a hang, not a duration. If describe() ever awaits the graph,
    // this promise never settles and vitest fails the test on its own timeout instead of measuring
    // a millisecond count that a loaded CI runner would make flaky.
    const { fetchImpl } = neverResolvingFetch();
    const src = new WhisperOperatorSource({ fetchImpl, onWarning: () => undefined });
    expect(await src.describe('https://www.shopify.com')).toBeNull();
    // Called twice on purpose: the first call is a cold miss that enqueues, and the second finds the
    // name already in flight. That second path is the one that would await an outstanding resolution
    // if it were written to, so it has to settle too.
    expect(await src.describe('https://www.shopify.com')).toBeNull();
  });

  it('does not touch the network AT ALL for an origin it will refuse', async () => {
    const { fetchImpl, calls } = neverResolvingFetch();
    const src = new WhisperOperatorSource({ fetchImpl, onWarning: () => undefined });
    for (const bad of ['http://shopify.com', 'https://[2001:db8::1]', 'https://localhost', '', 'urn:x']) {
      expect(await src.describe(bad)).toBeNull();
    }
    expect(calls()).toBe(0);
  });

  it('serves a resolved record from cache with no further graph calls', async () => {
    let calls = 0;
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(SHOPIFY, () => { calls += 1; }),
      onWarning: () => undefined,
    });
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBeGreaterThan(0));
    const after = calls;
    for (let i = 0; i < 25; i += 1) expect(await src.describe('https://www.shopify.com')).not.toBeNull();
    expect(calls).toBe(after);
    expect(src.stats().hitFresh).toBeGreaterThanOrEqual(25);
  });
});

describe('the record it publishes', () => {
  it('names the REGISTRANT as the operator, never the network organisation', async () => {
    const record = await resolved('https://www.shopify.com', SHOPIFY);
    expect(record?.operator).toBe('Shopify Inc.');
    // The single most important assertion in this file. The network org is the HOSTING PROVIDER.
    // It may appear only inside the advisory network block, which documents itself as being about
    // the address rather than the accountable party. It must never reach either field a reader
    // would take as "who is answerable for this merchant".
    expect(record?.operator).not.toBe(NETORG);
    expect(record?.abuseContact).toBeUndefined();
    expect(record?.network?.organisation).toBe(NETORG); // correctly placed, and only here
    const { network, ...accountability } = record as WhisperOperatorRecord;
    void network;
    expect(JSON.stringify(accountability)).not.toContain(NETORG);
    expect(JSON.stringify(accountability)).not.toContain('cloudflare');
  });

  it('attaches routing context WITHOUT collapsing two prefixes into one', async () => {
    const record = await resolved('https://www.shopify.com', SHOPIFY);
    // Both prefixes survive: a Cloudflare-fronted host genuinely has more than one, and collapsing
    // them to a scalar would state something false. Order is normalised so two resolutions of the
    // same name produce byte-identical records.
    expect(record?.network?.prefixes).toEqual(['104.18.42.0/24', '172.64.145.0/24']);
    expect(record?.network?.asns).toEqual(['AS13335']);
  });

  it('discloses that the WHOIS answer is about the registrable parent, not the host asked for', async () => {
    const record = await resolved('https://www.shopify.com', SHOPIFY);
    // We asked about www.shopify.com and the graph answered about shopify.com. Saying so is the
    // difference between a provenance record and a claim we cannot support.
    expect(record?.queriedName).toBe('www.shopify.com');
    expect(record?.resolvedName).toBe('shopify.com');
    // ...and the pair is all-or-nothing: a half-disclosed fold is worse than none.
    expect(record?.queriedName === undefined).toBe(record?.resolvedName === undefined);
  });

  it('stamps observedAt from the WHOIS snapshot, not from now', async () => {
    const clock = testClock();
    const record = await resolved('https://www.shopify.com', SHOPIFY, { nowMs: clock.now });
    expect(record?.observedAt).toBe('2025-03-19T15:44:35.000Z');
    expect(record?.observedAt).not.toBe(new Date(clock.now()).toISOString());
  });

  it('is frozen, so a downstream caller cannot mutate the cached copy for everyone else', async () => {
    const record = await resolved('https://www.shopify.com', SHOPIFY);
    expect(Object.isFrozen(record)).toBe(true);
    expect(() => {
      (record as unknown as { operator: string }).operator = 'Attacker Inc.';
    }).toThrow();
  });

  it('publishes NOTHING when WHOIS is redacted, rather than a record with a redaction in it', async () => {
    // OperatorRecord.operator is a REQUIRED string in their types, so a redacted registrant leaves
    // no honest record to publish: null is the answer, and the redaction text never travels.
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch({
        ...SHOPIFY,
        whois: {
          registrants: ['REDACTED FOR PRIVACY'],
          registrars: ['GoDaddy.com, LLC'],
          queryTimes: ['2025-03-19 15:44:35'],
          nameServerSets: ['ns1.example.com'],
          createDates: ['2005-03-11'],
        },
      }),
      onWarning: () => undefined,
    });
    expect(await src.describe('https://www.example-redacted.com')).toBeNull();
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBeGreaterThan(0));
    expect(await src.describe('https://www.example-redacted.com')).toBeNull();
    // A resolved absence, not an outage and not a permanent miss.
    expect(src.stats().hitNegative).toBeGreaterThan(0);
    expect(src.stats().outageEntries).toBe(0);
  });
});

describe('a failure is not a negative', () => {
  const FAILURES: Array<[string, () => typeof fetch]> = [
    ['a transport error', () => (() => Promise.reject(new TypeError('network'))) as unknown as typeof fetch],
    ['a 500', () => (() => Promise.resolve(new Response('no', { status: 500 }))) as unknown as typeof fetch],
    ['a 429', () => (() => Promise.resolve(new Response('slow down', { status: 429 }))) as unknown as typeof fetch],
    ['HTML where JSON belongs', () => (() => Promise.resolve(new Response('<html>502</html>', {
      status: 200, headers: { 'content-type': 'text/html' },
    }))) as unknown as typeof fetch],
    ['JSON of the wrong shape', () => (() => Promise.resolve(jsonResponse({ nope: true }))) as unknown as typeof fetch],
    ['a row shorter than its column list', () => (() => Promise.resolve(
      jsonResponse({ columns: PREFIX_COLUMNS, rows: [['only-one-value']] }),
    )) as unknown as typeof fetch],
  ];

  it.each(FAILURES)('records %s as an outage, and never as "no record"', async (_label, make) => {
    const warnings: string[] = [];
    const src = new WhisperOperatorSource({
      fetchImpl: make(), onWarning: (m) => warnings.push(m),
    });
    expect(await src.describe('https://www.shopify.com')).toBeNull();
    await vi.waitFor(() => expect(src.stats().resolutionsFailed).toBeGreaterThan(0));
    const s = src.stats();
    expect(s.resolutionsCompleted).toBe(0); // nothing was published, and nothing pretends otherwise
    // The whole point: an outage entry, not a negative entry. Caching this as a negative would
    // suppress a real answer for the full negative TTL because one request failed once.
    expect(s.outageEntries).toBeGreaterThan(0);
    expect(s.hitNegative).toBe(0);
    // And it must be visible. A silent outage is the failure mode an operator cannot diagnose.
    expect(warnings.join('\n')).not.toBe('');
  });

  it('retries after the outage TTL instead of staying dark', async () => {
    const clock = testClock();
    let fail = true;
    const fetchImpl = ((url: unknown, init?: RequestInit) => (fail
      ? Promise.reject(new TypeError('network'))
      : (cannedFetch(SHOPIFY) as unknown as (u: unknown, i?: RequestInit) => Promise<Response>)(url, init)
    )) as unknown as typeof fetch;

    const src = new WhisperOperatorSource({ fetchImpl, nowMs: clock.now, onWarning: () => undefined });
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().outageEntries).toBeGreaterThan(0));

    fail = false;
    clock.advance(10 * 60_000); // past any sane outage TTL
    expect(await src.describe('https://www.shopify.com')).toBeNull(); // re-enqueues rather than refusing
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBe(1));
    expect((await src.describe('https://www.shopify.com'))?.operator).toBe('Shopify Inc.');
  });

  it('caches a TRUE negative for a name it HAS observed but holds no operator for', async () => {
    // The distinction the gate rests on: this name has a HOSTNAME row, so it exists as far as the
    // graph is concerned. It simply has no publishable registrant. That is a resolved absence.
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch({
        prefixRows: [{ subject: 'nothing-here.example.com', prefixes: [] }],
        zone: { subject: 'nothing-here.example.com', dnssecAlgorithms: [] },
      }),
      onWarning: () => undefined,
    });
    await src.describe('https://nothing-here.example.com');
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBeGreaterThan(0));
    expect(await src.describe('https://nothing-here.example.com')).toBeNull();
    const s = src.stats();
    expect(s.hitNegative).toBeGreaterThan(0);
    expect(s.outageEntries).toBe(0); // a clean "we have nothing" is not an outage
    expect(s.gatedNoHostRow).toBe(0); // and it was not gated: the name was observed
  });

  it('says "could not check" by THROWING, which is the contract, and never by returning null', async () => {
    // Their interface gives null exactly one meaning - no record - and documents that a throw is
    // swallowed. So a throw is the only way to say "I could not check" without lying, and the first
    // describe() after a failure must take it.
    const src = new WhisperOperatorSource({
      fetchImpl: (() => Promise.reject(new TypeError('network'))) as unknown as typeof fetch,
      onWarning: () => undefined,
    });
    expect(await src.describe('https://www.shopify.com')).toBeNull(); // cold miss: nothing known yet
    await vi.waitFor(() => expect(src.stats().outageEntries).toBeGreaterThan(0));
    await expect(src.describe('https://www.shopify.com')).rejects.toThrow(/could not check/i);
  });

  it('gives that error a message a merchant operator can act on', async () => {
    const src = new WhisperOperatorSource({
      fetchImpl: (() => Promise.resolve(new Response('nope', { status: 500 }))) as unknown as typeof fetch,
      onWarning: () => undefined,
    });
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().outageEntries).toBeGreaterThan(0));
    const err = await src.describe('https://www.shopify.com').catch((e: unknown) => e as Error);
    expect(err).toBeInstanceOf(Error);
    // Asserted as an EXACT shape rather than by listing words the message must not contain. A denylist
    // in a test is weaker - it catches only what it happens to name - and for internal vocabulary it
    // also publishes the very strings it exists to keep out, which makes the guard the disclosure.
    expect((err as Error).message).toMatch(
      /^whisper-graph: could not check www\.shopify\.com \([a-z0-9]+\); this is an outage on our side, not an absence of record$/,
    );
  });

  it('never throws for a shape it simply does not handle, however hostile the graph is', async () => {
    // A throw is reserved for an outage. Anything else - a hostile body, a wrong shape, a torn row -
    // must not turn into a throw on the FIRST call, because the host swallows it and the merchant is
    // left unable to tell a broken source from a quiet one.
    const hostile: Array<[string, typeof fetch]> = [
      ['a sync throw from fetch itself', (() => { throw new Error('sync'); }) as unknown as typeof fetch],
      ['a rejection that is not an Error', (() => Promise.reject('a string')) as unknown as typeof fetch],
      ['no Response at all', (() => Promise.resolve(undefined as unknown as Response)) as unknown as typeof fetch],
      ['truncated JSON', (() => Promise.resolve(new Response('{', {
        status: 200, headers: { 'content-type': 'application/json' },
      }))) as unknown as typeof fetch],
    ];
    for (const [label, fetchImpl] of hostile) {
      const src = new WhisperOperatorSource({ fetchImpl, onWarning: () => undefined });
      await expect(src.describe('https://www.shopify.com'), label).resolves.toBeNull();
    }
  });
});

describe('concurrency', () => {
  it('collapses a burst for one origin into a single resolution', async () => {
    let calls = 0;
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(SHOPIFY, () => { calls += 1; }), onWarning: () => undefined,
    });
    const burst = await Promise.all(
      Array.from({ length: 50 }, () => src.describe('https://www.shopify.com')),
    );
    expect(burst.every((r) => r === null)).toBe(true);
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBeGreaterThan(0));
    // One resolution's worth of lanes, not fifty. Without single-flight this is 50x the graph calls
    // and fifty times the request budget spent on one origin.
    expect(src.stats().resolutionsStarted).toBe(1);
    expect(src.stats().coalesced).toBeGreaterThan(0);
    expect(calls).toBeLessThanOrEqual(4);
  });

  it('keeps distinct origins distinct under an interleaved burst', async () => {
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(SHOPIFY), onWarning: () => undefined,
    });
    const origins = Array.from({ length: 12 }, (_, i) => `https://host-${i}.example.com`);
    await Promise.all(origins.flatMap((o) => [src.describe(o), src.describe(o), src.describe(o)]));
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBe(12));
    expect(src.stats().resolutionsStarted).toBe(12);
  });

  it('bounds the queue and counts what it dropped rather than growing without limit', async () => {
    const { fetchImpl } = neverResolvingFetch();
    const src = new WhisperOperatorSource({ fetchImpl, maxQueue: 4, onWarning: () => undefined });
    for (let i = 0; i < 200; i += 1) await src.describe(`https://h${i}.example.com`);
    const s = src.stats();
    expect(s.queueDepth).toBeLessThanOrEqual(4);
    expect(s.enqueueDropped).toBeGreaterThan(0); // visible, not silent
  });

  it('bounds the entry cache, because the origin comes from a request header', async () => {
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(SHOPIFY), maxEntries: 16, onWarning: () => undefined,
    });
    for (let i = 0; i < 400; i += 1) await src.describe(`https://f${i}.example.com`);
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBeGreaterThan(50));
    expect(src.stats().fqdnEntries).toBeLessThanOrEqual(16);
  });
});

describe('composition with the host verifier', () => {
  it('annotates a trusted result and leaves trust untouched', async () => {
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(SHOPIFY), onWarning: () => undefined,
    });
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBeGreaterThan(0));

    const trusted: { trusted: true; protocol: string; operator?: OperatorRecord } =
      { trusted: true, protocol: 'test' };
    const out = await annotateWithOperator(trusted, src, 'https://www.shopify.com');
    expect(out.trusted).toBe(true); // annotation is provenance; it must never move trust
    expect(out.operator?.operator).toBe('Shopify Inc.');
    expect(out.operator?.registry).toBe('whisper-graph');
  });

  it('leaves an untrusted result entirely alone, and asks us nothing', async () => {
    const { fetchImpl, calls } = neverResolvingFetch();
    const src = new WhisperOperatorSource({ fetchImpl, onWarning: () => undefined });
    const out = await annotateWithOperator({ trusted: false as const }, src, 'https://www.shopify.com');
    expect(out.trusted).toBe(false);
    expect('operator' in out ? out.operator : undefined).toBeUndefined();
    expect(calls()).toBe(0);
  });
});

describe('the breaker, and what it must not take down with it', () => {
  /**
   * The defect this test was written for: recordOutage() used to open the GLOBAL breaker on the
   * FIRST failure of ANY name. One odd origin - or one attacker pointing a hostile origin at a
   * merchant - therefore made describe() throw for every other origin in the process. Provenance
   * for the whole merchant, denied by one bad input.
   */
  it('lets one unresolvable name fail without blinding a healthy one', async () => {
    const fetchImpl = (async (_u: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { parameters?: { name?: string } };
      if (body.parameters?.name === 'broken.example.com') throw new TypeError('network');
      return (cannedFetch(SHOPIFY) as unknown as (u: unknown, i?: RequestInit) => Promise<Response>)(_u, init);
    }) as unknown as typeof fetch;

    const src = new WhisperOperatorSource({ fetchImpl, onWarning: () => undefined });
    await src.describe('https://broken.example.com');
    await vi.waitFor(() => expect(src.stats().resolutionsFailed).toBeGreaterThan(0));

    // The healthy name still resolves and still serves...
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBeGreaterThan(0));
    expect((await src.describe('https://www.shopify.com'))?.operator).toBe('Shopify Inc.');
    // ...while the broken one still tells the truth about itself.
    await expect(src.describe('https://broken.example.com')).rejects.toThrow(/could not check/i);
    expect(src.stats().graphUnreachable).toBe(false);
  });

  it('opens only after outageTripAfter consecutive failures, and closes on one success', async () => {
    let fail = true;
    const fetchImpl = ((u: unknown, init?: RequestInit) => (fail
      ? Promise.reject(new TypeError('network'))
      : (cannedFetch(SHOPIFY) as unknown as (a: unknown, b?: RequestInit) => Promise<Response>)(u, init)
    )) as unknown as typeof fetch;
    const warnings: string[] = [];
    const src = new WhisperOperatorSource({
      fetchImpl, outageTripAfter: 3, onWarning: (m) => warnings.push(m),
    });

    await src.describe('https://a.example.com');
    await vi.waitFor(() => expect(src.stats().resolutionsFailed).toBe(1));
    expect(src.stats().graphUnreachable).toBe(false); // one failure is not evidence
    await src.describe('https://b.example.com');
    await vi.waitFor(() => expect(src.stats().resolutionsFailed).toBe(2));
    expect(src.stats().graphUnreachable).toBe(false);
    await src.describe('https://c.example.com');
    await vi.waitFor(() => expect(src.stats().resolutionsFailed).toBe(3));
    expect(src.stats().graphUnreachable).toBe(true); // three is
    expect(warnings.filter((w) => /consecutive failures/.test(w))).toHaveLength(1); // said once, not thrice

    fail = false;
    // While open, every name reports "could not check" rather than inventing an absence.
    await expect(src.describe('https://d.example.com')).rejects.toThrow(/could not check/i);
    // One success is proof of reachability and closes it immediately, without waiting out a TTL.
    const recovered = new WhisperOperatorSource({ fetchImpl, outageTripAfter: 3, onWarning: () => undefined });
    await recovered.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(recovered.stats().resolutionsCompleted).toBe(1));
    expect(recovered.stats().graphUnreachable).toBe(false);
    expect(recovered.stats().consecutiveFailures).toBe(0);
  });
});

describe('accounting an operator can reconcile', () => {
  /**
   * The invariant that made the missing counter visible: if a started resolution can end without
   * incrementing anything terminal, an operator watching started-vs-completed sees a permanent gap
   * and cannot tell a stuck queue from a failing graph.
   */
  it('lands every started resolution in exactly one terminal counter', async () => {
    // Failure is keyed on the NAME, so the split between outcomes is fixed rather than depending on
    // how many lanes a resolution happens to run.
    const fetchImpl = ((u: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { parameters?: { name?: string } };
      const name = body.parameters?.name ?? '';
      if (/^m(3|6|9|12)\./.test(name)) return Promise.reject(new TypeError('network'));
      if (/^m(4|8)\./.test(name)) return Promise.resolve(new Response('x', { status: 500 }));
      return (cannedFetch(SHOPIFY) as unknown as (a: unknown, b?: RequestInit) => Promise<Response>)(u, init);
    }) as unknown as typeof fetch;

    const src = new WhisperOperatorSource({ fetchImpl, outageTripAfter: 1_000, onWarning: () => undefined });
    for (let i = 0; i < 30; i += 1) {
      await src.describe(`https://m${i}.example.com`).catch(() => undefined);
    }
    await vi.waitFor(() => {
      const s = src.stats();
      expect(s.queueDepth + s.inflight).toBe(0);
    }, { timeout: 5_000 });

    const s = src.stats();
    expect(s.resolutionsStarted).toBeGreaterThan(0);
    expect(s.resolutionsCompleted + s.resolutionsFailed + s.inflight).toBe(s.resolutionsStarted);
    expect(s.resolutionsCompleted).toBeGreaterThan(0); // the mix really did contain both outcomes
    expect(s.resolutionsFailed).toBeGreaterThan(0);
  });

  it('exposes each cache outcome separately, so a miss is never mistaken for an outage', async () => {
    const src = new WhisperOperatorSource({ fetchImpl: cannedFetch(SHOPIFY), onWarning: () => undefined });
    const before = src.stats();
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBe(1));
    await src.describe('https://www.shopify.com');
    const after = src.stats();
    expect(after.describeCalls - before.describeCalls).toBe(2);
    expect(after.missEnqueued).toBe(1);
    expect(after.hitFresh).toBe(1);
    expect(after.hitNegative).toBe(0);
    expect(after.outageEntries).toBe(0);
    expect(Object.isFrozen(after)).toBe(true);
  });
});

describe('construction refuses a configuration that cannot work', () => {
  it.each([
    ['maxEntries', 0],
    ['maxEntries', -1],
    ['zoneTtlMs', Number.NaN],
    ['networkTtlMs', Number.POSITIVE_INFINITY],
    ['maxQueue', 0],
    ['outageTripAfter', 0],
    ['maxCallsPerMinute', -5],
  ])('names %s in the error rather than failing silently later', (option, value) => {
    // maxEntries: 0 would evict everything it writes, so every describe() would miss forever and the
    // source would look broken with nothing to point at. A NaN TTL makes every expiry comparison
    // false, so nothing ever expires. Both are refused here, with the option named.
    expect(() => new WhisperOperatorSource({
      [option]: value, fetchImpl: cannedFetch(SHOPIFY), onWarning: () => undefined,
    })).toThrow(new RegExp(option));
  });

  it('accepts an empty options object and runs entirely keyless', async () => {
    const warnings: string[] = [];
    const src = new WhisperOperatorSource({ fetchImpl: cannedFetch(SHOPIFY), onWarning: (m) => warnings.push(m) });
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBe(1));
    expect((await src.describe('https://www.shopify.com'))?.operator).toBe('Shopify Inc.');
    // Keyless is a supported tier, not a degraded one: every field resolves. The notice deliberately
    // makes no claim about what a key would buy, because an earlier version claimed it raised the rate
    // limits and that is not true at this endpoint.
    expect(warnings.join('\n')).toMatch(/no API key/i);
    expect(warnings.join('\n')).toMatch(/every field still resolves/i);
    expect(src.stats().keyless).toBe(true);
  });
});

/* ================================================== the security controls, one test each */

describe('the fold gate: a brand is not the operator of a name the graph never saw', () => {
  /**
   * The control this file exists for. WHOIS folds ANY subdomain to its registrable parent, so an
   * invented name under a brand comes back with that brand's registrant AND a perfectly genuine fold
   * advisory. A subdomain-takeover origin verifies legitimately - the attacker controls the host,
   * serves the well-known directory, and gets trusted: true - so the only thing between that and a
   * payments record reading "Shopify Inc." is the requirement that we have observed the name.
   */
  const NEVER_OBSERVED: Canned = {
    prefixRows: [], // exercises the no-rows early refusal; an invented subdomain often returns a row
    zone: { subject: 'example.com', dnssecAlgorithms: [], companyName: 'Example Brand Inc.' },
    whois: {
      registrants: ['Example Brand Inc.'],
      registrars: ['MarkMonitor Inc.'],
      queryTimes: ['2025-03-19 15:44:35'],
      nameServerSets: ['ns1.example.com'],
      createDates: ['2005-03-11'],
    },
    advisories: [{
      kind: 'whois-parent-fold',
      queried: 'abandoned.example.com',
      resolved: 'example.com',
    }],
  };

  it('publishes nothing, and the brand appears nowhere in what it hands back', async () => {
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(NEVER_OBSERVED), onWarning: () => undefined,
    });
    const origin = 'https://abandoned.example.com';
    expect(await src.describe(origin)).toBeNull();
    await vi.waitFor(() => expect(src.stats().gatedNoHostRow).toBe(1));
    const served = await src.describe(origin);
    expect(served).toBeNull();
    expect(JSON.stringify(served ?? {})).not.toContain('Example Brand');
    expect(src.stats().zoneEntries).toBe(0); // nothing was cached under the brand's zone either
  });

  it('never even asks WHOIS about a name it has not observed', async () => {
    const queries: string[] = [];
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(NEVER_OBSERVED, (q) => queries.push(q)), onWarning: () => undefined,
    });
    await src.describe('https://abandoned.example.com');
    await vi.waitFor(() => expect(src.stats().gatedNoHostRow).toBe(1));
    // The gate is in front of the registrant lane, so a flood of invented subdomains costs one call
    // each rather than four, and the brand's registrant is never even retrieved.
    expect(queries.some((q) => q.includes('whisper.history.whois'))).toBe(false);
  });

  it('still resolves the real host of the same zone, so the gate is not simply "always null"', async () => {
    const record = await resolved('https://www.shopify.com', SHOPIFY);
    expect(record?.operator).toBe('Shopify Inc.');
    expect(record?.resolvedName).toBe('shopify.com');
  });
});

describe('the fold advisory is untrusted data', () => {
  const foldTo = (resolved: string): Canned => ({
    prefixRows: [{ subject: 'evil.example.com', prefixes: ['192.0.2.0/24'] }],
    zone: { subject: resolved, dnssecAlgorithms: [], companyName: 'Shopify Inc.' },
    whois: {
      registrants: ['Shopify Inc.'],
      registrars: ['MarkMonitor Inc.'],
      queryTimes: ['2025-03-19 15:44:35'],
      nameServerSets: ['ns1.shopify.com'],
      createDates: ['2005-03-11'],
    },
    advisories: [{ kind: 'whois-parent-fold', queried: 'evil.example.com', resolved }],
  });

  it('refuses a fold to a bare TLD, which would poison the zone cache for every sibling', async () => {
    // Keying the shared zone cache on "com" means every other .com origin that folds the same way
    // reads whatever operator the first one learned.
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(foldTo('com')), onWarning: () => undefined,
    });
    await src.describe('https://evil.example.com');
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBe(1));
    expect(src.stats().foldsRejected).toBe(1);
    expect(src.stats().foldsLearned).toBe(0);
    const record = (await src.describe('https://evil.example.com')) as WhisperOperatorRecord | null;
    expect(record?.resolvedName).not.toBe('com');
  });

  it('refuses a fold to a name that is not a suffix of the name we sent', async () => {
    const canned = foldTo('shopify.com'); // not a suffix of evil.example.com
    const src = new WhisperOperatorSource({ fetchImpl: cannedFetch(canned), onWarning: () => undefined });
    await src.describe('https://evil.example.com');
    await vi.waitFor(() => expect(src.stats().resolutionsCompleted).toBe(1));
    expect(src.stats().foldsRejected).toBe(1);
  });
});

describe('every string the record publishes, not only `operator`', () => {
  it('carries no markup, no bidi override and no redaction text in the network block', async () => {
    const record = await resolved('https://evil-shop.example.com', {
      prefixRows: [{
        subject: 'evil-shop.example.com',
        prefixes: ['192.0.2.0/24'],
        netAbuseEmails: ['\u202eabuse@evil.example'],
        rirs: ['REDACTED FOR PRIVACY'],
        rpkiStatuses: ['valid'],
        roaAsns: [-1e308],
        roaMaxLengths: [0.5],
        anycasts: [true],
        moases: [false],
      }],
      asn: {
        asns: [`AS${'X'.repeat(3000)}`],
        asNames: Array.from({ length: 200 }, (_, i) => `FAKE-${i}`),
        netOrgNames: ['<script>alert(1)</script>'],
      },
      zone: { subject: 'evil-shop.example.com', dnssecAlgorithms: [], companyName: 'Evil Shop Ltd' },
      whois: {
        registrants: ['Evil Shop Ltd'],
        registrars: ['GoDaddy.com, LLC'],
        queryTimes: ['2025-03-19 15:44:35'],
        nameServerSets: ['ns1.evil.example'],
        createDates: ['2005-03-11'],
      },
    });

    const serialised = JSON.stringify(record);
    // The WHOLE record travels to the merchant and into their logs, so the whole record is checked.
    expect(serialised).not.toMatch(/[\u0000-\u001f\u200e\u200f\u202a-\u202e\u2066-\u2069]/);
    expect(serialised).not.toContain('<script');
    expect(record?.network?.rirs ?? []).not.toContain('REDACTED FOR PRIVACY');
    expect(record?.network?.organisation).toBeUndefined(); // the markup value was dropped, not escaped
    expect(record?.network?.abuseContact).toBeUndefined(); // the bidi value was dropped
    // Bounded, because these are re-served on every cache hit.
    expect(record?.network?.asNames?.length ?? 0).toBeLessThanOrEqual(8);
    // An ASN is a 32-bit unsigned integer; a ROA max-length is a prefix length. Neither is a float.
    expect(record?.network?.rpki?.roaOrigin).toBeUndefined();
    expect(record?.network?.rpki?.maxLength).toBeUndefined();
  });

  it('freezes the arrays, not just the record, since the cache serves the same instances', async () => {
    const record = await resolved('https://www.shopify.com', SHOPIFY);
    const prefixes = record?.network?.prefixes;
    expect(Object.isFrozen(prefixes)).toBe(true);
    expect(() => (prefixes as string[]).push('0.0.0.0/0')).toThrow();
  });
});

describe('what a registrant has to survive to be called the operator', () => {
  const withRegistrant = (registrants: string[], registrars: string[], companyName: string): Canned => ({
    prefixRows: [{ subject: 'shop.example.com', prefixes: ['192.0.2.0/24'] }],
    zone: { subject: 'shop.example.com', dnssecAlgorithms: [], companyName },
    whois: {
      registrants,
      registrars,
      queryTimes: registrants.map(() => '2025-03-19 15:44:35'),
      nameServerSets: registrants.map(() => 'ns1.example.com'),
    },
  });

  it('refuses the registrar bleeding into the registrant field, in any spelling', async () => {
    const record = await resolved('https://shop.example.com',
      withRegistrant(['TUCOWS.COM, CO.'], ['Tucows Domains Inc.'], 'Caraway'));
    expect(record).toBeNull();
  });

  it('refuses a registrant nothing outside WHOIS agrees with', async () => {
    // "Identity Protection Service" is shaped exactly like a company and is a privacy product. No
    // denylist can enumerate these, which is why corroboration is the test rather than a list.
    const record = await resolved('https://shop.example.com',
      withRegistrant(['Identity Protection Service'], ['GoDaddy.com, LLC'], 'Bombas'));
    expect(record).toBeNull();
  });

  it('walks back past a proxy to the corroborated value underneath it', async () => {
    // Measured against live data: this is the difference between publishing nothing for real
    // merchants and publishing their actual name.
    const record = await resolved('https://shop.example.com',
      withRegistrant(['Domains By Proxy, LLC', 'Ruggable LLC'], ['GoDaddy.com, LLC', 'GoDaddy.com, LLC'], 'Ruggable'));
    expect(record?.operator).toBe('Ruggable LLC');
  });

  it('does not walk back into a FORMER holder of a transferred name', async () => {
    // The risk of walking backwards. Corroboration is what bounds it: a previous holder does not
    // agree with today's company name or today's label.
    const record = await resolved('https://shop.example.com',
      withRegistrant(['REDACTED FOR PRIVACY', 'Former Holder Corporation'], ['CSC', 'CSC'], 'Newco'));
    expect(record).toBeNull();
  });

  it('publishes nothing rather than dating a registrant by our own clock', async () => {
    for (const asOf of ['not-a-date', null, 42, '2022-07-11T03:14:15+02:00']) {
      const canned = withRegistrant(['Shopify Inc.'], ['MarkMonitor Inc.'], 'Shopify Inc.');
      canned.whois = { ...canned.whois, queryTimes: [asOf] };
      const record = await resolved('https://shop.example.com', canned);
      expect(record, `queryTime=${JSON.stringify(asOf)}`).toBeNull();
    }
  });
});

describe('DNSSEC is stated in the direction that cannot be stale-wrong', () => {
  it('never claims a zone is unsigned, and lists every algorithm rather than picking one', async () => {
    const canned: Canned = {
      ...SHOPIFY,
      zone: {
        subject: 'shopify.com',
        // A zone mid-rollover legitimately carries two.
        dnssecAlgorithms: ['ECDSAP256SHA256', 'ED25519'],
        companyName: 'Shopify Inc.',
      },
    };
    const record = await resolved('https://www.shopify.com', canned);
    // 'absent' is a positive claim read from an ingested snapshot, so a lagging ingest would make it
    // confidently wrong about a freshly-signed zone. We never make it.
    expect(record?.dnssec).toBe('unchecked');
    expect(record?.dnssecAlgorithms).toEqual(['ECDSAP256SHA256', 'ED25519']);
  });
});

describe('a warning sink is never load-bearing', () => {
  it('does not let a throwing onWarning escape describe()', async () => {
    // onWarning runs synchronously inside describe() via enqueue. A merchant wires it to their app
    // logger, and a logger that throws on a closed stream would look exactly like a bug in us.
    const src = new WhisperOperatorSource({
      maxQueue: 1,
      fetchImpl: (() => new Promise<Response>(() => undefined)) as unknown as typeof fetch,
      onWarning: () => { throw new Error('host logger blew up'); },
    });
    void src.describe('https://one.example.com');
    void src.describe('https://two.example.com');
    await expect(src.describe('https://three.example.com')).resolves.toBeNull();
  });
});

/* ============================================ the fixes above, each proved on the bug it shipped with */

describe('names are compared as labels, not as strings', () => {
  it('is not defeated by an escaped dot, which a suffix test answers WRONGLY', () => {
    // `a\.b.example` is the two-label name [a.b, example] per RFC 1035 section 5.1. It ends with
    // ".b.example" and is not beneath it. A string suffix test returns true here.
    expect(isSameOrSubdomainOf('a\\.b.example', 'b.example')).toBe(false);
  });

  it('folds ASCII case, because DNS does (RFC 4343)', () => {
    expect(isSameOrSubdomainOf('www.shopify.com', 'SHOPIFY.com')).toBe(true);
    expect(isSameOrSubdomainOf('WWW.SHOPIFY.COM', 'shopify.com')).toBe(true);
  });

  it('treats a trailing root dot on either side as the same name', () => {
    expect(isSameOrSubdomainOf('www.shopify.com.', 'shopify.com')).toBe(true);
    expect(isSameOrSubdomainOf('www.shopify.com', 'shopify.com.')).toBe(true);
  });

  it('still refuses a sibling that merely ends in the parent', () => {
    // The property that mattered most all along. Kept pinned.
    expect(isSameOrSubdomainOf('evil-shopify.com', 'shopify.com')).toBe(false);
    expect(isSameOrSubdomainOf('notshopify.com', 'shopify.com')).toBe(false);
  });

  it('never accepts the empty string as a parent', () => {
    expect(isSameOrSubdomainOf('evil.example.', '')).toBe(false);
  });
});

describe('hostnameForOrigin, the cases that used to slip through', () => {
  it('rejects a doubled trailing dot instead of normalising it into a legal name', () => {
    // WHATWG keeps it and calls it canonical; a zero-length non-root label is not a name.
    expect(hostnameForOrigin('https://example.com..')).toBeNull();
    expect(hostnameForOrigin('https://example.com.')).toBe('example.com'); // one root dot is fine
  });

  it('rejects a Reserved LDH label that is not an A-label (RFC 5890 2.3.1)', () => {
    expect(hostnameForOrigin('https://ab--cd.com')).toBeNull();
    expect(hostnameForOrigin('https://xn--bcher-kva.com')).toBe('xn--bcher-kva.com');
  });

  it('rejects names that can never have a registry answer', () => {
    for (const o of ['https://printer.local', 'https://relay.onion', 'https://foo.alt',
      'https://1.0.0.127.in-addr.arpa', 'https://nas.lan', 'https://x.intranet']) {
      expect(hostnameForOrigin(o), o).toBeNull();
    }
  });

  it('bounds the input BEFORE anything walks its characters', () => {
    // The fix is STRUCTURAL, not a speed-up, and this comment used to claim otherwise: it said a trailing
    // run of dots "backtracks once per dot from every start position" - which turned out to be RIGHT,
    // twice re-measured on the wrong input shape before that was established. What this asserts is the
    // property that holds either way - the origin
    // bound is the longest origin that can possibly be legal, so a pathological input is refused on
    // LENGTH before anything walks its characters, whatever the per-character cost would have been.
    //
    // Deliberately NOT a timing assertion. An earlier version of this test compared two durations and
    // was flaky on a loaded machine, which is exactly what this file says elsewhere it will not do. The
    // bound is a property, so it is asserted as one.
    const label = 'a'.repeat(49);
    const longestLegal = `https://${label}.${label}.${label}.${label}.${label}.aaa`;
    expect(hostnameForOrigin(longestLegal)).not.toBeNull();

    // One octet more is refused, and so is a run of dots of any length.
    expect(hostnameForOrigin(`${longestLegal}a`)).toBeNull();
    expect(hostnameForOrigin(`https://a${'.'.repeat(250)}a`)).toBeNull();
    expect(hostnameForOrigin(`https://a${'.'.repeat(100_000)}a`)).toBeNull();

    // And whatever it DOES accept is a legal DNS name measured in octets, which is the real property.
    const accepted = hostnameForOrigin('https://www.shopify.com');
    expect(accepted).not.toBeNull();
    expect((accepted as string).length).toBeLessThanOrEqual(253);
  });
});

describe('the two classes that fail one comparison for opposite reasons', () => {
  // A comment in the source draws this distinction; these are the cases it draws it about. The point
  // is that "rejected" does NOT mean "deceptive": three of these name exactly the host they appear to.
  it.each([
    ['an uppercase scheme', 'HTTPS://shopify.com', 'shopify.com'],
    ['a mixed-case host', 'https://WWW.Shopify.com', 'www.shopify.com'],
    ['the slash WHATWG adds', 'https://shopify.com/', 'shopify.com'],
  ])('refuses %s, and one line at the boundary recovers it', (_label, raw, host) => {
    // Strict at the core: the caller asked about a string we would not be answering about.
    expect(hostnameForOrigin(raw)).toBeNull();
    // Liberal at the edge: the documented one-liner, which is what the example does before calling in.
    expect(hostnameForOrigin(new URL(raw).origin)).toBe(host);
  });

  it('refuses a userinfo lie in BOTH directions, because that one really is a different host', () => {
    // The distinction has to cut: canonicalising this does not rescue it into shopify.com. It names
    // evil.test, and would still be refused there for being an RFC 6761 special-use TLD.
    expect(hostnameForOrigin('https://shopify.com@evil.test')).toBeNull();
    expect(new URL('https://shopify.com@evil.test').origin).toBe('https://evil.test');
    // And with an ordinary registrable host in place of the reserved one, canonicalising still does
    // not produce shopify.com. It produces the attacker's host, which is the whole objection.
    expect(hostnameForOrigin('https://shopify.com@evil-shop.net')).toBeNull();
    expect(hostnameForOrigin(new URL('https://shopify.com@evil-shop.net').origin)).toBe('evil-shop.net');
  });
});

describe('isPublishableOperator, the classes a denylist kept missing', () => {
  it.each([
    ['a script tag', '<script>alert(1)</script>'],
    ['an event handler', '<img src=x onerror=alert(1)>'],
    ['a spreadsheet formula', '=HYPERLINK("https://evil.example","Shopify Inc.")'],
    ['a markdown javascript link', 'Shopify Inc. [click](javascript:alert(1))'],
    ['a URL', 'https://www.markmonitor.com'],
    ['an email', 'abuse@godaddy.com'],
    ['a nameserver', 'ns1.mailbank.com'],
    ['a bare date', '2025-05-07'],
    ['a title', 'mr'],
  ])('refuses %s', (_why, value) => {
    expect(isPublishableOperator(value)).toBe(false);
  });

  it.each([
    ['a non-breaking space', 'Not\u00a0Disclosed'],
    ['two spaces', 'Not  Disclosed'],
    ['NBSP inside DATA PROTECTED', 'Data\u00a0Protected'],
    ['NBSP inside DOMAINS BY PROXY', 'Domains\u00a0By\u00a0Proxy, LLC'],
  ])('refuses a redaction sentinel spelled with %s', (_why, value) => {
    // Every multi-word sentinel was bypassable by changing one space, and these are the very values
    // the sentinel list was derived from.
    expect(isPublishableOperator(value)).toBe(false);
  });

  it.each([
    ['Cyrillic S', 'Ѕhopify Inc.'],
    ['Cyrillic a', 'PаyPal, Inc.'],
    ['Greek o', 'Gοogle LLC'],
  ])('refuses a mixed-script homoglyph: %s', (_why, value) => {
    // The field's entire value is that a human reads the name and recognises it.
    expect(isPublishableOperator(value)).toBe(false);
  });

  it('accepts a legitimate non-Latin company name', () => {
    // The same line must not reject a real Japanese or Greek merchant while accepting a homoglyph.
    expect(isPublishableOperator('トヨタ自動車株式会社')).toBe(true);
    expect(isPublishableOperator('ΟΤΕ ΑΕ')).toBe(true);
  });

  it('recognises repetition at a prime count, not only 2, 3 and 4', () => {
    expect(isRepeatedPhrase('Acme LLC Acme LLC Acme LLC Acme LLC Acme LLC')).toBe(true);
    expect(isRepeatedPhrase('Acme Acme Acme Acme Acme Acme Acme')).toBe(true);
    expect(isRepeatedPhrase('Wal-Mart Stores, Inc.')).toBe(false);
  });
});

describe('liveness: the drain always comes back', () => {
  it('starts no network work on describe()\'s own synchronous stack', async () => {
    // describe() contains no await, so by the time the call expression yields a promise its whole
    // body has run, including everything enqueue() reaches. Anything it kicked is visible NOW. The
    // drain used to be started inline, which charged the query build, the JSON.stringify, the abort
    // signal and the fetch call itself to the merchant's request.
    const seen: string[] = [];
    const src = new WhisperOperatorSource({
      onWarning: () => undefined,
      fetchImpl: (async (_u: unknown, init?: RequestInit) => {
        seen.push(String((JSON.parse(String(init?.body ?? '{}')) as { query?: string }).query));
        return new Promise<Response>(() => undefined);
      }) as unknown as typeof fetch,
    });

    const pending = src.describe('https://www.shopify.com');
    expect(seen).toEqual([]); // nothing on this stack

    await expect(pending).resolves.toBeNull();
    // ...and the other half, so the fix can never be "stop resolving": the work still happens, later.
    await vi.waitFor(() => expect(src.stats().graphCallsTotal).toBeGreaterThan(0));
  });

  it('resumes draining after its own budget refills, for names already queued', async () => {
    // The wedge: enqueue used to re-arm the drain only on the path that ADDS a name. With the queue
    // at its cap and the budget spent, every later describe() coalesced or dropped, nothing called
    // the budget again, and the source made no further graph call for the life of the process.
    const clock = testClock();
    const src = new WhisperOperatorSource({
      fetchImpl: cannedFetch(SHOPIFY),
      nowMs: clock.now,
      maxCallsPerMinute: 1,
      maxQueue: 4,
      onWarning: () => undefined,
    });

    for (const h of ['a', 'b', 'c']) await src.describe(`https://${h}.example.com`);
    // Wait for the budget to actually deny a take, rather than for the queue to be non-empty: the
    // drain is deferred to a later turn, so a non-empty queue proves only that it has not run yet.
    await vi.waitFor(() => expect(src.stats().budgetDeferrals).toBeGreaterThan(0));
    expect(src.stats().queueDepth).toBeGreaterThan(0); // work is owed, and visibly deferred

    const stalled = src.stats().resolutionsCompleted;
    clock.advance(61_000); // the window has rolled over

    // Only repeat traffic for a name ALREADY pending, which is exactly the case that used to be
    // terminal: it takes the coalesced branch, which used to return without re-arming the drain.
    for (let i = 0; i < 5; i += 1) await src.describe('https://c.example.com');

    // The property is that progress RESUMES, not that the queue empties: a budget of one call per
    // minute needs one window per name, so an emptied queue would take three windows and asserting it
    // would be asserting the budget rather than the liveness.
    await vi.waitFor(
      () => expect(src.stats().resolutionsCompleted).toBeGreaterThan(stalled),
      { timeout: 5_000 },
    );
  });
});

describe('the fold gate, second half: a node is not evidence of an announced-prefix observation', () => {
  /**
   * The stronger half of the control, and the one that carries the weight.
   *
   * A HOSTNAME row's mere existence is not evidence of any observation about the name. So where
   * a registrant is being inherited from a DIFFERENT name - which is only when a fold happened - the
   * queried name must additionally have an ANNOUNCED-PREFIX OBSERVATION.
   */
  const observedButUnresolved: Canned = {
    // A row exists, so the first half of the gate passes. No prefixes, so the graph holds no
    // announced-prefix observation - which is the shape an invented or long-dead subdomain has AND the
    // shape a live storefront can have: `www.bombas.com` measures identically. The gate is a
    // conservative proxy, not a test for invention.
    prefixRows: [{ subject: 'abandoned.example.com', prefixes: [] }],
    zone: { subject: 'example.com', dnssecAlgorithms: [], companyName: 'Example Brand Inc.' },
    whois: {
      registrants: ['Example Brand Inc.'],
      registrars: ['MarkMonitor Inc.'],
      queryTimes: ['2025-03-19 15:44:35'],
      nameServerSets: ['ns1.example.com'],
      createDates: ['2005-03-11'],
    },
    advisories: [{
      kind: 'whois-parent-fold',
      queried: 'abandoned.example.com',
      resolved: 'example.com',
    }],
  };

  it('refuses to inherit a brand for a folded name with no announced-prefix observation', async () => {
    const record = await resolved('https://abandoned.example.com', observedButUnresolved);
    expect(record).toBeNull();
    expect(JSON.stringify(record ?? {})).not.toContain('Example Brand');
  });

  it('leaves an UNFOLDED name with no routing alone, because it answers for itself', async () => {
    // shopify.com itself has no observed prefixes in the graph, and must still resolve: there is no
    // inheritance to guard against when the name IS the zone. A gate that caught this would be
    // refusing most apexes for no security gain.
    const apex: Canned = {
      prefixRows: [{ subject: 'shopify.com', prefixes: [] }],
      zone: { subject: 'shopify.com', dnssecAlgorithms: [], companyName: 'Shopify Inc.' },
      whois: {
        registrants: ['Shopify Inc.'],
        registrars: ['MarkMonitor Inc.'],
        queryTimes: ['2025-03-19 15:44:35'],
        nameServerSets: ['ns1.shopify.com'],
        createDates: ['2005-03-11'],
      },
      // no fold advisory: the queried name is already the registrable parent
    };
    const record = await resolved('https://shopify.com', apex);
    expect(record?.operator).toBe('Shopify Inc.');
    expect(record?.queriedName).toBeUndefined(); // nothing folded, so nothing to disclose
  });

  it('still publishes for a folded name that HAS an announced-prefix observation', async () => {
    // The positive control, so neither half of the gate can pass by refusing everything.
    const record = await resolved('https://www.shopify.com', SHOPIFY);
    expect(record?.operator).toBe('Shopify Inc.');
    expect(record?.resolvedName).toBe('shopify.com');
  });
});

describe('the registry provenance beside the operator', () => {
  /**
   * These three accompany the operator rather than standing in for it. A record exists only when an
   * operator was corroborated, so they deepen a record that is already published; they never appear on
   * their own. The test below pins that, because an earlier version of this comment claimed the
   * opposite and a reader of the type would have written a branch that can never run.
   */
  it('publishes the registrar, nameservers and registration date from the operator\'s own snapshot', async () => {
    const record = await resolved('https://www.shopify.com', SHOPIFY);
    expect(record?.registrar).toBe('MarkMonitor Inc.');
    expect(record?.nameservers).toEqual(['ns1.shopify.com', 'ns2.shopify.com']);
    expect(record?.firstRegistered).toBe('2005-03-11');
  });

  it('takes all three from the SAME snapshot the operator came from, not the newest', async () => {
    // Otherwise the four fields describe different observations and can contradict each other. Here
    // the newest snapshot is a proxy that corroborates nothing, so the operator comes from the second
    // row and every companion field must come from that row too.
    const record = await resolved('https://www.shopify.com', {
      ...SHOPIFY,
      whois: {
        registrants: ['Domains By Proxy, LLC', 'Shopify Inc.'],
        registrars: ['GoDaddy.com, LLC', 'MarkMonitor Inc.'],
        queryTimes: ['2026-01-01 00:00:00', '2025-03-19 15:44:35'],
        nameServerSets: ['ns1.godaddy-parking.com|ns2.godaddy-parking.com', 'ns1.shopify.com'],
        createDates: ['2001-01-01', '2005-03-11'],
      },
    });
    expect(record?.operator).toBe('Shopify Inc.');
    expect(record?.registrar).toBe('MarkMonitor Inc.');       // not GoDaddy, the shadowed row
    expect(record?.nameservers).toEqual(['ns1.shopify.com']);  // not the parking set
    expect(record?.firstRegistered).toBe('2005-03-11');        // not 2001, the shadowed row
    expect(record?.observedAt).toBe('2025-03-19T15:44:35.000Z');
  });

  it('publishes a privacy-BRANDED registrar and nameserver set rather than erasing them', async () => {
    // The bug this pins. The redaction sentinels exist to keep a non-answer out of the ACCOUNTABILITY
    // field, and `PRIVACY` is matched as a bare substring. Applying them to content erased the exact
    // values that reveal a proxied or parked name: `ns1.privacyprotect.org` made the whole nameservers
    // field vanish, and a registrar trading as "Domains By Proxy, LLC" vanished too. So the record said
    // "not established" in precisely the case the fields were added to illuminate.
    const record = await resolved('https://parked.example.com', {
      prefixRows: [{ subject: 'parked.example.com', prefixes: ['192.0.2.0/24'] }],
      zone: { subject: 'parked.example.com', dnssecAlgorithms: [], companyName: 'Parked Example Inc.' },
      whois: {
        registrants: ['Parked Example Inc.'],
        registrars: ['Domains By Proxy, LLC'],
        queryTimes: ['2025-03-19 15:44:35'],
        nameServerSets: ['ns1.privacyprotect.org|ns2.privacyprotect.org'],
        createDates: ['1998-06-06'],
      },
    });
    expect(record?.operator).toBe('Parked Example Inc.');
    expect(record?.registrar).toBe('Domains By Proxy, LLC');
    expect(record?.nameservers).toEqual(['ns1.privacyprotect.org', 'ns2.privacyprotect.org']);
  });

  it('still refuses a redaction sentinel in the ACCOUNTABILITY field', async () => {
    // The other half, so the fix above cannot have simply disabled the sentinels. A proxy name as the
    // REGISTRANT is still a non-answer and still yields no record.
    const record = await resolved('https://proxied.example.com', {
      prefixRows: [{ subject: 'proxied.example.com', prefixes: ['192.0.2.0/24'] }],
      zone: { subject: 'proxied.example.com', dnssecAlgorithms: [], companyName: 'Proxied Example' },
      whois: {
        registrants: ['Domains By Proxy, LLC'],
        registrars: ['GoDaddy.com, LLC'],
        queryTimes: ['2025-03-19 15:44:35'],
        nameServerSets: ['ns1.example.com'],
        createDates: ['1998-06-06'],
      },
    });
    expect(record).toBeNull();
  });

  it('refuses a nameserver value that is not a hostname', async () => {
    // The registry's field is free text, so a value that is not a name must not travel as one.
    const record = await resolved('https://odd.example.com', {
      prefixRows: [{ subject: 'odd.example.com', prefixes: ['192.0.2.0/24'] }],
      zone: { subject: 'odd.example.com', dnssecAlgorithms: [], companyName: 'Odd Example Inc.' },
      whois: {
        registrants: ['Odd Example Inc.'],
        registrars: ['Example Registrar'],
        queryTimes: ['2025-03-19 15:44:35'],
        nameServerSets: ['not a hostname|n/a|ns1.ok.example.com|-bad-.com|localhost'],
        createDates: ['2001-01-01'],
      },
    });
    expect(record?.nameservers).toEqual(['ns1.ok.example.com']);
  });

  it('publishes a registration DATE, never an invented instant, and refuses an impossible one', async () => {
    const dated = async (createDate: unknown): Promise<string | undefined> => {
      const record = await resolved('https://dated.example.com', {
        prefixRows: [{ subject: 'dated.example.com', prefixes: ['192.0.2.0/24'] }],
        zone: { subject: 'dated.example.com', dnssecAlgorithms: [], companyName: 'Dated Example Inc.' },
        whois: {
          registrants: ['Dated Example Inc.'],
          registrars: ['Example Registrar'],
          queryTimes: ['2025-03-19 15:44:35'],
          nameServerSets: ['ns1.example.com'],
          createDates: [createDate],
        },
      });
      return record?.firstRegistered;
    };

    // A date stays a date. Widening it to an instant would invent a second and a zone the registry
    // does not publish, in a record whose other timestamps are real instants.
    expect(await dated('1996-06-06')).toBe('1996-06-06');
    // An impossible date is refused rather than rolled forward into a plausible-looking wrong one.
    expect(await dated('2026-02-31')).toBeUndefined();
    for (const bad of ['1996-06-06 00:00:00', 'not-a-date', '', null, 19960606, '96-06-06']) {
      expect(await dated(bad), JSON.stringify(bad)).toBeUndefined();
    }
    // And an absent companion field never blocks the operator itself.
    const record = await resolved('https://dated.example.com', {
      prefixRows: [{ subject: 'dated.example.com', prefixes: ['192.0.2.0/24'] }],
      zone: { subject: 'dated.example.com', dnssecAlgorithms: [], companyName: 'Dated Example Inc.' },
      whois: {
        registrants: ['Dated Example Inc.'], registrars: [null],
        queryTimes: ['2025-03-19 15:44:35'], nameServerSets: [null], createDates: ['nope'],
      },
    });
    expect(record?.operator).toBe('Dated Example Inc.');
    expect(record?.registrar).toBeUndefined();
    expect(record?.nameservers).toBeUndefined();
    expect(record?.firstRegistered).toBeUndefined();
  });
});

describe('a non-answer and a proxy company are different things', () => {
  /**
   * Two wrong answers preceded this, in opposite directions.
   *
   * Matching a redaction sentinel as a SUBSTRING erased real content: a registrar trading as
   * "Domains By Proxy, LLC" and a nameserver on privacyprotect.org both vanished, which are precisely
   * the values that reveal a proxied name. Dropping the check then published "REDACTED FOR PRIVACY" as
   * the registrar, reproducing a registry saying nothing as though it were a fact.
   *
   * The rule that survives both: the whole value being a non-answer refuses it, and the list read here
   * is narrower than the one guarding the accountability field, because a named proxy service IS
   * informative as a registrar and is useless as a registrant.
   */
  const withRegistrar = (registrar: string): Canned => ({
    prefixRows: [{ subject: 'r.example.com', prefixes: ['192.0.2.0/24'] }],
    zone: { subject: 'r.example.com', dnssecAlgorithms: [], companyName: 'R Example Inc.' },
    whois: {
      registrants: ['R Example Inc.'],
      registrars: [registrar],
      queryTimes: ['2025-03-19 15:44:35'],
      nameServerSets: ['ns1.ok.example.com'],
      createDates: ['2001-01-01'],
    },
  });

  it.each([
    'REDACTED FOR PRIVACY',
    'Redacted for Privacy',        // case
    'REDACTED  FOR  PRIVACY',      // doubled space
    'REDACTED FOR PRIVACY, LLC',   // the same non-answer wearing a legal form
    'Data Protected',
    'Not Disclosed',
    'Statutory Masking Enabled',
    'Privacy',
  ])('refuses %j as a registrar, because it is a registry declining to answer', async (registrar) => {
    const record = await resolved('https://r.example.com', withRegistrar(registrar));
    expect(record?.operator).toBe('R Example Inc.'); // the operator is unaffected
    expect(record?.registrar).toBeUndefined();
  });

  it.each([
    'Domains By Proxy, LLC',
    'Private by Design, LLC',
    'Whois Privacy Protection Service, Inc.',
    'Perfect Privacy, LLC',
    'MarkMonitor Inc.',
    'Wild West Domains, LLC',
  ])('publishes %j, because a named company is a signal and not an absence', async (registrar) => {
    const record = await resolved('https://r.example.com', withRegistrar(registrar));
    expect(record?.registrar).toBe(registrar);
  });

  it('still refuses every one of those as the REGISTRANT, where none of them names anyone', async () => {
    // The wider list keeps guarding the accountability field, so the split cannot be read as a
    // weakening of it.
    for (const value of ['REDACTED FOR PRIVACY', 'Domains By Proxy, LLC', 'Perfect Privacy, LLC']) {
      const record = await resolved('https://r.example.com', {
        ...withRegistrar('MarkMonitor Inc.'),
        whois: {
          registrants: [value], registrars: ['MarkMonitor Inc.'],
          queryTimes: ['2025-03-19 15:44:35'], nameServerSets: ['ns1.ok.example.com'],
          createDates: ['2001-01-01'],
        },
      });
      expect(record, value).toBeNull();
    }
  });

  it('refuses markup, bidi, control characters and an over-long value in BOTH new fields', async () => {
    // Safety is unconditional; only the sentinel pass differs between a claim and content.
    for (const hostile of ['<script>x</script>', 'Evil\u202eRegistrar', 'Reg\u0000istrar',
      '=HYPERLINK("//evil","R")', 'A'.repeat(60_000)]) {
      const record = await resolved('https://r.example.com', withRegistrar(hostile));
      expect(record?.registrar, hostile.slice(0, 20)).toBeUndefined();
    }
    const nsRecord = await resolved('https://r.example.com', {
      ...withRegistrar('MarkMonitor Inc.'),
      whois: {
        registrants: ['R Example Inc.'], registrars: ['MarkMonitor Inc.'],
        queryTimes: ['2025-03-19 15:44:35'],
        nameServerSets: ['<script>x</script>|ns\u202e1.evil.com|https://evil.example/|ns1.ok.example.com'],
        createDates: ['2001-01-01'],
      },
    });
    expect(nsRecord?.nameservers).toEqual(['ns1.ok.example.com']);
  });
});

describe('the network abuse address', () => {
  /**
   * The address is CONTENT, not an accountability claim, which is the distinction the string validators
   * were split to make. It shipped without a single positive assertion: the only two in the suite were
   * `toBeUndefined()`, so a `safeEmail` that returned null for every input would have kept the whole
   * suite green while emptying a field the README publishes a value for.
   */
  const withAbuse = (emails: readonly unknown[]): Canned => ({
    prefixRows: [{
      subject: 'a.example.com',
      prefixes: ['192.0.2.0/24'],
      netAbuseEmails: emails,
    }],
    zone: { subject: 'a.example.com', dnssecAlgorithms: [], companyName: 'A Example Inc.' },
    whois: {
      registrants: ['A Example Inc.'], registrars: ['Example Registrar'],
      queryTimes: ['2025-03-19 15:44:35'], nameServerSets: ['ns1.example.com'],
      createDates: ['2001-01-01'],
    },
  });

  it('publishes a plain address', async () => {
    const record = await resolved('https://a.example.com', withAbuse(['abuse@example.com']));
    expect(record?.network?.abuseContact).toBe('abuse@example.com');
  });

  it('publishes a privacy-BRANDED address, which is the one that matters most', async () => {
    // The whole reason this field takes the content path. A complaint about a privacy-fronted name has
    // to go to exactly this address, and a substring sentinel match dropped it.
    const record = await resolved('https://a.example.com', withAbuse(['abuse@privacyprotect.org']));
    expect(record?.network?.abuseContact).toBe('abuse@privacyprotect.org');
  });

  it('treats two spellings of one address as one, rather than emptying the field', async () => {
    // A domain is case-insensitive and RIR data is inconsistent in case across the prefixes of one
    // network, so an un-canonicalised value made one address look like two and the one-distinct-value
    // rule then published neither.
    for (const pair of [
      ['abuse@example.com', 'abuse@EXAMPLE.com'],
      ['abuse@example.com', 'abuse@Example.Com'],
    ]) {
      const record = await resolved('https://a.example.com', withAbuse(pair));
      expect(record?.network?.abuseContact, pair.join(' / ')).toBe('abuse@example.com');
    }
  });

  it('keeps the local part case-sensitive, because only the domain is not', async () => {
    const record = await resolved('https://a.example.com', withAbuse(['Abuse.Team@Example.COM']));
    expect(record?.network?.abuseContact).toBe('Abuse.Team@example.com');
  });

  it('omits the field when two GENUINELY different addresses are held', async () => {
    // Still one-distinct-value: picking one of two real abuse contacts would assert something the data
    // does not say. This is the rule working, not the bug above.
    const record = await resolved('https://a.example.com',
      withAbuse(['abuse@one.example.com', 'abuse@two.example.com']));
    expect(record?.network?.abuseContact).toBeUndefined();
  });

  it.each([
    ['no domain dot', 'abuse@localhost'],
    ['two at-signs', 'abuse@x@example.com'],
    ['no local part', '@example.com'],
    ['no domain', 'abuse@'],
    ['not an address', 'abuse at example dot com'],
    ['markup', '<script>x</script>@example.com'],
    ['a bidi override', 'abuse\u202e@example.com'],
    ['a 250-character local part', `${'a'.repeat(250)}@example.com`],
  ])('refuses %s', async (_why, email) => {
    const record = await resolved('https://a.example.com', withAbuse([email]));
    expect(record?.network?.abuseContact).toBeUndefined();
  });
});

describe('a non-answer wearing punctuation is still a non-answer', () => {
  const asRegistrar = (registrar: string): Canned => ({
    prefixRows: [{ subject: 'p.example.com', prefixes: ['192.0.2.0/24'] }],
    zone: { subject: 'p.example.com', dnssecAlgorithms: [], companyName: 'P Example Inc.' },
    whois: {
      registrants: ['P Example Inc.'], registrars: [registrar],
      queryTimes: ['2025-03-19 15:44:35'], nameServerSets: ['ns1.example.com'],
      createDates: ['2001-01-01'],
    },
  });

  it.each([
    'REDACTED FOR PRIVACY!',
    '(REDACTED FOR PRIVACY)',
    'Not Disclosed*',
    '"Data Protected"',
    '- REDACTED -',
    '[Privacy]',
  ])('refuses %j, which whole-value equality alone let through', async (registrar) => {
    // Parenthesised and asterisked values are ordinary in real registry text, and each of these
    // published as the registrar until the comparison stripped the edges.
    const record = await resolved('https://p.example.com', asRegistrar(registrar));
    expect(record?.registrar).toBeUndefined();
  });

  it.each([
    'Domains By Proxy, LLC',
    'Private by Design, LLC',
    'MarkMonitor Inc.',
  ])('still publishes %j, so the widened strip did not start eating real names', async (registrar) => {
    const record = await resolved('https://p.example.com', asRegistrar(registrar));
    expect(record?.registrar).toBe(registrar);
  });
});

describe('the published-string cap applies to an address too', () => {
  const withAbuse = (email: string): Canned => ({
    prefixRows: [{ subject: 'c.example.com', prefixes: ['192.0.2.0/24'], netAbuseEmails: [email] }],
    zone: { subject: 'c.example.com', dnssecAlgorithms: [], companyName: 'C Example Inc.' },
    whois: {
      registrants: ['C Example Inc.'], registrars: ['Example Registrar'],
      queryTimes: ['2025-03-19 15:44:35'], nameServerSets: ['ns1.example.com'],
      createDates: ['2001-01-01'],
    },
  });

  it('refuses an address longer than the cap the file states for every published string', async () => {
    // The outer allowance exists so a legal 64-octet local part beside a legal 253-octet domain is not
    // refused by arithmetic, but what TRAVELS is still bounded: this value is re-served on every cache
    // hit and lands in the merchant's logs.
    const long = `${'a'.repeat(60)}@${'b'.repeat(60)}.${'c'.repeat(60)}.${'d'.repeat(40)}.example.com`;
    expect(long.length).toBeGreaterThan(200);
    expect((await resolved('https://c.example.com', withAbuse(long)))?.network?.abuseContact)
      .toBeUndefined();
  });

  it('refuses an address with internal whitespace, which nothing can send to', async () => {
    expect((await resolved('https://c.example.com', withAbuse('first last@example.com')))
      ?.network?.abuseContact).toBeUndefined();
  });

  it('still publishes an ordinary address of ordinary length', async () => {
    expect((await resolved('https://c.example.com', withAbuse('abuse@example.com')))
      ?.network?.abuseContact).toBe('abuse@example.com');
  });
});

describe('the one-word PRIVACY sentinel, and what it deliberately costs', () => {
  const asRegistrar = (registrar: string): Canned => ({
    prefixRows: [{ subject: 'w.example.com', prefixes: ['192.0.2.0/24'] }],
    zone: { subject: 'w.example.com', dnssecAlgorithms: [], companyName: 'W Example Inc.' },
    whois: {
      registrants: ['W Example Inc.'], registrars: [registrar],
      queryTimes: ['2025-03-19 15:44:35'], nameServerSets: ['ns1.example.com'],
      createDates: ['2001-01-01'],
    },
  });

  it.each(['Privacy', '[Privacy]', 'Privacy, LLC', 'Privacy Inc.', '(Privacy) Ltd'])(
    'refuses %j, and the cost of that is recorded rather than discovered', async (registrar) => {
      // The widening this pins: the one-word entry plus the edge-strip plus the legal-form removal
      // refuses these too. Nobody could demonstrate an accredited registrar trading as exactly that,
      // and publishing a bare "Privacy" as the registrar would state something false.
      expect((await resolved('https://w.example.com', asRegistrar(registrar)))?.registrar)
        .toBeUndefined();
    });

  it.each([
    'Withheld for Privacy ehf',
    'Privacy Service Provided by Withheld for Privacy ehf',
    'PrivacyGuardian.org llc',
    'Privacy Protect, LLC',
    'Perfect Privacy, LLC',
    'Whois Privacy Corp.',
    'Domains By Proxy, LLC',
  ])('still publishes the real multi-word privacy company %j', async (registrar) => {
    // The line that matters: these are real accredited registrars and proxy services, and naming one is
    // the signal. Only the bare word is a non-answer.
    expect((await resolved('https://w.example.com', asRegistrar(registrar)))?.registrar).toBe(registrar);
  });
});

describe('a refusal we are not entitled to is never an absence', () => {
  /**
   * The `unservable` path had no test at all, and that is where a false claim about API keys was
   * hiding. With the key-gated lane removed nothing we ask for is entitlement-gated, so this drives
   * the 400 through an injected response rather than pretending a real input produces it. It stays in
   * the source because the endpoint documents this status for any caller, and reading it as "we checked
   * and there is nothing" would be the worst available misreading.
   */
  const refusing = (lane: RegExp): typeof fetch => (async (_u: unknown, init?: RequestInit) => {
    const q = (JSON.parse(String(init?.body ?? '{}')) as { query?: string }).query ?? '';
    if (lane.test(q)) {
      return new Response(
        JSON.stringify({ type: 'https://whisper.security/errors/query-unservable', status: 400,
          detail: 'not_entitled', reason: 'pl_not_entitled' }),
        { status: 400, headers: { 'content-type': 'application/json' } },
      );
    }
    return (cannedFetch(SHOPIFY) as unknown as (a: unknown, b?: RequestInit) => Promise<Response>)(_u, init);
  }) as unknown as typeof fetch;

  it('publishes NO record, and never a negative, when a lane is refused', async () => {
    const warnings: string[] = [];
    const src = new WhisperOperatorSource({
      fetchImpl: refusing(/whisper\.history\.whois/), onWarning: (m) => warnings.push(m),
    });
    expect(await src.describe('https://www.shopify.com')).toBeNull();
    await vi.waitFor(() => expect(src.stats().laneUnservable).toBe(1));
    // A refusal is not a resolved absence: nothing is cached as a negative and nothing is published.
    expect(src.stats().hitNegative).toBe(0);
    expect(src.stats().zoneEntries).toBe(0);
    expect(await src.describe('https://www.shopify.com')).toBeNull();
    expect(src.stats().hitNegative).toBe(0);
    // Nor an outage: it is permanent for this configuration, so it is not retried as if it were transient.
    expect(src.stats().outageEntries).toBe(0);
  });

  it('does not tell the reader to go and get an API key', async () => {
    // The message is the only surface of this path that reaches a merchant. It used to end "this lookup
    // needs one", which would send a keyless integrator after a credential that buys them nothing.
    const warnings: string[] = [];
    const src = new WhisperOperatorSource({
      fetchImpl: refusing(/whisper\.history\.whois/), onWarning: (m) => warnings.push(m),
    });
    await src.describe('https://www.shopify.com');
    await vi.waitFor(() => expect(src.stats().laneUnservable).toBe(1));
    const joined = warnings.join('\n');
    expect(joined).toContain('refused the whois lookup');
    expect(joined).toContain('Verification is unaffected');
    expect(joined).not.toMatch(/needs (one|a key)|supply an API key|carry this capability/i);
  });

  it('warns once for a lane, not once per origin', async () => {
    const warnings: string[] = [];
    const src = new WhisperOperatorSource({
      fetchImpl: refusing(/whisper\.history\.whois/), onWarning: (m) => warnings.push(m),
    });
    for (let i = 0; i < 6; i += 1) await src.describe(`https://u${i}.example.com`);
    await vi.waitFor(() => expect(src.stats().laneUnservable).toBeGreaterThan(2));
    expect(warnings.filter((w) => /refused the whois lookup/.test(w))).toHaveLength(1);
  });
});
