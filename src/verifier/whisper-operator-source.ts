/**
 * Whisper OperatorSource: who is accountable for an origin, from the Whisper graph.
 *
 * An OperatorSource answers "who answers for this origin, and which registry says so". It runs only
 * for results that already verified, its answer is attached as provenance, and it can never move a
 * trust decision. See src/verifier/operator-source.ts for the contract this implements and
 * docs/RESOLVER-SOURCES.md for what such a source owes its caller.
 *
 * Two properties of the seam shape everything below, and both were measured rather than assumed.
 *
 * FIRST: describe() runs on a merchant's request path and NOTHING wraps it. multi.ts calls
 * annotateWithOperator bare, and that function is a try/catch with no timer and no cache. The
 * per-source timeout and cache in this repo (CachingAgentDirectory, and the timeoutMs in
 * agent-directory.ts and visa-tap.ts) are each source's own, self-imposed. So describe() here is a
 * synchronous cache read and never awaits a socket: a background resolver owns every network call,
 * inside the 5 s / 64 KiB budget docs/RESOLVER-SOURCES.md places on a source. Worst case describe()
 * returns null in microseconds.
 *
 * SECOND: a record has TWO subjects. `operator`, `observedAt` and `dnssec` describe the registrable
 * parent; `network` describes the queried name. They genuinely diverge - paypal.com is DNSSEC-signed
 * and fronted by Fastly and Cloudflare, while www.paypal.com is unsigned, Fastly only, on five
 * different prefixes. So there are two caches, and each block carries its own timestamp rather than
 * making the reader consult prose to learn which subject a field describes.
 *
 * The registrable parent is LEARNED, never computed. Folding a name locally needs a public-suffix
 * list, and last-two-labels is wrong for co.uk and every other effective TLD. The graph folds
 * server-side and reports it in a machine-readable advisory, so this source caches that pointer and
 * adds no dependency.
 */

import type { OperatorRecord, OperatorSource } from './operator-source.js';

/** Provenance label. Names who answered, which is our graph and not a live RDAP call. */
const REGISTRY = 'whisper-graph';

/** The one endpoint this source will talk to. https only, no redirects, no alternatives. */
const DEFAULT_ENDPOINT = 'https://graph.whisper.online/api/query';

/**
 * Redaction sentinels, built by reading every registrant value in WHOIS history for 22 commerce and
 * infrastructure domains (611 rows in that sample) rather than by imagining the list.
 *
 * Without `DATA PROTECTED`, `NOT DISCLOSED` and `DOMAINS BY PROXY` this source publishes a non-answer
 * as an accountable party on 4 of a 30-domain check set: cloudflare.com resolves to "Data Protected",
 * homedepot.com and walmart.com to "Not Disclosed", perplexity.ai to "Domains By Proxy, LLC". Named
 * rather than cited by position: this said "the last three entries" until the list was extended, after
 * which the last three were different entries and the sentence was quietly false. Two of those are exactly the merchant
 * class this verifier serves. A privacy proxy is a category rather than a fixed list, so this is
 * documented as empirically derived and extended here when a new one is seen - never worked around
 * with a fallback, because "we do not know" is the honest answer and null is how it is said.
 */
const REDACTION_SENTINELS = [
  'REDACTED FOR PRIVACY',
  'DATA REDACTED',
  'REDACTED',
  'DATA PROTECTED',
  'NOT DISCLOSED',
  'DOMAINS BY PROXY',
  'WHOIS PRIVACY',
  'PERFECT PRIVACY',
  'CONTACT PRIVACY',
  'PRIVACY SERVICE',
  'PRIVACY',
  'STATUTORY MASKING ENABLED',
] as const;

/**
 * EPP status codes that leak into the registrant field in some snapshots, e.g. homedepot.com in 2020
 * carried "serverTransferProhibited". A status code is not a company.
 */
const EPP_STATUS_TOKENS = ['PROHIBITED', 'CLIENTTRANSFER', 'SERVERTRANSFER', 'PENDINGDELETE'] as const;

/** A registrant longer than this is not a company name; it is a dump. It travels to the merchant. */
const MAX_OPERATOR_LEN = 200;

/** DNS limits, which WHATWG URL parsing does not enforce. */
const MAX_HOSTNAME_LEN = 253;
const MAX_LABELS = 127;
const MAX_LABEL_LEN = 63;

/**
 * An origin longer than this is rejected BEFORE `new URL` is called. Measured: a 1 MB hostname parses
 * SUCCESSFULLY - WHATWG sets VerifyDnsLength to false, so nothing about its length makes it invalid -
 * and costs low SINGLE-DIGIT MILLISECONDS in the URL constructor alone, synchronously, on the
 * merchant's event loop. Three samples here gave 3.8, 4.9 and 3.9 ms; a second machine gave 0.9 to
 * 2.4 ms. A range rather than a figure, because an earlier version of this comment carried one number
 * ("7.4 ms") that does not reproduce anywhere, and a precise-looking number is the part a reader
 * trusts. What holds across every measurement is the shape of the argument: a single parse of one
 * hostile origin spends more than this source's entire per-origin budget, so the length screen has to
 * come before the parser rather than after it.
 */
const MAX_ORIGIN_LEN = 264; // "https://" (8) + a 253-octet name + one legal trailing dot + slack

/** RFC 6761 and friends: names that never have a registry answer, so they never cost a lookup. */
const SPECIAL_USE_SUFFIXES = [
  '.local',        // RFC 6762 section 3
  '.localhost',    // RFC 6761 section 6.3
  '.onion',        // RFC 7686
  '.invalid',      // RFC 6761 section 6.4
  '.test',         // RFC 6761 section 6.2
  '.example',      // RFC 6761 section 6.5
  '.alt',          // RFC 9476
  '.internal',     // ICANN-designated for private use, 2024. Not an RFC 6761 name.
  '.arpa',         // RFC 3172. Covers in-addr.arpa, ip6.arpa and home.arpa (RFC 8375).
  '.corp', '.lan', '.intranet', '.localdomain', // long-standing private use, never delegated
] as const;

/**
 * Words that are a non-answer spelled as a word. Compared whole, never as substrings, so a company
 * legitimately called "NA Holdings" is unaffected.
 */
const NON_ANSWER_WORDS = new Set([
  'N/A', 'NA', 'N.A.', 'NIL', 'NULL', 'NONE', 'NOT APPLICABLE', 'NOT AVAILABLE', 'UNKNOWN',
  'UNDISCLOSED', 'WITHHELD', 'ANONYMOUS', 'REGISTRANT', 'DOMAIN ADMINISTRATOR', 'ADMIN',
  'OWNER', 'OK', 'YES', 'NO', 'TBD', 'XXX', 'TEST', 'PRIVATE', 'PRIVATE PERSON', 'MR', 'MRS', 'MS',
]);

/**
 * Legal forms and filler, stripped before corroboration so two unrelated companies do not agree
 * merely on being incorporated.
 */
const LEGAL_FORM_WORDS = new Set([
  'inc', 'inc.', 'llc', 'ltd', 'limited', 'plc', 'corp', 'corporation', 'company', 'co', 'gmbh',
  'ag', 'sa', 'sas', 'srl', 'bv', 'nv', 'oy', 'ab', 'as', 'aps', 'kk', 'pty', 'pte', 'holdings',
  'holding', 'group', 'international', 'global', 'services', 'service', 'solutions', 'technologies',
  'technology', 'systems', 'the', 'and', 'com', 'www', 'org', 'net', 'domains', 'domain',
]);

/** How a record's `operator` was derived, so a reader can weigh it. */
export type WhisperOperatorProvenance = 'registrant-corroborated';

/** Advisory network context. NEVER promoted into `operator` or `abuseContact`. */
export interface WhisperNetworkBlock {
  /** Who operates the ADDRESS, e.g. "Cloudflare, Inc.". Not the accountable party. */
  organisation?: string;
  /** Abuse contact for the NETWORK, not for the accountable organisation. */
  abuseContact?: string;
  asns?: readonly string[];
  asNames?: readonly string[];
  prefixes?: readonly string[];
  rirs?: readonly string[];
  rpki?: { status: 'valid' | 'invalid' | 'notfound'; roaOrigin?: number; maxLength?: number };
  anycast?: boolean;
  moas?: boolean;
  /**
   * When WE read this routing data. Named `retrievedAt`, not `observedAt`, because the graph
   * publishes no routing-observation timestamp and this is our clock, not the network's.
   */
  retrievedAt?: string;
}

/**
 * The record this source produces: their required fields plus an advisory block.
 *
 * Declared as an extension rather than by widening every call site. Both files that declare
 * OperatorRecord carry the additive fields, so a consumer reads them without a cast.
 */
export interface WhisperOperatorRecord extends OperatorRecord {
  network?: WhisperNetworkBlock;
  /**
   * Who the name was registered THROUGH, as the registry reports it, from the same snapshot as
   * `operator`. Reproduced, never scored: a brand-protection registrar and a bulk reseller are both
   * ordinary choices, and which one reassures a reader is the reader's call.
   */
  registrar?: string;
  /**
   * The nameservers that snapshot recorded, sorted and capped, so registry order is not preserved.
   *
   * Accompanies `operator` rather than standing in for it, from the same snapshot, which is what stops
   * the two contradicting each other about which observation they describe. It answers a different
   * question - whether the name is served from its own infrastructure or sits on a registrar's parking
   * set - and that is often the more telling one.
   */
  nameservers?: readonly string[];
  /**
   * The creation date the registry publishes for the registration in this snapshot, as a DATE with no
   * time. Not the merchant's age: a name is often much older than whoever holds it now, and a name that
   * dropped and was re-registered carries the later registration's date rather than its first ever.
   */
  firstRegistered?: string;
  /**
   * Every DNSSEC algorithm the zone apex is signed with, sorted. A LIST, because a zone mid-rollover
   * legitimately carries two and picking one would assert something the data does not say.
   */
  dnssecAlgorithms?: readonly string[];
  /** Set when the queried name was folded to its registrable parent. Both fields, or neither. */
  queriedName?: string;
  resolvedName?: string;
  /**
   * How `operator` was derived. Only ever `registrant-corroborated`: the registry's registrant
   * string, published only because something outside WHOIS agreed it names this business.
   */
  operatorSource?: WhisperOperatorProvenance;
  /** When WE resolved this, as distinct from `observedAt`, which is the snapshot's own time. */
  retrievedAt?: string;
  /** Present only when served past its TTL with a refresh already enqueued. */
  stale?: true;
}

/** Everything the registrant lane established, from one snapshot, so the parts cannot disagree. */
interface PickedOperator {
  readonly name: string;
  readonly observedAt: string;
  readonly registrar?: string;
  readonly nameservers?: readonly string[];
  readonly firstRegistered?: string;
}

/**
 * A registry date-only value as an ISO date, or null.
 *
 * Deliberately NOT widened to an instant. The registry publishes `1996-06-06` with no time and no
 * zone, so emitting `1996-06-06T00:00:00.000Z` would invent a second and a zone the datum does not
 * have. A date is published as a date.
 */
function dateOnlyToIso(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value.trim());
  if (!match) return null;
  const [, y, m, d] = match;
  const year = Number(y); const month = Number(m); const day = Number(d);
  // Round-tripped through Date.UTC so an impossible date (2026-02-31) is refused rather than rolled
  // forward into a plausible-looking wrong one.
  const stamp = new Date(Date.UTC(year, month - 1, day));
  if (stamp.getUTCFullYear() !== year || stamp.getUTCMonth() !== month - 1 || stamp.getUTCDate() !== day) {
    return null;
  }
  return `${y}-${m}-${d}`;
}

/** The single terminal outcome of one resolution attempt. Exactly one is reached, always. */
type ResolveOutcome = 'published' | 'failed';

/** Why a resolution failed, which decides whether a later describe() throws or answers null. */
type OutageClass = 'transport' | 'http5xx' | 'http429' | 'auth' | 'malformed';

/** Facts about the QUERIED name. Frozen on insert, replaced never mutated. */
interface FqdnEntry {
  /**
   * The registrable parent this name's zone facts are keyed on, or the name itself when no fold
   * happened. Never null: an earlier version declared it nullable and nothing could produce the
   * null, so `describe()` carried a branch that could not execute.
   */
  readonly zoneKey: string;
  readonly network: WhisperNetworkBlock | null;
  readonly networkExpiresAt: number;
}

/** Facts about the REGISTRABLE PARENT. Frozen on insert, replaced never mutated. */
interface ZoneEntry {
  /**
   * The operator and the time it was observed, together or not at all.
   *
   * A PAIR rather than two independently-nullable fields, for the same reason PickedOperator is one:
   * they describe one observation and must not be able to disagree about which. It also makes the
   * invariant unrepresentable rather than explained - narrowing this to null narrows both halves, so
   * the `observedAt ?? retrievedAt` fallback that three surfaces here forbid cannot be written at all,
   * and there is no unreachable branch left behind to buy it back.
   *
   * Null means resolved-and-nothing-publishable, which is a fact. It never means "not checked".
   */
  readonly operator: { readonly name: string; readonly observedAt: string } | null;
  readonly registrar?: string;
  readonly nameservers?: readonly string[];
  readonly firstRegistered?: string;
  readonly retrievedAt: string;
  readonly dnssecAlgorithms?: readonly string[];
  readonly expiresAt: number;
  readonly staleUntil: number;
}

interface OutageEntry {
  readonly outage: OutageClass;
  readonly until: number;
}

/* ------------------------------------------------------------------------------------------------
 * Pure helpers. Every one of these is total: it returns a value or null, and never throws, so the
 * hot path cannot fail on a malformed input it was handed.
 * ---------------------------------------------------------------------------------------------- */

/** Snapshots walked back through before giving up. Bounded so history size cannot drive cost. */
const MAX_HISTORY_ROWS = 12;

/** Published arrays are capped: an unbounded list is re-served on every hit and lands in logs. */
const MAX_LIST_VALUES = 8;

/** Published strings are capped at the same length as an operator name, for the same reason. */
const MAX_PUBLISHED_LEN = 200;

/**
 * A string that is SAFE to put in a record travelling to a merchant and into their logs, or null.
 *
 * Safety only: length, control and bidi characters, markup and formula injection. Every string the
 * record publishes goes through this, not just `operator`. An earlier version hardened `operator` with
 * a dozen checks and published its neighbours raw, so a network organisation could carry markup or a
 * right-to-left override in a sibling field of the same record.
 */
function safeString(value: unknown, maxLength: number = MAX_PUBLISHED_LEN): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength) return null;
  if (hasUnsafeCharacter(trimmed)) return null;
  if (hasMarkup(trimmed)) return null;
  return trimmed;
}

/**
 * A string safe to publish AND not a redaction non-answer, or null. For accountability fields only.
 *
 * The two checks are separate because they answer different questions, and conflating them broke a
 * field. Safety asks "can this be rendered and logged". The sentinel pass asks "is this value really a
 * registry saying nothing", which is a question about an ACCOUNTABILITY claim - an operator name, a
 * network organisation - and is wrong everywhere else.
 *
 * `PRIVACY` is a bare substring, so applying this to content rather than to a claim erased real data:
 * a nameserver set of `ns1.privacyprotect.org` vanished entirely, and a registrar legitimately trading
 * as "Domains By Proxy, LLC" vanished too. Those are the values that reveal a parked or proxied name,
 * so the field went silent in exactly the case it was added to illuminate. A registrar's trade name
 * and a hostname are content. They are reproduced, and the reader judges them.
 */
function safePublished(value: unknown): string | null {
  const safe = safeString(value);
  if (safe === null) return null;
  // Whitespace NORMALISED before the comparison. Without it, every multi-word sentinel is bypassed by
  // changing one space: "Not\u00a0Disclosed" and "Not  Disclosed" both published, and those are the
  // exact values the list was built from.
  const upper = safe.toUpperCase().replace(/\s+/g, ' ');
  for (const sentinel of REDACTION_SENTINELS) if (upper.includes(sentinel)) return null;
  return safe;
}

/**
 * Whether a value IS a redaction non-answer, rather than merely containing one of its words.
 *
 * The distinction earns its own function because both directions were wrong in turn. Matching a
 * sentinel as a SUBSTRING erased real content: a registrar legitimately trading as "Domains By Proxy,
 * LLC" or "Private by Design, LLC" disappeared, and so did a nameserver on `privacyprotect.org`, which
 * are the values that reveal a proxied name. Dropping the check entirely then published
 * "REDACTED FOR PRIVACY" as the registrar, which is a registry saying nothing, reproduced as if it
 * were a fact.
 *
 * So the test is whether the WHOLE value is the non-answer. A trailing legal form is stripped first,
 * because "REDACTED FOR PRIVACY, LLC" is the same non-answer wearing a suffix, and comparison is on the
 * normalised form so a doubled or non-breaking space cannot slip past.
 *
 * It also reads a NARROWER list than the accountability check, because REDACTION_SENTINELS holds two
 * different kinds of entry and only one of them is a non-answer:
 *
 *   "REDACTED FOR PRIVACY", "NOT DISCLOSED"   a registry declining to say. Never a fact about anyone.
 *   "Domains By Proxy, LLC", "Whois Privacy"  real companies, which happen to sell privacy services.
 *
 * As a REGISTRANT both are useless, because neither names who is accountable, which is why the wider
 * list guards that field. As a REGISTRAR the second kind is genuinely informative: telling a reader the
 * name sits behind a named proxy service is the signal, not the absence of one. So the narrow list
 * refuses only the first kind here.
 */
const NON_ANSWER_SENTINELS = [
  'REDACTED FOR PRIVACY',
  'DATA REDACTED',
  'REDACTED',
  'DATA PROTECTED',
  'NOT DISCLOSED',
  // Kept as a one-word entry, deliberately, and it widens the refusal further than the doc above
  // describes: combined with the edge-strip and the legal-form removal it also refuses "Privacy, LLC",
  // "Privacy Inc." and "(Privacy) Ltd". Nobody could demonstrate an accredited registrar trading as
  // exactly that, and the two directions cost differently. Refusing a real one loses a single advisory
  // field on one domain; publishing a bare "Privacy" or "[Privacy]" as the registrar states something
  // false in a payments record. Conservative in what we emit, and written down rather than discovered.
  'PRIVACY',
  'STATUTORY MASKING ENABLED',
] as const;

function isRedactionNonAnswer(value: string): boolean {
  // Non-alphanumerics are stripped from BOTH ends before the comparison. Whole-value equality alone
  // was defeated by any punctuation on an edge, and "(REDACTED FOR PRIVACY)" or "Not Disclosed*" are
  // ordinary shapes in real registry text: measured, both published as the registrar.
  const normalised = value.toUpperCase().replace(/\s+/g, ' ').trim()
    .replace(/^[^A-Z0-9]+/, '')
    .replace(/[^A-Z0-9]+$/, '')
    .replace(/[,.]?\s*(LLC|INC|LTD|LIMITED|CORP|B\.?V\.?|GMBH|S\.?A\.?|PLC)\.?$/, '')
    .replace(/[^A-Z0-9]+$/, '')
    .trim();
  return NON_ANSWER_SENTINELS.some((sentinel) => normalised === sentinel);
}

/**
 * A hostname safe to publish, or null. Validated as a NAME rather than as prose.
 *
 * Used for nameservers, which are content and not a claim, so no redaction sentinel applies. What does
 * apply is that the value has to be a plausible hostname at all: the registry's field is free text and
 * a value that is not a name should not travel as one.
 */
function safeHostname(value: unknown): string | null {
  // Bounded at the DNS limit, not the prose limit. A hostname may legally run to 253 octets, longer
  // than any company name should be, so inheriting the prose cap would reject a legal name. It also
  // made the check below unreachable, which read as a DNS bound being enforced when a 200-character
  // prose bound was quietly doing the work.
  const safe = safeString(value, MAX_HOSTNAME_LEN + 1);
  if (safe === null) return null;
  const host = safe.endsWith('.') ? safe.slice(0, -1) : safe;
  if (host.length === 0 || host.length > MAX_HOSTNAME_LEN) return null;
  const labels = host.toLowerCase().split('.');
  if (labels.length < 2) return null;
  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_LABEL_LEN) return null;
    if (label.startsWith('-') || label.endsWith('-')) return null;
    if (!/^[a-z0-9-]+$/.test(label)) return null;
  }
  return host.toLowerCase();
}

/**
 * An email address safe to publish, or null.
 *
 * `safeString`, not `safePublished`, for the same reason a nameserver takes the hostname path: an
 * address is CONTENT. A network abuse address at a privacy-branded domain - `abuse@privacyprotect.org`
 * - is the address a complaint actually has to go to, and a substring sentinel match would drop it and
 * empty the field in exactly the case where knowing it matters most.
 */
function safeEmail(value: unknown): string | null {
  const safe = safeString(value, MAX_HOSTNAME_LEN + 64);
  if (safe === null) return null;
  const at = safe.lastIndexOf('@');
  if (at <= 0 || at === safe.length - 1) return null;
  const local = safe.slice(0, at);
  if (local.includes('@')) return null;
  // RFC 5321 section 4.5.3.1.1 bounds the local part at 64 octets. Enforced rather than merely
  // budgeted for: the outer allowance was MAX_HOSTNAME_LEN + 64 while nothing checked the 64, so a
  // 250-character local part published in full, past the length cap this file states for every other
  // published string.
  if (local.length > 64) return null;
  const domain = safeHostname(safe.slice(at + 1));
  if (domain === null) return null;
  // An address is a published string like any other, so it takes the published cap. The outer
  // allowance exists to leave room for a legal 253-octet domain beside a legal 64-octet local part,
  // which together exceed the prose cap; what travels to a merchant is still bounded by it.
  if (`${local}@${domain}`.length > MAX_PUBLISHED_LEN) return null;
  // No internal whitespace. `first last@example.com` is safe to render and is not an address anything
  // can send to, and this field exists to be actioned.
  if (/\s/.test(local)) return null;
  // Returned CANONICALISED, unlike the first version of this function. A domain is case-insensitive
  // and RIR data is inconsistent in case across the prefixes of one network, so two spellings of one
  // address counted as two distinct values and the field went silent on a one-distinct-value rule.
  // The local part keeps its case, because that is the only half that is case-sensitive.
  return `${local}@${domain}`;
}

/**
 * A bounded, deduplicated, sorted list of hostnames, or undefined if nothing survives.
 *
 * SORTED BEFORE CAPPED, for the reason `boundedList` is: `collect()` order is unspecified, so capping
 * during collection makes the published subset a function of arrival order. Measured on 12 nameservers
 * arriving reversed, capping first published ns04..ns11 and called it sorted; the same input now
 * publishes ns00..ns07 whichever order it arrives in. Two doc comments in the shipped types promise
 * exactly this, so the fix is what makes them true rather than an improvement on them.
 */
function boundedHostnames(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out = new Set<string>();
  for (const raw of value) {
    const safe = safeHostname(raw);
    if (safe !== null) out.add(safe);
  }
  if (out.size === 0) return undefined;
  return Object.freeze([...out].sort().slice(0, MAX_LIST_VALUES));
}

/** A bounded, deduplicated, sorted, individually-validated list, or undefined if nothing survives. */
function boundedStrings(value: unknown): readonly string[] | undefined {
  // safeString plus the WHOLE-VALUE non-answer test, which is the same line already drawn for the
  // registrar. A value that IS a non-answer is not content whatever field it arrives in: an RIR of
  // "REDACTED FOR PRIVACY" is a registry saying nothing, and reproducing it puts a non-answer in a
  // record. A value that merely CONTAINS one of those words is content, and the substring pass was
  // erasing real ASN names on exactly that confusion.
  return boundedList(value, (raw) => {
    const safe = safeString(raw);
    return safe !== null && !isRedactionNonAnswer(safe) ? safe : null;
  });
}

/**
 * The redaction-sentinel substring pass now has exactly ONE reader, `isPublishableOperator`, and that is
 * the whole of the distinction this file spent three fixes converging on.
 *
 * `operator` is the only field carrying a WHOIS registrant, which is the only place a redaction string is
 * a non-answer ABOUT THE SUBJECT rather than a word inside a name. Everything else divides into the five
 * lanes below. It is written out in full, and as a PARTITION with every member named, because two earlier
 * versions of this comment described a subset and read as though they described everything - first one
 * sentence about "everything else", then two lanes that between them missed six fields.
 *
 *   FREE TEXT + WHOLE-VALUE test   the registrar, the ASN names (`asNames`), the RIRs and the network
 *                                  organisation are free text a registry may fill with a redaction
 *                                  string INSTEAD of an answer, so the whole value is compared and a
 *                                  value that IS the non-answer is refused, while `Domains By Proxy,
 *                                  LLC`, `DOMAIN-PRIVACY` and `Unredacted Inc` publish - all three of
 *                                  which a substring pass erased.
 *                                  `prefixes`, `asns` and `dnssecAlgorithms` are in this lane because
 *                                  they share the helper, NOT because a redaction string could reach
 *                                  them: they are machine-shaped (CIDR, `AS[0-9]+` for all 116,028 ASN
 *                                  nodes, and one of eight algorithm names). The pass is harmless there
 *                                  and the shape is the real guarantee.
 *   SHAPE ONLY                     the nameservers (`safeHostname`) and the abuse address (`safeEmail`).
 *                                  No redaction test, and it needs none as a PROPERTY rather than as a
 *                                  prediction about registries: "REDACTED FOR PRIVACY" cannot survive
 *                                  `safeHostname` (whitespace, label count) or `safeEmail` (no `@`), so
 *                                  the shape IS the test. `ns1.privacyprotect.org` is meanwhile a real
 *                                  nameserver that a substring pass erased.
 *   RECONSTRUCTED                  `firstRegistered` (`dateOnlyToIso`, matched digit groups), and
 *                                  `queriedName` / `resolvedName`, which are LDH-validated names from
 *                                  `hostnameForOrigin` and `isSameOrSubdomainOf` rather than free text.
 *                                  Nothing arbitrary reaches these, so neither pass applies.
 *   MACHINE-BUILT TIMESTAMPS       `observedAt`, rebuilt from the SNAPSHOT's own clock, and BOTH
 *                                  `retrievedAt` values - the record's own and `network.retrievedAt` -
 *                                  which are ours. Never registry text. The lane was
 *                                  called "our own clock", which contradicted the distinction this file
 *                                  is built on and states in three other places: `observedAt` is
 *                                  emphatically NOT our clock, and a record we cannot date is not
 *                                  published at all.
 *   NEITHER REGISTRY TEXT NOR A    `registry`, `dnssec`, `operatorSource` and `stale` are constants this
 *   STRING WE WERE HANDED          file writes. `network.rpki.status` is an enum through `soleValue`,
 *                                  `roaOrigin` and `maxLength` are numbers through `asInteger`, and
 *                                  `anycast` / `moas` are booleans through `strictBoolean`, so no string
 *                                  pass can apply to any of them. And `origin` is echoed VERBATIM from
 *                                  the caller, the single field whose content comes from outside the
 *                                  graph entirely. It takes no string pass; `hostnameForOrigin` runs
 *                                  more checks than these, and FIVE OF THEM BEAR ON THE ECHO, doing two
 *                                  different jobs.
 *                                  `url.origin === origin` makes the echo FAITHFUL - what we hand back
 *                                  is the string that was asked about. The length cap before parsing,
 *                                  `protocol !== 'https:'`, `port !== ''` and the LDH/label/octet
 *                                  validation are what make it SAFE. Deleting any of those four on the
 *                                  grounds that the equality covers it would be a mistake, which is why
 *                                  they are listed rather than summarised.
 */
function boundedList(
  value: unknown,
  validate: (raw: unknown) => string | null,
): readonly string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const out = new Set<string>();
  for (const raw of value) {
    const safe = validate(raw);
    if (safe !== null) out.add(safe);
  }
  if (out.size === 0) return undefined;
  // Sorted BEFORE the cap, not after, and then capped FAIRLY ACROSS ADDRESS FAMILIES.
  //
  // Two bugs stacked here and the second was created by the fix for the first. Capping in response order
  // and sorting the survivors made the documented determinism accidental: `collect()` order is
  // unspecified, so the eight that shipped were the first eight the engine happened to return. Sorting
  // first fixed that - and made the loss DETERMINISTIC, on a whole address family.
  //
  // WHICH family it falls on depends on the leading characters, not on the version, and an earlier draft
  // of this comment got that wrong by asserting v4 always sorts first. Lexicographically `2606:4700`
  // sorts AFTER `104.`, `151.`, `172.` and `198.`, so a Cloudflare-fronted origin loses its v6;
  // but `2600:9000` sorts BEFORE `3.160.0.0` and `2001:4860` before `8.34.208.0` and `34.96.0.0`, so an
  // AWS- or Google-fronted origin loses its v4 instead, and an 8-v4-plus-3-v6 AWS set capped at 8 loses
  // no family at all. So the bug was never "v6 disappears". It was: the truncation falls on whichever
  // family sorts LATER, and removes that family ENTIRELY when the earlier-sorting values already fill
  // the cap - which the Cloudflare-shaped fixture does and that AWS set does not. Silent and
  // reproducible either way, and a wrong answer rather than a shorter one.
  //
  // Measured on the 11-prefix mixed fixture in the suite, whose v4 all sort before its v6: cap-then-sort
  // kept all 3 v6 prefixes by luck of arrival order, sort-then-cap kept 0 by rule.
  //
  // So the cap takes a proportional slice of each family instead of the lexicographic head. A family
  // still present in the data is still present in the record, and if one family alone exceeds the cap it
  // fills only the slots the other does not need. Deterministic, order-independent, and it cannot report
  // a v4-only footprint for a dual-stack origin.
  //
  // Frozen because the same array instance is served from cache to every later caller.
  return Object.freeze(familyFairCap([...out].sort(), MAX_LIST_VALUES));
}

/**
 * Cap a sorted list without letting one address family crowd out another.
 *
 * Generic over the list's contents on purpose: a value containing a colon is treated as IPv6 and
 * everything else as the other group. One function serves every caller and no caller has to know whether
 * its values are addresses.
 *
 * Every caller, because "it is all one group anyway" is true of most of them and NOT of all:
 *
 *   prefixes          genuinely two families. The reason this function exists.
 *   asns              `AS1`..`ASnnnn`, colon-free (0 of 116,028 ASN nodes, which is all of them:
 *                     `count(a)` and `count(DISTINCT a.name)` agree at that figure).
 *   asNames           `autNumAsName`, colon-free on the live graph.
 *   rirs              one of APNIC / ARIN / RIPE / LACNIC / AFRINIC.
 *   dnssecAlgorithms  the eight algorithm names.
 *   netOrgNames       CAN CONTAIN A COLON. 21 live ASN nodes carry one in `orgName` from RPSL bleed,
 *                     e.g. "descr: No. 14, 256 Bach Dang, ..." and "... desc: 7F.-3, NO.119, ...". So
 *                     the split really does bisect this list, and it is safe for a reason that belongs
 *                     to the CALLER, not to this function: `one()` publishes `organisation` only when
 *                     the collection holds exactly ONE distinct value, and this function is a no-op at
 *                     or below the cap, so the split can never change what is published. Written down
 *                     here because "they are all one group" would have been the wrong reason to trust.
 */
function familyFairCap(sorted: readonly string[], cap: number): string[] {
  if (sorted.length <= cap) return [...sorted];
  const v6 = sorted.filter((x) => x.includes(':'));
  const v4 = sorted.filter((x) => !x.includes(':'));
  if (v6.length === 0 || v4.length === 0) return [...sorted].slice(0, cap);
  // Half each, then let either group spend the slots the other cannot use. Both groups are already
  // sorted, so each slice is the head of its own family.
  //
  // THE GUARANTEE, stated once and checked: each family gets `floor(cap/2)` or everything it has,
  // whichever is smaller, and whatever one family cannot use flows to the other - in EITHER direction.
  // So a family present in the data is present in the output whenever the cap is 2 or more, and neither
  // family can be crowded out by the other's abundance. Verified exhaustively over cap 2..13 x v4 1..15
  // x v6 1..15: zero violations, and the formula matches that statement in every one of those shapes.
  // The `Math.max(half, ...)` is redundant arithmetic rather than a second rule, because
  // `cap - min(v6, half)` is already at least `ceil(cap/2)`.
  //
  // On an odd cap the unpaired slot lands on the non-IPv6 group when it has a value for it, and on v6
  // otherwise. Measured: cap 7 with 20 v6 gives 4 v4 + 3 v6 whether v4 has 4 or 5, so the spare can go
  // to the SMALLER group; cap 9 with 5 v4 gives 5 + 4; but cap 9 with only 4 v4 gives 4 + 5, and cap 11
  // with 4 gives 4 + 7, because there v4 has nothing to spend it on.
  //
  // THREE descriptions preceded that one and each was wrong in a different direction: "favours the
  // larger group", then "favours the non-IPv6 group", then "the non-IPv6 group takes ceil(cap/2)
  // whenever it has that many". The last is the instructive failure. It mismatched the code in 225 of
  // the shapes above and was refuted by this suite's own headline fixture - 8 v4 + 3 v6 at the live cap
  // of 8, where the code publishes 5 + 3 while that rule says 4 + 3 and leaves a slot unused. It read as
  // right because every example I checked it against had 20 v6, the one region where a one-sided rule
  // and this symmetric one agree. So: state the guarantee, enumerate it, and never describe a symmetric
  // mechanism from asymmetric examples.
  const half = Math.floor(cap / 2);
  const takeV4 = Math.min(v4.length, Math.max(half, cap - Math.min(v6.length, half)));
  const takeV6 = Math.min(v6.length, cap - takeV4);
  // Re-sorted so the published order is still a pure function of the values, not of the split.
  return [...v4.slice(0, takeV4), ...v6.slice(0, takeV6)].sort();
}

/**
 * Whether two organisation strings name the same organisation, loosely enough to catch a registrar's
 * name bleeding into the registrant field in a different spelling.
 *
 * Live examples of the same registrar in one field: "TUCOWS.COM, CO.", "Tucows Domains Inc.",
 * "TUCOWS, INC.", "TUCOWS DOMAINS INC.". A case-sensitive compare catches none of them.
 */
function sameOrganisation(a: string, b: string): boolean {
  const squash = (v: string): string => v.toLowerCase().replace(/[^a-z0-9]+/g, '');
  const x = squash(a);
  const y = squash(b);
  if (x.length === 0 || y.length === 0) return false;
  return x === y || (x.length >= 5 && y.includes(x)) || (y.length >= 5 && x.includes(y));
}

/**
 * Whether a value contains markup or a formula, which a company name never does.
 *
 * A denylist of payloads would be endless, so this refuses the CHARACTERS that make a payload
 * possible in the places a name is rendered: an HTML tag, an attribute break, a scheme, a markdown
 * link, and a leading `=` or `+` that a spreadsheet evaluates as a formula.
 */
function hasMarkup(value: string): boolean {
  if (/[<>]/.test(value)) return true;
  if (/^[=+@\t]/.test(value)) return true;        // spreadsheet formula injection
  if (/[a-z][a-z0-9+.-]*:\/\//i.test(value)) return true; // a URL scheme
  if (/\[[^\]]*\]\([^)]*\)/.test(value)) return true;   // a markdown link
  if (/["']\s*\w+\s*=/.test(value)) return true;         // an attribute break
  return false;
}

/**
 * A positive, finite option value, or a clear error naming the option that was wrong.
 *
 * Conservative in what we emit, liberal in what we accept: an omitted option takes the default
 * silently, but a value that cannot mean anything is refused HERE, with the option's name in the
 * message, rather than silently disabling the cache or the queue several layers away.
 */
function positiveMs(value: number | undefined, fallback: number, option: string): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new RangeError(
      `whisper-graph: ${option} must be a finite number greater than 0, received ${String(value)}`,
    );
  }
  return value;
}

/**
 * The hostname this source will describe, or null if the origin is not its shape.
 *
 * The record echoes `origin` back to the merchant, so anything not rejected here becomes output.
 * WHATWG URL parsing is extremely permissive, and each of these parses to a DIFFERENT host than it
 * appears to name:
 *
 *   https://evil@shopify.com            -> https://shopify.com
 *   https://shopify.com%2F@evil.example -> https://evil.example
 *   https://SHOPIFY.com (fullwidth)     -> https://shopify.com
 *   https://0x7f.1                      -> https://127.0.0.1
 *
 * So userinfo, a query, a fragment, a path and a port are refused by component, and the host we use
 * is `url.hostname`, which is already the UTS-46 ToASCII form. That is also the form the graph
 * stores: it holds `xn--bcher-kva.de` and holds no row for the U-label spelling, so taking the
 * A-label is what lets an IDN origin resolve at all, rather than a strictness we impose.
 *
 * What this DOES NOT do, and must not be read as doing, is detect confusables. The A-label of a
 * homograph is an ordinary hostname: `xn--hopify-hvf.com` parses, is canonical, and is accepted
 * here. It has to be. The DNS cannot tell a homograph from a legitimate IDN, an attacker publishes
 * the A-label form in any case, and a source that silently dropped IDNs would be wrong about a large
 * part of the internet. Screening confusables is a different job, for a layer that knows what the
 * merchant expected to see.
 *
 * WHATWG enforces none of the DNS's own limits (the URL Standard sets VerifyDnsLength to false), so
 * every one of those is checked explicitly below, in octets of the A-label.
 */
export function hostnameForOrigin(origin: string): string | null {
  if (typeof origin !== 'string' || origin.length === 0 || origin.length > MAX_ORIGIN_LEN) return null;

  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:') return null;

  // Canonical-or-nothing, and the reason is NOT uniform across what it rejects.
  //
  // Two different classes fail this one comparison, and only the first names a different host than it
  // appears to. That class is small and specific: USERINFO, plain (`https://shopify.com@evil.test`) or
  // with an escape hiding the delimiter (`https://shopify.com%2F@evil.example`). Both read as shopify.com
  // and resolve to somebody else. Refusing those is refusing a lie.
  //
  // The second class names EXACTLY the host it appears to, and it is nearly everything else:
  // `HTTPS://shopify.com` and `https://WWW.Shopify.com` differ from their own `url.origin` only in case;
  // `https://shopify.com/`, `/path`, `?q=1` and `#frag` differ only by a component an origin does not
  // carry - the trailing slash WHATWG adds is literally an empty path. Measured: each of those FOUR has
  // origin `https://shopify.com`, and the two case examples have their own (`https://shopify.com` and
  // `https://www.shopify.com`), which is the point - each names the host it appears to name. They are not
  // deceptions and this is not detecting one.
  //
  // A path can mislead, in the OTHER direction - `https://shopify.com/@evil.example` has origin
  // `https://shopify.com`, exactly as it should, while reading to a human like evil.example. That is a
  // reason not to show a caller's raw string back to them, not a reason to call this check a lie
  // detector. They are refused because this function's answer is keyed by the string the
  // caller handed us and echoed back as the record's subject, and answering about a host spelled
  // differently from the one asked about is the failure we will not have inside a payment decision.
  //
  // That strictness is CONSERVATIVE IN WHAT WE EMIT, and it is paid for at the boundary rather than
  // charged to the caller: one line, `new URL(raw).origin`, canonicalises any of those spellings, and
  // examples/whisper-operator.ts does exactly that before it calls in. Liberal at the edge, strict at
  // the core - not strict everywhere.
  if (url.origin !== origin) return null;
  if (url.port !== '') return null;

  // ONE trailing dot is canonical to WHATWG and unknown to the graph, which returns zero rows for it.
  // Stripping it for the lookup is Postel: the two spellings name the same zone. More than one is not
  // a name at all: a doubled dot is a zero-length non-root label, which is rejected below as an empty
  // label rather than quietly normalised away here.
  //
  // Two reasons, and the SEMANTIC one is sufficient on its own: the slice removes exactly ONE dot,
  // which is the rule above, where /\.+$/ removes all of them. Measured exactly: `https://example.com..`
  // gives hostname `example.com..`; the slice yields `example.com.`, refused downstream as an empty
  // label, and the regex yields `example.com`, accepted. That difference is the whole point.
  //
  // The second reason is that /\.+$/ really is QUADRATIC on the adversarial input, and the history of
  // this comment is worth keeping because it took three tries to say so correctly and the FIRST version
  // was right. It said the regex "backtracks once per dot from every start position". Two later
  // versions "corrected" that to linear, and both were measured on the wrong input shape - a non-dot
  // followed by dots, where the match succeeds at once. The shape that backtracks is DOTS FOLLOWED BY A
  // NON-DOT, and on V8:
  //
  //     250 dots + "x"      0.028 ms        16,000 dots + "x"    108.6 ms
  //   1,000 dots + "x"      3.28 ms         64,000 dots + "x"  1,599.3 ms
  //
  // Four times the length costs about fourteen and a half times the work, which is quadratic, not the
  // 4x of linear. And the shape is REACHABLE: `https://` + 250 dots + `x` is 259 characters, inside
  // `MAX_ORIGIN_LEN` (264), and `new URL` parses it to a 251-character hostname. So the bound does
  // contain the cost at tens of microseconds rather than milliseconds, and the mechanism the first
  // version named was real. The slice is O(1) and immune either way.
  //
  // The lesson, since it cost three rounds: I measured the input that was easy to construct instead of
  // the input an attacker would send, twice, and each time wrote the result down as "measured".
  const raw = url.hostname;
  const host = (raw.endsWith('.') ? raw.slice(0, -1) : raw).toLowerCase();
  // Bounded in OCTETS of the A-label. url.hostname is already the UTS-46 ToASCII form, so it is
  // ASCII and .length is octets. That equivalence is the reason the bound is applied here and not to
  // the original input: for a U-label, JS string length and DNS octet length differ by up to 4.7x.
  if (host.length === 0 || host.length > MAX_HOSTNAME_LEN) return null;

  // An IP literal has no registrant and no registrable parent. v6 arrives bracketed.
  if (host.startsWith('[') || /^[0-9.]+$/.test(host)) return null;

  const labels = host.split('.');
  if (labels.length < 2 || labels.length > MAX_LABELS) return null;
  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_LABEL_LEN) return null;
    if (label.startsWith('-') || label.endsWith('-')) return null;
    if (!/^[a-z0-9-]+$/.test(label)) return null; // already ToASCII, so an A-label is plain LDH here
    // RFC 5890 section 2.3.1: `--` in the third and fourth positions is a Reserved LDH label, and
    // RFC 5891 section 4.2.3.1 assigns only `xn--`. WHATWG cannot reject these because the URL
    // Standard sets CheckHyphens to false.
    if (label.length > 3 && label[2] === '-' && label[3] === '-' && !label.startsWith('xn--')) {
      return null;
    }
  }
  for (const suffix of SPECIAL_USE_SUFFIXES) {
    if (host === suffix.slice(1) || host.endsWith(suffix)) return null;
  }
  return host;
}

/**
 * A presentation-format name split into labels, or null if it is not one we will reason about.
 *
 * RFC 1035 section 5.1 allows a literal dot inside a label as `\.`, and section 4.1.2 puts no
 * separator on the wire at all: a name is a SEQUENCE OF LABELS, never a string to be suffix-matched.
 * Escapes are refused rather than decoded, because every name this source handles has already been
 * through hostnameForOrigin and is plain LDH. Refusing is how that stays true.
 */
function labelsOf(name: string): readonly string[] | null {
  if (typeof name !== 'string' || name.length === 0 || name.includes('\\')) return null;
  const trimmed = name.endsWith('.') ? name.slice(0, -1) : name; // the root label is implicit
  if (trimmed.length === 0) return null;
  const labels = trimmed.split('.');
  if (labels.some((l) => l.length === 0)) return null; // RFC 1035 3.1: only the root may be empty
  // RFC 4343 section 1: name comparison is case-insensitive over ASCII A-Z ONLY. Deliberately not
  // toLowerCase(), which is full-Unicode and would fold U+212A KELVIN SIGN to 'k', changing the name.
  return labels.map((l) => l.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32)));
}

/**
 * Whether `child` is `parent` or sits beneath it, compared label by label from the right.
 *
 * A suffix test on the raw strings gets three things wrong, and one of them returns a wrong TRUE:
 * `a\.b.example` is the two-label name [a.b, example] and is NOT beneath `b.example`, though it ends
 * with it. The other two are quiet failures: a case difference or a trailing root dot on either side
 * makes two spellings of the same name compare unequal, which silently loses every fold.
 */
export function isSameOrSubdomainOf(child: string, parent: string): boolean {
  const c = labelsOf(child);
  const p = labelsOf(parent);
  if (c === null || p === null || p.length === 0 || p.length > c.length) return false;
  for (let i = 1; i <= p.length; i += 1) {
    if (c[c.length - i] !== p[p.length - i]) return false;
  }
  return true;
}

/**
 * Whether a registrant string is publishable as an accountable party.
 *
 * "Do not normalise the registry's string" is not "publish any byte the graph returns". Everything
 * rejected here is either a non-answer wearing a company's grammar, or a value that is unusable as a
 * name in a merchant's admin UI and log.
 */
export function isPublishableOperator(value: unknown): value is string {
  // safePublished carries the shared safety floor (length, control and bidi characters, markup and
  // formula injection) AND the redaction-sentinel substring pass. Called from here rather than
  // duplicated, because this is the one field that pass belongs to and the two copies had already
  // drifted once: the sentinel loop here normalised whitespace and the one in safePublished did not.
  if (safePublished(value) === null) return false;
  const trimmed = (value as string).trim();
  if (trimmed.length > MAX_OPERATOR_LEN) return false;

  const upper = trimmed.toUpperCase().replace(/\s+/g, ' ');
  for (const token of EPP_STATUS_TOKENS) if (upper.includes(token)) return false;

  // Mixed script. The whole value of this field is that a human reads the name and recognises it, so
  // a value that mixes Latin with Cyrillic or Greek is refused: "\u0405hopify Inc." renders as
  // "Shopify Inc." and is not it. This is the one confusable check that belongs here, because it needs
  // no knowledge of what the reader expected - a single name drawn from two alphabets is suspect on
  // its own terms. Detecting that one name resembles ANOTHER is a different job, for a layer that
  // knows the target.
  const scripts = [/\p{Script=Latin}/u, /\p{Script=Cyrillic}/u, /\p{Script=Greek}/u]
    .filter((re) => re.test(trimmed)).length;
  if (scripts > 1) return false;

  // An exactly-repeated value is a graph artifact, not the registry's string:
  // "Clickverge LLC Clickverge LLC Clickverge LLC", "Audible, Inc. Audible Inc.".
  if (isRepeatedPhrase(trimmed)) return false;

  // Something has to look like a name rather than punctuation.
  // \p{L} rather than [A-Za-z], so a legitimate Japanese, Greek or Arabic company name is publishable.
  // Paired with the mixed-script check above, which is what keeps that from widening the homoglyph
  // surface: an earlier version rejected every non-Latin merchant from the same line that accepted a
  // Cyrillic homoglyph of a US brand.
  if (!/\p{L}/u.test(trimmed)) return false;

  // POSITIVE shape rules, which need no list and cannot rot. The denylist above was derived from
  // the strings a sample of domains happened to contain, and that category does not enumerate: a
  // privacy proxy is a commercial product any registrar may name anything. These rules instead
  // reject values by what they ARE, and each one was seen in live data in this field:
  //   "ns1.mailbank.com"      a nameserver
  //   "abuse@godaddy.com"     an email
  //   "https://www.markmonitor.com"  a URL
  //   "2025-05-07"            a bare date
  //   "mr"                    a title, in a payments record
  //   "N/A", "ok", "null"     a non-answer spelled as a word
  if (trimmed.length < 3) return false;
  if (NON_ANSWER_WORDS.has(upper)) return false;
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(trimmed)) return false;      // a hostname
  if (trimmed.includes('@') || /^[a-z]+:\/\//i.test(trimmed)) return false; // an email or a URL
  if (/^\d{4}-\d{2}-\d{2}/.test(trimmed)) return false;            // a date
  if (/^[\d\s.,-]+$/.test(trimmed)) return false;                   // only digits and punctuation
  // Three or more question marks in a row is mojibake, not a name: the graph holds
  // "Zhejiang Taobao Network Limited (??????????)" where a CJK name was lost in transcoding.
  if (/\?{3}/.test(trimmed)) return false;
  return true;
}

/**
 * Whether a registrant string is corroborated by something that did not come from WHOIS.
 *
 * This is the inversion that matters most in this file, and it replaced a denylist. Deciding what
 * NOT to publish by listing the non-answers cannot converge: a privacy or proxy service is a product
 * that any of fifty thousand registrars can name anything, and the dangerous ones are precisely the
 * ones shaped like a company. Measured against live data, a denylist of the forms we had actually
 * seen still published "Identity Protection Service" as the operator of two real merchants.
 *
 * So the question is turned around. A registrant is published as the OPERATOR only when an
 * independent source agrees it names this business: either the graph's own company name for the
 * host, or the registrable label itself. Both are outside WHOIS, so a proxy cannot satisfy either.
 *
 * Measured consequences, and the point is that the good cases survive:
 *   "Wal-Mart Stores, Inc."      vs companyName "Walmart Inc."  -> corroborated (walmart)
 *   "Ruggable LLC"               vs label "ruggable"            -> corroborated
 *   "Shopify Inc."               vs label "shopify"             -> corroborated
 *   "Identity Protection Service" vs companyName "Bombas"       -> NOT corroborated, so no operator
 *   "Tucows.com Co"              vs companyName "Caraway"       -> NOT corroborated
 *   "BBY Solutions, Inc."        vs companyName "Best Buy Co."  -> NOT corroborated
 *
 * That last one is the honest cost and it is the right answer: BBY Solutions is Best Buy's
 * intellectual-property subsidiary, and naming it as who operates bestbuy.com to someone deciding
 * whether to pay would be a claim we cannot support.
 */
export function corroborates(registrant: string, companyName: unknown, registrableLabel: string): boolean {
  const tokens = (value: string): Set<string> => {
    const out = new Set<string>();
    for (const raw of value.toLowerCase().split(/[^a-z0-9]+/)) {
      // Legal-form and filler words carry no identity: "Shopify Inc." and "Bombas Inc." would
      // otherwise corroborate each other on "inc".
      if (raw.length >= 3 && !LEGAL_FORM_WORDS.has(raw)) out.add(raw);
    }
    return out;
  };
  const claimed = tokens(registrant);
  if (claimed.size === 0) return false;

  const candidates = [registrableLabel, ...(typeof companyName === 'string' ? [companyName] : [])];
  for (const candidate of candidates) {
    for (const token of tokens(candidate)) if (claimed.has(token)) return true;
  }

  // Token overlap alone misses a brand that punctuation splits: "Wal-Mart Stores, Inc." tokenises to
  // {wal, mart, stores} and never matches the company name "Walmart Inc." or the label "walmart".
  // So compare the squashed forms too, which is what a reader's eye does. Bounded to identifiers of
  // real length so two short words cannot agree by accident.
  const squash = (value: string): string => value.toLowerCase().replace(/[^a-z0-9]+/g, '');
  const claimedSquashed = squash(registrant);
  for (const candidate of candidates) {
    const other = squash(candidate);
    if (other.length >= 5 && (claimedSquashed.includes(other) || other.includes(claimedSquashed))) {
      return true;
    }
  }
  return false;
}

/**
 * Control characters, bidi controls and line/paragraph separators, tested by CODE POINT.
 *
 * Deliberately not a regex literal containing the characters themselves. Writing them inline put a
 * real U+202E override into this file and the parser rejected it - the function that refuses bidi
 * text cannot be the one that smuggles it. Ranges, not literals.
 */
function hasUnsafeCharacter(value: string): boolean {
  for (const ch of value) {
    const c = ch.codePointAt(0);
    if (c === undefined) continue;
    if (c <= 0x1f || c === 0x7f) return true;              // C0 controls and DEL
    if (c >= 0x80 && c <= 0x9f) return true;               // C1 controls
    if (c === 0x200e || c === 0x200f) return true;         // LRM, RLM
    if (c >= 0x202a && c <= 0x202e) return true;           // embedding and override
    if (c >= 0x2066 && c <= 0x2069) return true;           // isolates
    if (c === 0x2028 || c === 0x2029) return true;         // line and paragraph separators
    if (c === 0xfeff) return true;                         // zero-width no-break space
  }
  return false;
}

/**
 * True when the value is one phrase repeated, ignoring punctuation.
 *
 * Comma variants matter: "Audible, Inc. Audible Inc." is not an exact repetition of its own first
 * half, which is why comparing the raw halves is not enough.
 */
export function isRepeatedPhrase(value: string): boolean {
  const words = value
    .toLowerCase()
    .replace(/[.,]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 0);
  if (words.length < 2) return false;
  // Every divisor, not a fixed 2..4. A 5-fold or 7-fold repetition is a prime count and used to pass:
  // "Acme LLC Acme LLC Acme LLC Acme LLC Acme LLC" published.
  for (let parts = 2; parts <= words.length; parts += 1) {
    if (words.length % parts !== 0) continue;
    const unit = words.length / parts;
    const head = words.slice(0, unit).join(' ');
    let allEqual = true;
    for (let i = 1; i < parts; i += 1) {
      if (words.slice(i * unit, (i + 1) * unit).join(' ') !== head) {
        allEqual = false;
        break;
      }
    }
    if (allEqual) return true;
  }
  return false;
}

/**
 * The graph's `queryTime` as an ISO 8601 instant, or null when it is not the shape we measured.
 *
 * Measured: 657 of 657 values are exactly `YYYY-MM-DD HH:MM:SS`, space-separated and zoneless, so
 * lexicographic ordering equals chronological and this conversion is total on real data.
 *
 * It is built from the parts rather than handed to `new Date(...)`, because `new Date` on a zoneless
 * string is interpreted in the LOCAL zone: the same snapshot yields 2025-03-19T15:44:35Z under UTC
 * and 2025-03-20T02:44:35Z under Pacific/Niue, a different DAY. The record travels to merchants in
 * every timezone, and target.com's registrant is from 2022, which is exactly when a shifted date
 * stops being a nit. It also never double-stamps: 'Z'.replace(' ','T') + 'Z' yields "...ZZ", whose
 * Date.parse is NaN, in a field their SDK types as a plain string so TypeScript catches nothing.
 */
export function snapshotToIso(queryTime: unknown): string | null {
  if (typeof queryTime !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z?$/.exec(queryTime.trim());
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m;
  const ms = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
  if (!Number.isFinite(ms)) return null;
  const iso = new Date(ms).toISOString();
  // Round-trip guard: rejects 2026-02-31 and friends, which Date.UTC silently rolls over.
  return iso.slice(0, 19) === `${y}-${mo}-${d}T${h}:${mi}:${s}` ? iso : null;
}

/** Exactly one distinct non-null value, or undefined. Used for fields their type declares scalar. */
function soleValue<T>(values: readonly unknown[], guard: (v: unknown) => v is T): T | undefined {
  const seen = new Set<T>();
  for (const v of values) if (guard(v)) seen.add(v);
  return seen.size === 1 ? [...seen][0] : undefined;
}

/** Every distinct non-empty string, sorted, or undefined. Deterministic AND complete. */
function sortedStrings(values: unknown): readonly string[] | undefined {
  if (!Array.isArray(values)) return undefined;
  const seen = new Set<string>();
  for (const v of values) if (typeof v === 'string' && v.length > 0) seen.add(v);
  return seen.size > 0 ? [...seen].sort() : undefined;
}

const isNonEmptyString = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isFiniteNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);

/**
 * Strict tri-state for a boolean the graph may omit.
 *
 * Deliberately not truthiness: a corrupt `"false"` is a truthy STRING, and publishing
 * `anycast: true` for a non-anycast prefix inverts a fact inside a merchant trust record. The body
 * is `unknown`, so TypeScript cannot see this.
 */
function strictBoolean(values: readonly unknown[]): boolean | undefined {
  return soleValue(values, (v): v is boolean => typeof v === 'boolean');
}

/* ------------------------------------------------------------------------------------------------
 * The three queries.
 *
 * Every one is anchored on `{name: $name}` and projects properties explicitly. Anchoring here is
 * availability, not style: an unanchored match is not a cheap query, and a query that does not return
 * in time is one this source would report as an outage for every origin at once. So each query binds
 * an indexed property, and a collection of names is driven with `UNWIND` plus an anchored match per
 * row rather than with a `WHERE ... IN`.
 *
 * Every aggregation over an ANCHORED MATCH carries a NON-AGGREGATED grouping key. Without one,
 * `collect()` returns a single row of empty arrays for a name that does not exist, which is
 * byte-identical to a real name with no edges - and this source would then assert `dnssec: 'absent'`,
 * a positive claim, about a domain it has never seen. With the key, an unknown name returns zero rows
 * and is unambiguously null, and it is also the cheaper plan.
 *
 * TWO queries are exempt, deliberately, and both are named here so the exemption is a decision rather
 * than an oversight:
 *
 *   Q_NET_ASN      driven by `UNWIND $prefixes`, never by a name. It runs ONLY with prefixes that a
 *                  previous anchored answer returned, so existence is already settled before it is
 *                  sent and empty collections can only mean "no routing observation for these
 *                  prefixes". It publishes no ASN in that case, which is the absence of a claim.
 *   Q_REGISTRANT   a procedure lane (`CALL whisper.history.whois`). Every column it returns is an
 *                  aggregation on purpose, over up to 12 history rows, so there is no non-aggregated
 *                  property to group by; `$name` would be a constant, not a key. A procedure that
 *                  yields nothing gives one row of empty collections, and the reader treats an empty
 *                  registrant list as "no publishable registrant" - again the absence of a claim,
 *                  never a positive one.
 *
 * The invariant exists to stop emptiness from becoming an assertion. Neither exempt lane turns
 * emptiness into an assertion, which is why neither needs the key.
 * ---------------------------------------------------------------------------------------------- */

/**
 * Network facts for the QUERIED name, and the existence signal the fold gate depends on.
 *
 * TWO queries rather than one, because the public endpoint caps a query at TWO relationship
 * traversals and rejects a deeper one outright:
 *
 *   {"type":".../query-depth-exceeded","status":400,
 *    "detail":"Query depth 5 exceeds maximum allowed depth of 2..."}
 *
 * The single five-hop query this replaced (hostname to ip to prefix to asn to org, plus asn to name)
 * was therefore rejected for every caller, and the rejection presented as an absent network block
 * rather than as an error. So the traversal is split to fit inside the published limit.
 *
 * The first query's `MATCH` is unconditional and its `OPTIONAL MATCH` carries both hops, which keeps
 * it at depth 2 while preserving two DIFFERENT signals that must not be conflated:
 *
 *   prefixes present   observed routing                -> the network block is published
 *   prefixes empty     no routing observation for it    -> publish without a network block, and, where
 *                                                         a fold is at stake, the fold gate REFUSES
 *
 * The discriminator is the PREFIX COLLECTION, never the row count. An invented subdomain may return a
 * row with empty collections or may return nothing at all - both occur on the live endpoint, and which
 * one a given name gives is not a property this client relies on. An earlier version of this comment
 * said an invented subdomain returns zero rows and made that the gate's control, which was both
 * unreliable and a weaker test than the one the code actually applies.
 *
 * Verified against the live endpoint: `www.shopify.com` returns both of its prefixes with a populated
 * collection, while `shopify.com` and an invented subdomain BOTH return one row with EMPTY collections -
 * indistinguishable by row count, separated only by the prefix collection, which is what the fold gate
 * below keys on. The apex is empty for the reason documented at the gate itself: its resolution is
 * recorded in a shape this query does not match, not because nothing was observed.
 */
const Q_NET_PREFIX = `MATCH (h:HOSTNAME {name: $name})
OPTIONAL MATCH (h)-[:RESOLVES_TO]->(ip:IPV4|IPV6)-[:ANNOUNCED_BY]->(p:ANNOUNCED_PREFIX)
RETURN h.name AS subject,
       collect(DISTINCT p.name) AS prefixes,
       collect(DISTINCT p.abuseEmail) AS netAbuseEmails,
       collect(DISTINCT p.rir) AS rirs,
       collect(DISTINCT p.rpkiStatus) AS rpkiStatuses,
       collect(DISTINCT p.roaAsn) AS roaAsns,
       collect(DISTINCT p.roaMaxLength) AS roaMaxLengths,
       collect(DISTINCT p.isAnycast) AS anycasts,
       collect(DISTINCT p.isMoas) AS moases` as const;

const Q_NET_PREFIX_COLUMNS = [
  'subject', 'prefixes', 'netAbuseEmails', 'rirs', 'rpkiStatuses',
  'roaAsns', 'roaMaxLengths', 'anycasts', 'moases',
] as const;

/**
 * The ASN behind those prefixes.
 *
 * `UNWIND` then an anchored `{name: pn}` rather than `WHERE p.name IN $prefixes`: the `IN` form is
 * not anchored on the index, and an unanchored query here does not error, it returns EMPTY
 * COLLECTIONS. An empty answer that means "your query was not anchored" is indistinguishable from one
 * that means "there is no ASN", which is the failure mode this whole file exists to avoid, so the
 * shape matters here for correctness and not only for cost.
 *
 * `orgName` and `autNumAsName` are read off the ASN node, which carries them denormalised. That is
 * what keeps this at depth 2 while still naming the organisation, where the hop to ORGANIZATION
 * would not fit.
 *
 * One ASN-level classification available here is deliberately not selected: it is a true fact about a
 * network that reads as an accusation beside an ordinary merchant, because a large share of legitimate
 * commerce is proxied. Conservative in what we emit.
 */
const Q_NET_ASN = `UNWIND $prefixes AS pn
MATCH (p:ANNOUNCED_PREFIX {name: pn})-[:ROUTES]->(a:ASN)
RETURN collect(DISTINCT a.name) AS asns,
       collect(DISTINCT a.autNumAsName) AS asNames,
       collect(DISTINCT a.orgName) AS netOrgNames` as const;

const Q_NET_ASN_COLUMNS = ['asns', 'asNames', 'netOrgNames'] as const;

/**
 * Zone facts, anchored on the REGISTRABLE PARENT.
 *
 * `SIGNED_WITH` exists only at the apex: paypal.com carries ECDSAP256SHA256 and www.paypal.com
 * carries nothing. Anchored on the queried name this source would report `dnssec: 'absent'` for a
 * signed zone on the majority of real origins, since merchants serve from www. That is a false
 * NEGATIVE security claim, which is the worse direction.
 */
const Q_ZONE = `MATCH (z:HOSTNAME {name: $name})
OPTIONAL MATCH (z)-[:SIGNED_WITH]->(alg:DNSSEC_ALGORITHM)
RETURN z.name AS subject,
       collect(DISTINCT alg.name) AS dnssecAlgorithms,
       z.companyName AS companyName` as const;

const Q_ZONE_COLUMNS = ['subject', 'dnssecAlgorithms', 'companyName'] as const;

/**
 * The registrant, from WHOIS HISTORY rather than the latest snapshot.
 *
 * The latest snapshot's registrant is redacted for most major merchants, so reading only that answers
 * nothing. Searching history for the most recent publishable value resolves a real company for 7 of 8
 * tested. The name and its timestamp are collected as ONE pair, so `observedAt` cannot separate from
 * the name it describes - two independent `head(collect(...))` calls are two aggregations and nothing
 * binds them to the same row.
 *
 * Filtering happens HERE as well as in isPublishableOperator, so a redacted recent snapshot does not
 * shadow a publishable older one.
 */
const Q_REGISTRANT = `CALL whisper.history.whois($name)
  YIELD registrant, registrar, queryTime, nameServers, createDate
WITH registrant, registrar, queryTime, nameServers, createDate
WHERE registrant IS NOT NULL AND trim(registrant) <> ""
WITH registrant, registrar, queryTime, nameServers, createDate ORDER BY queryTime DESC LIMIT 12
RETURN collect(registrant) AS registrants,
       collect(registrar) AS registrars,
       collect(queryTime) AS queryTimes,
       collect(nameServers) AS nameServerSets,
       collect(createDate) AS createDates` as const;

const Q_REGISTRANT_COLUMNS = [
  'registrants', 'registrars', 'queryTimes', 'nameServerSets', 'createDates',
] as const;

/** A graph answer, or the reason it is not one. */
type GraphOutcome<T> =
  | { readonly kind: 'rows'; readonly rows: readonly Record<string, unknown>[]; readonly advisories: readonly Record<string, unknown>[] }
  | { readonly kind: 'unservable' }          // a capability this key does not hold. Permanent, not an outage.
  | { readonly kind: 'defect'; readonly detail: string }  // our own broken Cypher. Loud, once, never retried.
  | { readonly kind: 'outage'; readonly outage: OutageClass };

/* ------------------------------------------------------------------------------------------------
 * The graph client.
 * ---------------------------------------------------------------------------------------------- */

export interface WhisperGraphClientOptions {
  /** Single allowlisted endpoint. https only. */
  endpoint?: string;
  /** Read from the environment by the caller; never defaulted, never logged. */
  apiKey?: string;
  /** Override fetch (tests). */
  fetchImpl?: typeof fetch;
  /** Hard deadline per call. Matches the 5s budget docs/RESOLVER-SOURCES.md places on a source. */
  timeoutMs?: number;
  /** Hard cap on bytes read from a response body. */
  maxResponseBytes?: number;
}

export class WhisperGraphClient {
  private readonly endpoint: string;
  private readonly apiKey: string | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(opts: WhisperGraphClientOptions = {}) {
    this.endpoint = opts.endpoint ?? DEFAULT_ENDPOINT;
    if (!this.endpoint.startsWith('https://')) {
      throw new Error('WhisperGraphClient requires an https endpoint.');
    }
    this.apiKey = opts.apiKey;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 5_000;
    this.maxResponseBytes = opts.maxResponseBytes ?? 64 * 1024;
  }

  /**
   * True when a key is configured. No lookup requires one, and no answer depends on one.
   *
   * Read in exactly two places, and neither is a lane: the constructor's one-time notice and the
   * `keyless` stat. It is deliberately NOT consulted before a query, because every query this source
   * makes answers without a key.
   */
  get hasKey(): boolean {
    return typeof this.apiKey === 'string' && this.apiKey.length > 0;
  }

  /**
   * Run one anchored, parameterised query.
   *
   * Every value is bound as a `parameters` entry, never interpolated. Two things make that more than
   * hygiene here: the API rejects a missing binding outright rather than silently matching nothing,
   * and a value of the wrong type is planned differently rather than refused, so the type is asserted
   * before the call instead of being discovered from the answer.
   */
  async run<K extends readonly string[]>(
    query: string,
    parameters: Readonly<Record<string, string | readonly string[]>>,
    expectedColumns: K,
  ): Promise<GraphOutcome<K>> {
    // A binding is a non-empty string, or a bounded list of them. The list case exists for the one
    // query that drives an `UNWIND`, and it is bounded HERE rather than at the call site: the values
    // come from a graph response, so an unbounded list would let one response decide the size of the
    // next query we send. The type is asserted rather than coerced, because a value of the wrong type
    // is planned differently instead of refused, and the symptom would be a slow answer.
    for (const [k, v] of Object.entries(parameters)) {
      if (typeof v === 'string') {
        if (v.length === 0) return { kind: 'defect', detail: `parameter ${k} must not be empty` };
        continue;
      }
      if (!Array.isArray(v) || v.length === 0 || v.length > MAX_LIST_VALUES) {
        return {
          kind: 'defect',
          detail: `parameter ${k} must be a non-empty string or a list of at most ${MAX_LIST_VALUES}`,
        };
      }
      if (v.some((item) => typeof item !== 'string' || item.length === 0)) {
        return { kind: 'defect', detail: `parameter ${k} must contain only non-empty strings` };
      }
    }

    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json',
    };
    if (this.apiKey) headers['x-api-key'] = this.apiKey;

    let res: Response;
    try {
      res = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({ query, parameters }),
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch {
      // A DNS failure, a TLS failure, a refused connection, a redirect, or the deadline. All of them
      // mean "we could not check", which is an outage and never "no record".
      return { kind: 'outage', outage: 'transport' };
    }

    if (res.status === 429) return { kind: 'outage', outage: 'http429' };
    if (res.status === 401 || res.status === 403) return { kind: 'outage', outage: 'auth' };
    if (res.status >= 500) return { kind: 'outage', outage: 'http5xx' };

    const text = await this.readBounded(res);
    if (text === null) return { kind: 'outage', outage: 'malformed' };

    if (res.status === 400) {
      // A 400 is two different things and the body says which. A capability this key does not hold is
      // PERMANENT and not our defect; broken Cypher is OUR defect and must be loud. Guessing from the
      // status code alone would latch a permanent condition as a transient outage, retry it forever,
      // and bury a real bug of ours in the noise.
      const lowered = text.toLowerCase();
      if (lowered.includes('unservable') || lowered.includes('not_entitled') || lowered.includes('entitle')) {
        return { kind: 'unservable' };
      }
      return { kind: 'defect', detail: firstDetail(text) };
    }
    if (!res.ok) return { kind: 'outage', outage: 'malformed' };

    // A 200 is not success. A captive portal, a WAF interstitial or an HTML error page is a 200 whose
    // body has no rows, and reading that as "zero rows" would publish "no such operator" for an origin
    // that has one. Require the shape, not the status.
    const contentType = res.headers.get('content-type') ?? '';
    if (!contentType.toLowerCase().includes('json')) return { kind: 'outage', outage: 'malformed' };

    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return { kind: 'outage', outage: 'malformed' };
    }
    if (typeof body !== 'object' || body === null) return { kind: 'outage', outage: 'malformed' };
    const envelope = body as { columns?: unknown; rows?: unknown; advisories?: unknown };

    // The columns we asked for, or it is not our answer.
    //
    // BE PRECISE ABOUT WHAT THIS CATCHES, because it is narrower than it looks. Every name in
    // `expectedColumns` is one of THIS FILE's own `AS` aliases, so the check proves the envelope we
    // got belongs to the query we sent: a truncated or reordered column list, an error body shaped
    // like a result, or a response paired with the wrong request. A mismatch is not something a
    // caller can fix, so it is an outage rather than a defect.
    //
    // It does NOT catch an upstream PROPERTY rename, and cannot: `RETURN z.companyName AS companyName`
    // keeps emitting the column `companyName` after the property behind it is renamed, now holding
    // null. The alias is the point of the alias. Such a rename degrades that ONE field to absent,
    // which is the safe direction and is why nothing downstream turns an absent field into a claim -
    // the fold gate refuses an operator it cannot corroborate rather than publishing a guess. A
    // renamed procedure YIELD is a different story and IS caught, loudly: the API rejects the unknown
    // name and `run` reports it as our `defect`, once, without retrying.
    if (!Array.isArray(envelope.columns)) return { kind: 'outage', outage: 'malformed' };
    const got = new Set(envelope.columns.filter((c): c is string => typeof c === 'string'));
    for (const want of expectedColumns) {
      if (!got.has(want)) return { kind: 'outage', outage: 'malformed' };
    }

    const rows = Array.isArray(envelope.rows)
      ? envelope.rows.filter((r): r is Record<string, unknown> => typeof r === 'object' && r !== null)
      : [];
    const advisories = Array.isArray(envelope.advisories)
      ? envelope.advisories.filter((a): a is Record<string, unknown> => typeof a === 'object' && a !== null)
      : [];
    return { kind: 'rows', rows, advisories };
  }

  /**
   * Read at most `maxResponseBytes`, counted off the stream.
   *
   * `await res.text()` then checking `.length` bounds NOTHING: measured against a SYNTHETIC chunked
   * body with no content-length, a correct 5 s AbortSignal still admitted gigabytes into the heap
   * before the deadline fired, and a `Promise.race` timeout returned while the orphaned read kept
   * growing afterwards. The cap has to be enforced per chunk, and the body cancelled when it is hit.
   */
  private async readBounded(res: Response): Promise<string | null> {
    if (!res.body) {
      return null;
    }
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        total += value.byteLength;
        if (total > this.maxResponseBytes) {
          await reader.cancel().catch(() => undefined);
          return null; // over budget is an outage, not a truncated parse
        }
        chunks.push(value);
      }
    } catch {
      return null;
    } finally {
      reader.releaseLock?.();
    }
    const joined = new Uint8Array(total);
    let at = 0;
    for (const c of chunks) {
      joined.set(c, at);
      at += c.byteLength;
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(joined);
  }
}

/** The `detail` of an RFC 7807 body, for one loud log line. Never the whole body. */
function firstDetail(text: string): string {
  try {
    const o = JSON.parse(text) as { detail?: unknown; title?: unknown };
    if (typeof o.detail === 'string') return o.detail.slice(0, 200);
    if (typeof o.title === 'string') return o.title.slice(0, 200);
  } catch {
    /* fall through */
  }
  return text.slice(0, 200);
}

/* ------------------------------------------------------------------------------------------------
 * The source.
 * ---------------------------------------------------------------------------------------------- */

export interface WhisperOperatorSourceOptions extends WhisperGraphClientOptions {
  /** Registry facts. A registrant snapshot changes about once a year; measured median. */
  zoneTtlMs?: number;
  /** How long past its TTL a record may still be served while a refresh is enqueued. */
  zoneStaleMs?: number;
  /** Routing facts. BGP genuinely moves. */
  networkTtlMs?: number;
  /** A negative is a fact about OUR coverage, which changes on ingest cadence, not in minutes. */
  negativeTtlMs?: number;
  /** An outage is remembered just long enough that the next describe() tells the truth about it. */
  outageTtlMs?: number;
  /**
   * Consecutive failures before the source declares the graph unreachable for ALL names.
   *
   * Per-name failures are always remembered individually; this is only the systemic breaker. It is
   * deliberately not 1: one failing name must not blind the source for every other name.
   */
  outageTripAfter?: number;
  /** Entry ceilings. The CACHE key comes from a caller-supplied header, so it must be bounded. */
  maxEntries?: number;
  /** Names waiting to be resolved. Bounded, drop-newest, counted. */
  maxQueue?: number;
  /** Graph calls per minute, independent of queue depth. Our own budget; the server publishes none. */
  maxCallsPerMinute?: number;
  /** Injected clock, per this repo's idiom. */
  nowMs?: () => number;
  /**
   * Injected randomness, used only to jitter cache expiry. Injectable for the same reason the clock
   * is: a deterministic jitter gives every process in a fleet the same expiry schedule, which is a
   * synchronised stampede rather than a spread.
   */
  random?: () => number;
  /** Transitions only, never per failure. Defaults to console.warn like the other sources here. */
  onWarning?: (message: string) => void;
}

/** A counter snapshot. Raw monotonic values; the host divides. */
export interface WhisperOperatorStats {
  readonly describeCalls: number;
  readonly hitFresh: number;
  readonly hitStale: number;
  readonly hitNegative: number;
  readonly missEnqueued: number;
  readonly coalesced: number;
  readonly enqueueDropped: number;
  readonly outageThrows: number;
  readonly notOurShape: number;
  /** Names refused because no ANNOUNCED-PREFIX observation was found for them. The takeover gate. */
  readonly gatedNoHostRow: number;
  /** Lanes skipped because this configuration may not ask. Never published as an absence. */
  readonly laneUnservable: number;
  /**
   * History rows whose registrant was not publishable at all: a redaction string, but also an EPP
   * status token, mixed script, a repeated phrase, a hostname, an email, a URL, a date or mojibake.
   * The commonest reason a record is withheld, which is why it is counted - it was incremented into a
   * field that was in neither this interface nor `stats()`, so nothing could read it and the README's
   * "each reason a record was withheld" stayed false while appearing to have been fixed.
   */
  readonly unpublishableRegistrant: number;
  /** Registrant values that were really the registrar's own name. */
  readonly registrarBleed: number;
  /** Registrant values nothing outside WHOIS agreed with, so no operator was published. */
  readonly uncorroborated: number;
  /** Registrant values whose snapshot could not be dated, so no operator was published. */
  readonly undateable: number;
  readonly servedWithoutNetwork: number;
  readonly resolutionsStarted: number;
  readonly resolutionsCompleted: number;
  /** Attempts that ended without publishing. `started === completed + failed + inflight`, always. */
  readonly resolutionsFailed: number;
  readonly failedTransport: number;
  readonly failedHttp5xx: number;
  readonly failedHttp429: number;
  readonly failedAuth: number;
  readonly failedMalformed: number;
  readonly queryDefects: number;
  /** True when no API key is configured. Nothing is disabled by its absence. */
  readonly keyless: boolean;
  /** True while the breaker is open: every describe() is reporting "could not check". */
  readonly graphUnreachable: boolean;
  /** Failures since the last success. Reaches `outageTripAfter` and the breaker opens. */
  readonly consecutiveFailures: number;
  readonly graphCallsTotal: number;
  readonly foldsLearned: number;
  readonly foldsRejected: number;
  readonly queueDepth: number;
  readonly queueHighWater: number;
  /**
   * Times our OWN per-minute ceiling deferred a drain. Distinct from failedHttp429, which is the
   * graph's limit: an operator seeing slow warming needs to know which of the two it is.
   */
  readonly budgetDeferrals: number;
  readonly inflight: number;
  readonly fqdnEntries: number;
  readonly zoneEntries: number;
  readonly outageEntries: number;
}

/**
 * Accountability provenance for a verified origin, from the Whisper graph.
 *
 * Wire it in place of the stub in examples/operator-composition.ts:
 *
 *   const operator = new WhisperOperatorSource();
 *   const verifier = new MultiProtocolVerifier({ ..., operator });
 *
 * EVERY field resolves without a key. An `apiKey` is optional: when present it is forwarded, and it
 * changes no answer. Deliberately NO claim about what it buys, because the only honest answer would
 * describe the endpoint's own shedding behaviour, and that is the endpoint's to publish rather than
 * this file's to guess at. There is no degraded mode that answers null for everything, because "no
 * record" would be a false statement about the whole internet.
 */
export class WhisperOperatorSource implements OperatorSource {
  readonly name = 'whisper-graph';

  private readonly client: WhisperGraphClient;
  private readonly zoneTtlMs: number;
  private readonly zoneStaleMs: number;
  private readonly networkTtlMs: number;
  private readonly negativeTtlMs: number;
  private readonly outageTtlMs: number;
  private readonly outageTripAfter: number;
  private readonly maxEntries: number;
  private readonly maxQueue: number;
  private readonly maxCallsPerMinute: number;
  private readonly nowMs: () => number;
  private readonly random: () => number;
  private readonly onWarning: (message: string) => void;

  private readonly fqdn = new Map<string, FqdnEntry>();
  private readonly zone = new Map<string, ZoneEntry>();
  private readonly outages = new Map<string, OutageEntry>();
  private readonly pending = new Set<string>();
  private readonly inflight = new Set<string>();

  private consecutiveFailures = 0;
  /** Advisories from the lane that just answered. Read only by the lane that set them. */
  private lastAdvisories: readonly Record<string, unknown>[] = [];
  private draining = false;
  private pumpScheduled = false;
  private globalOutageUntil = 0;
  private callWindowStart = 0;
  private callsInWindow = 0;
  private warnedAt = new Map<string, number>();
  private readonly counters = {
    describeCalls: 0, hitFresh: 0, hitStale: 0, hitNegative: 0, missEnqueued: 0, coalesced: 0,
    enqueueDropped: 0, outageThrows: 0, notOurShape: 0, servedWithoutNetwork: 0,
    gatedNoHostRow: 0, laneUnservable: 0, unpublishableRegistrant: 0, registrarBleed: 0,
    uncorroborated: 0, undateable: 0,
    budgetDeferrals: 0,
    resolutionsStarted: 0, resolutionsCompleted: 0, resolutionsFailed: 0,
    transport: 0, http5xx: 0, http429: 0,
    auth: 0, malformed: 0, queryDefects: 0, graphCallsTotal: 0, foldsLearned: 0, foldsRejected: 0,
    queueHighWater: 0,
  };

  constructor(opts: WhisperOperatorSourceOptions = {}) {
    this.client = new WhisperGraphClient(opts);
    // Validated at construction, not on use. `??` only substitutes for undefined, so without this a
    // maxEntries of 0 makes the cache evict everything it writes and every describe() miss forever,
    // and a NaN TTL makes every comparison false so nothing ever expires. Both would present as
    // "the Whisper source does not work" long after the line that caused it.
    this.zoneTtlMs = positiveMs(opts.zoneTtlMs, 7 * 24 * 60 * 60 * 1_000, 'zoneTtlMs');
    this.zoneStaleMs = positiveMs(opts.zoneStaleMs, 30 * 24 * 60 * 60 * 1_000, 'zoneStaleMs');
    this.networkTtlMs = positiveMs(opts.networkTtlMs, 60 * 60 * 1_000, 'networkTtlMs');
    this.negativeTtlMs = positiveMs(opts.negativeTtlMs, 60 * 60 * 1_000, 'negativeTtlMs');
    this.outageTtlMs = positiveMs(opts.outageTtlMs, 60 * 1_000, 'outageTtlMs');
    this.outageTripAfter = positiveMs(opts.outageTripAfter, 3, 'outageTripAfter');
    this.maxEntries = positiveMs(opts.maxEntries, 10_000, 'maxEntries');
    this.maxQueue = positiveMs(opts.maxQueue, 512, 'maxQueue');
    this.maxCallsPerMinute = positiveMs(opts.maxCallsPerMinute, 60, 'maxCallsPerMinute');
    if (opts.nowMs !== undefined && typeof opts.nowMs !== 'function') {
      throw new TypeError('whisper-graph: nowMs must be a function returning milliseconds');
    }
    this.nowMs = opts.nowMs ?? Date.now;
    if (opts.random !== undefined && typeof opts.random !== 'function') {
      throw new TypeError('whisper-graph: random must be a function returning a number in [0, 1)');
    }
    this.random = opts.random ?? Math.random;
    // Wrapped ONCE, here, rather than guarded at each call site.
    //
    // onWarning runs synchronously on describe()'s own stack (through enqueue) and on the
    // constructor's. A merchant wires it to their application logger, and a logger can throw for
    // reasons that have nothing to do with us: a closed stream, EPIPE on stdout, a transport in a bad
    // state. Their contract swallows a throw from describe(), so such a throw would disable this
    // source permanently and invisibly, and from the constructor it would take their startup down.
    // A telemetry sink is not allowed to be load-bearing.
    const sink = opts.onWarning ?? ((message: string) => console.warn(message));
    this.onWarning = (message: string): void => {
      try {
        sink(message);
      } catch {
        // Deliberately empty. There is nowhere left to report a failure of the reporting channel.
      }
    };
    if (!this.client.hasKey) {
      // Not a degraded mode. EVERY field this source publishes resolves without a key, because the
      // lane that needed one was removed rather than left in place to be permanently disabled.
      //
      // And deliberately NO claim about what a key would buy. An earlier version said it raised the
      // rate limits, which is not true at this endpoint and would have sent an integrator after a
      // credential for nothing. Stating it precisely would be worse: it would describe the endpoint's
      // shedding behaviour, which is not ours to publish. So the notice says what is verified and stops.
      this.onWarning(
        'whisper-graph: no API key configured. Every field still resolves; the key is optional and'
          + ' changes no answer.',
      );
    }
  }

  /**
   * Describe who is accountable for `origin`.
   *
   * Three synchronous map reads and a pure compose. It never awaits a socket, because nothing on the
   * caller's side bounds how long it may take: annotateWithOperator has no timer and no cache.
   */
  async describe(origin: string): Promise<OperatorRecord | null> {
    this.counters.describeCalls += 1;

    const host = hostnameForOrigin(origin);
    if (host === null) {
      this.counters.notOurShape += 1;
      return null; // "including when the origin is not its shape", per their interface
    }

    const now = this.nowMs();

    // An outage means "we could not check", and their contract says a throw is how that is said. A
    // cache-first source that only ever returns null would report "no such operator" for every
    // failure, which is the mistake docs/RESOLVER-SOURCES.md names as the dangerous one.
    const outage = this.outages.get(host);
    if ((outage && outage.until > now) || this.globalOutageUntil > now) {
      this.counters.outageThrows += 1;
      throw new Error(
        `whisper-graph: could not check ${host} (${outage?.outage ?? 'recent failures'}); this is an`
          + ' outage on our side, not an absence of record',
      );
    }

    const fq = this.fqdn.get(host);
    if (!fq) {
      this.counters.missEnqueued += 1;
      this.enqueue(host);
      return null; // we genuinely have nothing yet, which is exactly what null means
    }

    const zn = this.zone.get(fq.zoneKey);
    if (!zn) {
      this.counters.missEnqueued += 1;
      this.enqueue(host);
      return null;
    }

    if (zn.operator === null) {
      this.counters.hitNegative += 1;
      if (zn.expiresAt <= now) this.enqueue(host);
      return null; // resolved, and the graph holds no publishable operator. A record, not an error.
    }

    const stale = zn.expiresAt <= now;
    if (stale) {
      if (zn.staleUntil <= now) {
        this.counters.missEnqueued += 1;
        this.enqueue(host);
        return null; // past the serve-stale ceiling: a year-old value is not worth serving forever
      }
      this.counters.hitStale += 1;
      this.enqueue(host);
    } else {
      this.counters.hitFresh += 1;
    }

    const networkFresh = fq.network !== null && fq.networkExpiresAt > now;
    if (!networkFresh && fq.network !== null) {
      this.counters.servedWithoutNetwork += 1;
      this.enqueue(host);
    }

    // `observedAt` is the SNAPSHOT's own time, and there is deliberately no fallback to our clock.
    // A record whose snapshot could not be dated is never published at all (pickOperator drops it),
    // because substituting the retrieval time would present a years-old registrant as observed now,
    // silently, the day the graph starts emitting a timestamp shape this parser does not accept.
    const record: WhisperOperatorRecord = {
      origin, // echoed VERBATIM: a merchant correlates our record against their own result by this
      operator: zn.operator.name,
      registry: REGISTRY,
      // Never 'absent' and never 'valid'. 'absent' is a positive claim about a zone read from an
      // ingested snapshot rather than a live validation, so a lagging ingest would make us
      // confidently wrong in the unsafe direction; 'valid' would claim a chain we never walked.
      dnssec: 'unchecked',
      // No fallback, and none is possible: the pair narrowed together at the guard above.
      observedAt: zn.operator.observedAt,
      retrievedAt: zn.retrievedAt,
      operatorSource: 'registrant-corroborated',
      ...(zn.registrar ? { registrar: zn.registrar } : {}),
      ...(zn.nameservers ? { nameservers: zn.nameservers } : {}),
      ...(zn.firstRegistered ? { firstRegistered: zn.firstRegistered } : {}),
      ...(zn.dnssecAlgorithms ? { dnssecAlgorithms: zn.dnssecAlgorithms } : {}),
      // Disclosed unconditionally when a fold happened, because the operator names a DIFFERENT
      // subject from the origin and a reader who does not know that would misattribute it.
      ...(fq.zoneKey !== host ? { queriedName: host, resolvedName: fq.zoneKey } : {}),
      ...(networkFresh && fq.network ? { network: fq.network } : {}),
      ...(stale ? { stale: true as const } : {}),
    };
    // No abuseContact. The only abuse address these queries reach is the NETWORK's, and the contract
    // says to leave the field empty rather than fill it with an address that answers for someone else.
    return Object.freeze(record);
  }

  /** A counter snapshot. O(n) in entries, so this is a /healthz call and never a hot-path one. */
  stats(): WhisperOperatorStats {
    const c = this.counters;
    return Object.freeze({
      describeCalls: c.describeCalls, hitFresh: c.hitFresh, hitStale: c.hitStale,
      hitNegative: c.hitNegative, missEnqueued: c.missEnqueued, coalesced: c.coalesced,
      enqueueDropped: c.enqueueDropped, outageThrows: c.outageThrows, notOurShape: c.notOurShape,
      servedWithoutNetwork: c.servedWithoutNetwork,
      gatedNoHostRow: c.gatedNoHostRow, laneUnservable: c.laneUnservable,
      unpublishableRegistrant: c.unpublishableRegistrant,
      registrarBleed: c.registrarBleed, uncorroborated: c.uncorroborated, undateable: c.undateable,
      resolutionsStarted: c.resolutionsStarted,
      resolutionsCompleted: c.resolutionsCompleted, resolutionsFailed: c.resolutionsFailed,
      failedTransport: c.transport,
      failedHttp5xx: c.http5xx, failedHttp429: c.http429, failedAuth: c.auth,
      failedMalformed: c.malformed, queryDefects: c.queryDefects,
      keyless: !this.client.hasKey,
      graphUnreachable: this.globalOutageUntil > this.nowMs(),
      consecutiveFailures: this.consecutiveFailures,
      graphCallsTotal: c.graphCallsTotal,
      foldsLearned: c.foldsLearned, foldsRejected: c.foldsRejected,
      queueDepth: this.pending.size, queueHighWater: c.queueHighWater,
      budgetDeferrals: c.budgetDeferrals,
      inflight: this.inflight.size, fqdnEntries: this.fqdn.size, zoneEntries: this.zone.size,
      outageEntries: this.outages.size,
    });
  }

  /* ---------------------------------------------------------------------------------------------
   * The background resolver. Every network call in this file happens below this line.
   * ------------------------------------------------------------------------------------------- */

  /**
   * Queue a name, at most once.
   *
   * Callers never wait for a resolution, so there is no shared future to join and no promise map is
   * needed: two Sets give provable one-flight-per-key with no allocation. Five hundred concurrent
   * describe() calls for one cold name add one entry.
   */
  private enqueue(host: string): void {
    if (this.inflight.has(host) || this.pending.has(host)) {
      this.counters.coalesced += 1;
      // Re-arm even here. The drain used to be started ONLY from the path that adds a new name, so
      // once the queue sat at its cap with the call budget spent, every later describe() took this
      // branch or the drop below, nothing called the budget again, the window never rolled over, and
      // the source made no further graph call for the life of the process. The only outward sign was
      // a queueDepth pinned at the cap. schedulePump is idempotent, so this costs a boolean read.
      this.schedulePump();
      return;
    }
    if (this.pending.size >= this.maxQueue) {
      // Drop the NEWEST. The names a real merchant asked for arrived first; a flood's tail is what
      // should be lost. Counted, so an operator can see it rather than infer it from latency.
      this.counters.enqueueDropped += 1;
      this.warnOnce('queue-full', 'whisper-graph: resolve queue full, dropping new names');
      this.schedulePump();
      return;
    }
    this.pending.add(host);
    if (this.pending.size > this.counters.queueHighWater) {
      this.counters.queueHighWater = this.pending.size;
    }
    this.schedulePump();
  }

  /**
   * Arrange for the queue to drain, on a later turn of the event loop.
   *
   * Deferred deliberately, and not with queueMicrotask. `describe()` contains no `await`, so calling
   * an async function from it runs that function's body synchronously up to its first await: the
   * query build, the JSON.stringify, the AbortSignal.timeout and the fetch call itself would all be
   * charged to the merchant's request. A microtask would not help, because it still runs inside the
   * current turn, ahead of the caller's own continuation. setImmediate runs in the check phase, after
   * the verification has already resolved.
   *
   * unref'd so a pending drain can never hold a merchant's process - or a test runner - open.
   *
   * The TERMINAL catch matters: Node's default for an unhandled rejection is to terminate the
   * process, and an advisory source that is not permitted to affect a trust decision is certainly not
   * permitted to end the process.
   */
  private schedulePump(): void {
    if (this.pumpScheduled || this.draining) return;
    this.pumpScheduled = true;
    const handle = setImmediate(() => {
      this.pumpScheduled = false;
      void this.pump().catch(() => undefined);
    });
    handle.unref?.();
  }

  /**
   * Drain the queue on demand, one batch at a time.
   *
   * On demand rather than on an interval, matching InMemoryReplayGuard's sweep-on-access: it removes
   * the timer-leak class outright, keeps test runs from hanging, and makes a source with no traffic
   * cost nothing. ONE resolution in flight at a time: a shared public endpoint deserves one caller's
   * worth of load, so the width is one and the queue absorbs the rest.
   */
  private async pump(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.pending.size > 0) {
        if (!this.takeCallBudget()) {
          this.counters.budgetDeferrals += 1;
          this.warnOnce(
            'budget',
            'whisper-graph: our own call budget is spent for this minute, so resolutions are deferred'
              + ' to the next window. Records already held are still served.',
          );
          // Deferring work is correct; abandoning it is not. The resume comes from traffic, because
          // every enqueue() re-arms the drain unconditionally - including the coalesced path, which
          // is the one a name already in the queue takes. So the next describe() for ANY origin
          // re-enters pump(), which re-checks the budget against the clock and proceeds once the
          // window has rolled over.
          //
          // Deliberately not a setTimeout for the remainder of the window. The window is measured on
          // the INJECTED clock while a timer would fire on the real one, so the two would disagree
          // under a test clock and, worse, the source would own a timer whose only job is to do what
          // the next request already does. No timer means nothing to leak and nothing to unref.
          return;
        }
        // values().next() rather than spreading the whole Set: the spread allocated an array of the
        // entire queue on every iteration of the drain, so a full drain was quadratic in queue depth.
        const host = this.pending.values().next().value;
        if (host === undefined) return;
        this.pending.delete(host);
        this.inflight.add(host);
        try {
          await this.resolve(host);
        } catch {
          // resolve() records its own outages; this only stops one bad name ending the drain.
        } finally {
          this.inflight.delete(host);
        }
      }
    } finally {
      this.draining = false;
    }
  }

  /** Our own ceiling, because the API publishes no rate-limit headers to obey. */
  private takeCallBudget(): boolean {
    const now = this.nowMs();
    if (now - this.callWindowStart >= 60_000) {
      this.callWindowStart = now;
      this.callsInWindow = 0;
    }
    if (this.callsInWindow >= this.maxCallsPerMinute) return false;
    this.callsInWindow += 1;
    return true;
  }

  /**
   * Resolve one name: network facts, then the fold and the registrant, then the parent.
   *
   * Only the REQUIRED-field lane can block publication. If the registrant lane fails there is no
   * record AND NO NEGATIVE either, because a negative asserts "we checked and there is nothing",
   * which would be false. If the network lane fails but the registrant succeeded, the narrower record
   * is published: every required field is present and the advisory block is simply absent.
   */
  private async resolve(host: string): Promise<void> {
    this.counters.resolutionsStarted += 1;
    // Accounting lives HERE, not at each return inside resolveOnce, so the invariant
    //   resolutionsStarted === resolutionsCompleted + resolutionsFailed + inflight
    // holds by construction. Counting at each exit meant a later edit adding a fifth early return
    // would silently lose one, and an operator watching started-vs-completed would see an
    // unexplained permanent gap - which is exactly how this was found.
    let outcome: ResolveOutcome = 'failed';
    try {
      outcome = await this.resolveOnce(host);
    } finally {
      if (outcome === 'published') this.counters.resolutionsCompleted += 1;
      else this.counters.resolutionsFailed += 1;
    }
  }

  /**
   * Resolve one name, in four lanes, and publish only what we can stand behind.
   *
   * Every lane's outcome is handled through one exhaustive switch (`laneRows`), which is deliberate:
   * `GraphOutcome` has four variants and an earlier version of this method guarded two of them per
   * lane and let the rest fall through a ternary. The consequence was that "we are not permitted to
   * ask" and "our query is broken" both arrived as `undefined` rows and were published as a resolved
   * ABSENCE, cached for the negative TTL. A negative asserts that we checked. Falling through is how
   * that assertion became false, so the fall-through is gone.
   */
  private async resolveOnce(host: string): Promise<ResolveOutcome> {
    // ---- lane 1: prefixes, and the existence signal the fold gate depends on.
    const prefixLane = await this.laneRows('network', host, Q_NET_PREFIX, { name: host }, Q_NET_PREFIX_COLUMNS);
    if (prefixLane === null) return 'failed';

    // The first half of a two-part security control, not a detail.
    //
    // The WHOIS lane answers for the registrable parent, so an invented subdomain of any brand comes
    // back with that brand's registrant and a perfectly genuine fold advisory. Without this gate a
    // subdomain-takeover origin - where the attacker controls the host, serves the well-known
    // directory, and verifies legitimately - is published as the brand, inside a payments verifier.
    // An anchored HOSTNAME match returns zero rows when there is no HOSTNAME node at all, which is a
    // cheap early refusal and NOT evidence about observation: a name with no announced-prefix
    // observation can still have a node and still return a row. The observation test is the second
    // half, below.
    //
    // Note the two distinct facts kept apart here: zero ROWS means the name is unknown, while a row
    // with an empty `prefixes` collection means the name is known and simply has no announced-prefix
    // observation.
    //
    // What each one costs depends on whether a fold happened, and an earlier version of this comment got
    // that wrong by saying the second "publishes a narrower record" full stop. UNFOLDED, it does: the
    // record is published without a network block. FOLDED, the gate below REFUSES outright, because a
    // registrant is being inherited from a different name. Measured: `www.bombas.com` is a live merchant
    // storefront with a HOSTNAME node, no announced-prefix observation, and it is refused.
    //
    // The stated cost is a null for a genuinely brand-new origin the graph has not ingested yet, and
    // for a name whose HOSTNAME node is missing through a data defect on our side. That is the right
    // direction to be wrong in: a missing record is an absence a merchant can see, and a wrong
    // operator is a claim they would act on.
    //
    // A row's EXISTENCE is not on its own evidence of any observation about the name, which is
    // why the second half of this control tests ANNOUNCED-PREFIX OBSERVATION instead, and why this first
    // half is only a cheap early refusal rather than the control itself.
    if (prefixLane.length === 0) {
      this.counters.gatedNoHostRow += 1;
      this.warnOnce(
        'gated',
        `whisper-graph: declining to describe a name with no announced-prefix observation in the graph.`
          + ` This is how a subdomain of a known brand is prevented from inheriting that brand's`
          + ` registrant.`,
      );
      return 'failed';
    }
    const prefixRow = prefixLane[0] ?? {};
    const prefixes = boundedStrings(prefixRow['prefixes']);

    // ---- lane 2: the ASN behind those prefixes. Skipped entirely when there is no routing to ask
    // about, which is both cheaper and the only correct thing to do with an empty list.
    let asnRow: Record<string, unknown> = {};
    if (prefixes && prefixes.length > 0) {
      const asnLane = await this.laneRows('asn', host, Q_NET_ASN, { prefixes }, Q_NET_ASN_COLUMNS);
      if (asnLane === null) return 'failed';
      asnRow = asnLane[0] ?? {};
    }
    const network = this.networkFrom(prefixRow, asnRow);

    // ---- lane 3: the registrant history, and the fold.
    const whoisLane = await this.laneRows('whois', host, Q_REGISTRANT, { name: host }, Q_REGISTRANT_COLUMNS);
    if (whoisLane === null) return 'failed';
    const whoisRow = whoisLane[0] ?? {};

    const zoneKey = this.foldOf(host, this.lastAdvisories);

    // ---- lane 4: the zone apex, which carries DNSSEC and the corroborating company name.
    //
    // Anchored on the registrable parent, never on the queried name: SIGNED_WITH exists only at the
    // apex, so anchoring here on a www host reports an unsigned zone for a signed one, which is a
    // false negative on a security field.
    const zoneLane = await this.laneRows('zone', host, Q_ZONE, { name: zoneKey }, Q_ZONE_COLUMNS);
    if (zoneLane === null) return 'failed';
    const zoneRow = zoneLane[0] ?? {};
    const companyName = zoneRow['companyName'];

    // The second half of the control, and the one that carries the weight.
    //
    // It applies only when a fold happened, because that is the only case where a registrant is being
    // inherited from a DIFFERENT name: an unfolded name answers for itself and there is nothing to
    // inherit. Where inheritance is at stake, the queried name must have an ANNOUNCED-PREFIX
    // OBSERVATION, not merely be present as a node.
    //
    // Measured on live data, and the measurement is the reason the test is OBSERVED ROUTING rather than
    // node existence. Re-run against the live graph while writing this, with lane 1's own query:
    //
    //   www.shopify.com                      1 row, 2 prefixes   -> folded, observed, PUBLISHES
    //   totally-invented-xyz9q.shopify.com   1 row, 0 prefixes   -> folded, no routing obs, REFUSED
    //   shopify.com                          1 row, 0 prefixes   -> NOT folded, so this gate is not
    //                                                              consulted; it answers for itself
    //
    // Note the middle line, because it is the whole point. A name with NO announced-prefix observation
    // CAN still return a row, with an empty `prefixes` collection - some invented subdomains do, some
    // return nothing at all. Which of the two you get is not a property this client can rely on, so
    // "does a row come back" cannot distinguish an invented subdomain from a real one.
    //
    // NEITHER DOES THE EMPTY PREFIX COLLECTION, and saying it did was the previous version of this
    // sentence. Measured, all three of these are "1 row, 0 prefixes": the invented
    // `totally-invented-xyz9q.shopify.com`, the live `checkout.shopify.com`, and the live storefront
    // `www.bombas.com`. What the collection separates is HAS-AN-ANNOUNCED-PREFIX-OBSERVATION from
    // does-not, which is a proxy for "the graph has routing evidence about this name" and NOT a test for
    // invention. The gate keys on it because a name with an announced-prefix observation is one the graph
    // has seen RESOLVE INTO ANNOUNCED ADDRESS SPACE, so inheriting a parent's registrant for it is
    // defensible where inheriting it for a name with no such evidence is not. That is a conservative
    // proxy, not an oracle - and note what it is NOT: a DNS resolution plus a BGP announcement covering
    // the answer address is not a traffic observation, and nothing on this path carries flow data. An
    // earlier version of this sentence said "really seen carrying traffic", which is the same class of
    // overclaim this paragraph exists to correct.
    //
    // THE PREDICATE IS ANNOUNCED-PREFIX OBSERVATION, WHICH IS NARROWER THAN "RESOLVES", and the
    // difference is not academic. The graph records a resolution in more than one shape, and this
    // query matches one of them: `HOSTNAME -[:RESOLVES_TO]-> IPV4|IPV6 -[:ANNOUNCED_BY]->
    // ANNOUNCED_PREFIX`. Measured live:
    //
    //   www.shopify.com        -> IPV4 104.18.42.163, 172.64.145.93   2 prefixes   PUBLISHES
    //   help.shopify.com       -> IPV4 185.146.173.20                 1 prefix     PUBLISHES
    //   checkout.shopify.com   -> PREFIX 23.227.38.33/32              0 prefixes   REFUSED
    //   shopify.com            -> PREFIX 23.227.38.33/32              0 prefixes   no network block
    //
    // So `checkout.shopify.com` IS observed resolving - to a node labelled `PREFIX` that itself carries
    // `rpkiStatus`, `roaAsn`, `rir` and `abuseEmail` and `ROUTES` to AS13335 - and this source still
    // withholds it, because the label filter above does not reach that shape. The refusal is therefore
    // CONSERVATIVE rather than correct, and it is not confined to unusual names. Driven through this
    // source's own path over these 13 hosts, so the tally is reproducible rather than asserted:
    //
    //   PUBLISH (8)       www.shopify.com, shopify.com, help.shopify.com, www.paypal.com, paypal.com,
    //                     www.target.com, target.com, www.ruggable.com
    //   GATED (2)         checkout.shopify.com, www.bombas.com
    //   NO OPERATOR (3)   www.walmart.com, walmart.com, bombas.com
    //
    // Two refusals, not one, and `www.bombas.com` is a merchant STOREFRONT www origin - the primary
    // shape this verifier exists to describe rather than an edge case. The three NO OPERATOR hosts are a
    // different outcome entirely: nothing was withheld there, the graph simply has no publishable
    // registrant in the window read. Two earlier versions of this sentence each named a single refused
    // host and claimed a count, and both counts were wrong; naming the list is what makes it checkable.
    //
    // Every message here says "no announced-prefix observation" instead of "never observed resolving"
    // for exactly that reason: the earlier wording told an operator something false about a real host.
    //
    // Widening the query to the PREFIX shape is a behaviour change and is deliberately not made here.
    // Nor are these two shapes the whole set: `HOSTNAME -[:ALIAS_OF]-> HOSTNAME` records a CNAME and is
    // present on `www.paypal.com`, `www.target.com`, `www.walmart.com` and others. In every case checked
    // it co-occurs with a `RESOLVES_TO`, so nothing yet turns on it alone, and a HOSTNAME with no
    // resolution edge at all is a fourth case. "Two shapes" would be a tidier sentence and a false one.
    //
    // Two further residuals, stated rather than papered over. This does not defend a takeover of a name
    // that HAS an announced-prefix observation, such as a live subdomain whose CNAME target was released
    // while its records stayed. And a zone serving a wildcard weakens the signal there, because every
    // name under it resolves whether or not anyone provisioned it. Nothing available here closes either,
    // so the record DISCLOSES the fold instead of presenting the parent's registrant as a settled fact
    // about the queried name.
    const folded = zoneKey !== host;
    if (folded && (!prefixes || prefixes.length === 0)) {
      this.counters.gatedNoHostRow += 1;
      this.warnOnce(
        'gated-unresolved',
        'whisper-graph: declining to attribute a registrable parent\'s registrant to a subdomain for'
          + ' which the graph holds no announced-prefix observation. This is what stops an abandoned or'
          + ' invented name under a known brand from inheriting that brand as its operator.',
      );
      return 'failed';
    }

    const operator = this.pickOperator(whoisRow, companyName, zoneKey);

    // DNSSEC, stated in the direction that cannot be stale-wrong.
    //
    // `absent` is a positive claim: this zone is not signed. It is read from an ingested snapshot and
    // not from a live validation, so if ingestion lags, a freshly-signed zone would carry it and we
    // would be confidently wrong in the unsafe direction. So a zone we have a row for but no
    // algorithms on is reported as `unchecked`, which is exactly what their doc defines it as - the
    // source did not attempt validation - and is exactly true of us. `absent` is never emitted, and
    // `valid` cannot be: we read a record, we do not validate a chain.
    const algorithms = boundedStrings(zoneRow['dnssecAlgorithms']);

    this.publish(host, zoneKey, network, operator, algorithms);
    return 'published';
  }

  /**
   * One lane's rows, or null when this resolution must stop.
   *
   * The exhaustive switch is the point. Each non-row outcome is counted and surfaced on its own
   * terms, so a broken query, a capability we lack and a transient outage are three different things
   * to whoever is operating this, instead of three ways of quietly returning no rows.
   */
  private async laneRows<K extends readonly string[]>(
    lane: string,
    host: string,
    query: string,
    parameters: Readonly<Record<string, string | readonly string[]>>,
    columns: K,
  ): Promise<readonly Record<string, unknown>[] | null> {
    const outcome = await this.call(query, parameters, columns);
    this.lastAdvisories = outcome.kind === 'rows' ? outcome.advisories : [];
    switch (outcome.kind) {
      case 'rows':
        return outcome.rows;
      case 'outage':
        this.recordOutage(host, outcome.outage);
        return null;
      case 'unservable': // the graph refused this lane for this caller. Permanent, not an outage.
        // Defensive, and honestly labelled as such: with the key-gated lane removed, nothing this
        // source asks for is entitlement-gated, so no input we can name reaches here. It stays because
        // the endpoint documents this 400 for any caller and reading it as a resolved ABSENCE would be
        // the worst possible misreading. The test below drives it through an injected response rather
        // than pretending a real one exists.
        this.counters.laneUnservable += 1;
        this.warnOnce(
          `unservable:${lane}`,
          // Says what happened and what it costs, and does NOT tell the reader to go and get a key.
          // No lookup here needs one, so a message implying otherwise would send a keyless integrator
          // after a credential that buys them nothing.
          `whisper-graph: the graph refused the ${lane} lookup for this configuration, so no record is`
            + ` published from it. Verification is unaffected; this is provenance we could not read.`,
        );
        return null;
      case 'defect':
        // Our own query was rejected. Ours to fix, and loudly, because the alternative is a field
        // that is permanently absent with nothing anywhere saying why.
        this.counters.queryDefects += 1;
        this.warnOnce(
          `defect:${lane}`,
          `whisper-graph: our ${lane} query was rejected by the graph (${outcome.detail}). This is a`
            + ` defect on our side, not a problem with your configuration. Please report it.`,
        );
        return null;
      default: {
        const exhaustive: never = outcome;
        return exhaustive;
      }
    }
  }

  /**
   * The registrable parent to key zone facts on, learned from the advisory and never computed.
   *
   * Computing it locally needs a public-suffix list, and last-two-labels is wrong for co.uk and every
   * other effective TLD. So the graph's own fold is used, and then bounded, because an advisory is
   * untyped data in a response body:
   *
   *   - it must be about the name we SENT, or an advisory could redirect us to another zone entirely;
   *   - it must be a suffix of that name, compared label by label;
   *   - it must have at least two labels. Without this, an advisory claiming `resolved: "com"` keys
   *     the shared zone cache on "com", and every other .com origin that folds the same way then
   *     reads the operator learned from the first one. Two labels does not make it registrable
   *     (co.uk has two), so this bounds the damage rather than eliminating it, and the remaining case
   *     is why the fold is disclosed in the record instead of being presented as our own conclusion.
   */
  private foldOf(host: string, advisories: readonly Record<string, unknown>[]): string {
    const fold = advisories.find((a) => a['kind'] === 'whois-parent-fold');
    if (!fold) return host;
    const queried = fold['queried'];
    const resolved = fold['resolved'];
    if (
      typeof queried === 'string' && typeof resolved === 'string'
      && queried === host && resolved.includes('.') && isSameOrSubdomainOf(host, resolved)
    ) {
      this.counters.foldsLearned += 1;
      return resolved;
    }
    this.counters.foldsRejected += 1;
    return host;
  }

  /**
   * The operator to publish, or null, walking the registrant history newest first.
   *
   * Three independent conditions, and a row has to satisfy all of them:
   *
   *   1. it is shaped like a name at all (`isPublishableOperator`);
   *   2. it is not simply the registrar's own name bleeding into the registrant field, which is real
   *      and common: three separate spellings of Tucows appear as the "registrant" of names in that
   *      registrar's portfolio;
   *   3. something outside WHOIS corroborates it (`corroborates`).
   *
   * Walking backwards past a redacted recent snapshot is what recovers the real answer for the many
   * merchants whose current WHOIS is a proxy: measured, it is the difference between publishing
   * nothing and publishing "Ruggable LLC". Walking backwards is also how one would publish a FORMER
   * holder of a transferred domain, and condition 3 is what prevents that, because a previous
   * holder does not corroborate against today's company name or today's label.
   */
  private pickOperator(
    row: Record<string, unknown>,
    companyName: unknown,
    zoneKey: string,
  ): PickedOperator | null {
    const registrants = Array.isArray(row['registrants']) ? row['registrants'] : [];
    const registrars = Array.isArray(row['registrars']) ? row['registrars'] : [];
    const times = Array.isArray(row['queryTimes']) ? row['queryTimes'] : [];
    const nameServerSets = Array.isArray(row['nameServerSets']) ? row['nameServerSets'] : [];
    const createDates = Array.isArray(row['createDates']) ? row['createDates'] : [];
    const label = zoneKey.split('.')[0] ?? zoneKey;

    for (let i = 0; i < registrants.length && i < MAX_HISTORY_ROWS; i += 1) {
      const candidate = registrants[i];
      if (!isPublishableOperator(candidate)) {
        // Counted, because this is the MOST COMMON reason a record is withheld - every redacted
        // registrant lands here, and so does every EPP token, hostname, date and mojibake - and it was
        // the one branch of the three with no counter while the README promised one per reason. An
        // uncounted commonest case makes the other two read as the whole story. Named for what the
        // branch tests (`!isPublishableOperator`) rather than for redaction alone, which is only its
        // commonest cause.
        this.counters.unpublishableRegistrant += 1;
        continue;
      }
      const name = candidate.trim();

      const registrar = registrars[i];
      if (typeof registrar === 'string' && sameOrganisation(name, registrar)) {
        this.counters.registrarBleed += 1;
        continue;
      }

      if (!corroborates(name, companyName, label)) {
        this.counters.uncorroborated += 1;
        continue;
      }

      // The snapshot's own time, for the row we actually used. No fallback to our clock: when the
      // snapshot cannot be dated we publish nothing rather than presenting a years-old registrant as
      // observed now, which is what a fallback silently does the day the graph emits a zoned
      // timestamp this parser does not accept.
      const observedAt = snapshotToIso(times[i]);
      if (observedAt === null) {
        this.counters.undateable += 1;
        continue;
      }

      // Registry provenance from the SAME snapshot the name came from, so the three cannot disagree
      // about which observation they describe. All of it arrived in the round trip already made.
      //
      // These accompany the operator rather than standing in for it. This block only runs once a
      // registrant has passed the shape, registrar-bleed, corroboration and datability checks above, so
      // a record never carries them alone: they deepen a record that exists.
      //
      // What they add is a different question from who is accountable. Who the name was registered
      // through separates a brand-protection registrar from a bulk reseller; the nameservers say whether
      // anything is actually served or the name sits on a registrar's parking infrastructure; and the
      // creation date is the oldest thing the registry says about the registration in this snapshot.
      //
      // All three are reproduced, never scored. Whether a 2010 registration through a reseller is
      // reassuring is the reader's call, not ours.
      // A registrar's trade name is CONTENT, and several legitimate ones contain a word the redaction
      // sentinels match on, so a substring test would erase them. But a value that IS the non-answer
      // is not a registrar at all, so it is refused rather than reproduced.
      const registrarSafe = safeString(registrar);
      const registrarName = registrarSafe !== null && !isRedactionNonAnswer(registrarSafe)
        ? registrarSafe
        : null;
      const nameservers = typeof nameServerSets[i] === 'string'
        // The registry publishes them pipe-delimited in one field, and they are validated as names.
        ? boundedHostnames(String(nameServerSets[i]).split('|'))
        : undefined;
      const firstRegistered = dateOnlyToIso(createDates[i]);

      return {
        name,
        observedAt,
        ...(registrarName !== null ? { registrar: registrarName } : {}),
        ...(nameservers ? { nameservers } : {}),
        ...(firstRegistered !== null ? { firstRegistered } : {}),
      };
    }
    return null;
  }

  /**
   * Write both halves of a resolution, in one synchronous block.
   *
   * One block with no `await` in it is what makes the pair atomic from `describe()`'s point of view:
   * there is no interleaving in which a caller sees an fqdn entry pointing at a zone entry that has
   * not been written, or a record served while the source still believes it is in outage.
   */
  private publish(
    host: string,
    zoneKey: string,
    network: WhisperNetworkBlock | null,
    operator: PickedOperator | null,
    dnssecAlgorithms: readonly string[] | undefined,
  ): void {
    const now = this.nowMs();
    const retrievedAt = new Date(now).toISOString();
    // Jittered from an injected random so a fleet of merchant processes that boot together does not
    // expire the same origin in the same millisecond a week later and stampede as one. A deterministic
    // function of a process-local counter would give every process the same schedule, which is a
    // synchronised fleet with extra steps.
    const jitter = (ms: number): number => ms * (0.9 + this.random() * 0.2);

    this.fqdn.set(host, Object.freeze({
      zoneKey,
      network,
      networkExpiresAt: now + jitter(this.networkTtlMs),
    }));
    this.zone.set(zoneKey, Object.freeze({
      operator: operator === null ? null : { name: operator.name, observedAt: operator.observedAt },
      ...(operator?.registrar !== undefined ? { registrar: operator.registrar } : {}),
      ...(operator?.nameservers !== undefined ? { nameservers: operator.nameservers } : {}),
      ...(operator?.firstRegistered !== undefined ? { firstRegistered: operator.firstRegistered } : {}),
      retrievedAt,
      ...(dnssecAlgorithms ? { dnssecAlgorithms } : {}),
      expiresAt: now + jitter(operator === null ? this.negativeTtlMs : this.zoneTtlMs),
      staleUntil: now + jitter(this.zoneTtlMs) + jitter(this.zoneStaleMs),
    }));
    this.outages.delete(host);
    // One success proves the graph is reachable, so the breaker closes here rather than waiting out a
    // TTL. Inside the same synchronous block as the writes above, so there is no interleaving where a
    // record is visible while the source still reports an outage.
    this.consecutiveFailures = 0;
    this.globalOutageUntil = 0;
    // Insert THEN evict, so the write that just happened is never the one discarded. Skipping a write
    // for a key that would be evicted would make the next describe() miss and re-enqueue, forever.
    //
    // What is borrowed from `replay.ts` is the FRACTION - a tenth of the cap on overflow, so a flood
    // degrades how much history is kept rather than availability. Nothing else, and an earlier version
    // of this comment claimed otherwise: that file evicts BEFORE it inserts, and its eviction drops
    // expired entries first and then the soonest-EXPIRING tenth.
    //
    // This one drops the oldest tenth in INSERTION order, and the reason is not that the data is
    // missing - that same earlier version said these maps carry no per-entry expiry, which is false.
    // All three do: `FqdnEntry.networkExpiresAt`, `ZoneEntry.expiresAt` / `staleUntil`, and
    // `OutageEntry.until`. The reason is that `evict` is ONE helper shared by all three, typed
    // `Map<string, unknown>`, and the three entry types name their expiry differently, so a single
    // helper has no common key to sort on. Sorting by expiry would mean three evictors or a shared
    // field, which is a change worth making deliberately rather than a gap to describe away.
    this.evict(this.fqdn);
    this.evict(this.zone);
    this.evict(this.outages);
  }

  private evict(map: Map<string, unknown>): void {
    if (map.size <= this.maxEntries) return;
    const drop = Math.max(1, Math.floor(this.maxEntries / 10));
    let n = 0;
    for (const k of map.keys()) {
      map.delete(k);
      if (++n >= drop) break;
    }
  }

  /**
   * Remember that one name could not be checked, and trip the breaker only on systemic evidence.
   *
   * The per-name entry is always written: the next describe() for THAT name must say "could not
   * check" rather than "no record". The GLOBAL breaker is different, and deliberately hard to trip.
   * One name failing is not evidence the graph is down - it may be one odd name, one unlucky packet,
   * or one hostile origin someone pointed at a merchant. Tripping globally on a single failure let
   * any one origin blind the source for every OTHER origin in the process, which is a denial of
   * provenance for the whole merchant from one bad input. So it takes `outageTripAfter` consecutive
   * failures, and any single success resets the count.
   */
  private recordOutage(host: string, outage: OutageClass): void {
    const now = this.nowMs();
    this.counters[outage] += 1;
    this.outages.set(host, Object.freeze({ outage, until: now + this.outageTtlMs }));
    this.consecutiveFailures += 1;
    if (this.consecutiveFailures >= this.outageTripAfter) {
      const tripped = this.globalOutageUntil > now;
      this.globalOutageUntil = now + this.outageTtlMs;
      if (!tripped) {
        this.onWarning(
          `whisper-graph: ${this.consecutiveFailures} consecutive failures (latest: ${outage}), so`
            + ' the source is treating the graph as unreachable and will report "could not check"'
            + ' until it recovers. Verification is unaffected; only provenance is missing.',
        );
      }
    } else {
      this.warnOnce(`outage-${outage}`, `whisper-graph: could not check one name (${outage})`);
    }
    this.evict(this.outages);
  }

  private async call<K extends readonly string[]>(
    query: string,
    parameters: Readonly<Record<string, string | readonly string[]>>,
    columns: K,
  ): Promise<GraphOutcome<K>> {
    this.counters.graphCallsTotal += 1;
    return this.client.run(query, parameters, columns);
  }

  /** Transitions only, at most one line per five minutes. Per-failure logging is its own defect. */
  private warnOnce(key: string, message: string): void {
    const now = this.nowMs();
    const last = this.warnedAt.get(key) ?? 0;
    if (now - last < 5 * 60_000) return;
    this.warnedAt.set(key, now);
    this.onWarning(message);
  }

  /**
   * The advisory network block, assembled from the prefix row and the ASN row.
   *
   * Every value here describes the ADDRESS the name resolves to, never the party accountable for the
   * name. `organisation` is the network's operator - a CDN or a host - and is the single most likely
   * field in this record to be misread as the answer to "who runs this shop", so it is named for what
   * it is and never promoted into `operator`: a CDN fronts a great many origins it does not answer for.
   *
   * A scalar is emitted only when the underlying collection holds exactly one distinct value, because
   * the query does not order rows. A CDN-fronted origin returns many prefixes and can return more than
   * one ASN, and taking the first row would report a different value for the same origin on two
   * consecutive calls, inside a provenance record. The fields added here that are ARRAYS keep every
   * DISTINCT value, sorted, up to a cap of {@link MAX_LIST_VALUES}: two ASNs is a fact and discarding it
   * is a loss. Past the cap the list is truncated, which is why the truncation is taken proportionally
   * from each address family rather than from the lexicographic head - a record that said a dual-stack
   * merchant was IPv4-only would be a wrong answer, not a shorter one.
   */
  private networkFrom(
    prefixRow: Record<string, unknown>,
    asnRow: Record<string, unknown>,
  ): WhisperNetworkBlock | null {
    const prefixes = boundedStrings(prefixRow['prefixes']);
    if (!prefixes) return null; // known name, no routing observation: absent rather than an empty husk

    // Read as CONTENT, like every other field in this block. `organisation` is an RIR org name, not a
    // WHOIS registrant, and the substring sentinel pass was erasing real ones: `Unredacted Inc` is an
    // ISP, `Foundation for Applied Privacy` an Austrian non-profit, and both were dropped because their
    // names contain a word the list matches. The whole-value non-answer test still refuses an org of
    // "REDACTED FOR PRIVACY", which is the case the pass was there for.
    const one = (row: Record<string, unknown>, key: string): string | undefined => {
      const list = boundedStrings(row[key]);
      return list && list.length === 1 ? list[0] : undefined;
    };
    const rpkiStatus = soleValue(
      (Array.isArray(prefixRow['rpkiStatuses']) ? prefixRow['rpkiStatuses'] : []) as readonly unknown[],
      (v): v is 'valid' | 'invalid' | 'notfound' => v === 'valid' || v === 'invalid' || v === 'notfound',
    );
    // An ASN is a 32-bit unsigned integer and a max-length is a prefix length. A response is
    // untrusted input, so a fraction or a negative is dropped rather than published as a number.
    const asInteger = (values: unknown, max: number): number | undefined => {
      const v = soleValue((Array.isArray(values) ? values : []) as readonly unknown[], isFiniteNumber);
      return v !== undefined && Number.isInteger(v) && v >= 0 && v <= max ? v : undefined;
    };
    const roaOrigin = asInteger(prefixRow['roaAsns'], 4_294_967_295);
    const maxLength = asInteger(prefixRow['roaMaxLengths'], 128);
    const anycast = strictBoolean((Array.isArray(prefixRow['anycasts']) ? prefixRow['anycasts'] : []) as readonly unknown[]);
    const moas = strictBoolean((Array.isArray(prefixRow['moases']) ? prefixRow['moases'] : []) as readonly unknown[]);

    const organisation = one(asnRow, 'netOrgNames');
    // An address is content, so it takes the email path rather than the accountability path. Routing it
    // through the sentinel check dropped `abuse@privacyprotect.org`, which is precisely the address a
    // complaint about a privacy-fronted name has to go to.
    const abuseCandidates = Array.isArray(prefixRow['netAbuseEmails']) ? prefixRow['netAbuseEmails'] : [];
    // Wrapped rather than passed bare: `.map(safeEmail)` would hand the array index to a second
    // parameter if safeEmail ever gained one, and index 0 would reject everything. safeString gained
    // exactly such a parameter in this same round.
    const abuseSafe = [...new Set(
      abuseCandidates.map((v) => safeEmail(v)).filter((v): v is string => v !== null),
    )];
    const abuseContact = abuseSafe.length === 1 ? abuseSafe[0] : undefined;
    const asns = boundedStrings(asnRow['asns']);
    const asNames = boundedStrings(asnRow['asNames']);
    const rirs = boundedStrings(prefixRow['rirs']);

    const block: WhisperNetworkBlock = {
      ...(organisation !== undefined ? { organisation } : {}),
      ...(abuseContact !== undefined ? { abuseContact } : {}),
      ...(asns ? { asns } : {}),
      ...(asNames ? { asNames } : {}),
      prefixes,
      ...(rirs ? { rirs } : {}),
      ...(rpkiStatus
        ? {
          rpki: {
            status: rpkiStatus,
            ...(roaOrigin !== undefined ? { roaOrigin } : {}),
            ...(maxLength !== undefined ? { maxLength } : {}),
          },
        }
        : {}),
      ...(anycast !== undefined ? { anycast } : {}),
      ...(moas !== undefined ? { moas } : {}),
      // Our RETRIEVAL time, named as such. The graph publishes no routing-observation timestamp, and
      // calling this `observedAt` beside a genuine WHOIS snapshot time would invite a reader to
      // compare two different things and conclude the routing data is years fresher.
      retrievedAt: new Date(this.nowMs()).toISOString(),
    };
    return Object.freeze(block);
  }
}
