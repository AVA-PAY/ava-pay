/**
 * What leaves the store: the header set forwarded to AVA Pay /verify.
 *
 * The app sees every header the storefront request carried (the visitor's IP
 * in x-forwarded-for, their user agent, language, Shopify's own x-shopify-*
 * set). The verifier needs almost none of it, so AvaPayClient.verify() passes
 * the map through minimizeForwardedHeaders() and sends only:
 *
 *   (a) signature, signature-input, signature-agent;
 *   (b) every HTTP field the incoming Signature-Input names as a covered
 *       component, in any member (lower-cased, component parameters such as
 *       ;key= or ;req dropped, derived @components skipped since they are not
 *       headers);
 *   (c) the protocol headers the verifier reads by name without their being
 *       components: PROTOCOL_HEADERS always, BODY_HEADERS when a body travels;
 *   (d) host, which the caller has already rebuilt from a trusted source.
 *
 * NEVER_FORWARD is applied last and wins over all of the above, coverage
 * included: credentials never leave the store.
 *
 * If Signature-Input is absent or unreadable, (b) is empty and the verifier
 * still gets (a), (c) and (d), enough to return its honest reason (missing
 * credentials, or a malformed input).
 *
 * Minimizing is a statement about what we send, not what we read: callers keep
 * the full map for their own local use (resolveVisitSource, the request hints).
 * The WooCommerce plugin's AVA_Pay_Forwarded_Headers is the PHP twin, held to
 * this file by the golden cases in woocommerce-plugin/scripts.
 */

import { parseSignatureInput } from '@ava-pay/agent/protocol/visa';

/** (a) The signature itself. */
export const SIGNATURE_HEADERS = ['signature', 'signature-input', 'signature-agent'] as const;

/**
 * (c) Headers the API reads by name whether or not the signature covers them.
 *
 *   x-ava-mandate, x-ava-discount-hint      AVA TAP profile (src/verifier/visa.ts)
 *   ap2-checkout-mandate, ap2-payment-mandate  AP2 v0.2 (src/verifier/ap2.ts)
 *   ap2-attestation                         AP2 v0.1, read only to answer
 *                                           unsupported_protocol_version
 *   content-digest                          checked against the body, and
 *                                           against the EMPTY body when none
 *                                           arrives (visa.ts), so it travels
 *                                           with or without one
 */
export const PROTOCOL_HEADERS = [
  'x-ava-mandate',
  'x-ava-discount-hint',
  'ap2-checkout-mandate',
  'ap2-payment-mandate',
  'ap2-attestation',
  'content-digest',
] as const;

/** (c) Forwarded only alongside a body. */
export const BODY_HEADERS = ['content-type'] as const;

/**
 * Credentials, never forwarded, even when a Signature-Input names them as
 * covered. An agent that covers the shopper's cookies is misconfigured or
 * hostile; its request fails at the API with the covered component missing,
 * which is the intended outcome. This does not rely on any caller stripping
 * them first.
 */
export const NEVER_FORWARD = ['cookie', 'authorization', 'proxy-authorization', 'x-wp-nonce'] as const;

/**
 * Split a Structured Fields Dictionary into its member texts at top-level
 * commas. Commas inside a String (with its backslash escapes) or an Inner
 * List do not split. Returns null for a field that does not read as a
 * dictionary at all (unbalanced parentheses or an unterminated string).
 */
export function splitDictionaryMembers(value: string): string[] | null {
  const members: string[] = [];
  let depth = 0;
  let inString = false;
  let start = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (inString) {
      if (c === '\\') i++;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth < 0) return null;
    } else if (c === ',' && depth === 0) {
      members.push(value.slice(start, i));
      start = i + 1;
    }
  }
  if (inString || depth !== 0) return null;
  members.push(value.slice(start));
  return members.map((m) => m.trim());
}

/**
 * The HTTP field names Signature-Input covers across all its members, in first
 * appearance order, or null when the field is unreadable. Each member goes
 * through the SDK's own parseSignatureInput, the same reader the verifier
 * uses, so "readable" here means exactly what it means there.
 */
export function coveredHeaderFields(signatureInput: string | undefined): string[] | null {
  if (signatureInput === undefined) return null;
  const members = splitDictionaryMembers(signatureInput);
  if (members === null || members.some((m) => m === '')) return null;

  const fields: string[] = [];
  for (const member of members) {
    let parsed;
    try {
      parsed = parseSignatureInput(member);
    } catch {
      // SignatureParseError is the only thing the parser throws by design;
      // anything else still means we could not read the field.
      return null;
    }
    for (const { name } of parsed.componentIds) {
      if (name.startsWith('@')) continue;
      const field = name.toLowerCase();
      if (!fields.includes(field)) fields.push(field);
    }
  }
  return fields;
}

/**
 * The headers to forward. Names come out lower-cased, which is how the API
 * indexes them. `host` must already be the rebuilt value; this function
 * forwards it and never derives it.
 */
export function minimizeForwardedHeaders(
  headers: Record<string, string>,
  options: { hasBody: boolean },
): Record<string, string> {
  const lower: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) lower[name.toLowerCase()] = value;

  const keep = new Set<string>([...SIGNATURE_HEADERS, ...PROTOCOL_HEADERS, 'host']);
  if (options.hasBody) for (const name of BODY_HEADERS) keep.add(name);
  for (const field of coveredHeaderFields(lower['signature-input']) ?? []) keep.add(field);
  for (const name of NEVER_FORWARD) keep.delete(name);

  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(lower)) {
    if (keep.has(name)) out[name] = value;
  }
  return out;
}
