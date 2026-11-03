/**
 * The Accept-Signature value this store sends to unsigned and unverified
 * callers (draft-ietf-webbotauth-httpsig-protocol-01 Section 5.3, RFC 9421
 * Section 5): an origin that expects a signature SHOULD request one, SHOULD
 * include the request on a refusal, and MAY send it on a success to say a
 * signed request would be treated differently. We send it on the ping and on
 * every response whose verification outcome is not trusted, and never on a
 * trusted one (the agent already signs the way we need).
 *
 * ONE canonical value, mirrored byte for byte in the WooCommerce twin
 * (includes/core/class-ava-pay-accept-signature.php); the API suite's
 * tests/accept-signature.test.ts reads both sources and fails on drift, in
 * the style of check:type-sync. Change it here first, then the PHP.
 *
 * Why each piece is in it (RFC 9421 Section 5.1 defines the field as a
 * Dictionary whose member value is the requested covered-component list plus
 * requested signature parameters):
 *
 * - label `sig1`: the label deployed Web Bot Auth agents already sign under.
 *   RFC 9421 Section 5.2 makes the responding signature use this label, and
 *   the keyed component below ties the Signature-Agent member to it.
 * - `"@authority"`: the verifier requires @authority or @target-uri in the
 *   covered set; @authority is what deployed agents cover and it survives
 *   both twins' signed-URL reconstruction.
 * - `"content-digest"`: this endpoint takes a body on POST, and a covered
 *   Content-Digest binds it; a digest that is present is always validated
 *   strictly, and a digest of the empty body is valid on a bodyless request
 *   (the verifier checks it against the empty body that arrived). An agent
 *   MAY also ignore any requested component (RFC 9421 Section 5.2), which is
 *   the standard's own escape hatch, not a failure.
 * - `"signature-agent";key="sig1"`: -01 Section 5.2.1 requires the member
 *   keyed to the signature label to be signed as a component.
 * - `created;expires`: requested WITHOUT values, which RFC 9421 Section 5.1
 *   defines as "generate and include" them; the verifier requires both.
 * - `tag="web-bot-auth"`: the verifier dispatches and gates on this tag.
 * - No keyid (any key the agent's directory publishes is acceptable), no alg
 *   (two algorithms are accepted; the directory key decides), no nonce (the
 *   parameter's Section 5.1 meaning is "use THIS nonce value", and replay
 *   protection does not need a chosen value).
 */
export const ACCEPT_SIGNATURE_HEADER = 'Accept-Signature';

export const ACCEPT_SIGNATURE_VALUE =
  'sig1=("@authority" "content-digest" "signature-agent";key="sig1")'
  + ';created;expires;tag="web-bot-auth"';

/**
 * The header to attach for a given verification outcome: the request is sent
 * to callers we did not verify (unsigned, failed, inconclusive) and withheld
 * from trusted ones. Pure, so both the route and its tests use the same gate.
 */
export function acceptSignatureHeaders(trusted: boolean): Record<string, string> {
  return trusted ? {} : { [ACCEPT_SIGNATURE_HEADER]: ACCEPT_SIGNATURE_VALUE };
}
