/**
 * "View a test agent visit on your storefront": the merchant-initiated path
 * that makes the storefront banner reachable without waiting for a real AI
 * shopping agent.
 *
 * The shape of it: Settings signs a demo agent credential server side, puts
 * the signed material into the storefront URL as query parameters, and the
 * merchant opens that URL. The theme app embed forwards those parameters back
 * out as real HTTP headers to /apps/ava-pay/verify, the hosted verifier checks
 * the signature the same way it checks live traffic, and the banner renders
 * from a genuine trusted verdict. Nothing about the verdict is simulated and
 * no preview flag exists on the storefront: the only way to a banner is a
 * verification that actually passed.
 *
 * Two halves, split by what can run where:
 *   storefront-visit.ts         this file. URL assembly and the source rule.
 *                               No node builtins, so the Settings component and
 *                               the proxy route can both import it.
 *   storefront-visit.server.ts  the signing, via node:crypto and @ava-pay/agent.
 */

/**
 * Marker the merchant's own visit carries, so the Traffic page can label the
 * row "Test" rather than present a request the merchant sent themselves as
 * organic agent traffic. Same `source` column the Settings test visit uses.
 *
 * It travels as a signed header rather than a bare flag: see resolveVisitSource.
 */
export const VISIT_SOURCE_HEADER = 'x-ava-visit-source';
export const VISIT_SOURCE_TEST = 'test';

/**
 * Headers the storefront embed lifts out of the URL and sends on as headers.
 * Anything starting with `x-` travels too, which is how the mandate and the
 * source marker get across.
 *
 * Keep in step with SIG_PARAMS in routes/proxy.embed[.js].tsx; the test in
 * storefront-visit.test.ts asserts the two lists agree.
 */
export const FORWARDED_HEADERS = [
  'signature',
  'signature-input',
  'content-digest',
  'signature-agent',
  'x-ava-mandate',
] as const;

function isForwarded(name: string): boolean {
  return (FORWARDED_HEADERS as readonly string[]).includes(name) || name.startsWith('x-');
}

/**
 * The signed headers a storefront page load can carry, as query parameters.
 *
 * `host` is deliberately dropped: the browser sets it from the URL, and it is
 * the storefront origin either way, which is what the agent signed against.
 * `content-type` is dropped for the same reason, being set by the fetch the
 * embed makes rather than by us; it is not a covered component.
 */
export function agentUrlParams(headers: Record<string, string>): URLSearchParams {
  const params = new URLSearchParams();
  for (const [rawName, value] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (isForwarded(name)) params.set(name, value);
  }
  return params;
}

/**
 * The storefront URL that carries a signed agent visit. Defaults to the shop
 * home page, which every store has and no theme can remove.
 */
export function storefrontVisitUrl(
  shop: string,
  headers: Record<string, string>,
  path = '/',
): string {
  const url = new URL(path, `https://${shop}`);
  for (const [name, value] of agentUrlParams(headers)) {
    url.searchParams.set(name, value);
  }
  return url.toString();
}

export type VisitSource = 'storefront' | 'test';

/**
 * Whether a proxy-delivered request is the merchant's own test visit.
 *
 * The marker is only honoured when it was inside the signature. A query
 * parameter on a storefront URL is public and anyone can type one, so a bare
 * `x-ava-visit-source=test` proves nothing; what does prove something is the
 * header appearing in the signature's covered-component list of a signature
 * the verifier then accepted. The base is built from the declared components
 * using the request's own header values, so a trusted verdict over a cover set
 * naming this header means the signer chose the value, not the visitor.
 *
 * Everything else is 'storefront'. A real agent holds a key nobody else has and
 * would have to sign the marker deliberately to be labelled a test, and an
 * untrusted verdict proves nothing about anything the request claimed.
 *
 * The label grants no privilege of any kind. It only decides which word the
 * Traffic page prints in the Source column.
 */
export function resolveVisitSource(
  headers: Record<string, string>,
  trusted: boolean,
): VisitSource {
  if (!trusted) return 'storefront';
  if (headers[VISIT_SOURCE_HEADER] !== VISIT_SOURCE_TEST) return 'storefront';

  const signatureInput = headers['signature-input'];
  if (!signatureInput?.includes(`"${VISIT_SOURCE_HEADER}"`)) return 'storefront';

  return 'test';
}
