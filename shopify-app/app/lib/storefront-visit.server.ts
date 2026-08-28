/**
 * Signing the storefront test visit. See storefront-visit.ts for what the
 * feature is and why the source marker behaves the way it does.
 *
 * Server only: it reaches for node:crypto through the SDK, the same way
 * test-visit-request.ts does, and for the same reason it is kept out of the
 * module the Settings component imports.
 */

import { createPrivateKey } from 'node:crypto';
import { signWithVisa } from '@ava-pay/agent';
import {
  DEMO_AGENT_ID,
  DEMO_AGENT_PRIVATE_JWK,
  demoAgentMandate,
} from './test-visit-request.js';
import {
  VISIT_SOURCE_HEADER,
  VISIT_SOURCE_TEST,
  storefrontVisitUrl,
} from './storefront-visit.js';

/**
 * Covered components for a storefront visit: the Visa profile's usual set plus
 * the source marker.
 *
 * The marker has to be inside the signature for resolveVisitSource to honour
 * it. Signing it is also the only thing that makes it unforgeable by a passing
 * visitor, since the URL it travels in is public by construction.
 */
const COVERED_COMPONENTS = [
  '@method',
  '@target-uri',
  'host',
  'content-digest',
  'x-ava-mandate',
  VISIT_SOURCE_HEADER,
];

/**
 * Ask for the longest signature window the verifier will grant. It caps the
 * effective lifetime at its own maximum age regardless of what a signer
 * volunteers, so this is an upper bound rather than a claim, and the Settings
 * page reissues the link long before even the capped window runs out.
 */
const SIGNATURE_WINDOW_SECONDS = 600;

export interface BuildStorefrontVisitOptions {
  /** Unix seconds. Defaults to now. Tests pin it. */
  created?: number;
  /** Single-use replay nonce. Defaults to a fresh UUID inside the SDK. */
  nonce?: string;
  /** Storefront path the visit lands on. Defaults to the shop home page. */
  path?: string;
}

/**
 * A storefront URL carrying one signed demo agent visit.
 *
 * The body is empty on purpose. The embed forwards the signed material from
 * URL parameters into a bodyless POST, so signing over an empty body is what
 * makes the Content-Digest an honest statement about the request that actually
 * arrives rather than one about a cart that was never sent.
 */
export function buildStorefrontVisitUrl(
  shop: string,
  options: BuildStorefrontVisitOptions = {},
): string {
  const created = options.created ?? Math.floor(Date.now() / 1000);

  const signed = signWithVisa({
    method: 'POST',
    url: `https://${shop}/apps/ava-pay/verify`,
    body: '',
    agentId: DEMO_AGENT_ID,
    privateKey: createPrivateKey({ key: DEMO_AGENT_PRIVATE_JWK, format: 'jwk' }),
    mandate: demoAgentMandate(shop, created),
    created,
    expires: created + SIGNATURE_WINDOW_SECONDS,
    components: COVERED_COMPONENTS,
    extraHeaders: { [VISIT_SOURCE_HEADER]: VISIT_SOURCE_TEST },
    ...(options.nonce !== undefined ? { nonce: options.nonce } : {}),
  });

  return storefrontVisitUrl(shop, signed.headers, options.path ?? '/');
}
