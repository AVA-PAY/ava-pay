/**
 * Where the App Bridge script tag comes from, and which routes get one.
 *
 * Requirement 2.2.3 wants App Bridge loaded from Shopify's CDN as the first
 * script in the document head of every embedded admin page. The script tag the
 * library's AppProvider renders is a child of the route tree, which puts it in
 * the body: React 18 does not hoist a plain `<script src>` into the head, and
 * nothing else moves it. So root.tsx renders the tag itself, in the head, above
 * everything else, and app.tsx stops the library rendering a second one.
 *
 * It must not go on every document. `/` and `/auth/login` render outside the
 * Shopify admin and have no business loading App Bridge, so the tag follows a
 * route that declares itself embedded and supplies the API key: `handle` marks
 * the route, and its loader data carries the key.
 */

export const APP_BRIDGE_SRC = 'https://cdn.shopify.com/shopifycloud/app-bridge.js';

/** What a route match looks like to this module. Matches useMatches(). */
export interface RouteMatchLike {
  handle?: unknown;
  data?: unknown;
}

/** Marker an embedded route exports as `handle`. */
export const EMBEDDED_ROUTE_HANDLE = { embedded: true } as const;

/**
 * The API key to hand App Bridge, or null when this document is not an
 * embedded admin page.
 *
 * Null rather than an empty string on a missing key: a tag with no key cannot
 * initialise, and rendering one anyway would put a script in the head that is
 * guaranteed to fail rather than one that is simply absent.
 */
export function embeddedApiKey(matches: readonly RouteMatchLike[]): string | null {
  for (const match of matches) {
    const handle = match.handle as { embedded?: unknown } | undefined;
    if (handle?.embedded !== true) continue;

    const data = match.data as { apiKey?: unknown } | undefined;
    if (typeof data?.apiKey === 'string' && data.apiKey !== '') return data.apiKey;
  }
  return null;
}
