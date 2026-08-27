import type { LoaderFunctionArgs } from 'react-router';
import { authenticate } from '../shopify.server.js';
import { EMBED_SCRIPT } from '../lib/embed-script.js';

/**
 * Serves the storefront JS via the App Proxy at:
 *   https://{shop}.myshopify.com/apps/ava-pay/embed.js
 *
 * The script itself, and the reasoning behind every line of it, lives in
 * lib/embed-script.ts. This route is the App Proxy boundary around it: Shopify
 * HMAC-signs the request on the way in, and the response is a static asset that
 * is identical for every shop, so it caches.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  await authenticate.public.appProxy(request);

  return new Response(EMBED_SCRIPT, {
    status: 200,
    headers: {
      'content-type': 'application/javascript; charset=utf-8',
      'cache-control': 'public, max-age=60',
    },
  });
}
