import type { LoaderFunctionArgs } from '@remix-run/node';
import { authenticate } from '../shopify.server.js';

/**
 * Catch-all auth route. The Shopify Remix library handles OAuth, callback,
 * and session creation when we delegate authentication.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  await authenticate.admin(request);
  return null;
}
