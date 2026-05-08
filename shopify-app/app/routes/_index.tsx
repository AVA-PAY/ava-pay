import { redirect, type LoaderFunctionArgs } from '@remix-run/node';
import { login } from '../shopify.server.js';

/**
 * Public landing — anyone hitting the root URL gets redirected into the
 * embedded admin app (or to Shopify login if they aren't authed yet).
 */
export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  if (url.searchParams.get('shop')) {
    throw redirect(`/app?${url.searchParams.toString()}`);
  }
  return await login(request);
}
