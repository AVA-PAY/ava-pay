import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { login } from '../shopify.server.js';

/**
 * Configured login path. The library requires `login()` here (calling
 * `authenticate.admin()` on this path is a hard error since the React Router
 * package). With a valid ?shop= param this redirects into the OAuth/install
 * flow; without one it returns the login-error object.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  return await login(request);
}

export async function action({ request }: ActionFunctionArgs) {
  return await login(request);
}
