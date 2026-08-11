import {
  useLoaderData,
  type ActionFunctionArgs,
  type LoaderFunctionArgs,
} from 'react-router';
import { login } from '../shopify.server.js';
import { LoginForm } from '../login-form.js';

/**
 * Configured login path. The library requires `login()` here (calling
 * `authenticate.admin()` on this path is a hard error since the React Router
 * package). With a valid ?shop= param this redirects into the OAuth/install
 * flow; without one it returns the login-error object, which the form below
 * renders so the visitor can supply the shop domain.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  return await login(request);
}

export async function action({ request }: ActionFunctionArgs) {
  return await login(request);
}

export default function AuthLogin() {
  const errors = useLoaderData<typeof loader>() as { shop?: string };
  return <LoginForm shopError={errors?.shop} />;
}
