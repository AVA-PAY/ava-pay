import { redirect, useLoaderData, type LoaderFunctionArgs } from 'react-router';
import { login } from '../shopify.server.js';
import { LoginForm } from '../login-form.js';

/**
 * Public landing — a request carrying ?shop= goes straight into the embedded
 * admin app (or Shopify login if it isn't authed yet). Anyone else, including
 * an app reviewer opening the app URL by hand, gets the shop-domain form.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  if (url.searchParams.get('shop')) {
    throw redirect(`/app?${url.searchParams.toString()}`);
  }
  return await login(request);
}

export default function Index() {
  const errors = useLoaderData<typeof loader>() as { shop?: string };
  return <LoginForm shopError={errors?.shop} />;
}
