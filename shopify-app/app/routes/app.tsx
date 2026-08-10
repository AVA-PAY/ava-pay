import { Outlet, useLoaderData, useRouteError } from 'react-router';
import { boundary } from '@shopify/shopify-app-react-router/server';
import { AppProvider } from '@shopify/shopify-app-react-router/react';
// The react-router package's AppProvider only injects the web-component
// scripts; it does NOT provide the classic React Polaris context (the Remix
// package did). Our routes use classic @shopify/polaris components, so we
// must mount Polaris's own provider with i18n ourselves.
import { AppProvider as PolarisAppProvider } from '@shopify/polaris';
import polarisTranslations from '@shopify/polaris/locales/en.json';
import { NavMenu } from '@shopify/app-bridge-react';
import polarisStyles from '@shopify/polaris/build/esm/styles.css?url';
import type { HeadersFunction, LinksFunction, LoaderFunctionArgs } from 'react-router';
import { authenticate } from '../shopify.server.js';

export const links: LinksFunction = () => [{ rel: 'stylesheet', href: polarisStyles }];

export async function loader({ request }: LoaderFunctionArgs) {
  await authenticate.admin(request);
  return { apiKey: process.env.SHOPIFY_API_KEY ?? '' };
}

export default function App() {
  const { apiKey } = useLoaderData<typeof loader>();
  return (
    <AppProvider embedded apiKey={apiKey}>
      <PolarisAppProvider i18n={polarisTranslations}>
        <NavMenu>
          <a href="/app" rel="home">
            Settings
          </a>
          <a href="/app/traffic">Traffic</a>
          <a href="/app/policies">Policies</a>
        </NavMenu>
        <Outlet />
      </PolarisAppProvider>
    </AppProvider>
  );
}

export function ErrorBoundary() {
  return boundary.error(useRouteError());
}

export const headers: HeadersFunction = (args) => boundary.headers(args);
