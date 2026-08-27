import { Outlet, useNavigate, useRouteError } from 'react-router';
import { useEffect } from 'react';
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
import { EMBEDDED_ROUTE_HANDLE } from '../lib/app-bridge.js';

export const links: LinksFunction = () => [{ rel: 'stylesheet', href: polarisStyles }];

/**
 * Marks every page under /app as an embedded admin document, so root.tsx knows
 * to put the App Bridge script in the head with the apiKey below. See
 * lib/app-bridge.ts for why the tag is not left to AppProvider.
 */
export const handle = EMBEDDED_ROUTE_HANDLE;

export async function loader({ request }: LoaderFunctionArgs) {
  await authenticate.admin(request);
  return { apiKey: process.env.SHOPIFY_API_KEY ?? '' };
}

/**
 * App Bridge turns a click on a `<ui-nav-menu>` link into a `shopify:navigate`
 * event rather than a page load, and something has to route it. The library's
 * AppProvider does this only on its `embedded` branch, which is the same branch
 * that renders the App Bridge script tag we now render in the head instead, so
 * the listener comes back here.
 */
function useShopifyNavigate(): void {
  const navigate = useNavigate();

  useEffect(() => {
    const handleNavigate = (event: Event) => {
      const href = (event.target as HTMLElement | null)?.getAttribute('href');
      if (href) navigate(href);
    };

    document.addEventListener('shopify:navigate', handleNavigate);
    return () => document.removeEventListener('shopify:navigate', handleNavigate);
  }, [navigate]);
}

export default function App() {
  // The loader's apiKey is not read here: root.tsx picks it off this route's
  // match so the App Bridge tag can be rendered in the document head.
  useShopifyNavigate();

  return (
    // embedded={false} keeps AppProvider from rendering a second App Bridge
    // script in the body. It still adds the Polaris web components script.
    <AppProvider embedded={false}>
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
