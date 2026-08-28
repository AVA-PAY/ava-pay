import { Links, Meta, Outlet, Scripts, ScrollRestoration, useMatches } from 'react-router';
import { APP_BRIDGE_SRC, embeddedApiKey } from './lib/app-bridge.js';

export default function App() {
  // 2.2.3: App Bridge from Shopify's CDN, in the head, before any other script.
  // Only embedded admin documents get one; see lib/app-bridge.ts.
  const apiKey = embeddedApiKey(useMatches());

  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        {apiKey ? <script src={APP_BRIDGE_SRC} data-api-key={apiKey} /> : null}
        <Meta />
        <Links />
      </head>
      <body>
        <Outlet />
        <ScrollRestoration />
        <Scripts />
      </body>
    </html>
  );
}
