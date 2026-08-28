import { describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';

/**
 * Requirement 2.2.3: App Bridge is loaded from Shopify's CDN as the first
 * script in the document head of an embedded admin page.
 *
 * This is asserted against real rendered HTML rather than by reading the JSX,
 * because the thing that went wrong before was invisible in the source: the
 * library's AppProvider renders the tag as part of the route tree, and React 18
 * does not hoist a plain script into the head, so it came out in the body. The
 * framework components are stubbed with markup that stands in for what they
 * emit; only the ordering around them is under test.
 */

const matches = vi.fn();

vi.mock('react-router', () => ({
  useMatches: () => matches(),
  Meta: () => <meta name="stub-meta" content="x" />,
  Links: () => <link rel="stylesheet" href="/stub.css" />,
  Outlet: () => null,
  Scripts: () => <script src="/stub-client.js" />,
  ScrollRestoration: () => null,
}));

const { default: Root } = await import('./root.js');
const { EMBEDDED_ROUTE_HANDLE, APP_BRIDGE_SRC } = await import('./lib/app-bridge.js');

const API_KEY = 'a11383a35e184d1ca38fb0d1c7116a68';

function render(routeMatches: unknown[]): string {
  matches.mockReturnValue(routeMatches);
  return renderToStaticMarkup(<Root />);
}

function head(html: string): string {
  return html.slice(html.indexOf('<head>'), html.indexOf('</head>'));
}

const embeddedMatch = { handle: EMBEDDED_ROUTE_HANDLE, data: { apiKey: API_KEY } };

describe('the admin document', () => {
  it('loads App Bridge from the CDN, in the head, before any other script', () => {
    const html = render([{}, embeddedMatch]);
    const inHead = head(html);

    expect(inHead).toContain(APP_BRIDGE_SRC);
    expect(inHead).toContain(`data-api-key="${API_KEY}"`);

    // First script anywhere in the document, and the only one in the head.
    expect(html.indexOf('<script')).toBe(html.indexOf(`<script src="${APP_BRIDGE_SRC}"`));
    expect(inHead.match(/<script/g)).toHaveLength(1);
  });

  it('loads it ahead of the stylesheets and meta the framework emits', () => {
    const inHead = head(render([embeddedMatch]));
    expect(inHead.indexOf(APP_BRIDGE_SRC)).toBeLessThan(inHead.indexOf('stub.css'));
    expect(inHead.indexOf(APP_BRIDGE_SRC)).toBeLessThan(inHead.indexOf('stub-meta'));
  });

  it('still declares its charset first, which has to be early in the head', () => {
    const inHead = head(render([embeddedMatch]));
    expect(inHead.indexOf('charSet="utf-8"') >= 0 || inHead.indexOf('charset="utf-8"') >= 0).toBe(
      true,
    );
    expect(inHead.indexOf('utf-8')).toBeLessThan(inHead.indexOf(APP_BRIDGE_SRC));
  });
});

describe('a document outside the admin', () => {
  it('gets no App Bridge script at all', () => {
    // `/` and `/auth/login` render standalone. App Bridge there is a script
    // that can only fail.
    const html = render([{ handle: undefined, data: undefined }]);
    expect(html).not.toContain(APP_BRIDGE_SRC);
    expect(head(html).match(/<script/g)).toBeNull();
  });
});
