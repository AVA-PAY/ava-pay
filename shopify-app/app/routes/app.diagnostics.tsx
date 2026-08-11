import { useLoaderData, type LoaderFunctionArgs } from 'react-router';
import { authenticate, unauthenticated } from '../shopify.server.js';

/**
 * TEMPORARY diagnostic, added 2026-08-11 to explain a 403 Forbidden from the
 * Admin API inside the App Proxy path while the same shop's stored session
 * carried write_discounts. REMOVE once that is resolved.
 *
 * The point is the side-by-side: the embedded admin client is minted per
 * request through token exchange, while the App Proxy path loads the stored
 * offline session. If one works and the other does not, the token is the
 * difference rather than the scope or the mutation.
 *
 * Reports statuses, error messages and granted scopes only. Never tokens.
 */

interface Probe {
  label: string;
  ok: boolean;
  status: number | null;
  requestId: string | null;
  detail: string;
}

async function probe(label: string, run: () => Promise<Response>): Promise<Probe> {
  try {
    const res = await run();
    const body = await res.text();
    return {
      label,
      ok: res.ok,
      status: res.status,
      requestId: res.headers.get('x-request-id'),
      detail: body.slice(0, 400),
    };
  } catch (error) {
    const status = (error as { response?: { status?: number } })?.response?.status ?? null;
    return {
      label,
      ok: false,
      status,
      requestId: null,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
}

const SHOP_QUERY = '#graphql\n  query DiagShop { shop { name myshopifyDomain } }';
const SCOPES_QUERY =
  '#graphql\n  query DiagScopes { currentAppInstallation { accessScopes { handle } } }';
const DISCOUNT_PROBE = `#graphql
  mutation DiagDiscount($basicCodeDiscount: DiscountCodeBasicInput!) {
    discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
      codeDiscountNode { id }
      userErrors { field message }
    }
  }
`;

export async function loader({ request }: LoaderFunctionArgs) {
  const { session, admin } = await authenticate.admin(request);
  const shop = session.shop;

  // Same client the App Proxy route gets: built from the stored offline session.
  const offline = await unauthenticated.admin(shop);

  const probes: Probe[] = [
    await probe('embedded (token exchange): shop query', () => admin.graphql(SHOP_QUERY)),
    await probe('offline (stored session): shop query', () => offline.admin.graphql(SHOP_QUERY)),
    await probe('offline (stored session): granted scopes', () =>
      offline.admin.graphql(SCOPES_QUERY),
    ),
    await probe('offline (stored session): discount mutation', () =>
      offline.admin.graphql(DISCOUNT_PROBE, {
        variables: {
          basicCodeDiscount: {
            title: 'AVA Pay diagnostic (safe to delete)',
            code: `AVA-DIAG-${Date.now()}`,
            startsAt: new Date().toISOString(),
            customerSelection: { all: true },
            customerGets: { value: { percentage: 0.05 }, items: { all: true } },
            appliesOncePerCustomer: true,
            usageLimit: 1,
          },
        },
      }),
    ),
  ];

  return {
    shop,
    sessionScope: session.scope ?? null,
    sessionIsOnline: session.isOnline,
    apiVersion: '2026-01',
    probes,
  };
}

export default function Diagnostics() {
  const data = useLoaderData<typeof loader>();
  return (
    <main style={{ fontFamily: 'monospace', padding: '1.5rem', fontSize: '0.85rem' }}>
      <h1 style={{ fontSize: '1.1rem' }}>AVA Pay admin API diagnostics</h1>
      <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
        {JSON.stringify(data, null, 2)}
      </pre>
    </main>
  );
}
