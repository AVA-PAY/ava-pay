import type { AdminApiContext } from '@shopify/shopify-app-react-router/server';

/**
 * Create a one-time, single-use percentage discount via the Shopify Admin
 * GraphQL API. Returned `code` is what storefront JS appends to the cart
 * (e.g. /discount/AVA-XYZ?redirect=/cart).
 *
 * This is the simplest discount path that works on every Shopify plan,
 * including non-Plus stores. For Plus we'll later prefer a Shopify Function.
 *
 * Returns null when no discount could be created, for ANY reason: a
 * non-positive percentage, GraphQL userErrors, or the Admin API rejecting the
 * call outright (a 403 when the access token lacks write_discounts throws from
 * the client rather than returning userErrors). Verification and discount
 * minting are separate concerns: a verified agent must still be admitted when
 * the perk cannot be granted, and the caller decides what to do with null.
 * Every failure is logged with enough detail to diagnose it from the service
 * logs, since a merchant sees only a missing discount.
 */
export interface CreatedDiscount {
  code: string;
  percentage: number;
}

const DISCOUNT_CODE_PREFIX = 'AVA';

export async function createOneTimeDiscount(
  admin: AdminApiContext,
  percentagePct: number,
): Promise<CreatedDiscount | null> {
  if (percentagePct <= 0) return null;

  const code = `${DISCOUNT_CODE_PREFIX}-${randomCode()}`;
  const startsAt = new Date().toISOString();

  const mutation = `#graphql
    mutation CreateAvaDiscount($basicCodeDiscount: DiscountCodeBasicInput!) {
      discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
        codeDiscountNode { id }
        userErrors { field message }
      }
    }
  `;

  const variables = {
    basicCodeDiscount: {
      title: `AVA Pay verified agent (${code})`,
      code,
      startsAt,
      customerSelection: { all: true },
      customerGets: {
        value: { percentage: percentagePct / 100 },
        items: { all: true },
      },
      appliesOncePerCustomer: true,
      usageLimit: 1,
    },
  };

  try {
    const response = await admin.graphql(mutation, { variables });
    const json = (await response.json()) as {
      data?: {
        discountCodeBasicCreate?: {
          userErrors?: Array<{ message: string }>;
        };
      };
    };

    const userErrors = json.data?.discountCodeBasicCreate?.userErrors ?? [];
    if (userErrors.length > 0) {
      // eslint-disable-next-line no-console
      console.error('Discount creation failed:', userErrors);
      return null;
    }
    return { code, percentage: percentagePct };
  } catch (error) {
    // The Admin API client throws on non-2xx. The one worth calling out is 403
    // Forbidden, which means this shop's access token does not carry
    // write_discounts and no retry will help: the merchant has to reinstall or
    // re-grant. Anything else (network, 5xx) is transient.
    const status = (error as { response?: { status?: number } })?.response?.status;
    // eslint-disable-next-line no-console
    console.error(
      JSON.stringify({
        event: 'discount.create_failed',
        status: status ?? null,
        forbidden: status === 403,
        message: error instanceof Error ? error.message : String(error),
        hint:
          status === 403
            ? 'Admin API refused the call: the access token is missing write_discounts. Reinstall the app so the scope is granted.'
            : undefined,
      }),
    );
    return null;
  }
}

function randomCode(): string {
  // 8 alphanumeric chars; collision-resistant enough at our volume.
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 8; i++) {
    s += chars[Math.floor(Math.random() * chars.length)];
  }
  return s;
}
