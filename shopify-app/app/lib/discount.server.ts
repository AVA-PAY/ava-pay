import type { AdminApiContext } from '@shopify/shopify-app-react-router/server';

/**
 * Create a one-time, single-use percentage discount via the Shopify Admin
 * GraphQL API. Returned `code` is what storefront JS appends to the cart
 * (e.g. /discount/AVA-XYZ?redirect=/cart).
 *
 * This is the simplest discount path that works on every Shopify plan,
 * including non-Plus stores. For Plus we'll later prefer a Shopify Function.
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
