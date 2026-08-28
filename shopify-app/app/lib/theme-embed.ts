/**
 * Deep link into the theme editor with AVA Pay's app embed ready to activate.
 *
 * Shopify's documented format for activating an app embed block is
 *
 *   https://{shop}/admin/themes/current/editor
 *     ?context=apps&template={template}&activateAppId={api_key}/{handle}
 *
 * where `api_key` is the app's client_id (shopify.app.ava-pay.toml, surfaced to
 * the server as SHOPIFY_API_KEY) and `handle` is the filename of the block's
 * liquid file, so `ava-pay-embed` for
 * extensions/ava-pay-embed/blocks/ava-pay-embed.liquid. `template` defaults to
 * index when omitted; it is spelled out here to match the documented form.
 *
 * The one runtime input that can be missing is the API key. Rather than emit a
 * link with an empty activateAppId, which would land the merchant in the editor
 * with nothing selected and no explanation, we fall back to the app embeds
 * panel without the activation parameter. Same destination, one extra click.
 */

/** Filename of the app embed block, which is what activateAppId wants. */
export const APP_EMBED_HANDLE = 'ava-pay-embed';

export function themeAppEmbedDeepLink(shop: string, apiKey: string | undefined): string {
  const base = `https://${shop}/admin/themes/current/editor?context=apps`;
  if (!apiKey) return base;
  const activate = `${encodeURIComponent(apiKey)}/${APP_EMBED_HANDLE}`;
  return `${base}&template=index&activateAppId=${activate}`;
}

/**
 * The store's theme list, for a merchant who wants the embed on a theme other
 * than the published one. The deep link above always opens `themes/current`,
 * which is the published theme; from this page they press Customize on any
 * other theme and reach the same App embeds panel.
 */
export function themeListUrl(shop: string): string {
  return `https://${shop}/admin/themes`;
}
