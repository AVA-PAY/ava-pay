import { describe, expect, it } from 'vitest';
import { APP_EMBED_HANDLE, themeAppEmbedDeepLink, themeListUrl } from './theme-embed.js';

const SHOP = 'ava-pay-test-store.myshopify.com';

describe('themeAppEmbedDeepLink', () => {
  it('builds the documented activateAppId link for the app embed', () => {
    const url = new URL(themeAppEmbedDeepLink(SHOP, 'a11383a35e184d1ca38fb0d1c7116a68'));

    expect(url.origin).toBe(`https://${SHOP}`);
    expect(url.pathname).toBe('/admin/themes/current/editor');
    expect(url.searchParams.get('context')).toBe('apps');
    expect(url.searchParams.get('activateAppId')).toBe(
      `a11383a35e184d1ca38fb0d1c7116a68/${APP_EMBED_HANDLE}`,
    );
  });

  it('uses the block filename as the handle', () => {
    // activateAppId wants the liquid filename, so this must track
    // extensions/ava-pay-embed/blocks/ava-pay-embed.liquid.
    expect(APP_EMBED_HANDLE).toBe('ava-pay-embed');
  });

  it('falls back to the app embeds panel when the API key is missing', () => {
    // Better one extra click than an editor link with an empty activateAppId.
    const url = new URL(themeAppEmbedDeepLink(SHOP, undefined));

    expect(url.pathname).toBe('/admin/themes/current/editor');
    expect(url.searchParams.get('context')).toBe('apps');
    expect(url.searchParams.has('activateAppId')).toBe(false);
  });

  it('never asks the merchant to open a theme file', () => {
    const url = themeAppEmbedDeepLink(SHOP, 'key');
    expect(url).not.toContain('theme.liquid');
    expect(url).not.toContain('code');
  });
});

describe('themeListUrl', () => {
  it('opens the theme list, for a merchant setting this up off the published theme', () => {
    expect(themeListUrl(SHOP)).toBe(`https://${SHOP}/admin/themes`);
  });
});
