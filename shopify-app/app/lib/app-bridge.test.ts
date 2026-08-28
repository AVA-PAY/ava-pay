import { describe, expect, it } from 'vitest';
import { APP_BRIDGE_SRC, EMBEDDED_ROUTE_HANDLE, embeddedApiKey } from './app-bridge.js';

/**
 * Requirement 2.2.3 wants App Bridge loaded from Shopify's CDN as the first
 * script in the head of an embedded admin page, and nowhere else. root.tsx
 * renders the tag; this decides whether a given document gets one.
 */

const embedded = { handle: EMBEDDED_ROUTE_HANDLE, data: { apiKey: 'a11383a35e184d1ca38fb0d1' } };
const root = { handle: undefined, data: undefined };

describe('APP_BRIDGE_SRC', () => {
  it('is the CDN copy, never a bundled import', () => {
    expect(APP_BRIDGE_SRC).toBe('https://cdn.shopify.com/shopifycloud/app-bridge.js');
  });
});

describe('embeddedApiKey', () => {
  it('finds the key on an embedded route match', () => {
    expect(embeddedApiKey([root, embedded])).toBe('a11383a35e184d1ca38fb0d1');
  });

  it('gives nothing to a document outside the admin', () => {
    // The login page and the landing route render standalone; App Bridge there
    // would be a script that cannot do anything but fail.
    expect(embeddedApiKey([root])).toBeNull();
    expect(embeddedApiKey([])).toBeNull();
  });

  it('gives nothing when the route is embedded but the key is missing', () => {
    // A tag with no key cannot initialise. Better absent than broken.
    expect(embeddedApiKey([{ handle: EMBEDDED_ROUTE_HANDLE, data: {} }])).toBeNull();
    expect(embeddedApiKey([{ handle: EMBEDDED_ROUTE_HANDLE, data: { apiKey: '' } }])).toBeNull();
  });

  it('is not fooled by a route that merely has data', () => {
    expect(embeddedApiKey([{ handle: { embedded: 'yes' }, data: { apiKey: 'k' } }])).toBeNull();
    expect(embeddedApiKey([{ data: { apiKey: 'k' } }])).toBeNull();
  });
});
