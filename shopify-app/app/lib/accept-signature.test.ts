import { describe, expect, it } from 'vitest';
import {
  ACCEPT_SIGNATURE_HEADER,
  ACCEPT_SIGNATURE_VALUE,
  acceptSignatureHeaders,
} from './accept-signature.js';

/**
 * The route-facing gate for the -01 Section 5.3 signature request. Byte-level
 * parity with the WooCommerce mirror and the signed round trip live in the
 * API suite (tests/accept-signature.test.ts); this covers what the route
 * reads.
 */
describe('acceptSignatureHeaders', () => {
  it('requests a signature from callers we did not verify', () => {
    expect(acceptSignatureHeaders(false)).toEqual({
      [ACCEPT_SIGNATURE_HEADER]: ACCEPT_SIGNATURE_VALUE,
    });
  });

  it('sends nothing on a trusted outcome', () => {
    expect(acceptSignatureHeaders(true)).toEqual({});
  });

  it('asks for the web-bot-auth tag and the keyed signature-agent member', () => {
    expect(ACCEPT_SIGNATURE_VALUE).toContain('tag="web-bot-auth"');
    expect(ACCEPT_SIGNATURE_VALUE).toContain('"signature-agent";key="sig1"');
    expect(ACCEPT_SIGNATURE_VALUE).toContain(';created;expires');
  });
});
