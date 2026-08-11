import { describe, expect, it } from 'vitest';
import { wbaAllowedOrigins } from '../src/server.js';
import { DEFAULT_SIGNATURE_AGENTS } from '../src/verifier/web-bot-auth.js';

/**
 * Signature-Agent allowlist resolution.
 *
 * WBA_ALLOWED_SIGNATURE_AGENTS replaces the built-in set,
 * WBA_EXTRA_SIGNATURE_AGENTS adds to whichever set is in force. The second
 * variable exists so an operator can admit one more origin (a staging
 * directory, a private agent) without restating the defaults and silently
 * dropping chatgpt.com.
 */
describe('wbaAllowedOrigins', () => {
  it('defaults to the built-in set when neither variable is set', () => {
    expect(wbaAllowedOrigins({})).toEqual(DEFAULT_SIGNATURE_AGENTS);
  });

  it('lets the replacement variable take over entirely', () => {
    expect(
      wbaAllowedOrigins({ WBA_ALLOWED_SIGNATURE_AGENTS: 'https://a.example' }),
    ).toEqual(['https://a.example']);
  });

  it('adds the extra variable to the defaults', () => {
    expect(
      wbaAllowedOrigins({ WBA_EXTRA_SIGNATURE_AGENTS: 'https://directory-test.avalayer.com' }),
    ).toEqual([...DEFAULT_SIGNATURE_AGENTS, 'https://directory-test.avalayer.com']);
  });

  it('adds the extra variable to an explicit replacement set', () => {
    expect(
      wbaAllowedOrigins({
        WBA_ALLOWED_SIGNATURE_AGENTS: 'https://a.example',
        WBA_EXTRA_SIGNATURE_AGENTS: 'https://b.example',
      }),
    ).toEqual(['https://a.example', 'https://b.example']);
  });

  it('trims whitespace and drops empty entries', () => {
    expect(
      wbaAllowedOrigins({ WBA_EXTRA_SIGNATURE_AGENTS: ' https://a.example , , https://b.example ' }),
    ).toEqual([...DEFAULT_SIGNATURE_AGENTS, 'https://a.example', 'https://b.example']);
  });

  it('de-duplicates an extra origin that is already allowed', () => {
    const [first] = DEFAULT_SIGNATURE_AGENTS;
    expect(wbaAllowedOrigins({ WBA_EXTRA_SIGNATURE_AGENTS: first })).toEqual(
      DEFAULT_SIGNATURE_AGENTS,
    );
  });

  // Fail closed: an operator who sets the replacement variable to something
  // that parses to nothing has said "trust no origin". That must not be read
  // as "unset" and fall back to the defaults.
  it('keeps an explicit but empty replacement list empty', () => {
    expect(wbaAllowedOrigins({ WBA_ALLOWED_SIGNATURE_AGENTS: ',, ' })).toEqual([]);
  });

  it('keeps an explicit but empty replacement list empty even with an extra origin', () => {
    expect(
      wbaAllowedOrigins({
        WBA_ALLOWED_SIGNATURE_AGENTS: ',, ',
        WBA_EXTRA_SIGNATURE_AGENTS: 'https://b.example',
      }),
    ).toEqual(['https://b.example']);
  });

  it('treats an empty string replacement as unset, as it always has', () => {
    expect(wbaAllowedOrigins({ WBA_ALLOWED_SIGNATURE_AGENTS: '' })).toEqual(
      DEFAULT_SIGNATURE_AGENTS,
    );
  });
});
