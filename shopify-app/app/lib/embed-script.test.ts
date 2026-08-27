import { describe, expect, it } from 'vitest';
import {
  BANNER_ELEMENT_ID,
  BANNER_PREFIX,
  BANNER_SETTING_ATTRIBUTE,
  BANNER_SUFFIX,
  EMBED_SCRIPT,
} from './embed-script.js';

/**
 * The storefront script is the only part of this app a shopper ever meets, and
 * an app review looks at it directly. These are the properties a review will
 * check and a merchant depends on: what the banner says, when it can appear at
 * all, and that it disturbs nothing on the page.
 */

/** Everything the script puts in front of a person, and nothing else. */
const VISIBLE_TEXT = [BANNER_PREFIX, BANNER_SUFFIX, 'Dismiss', 'Dismiss this message'];

describe('the banner wording', () => {
  it('says what was proved, in plain words, with the code that was applied', () => {
    expect(BANNER_PREFIX + 'AVA-1234' + BANNER_SUFFIX).toBe(
      "This AI agent visit was verified. Discount code AVA-1234 was applied by this store's policy.",
    );
  });

  it('carries no app or company name, and no promotion of any kind', () => {
    // App Name Branding in a storefront component is not open to us: the
    // attribution pattern that is allowed is a 24x24 mark, which cannot carry a
    // name in prose. So the banner names the store's policy, never us.
    for (const text of VISIBLE_TEXT) {
      const lowered = text.toLowerCase();
      for (const forbidden of ['ava pay', 'avalayer', 'powered by', 'ava-pay']) {
        expect(lowered, text).not.toContain(forbidden);
      }
    }
  });

  it('offers nothing to click but the dismiss control', () => {
    // No link, no call to action, no review solicitation.
    expect(EMBED_SCRIPT).not.toContain('createElement(\'a\')');
    expect(EMBED_SCRIPT).not.toContain('href=');
    expect(EMBED_SCRIPT.match(/createElement\('button'\)/g)).toHaveLength(1);
  });
});

describe('when the banner can appear', () => {
  it('renders only from a code the verifier already returned', () => {
    // One call site, and it reads the code out of the pending key, which is
    // written in one place and only after `data.allow` and a minted code. That
    // is the whole reachability argument, and it is why this counts.
    expect(EMBED_SCRIPT.match(/showBanner\(/g)).toHaveLength(1);
    expect(EMBED_SCRIPT).toContain('showBanner(pending)');
    expect(EMBED_SCRIPT.match(/store\.set\(PENDING_KEY/g)).toHaveLength(1);
    expect(EMBED_SCRIPT).toContain('if (!data || !data.allow) return;');
    expect(EMBED_SCRIPT).toContain('if (bannerEnabled()) store.set(PENDING_KEY, code);');
  });

  it('has no preview, debug or force parameter of any kind', () => {
    // The only inputs are the signed parameters and the verifier's answer.
    for (const backdoor of ['preview', 'debug', 'force', 'demo=', 'test=']) {
      expect(EMBED_SCRIPT.toLowerCase(), backdoor).not.toContain(backdoor);
    }
  });

  it('obeys the merchant setting the app embed block carries', () => {
    expect(EMBED_SCRIPT).toContain(`script[${BANNER_SETTING_ATTRIBUTE}]`);
    expect(EMBED_SCRIPT).toContain(`getAttribute('${BANNER_SETTING_ATTRIBUTE}') !== 'false'`);
  });

  it('shows at most one, however many times the page loads it', () => {
    expect(EMBED_SCRIPT).toContain('if (window.__avaPayLoaded) return;');
    expect(EMBED_SCRIPT).toContain(`document.getElementById(BANNER_ID)`);
    expect(EMBED_SCRIPT).toContain(`const BANNER_ID = '${BANNER_ELEMENT_ID}'`);
  });
});

describe('how the banner behaves on the page', () => {
  it('announces itself to assistive technology without stealing focus', () => {
    expect(EMBED_SCRIPT).toContain("setAttribute('role', 'status')");
    expect(EMBED_SCRIPT).toContain("setAttribute('aria-live', 'polite')");
    expect(EMBED_SCRIPT).toContain("setAttribute('aria-label', 'Dismiss this message')");
  });

  it('floats above the theme in its own container, so nothing on the page moves', () => {
    expect(EMBED_SCRIPT).toContain('position:fixed');
    expect(EMBED_SCRIPT).toContain('z-index:2147483000');
    expect(EMBED_SCRIPT).toContain('-apple-system,BlinkMacSystemFont');
    // Its own element, appended to the body: it never reaches into the theme.
    expect(EMBED_SCRIPT).toContain('document.body.appendChild(banner)');
    expect(EMBED_SCRIPT).not.toContain('innerHTML');
  });

  it('writes the code as text, never as markup', () => {
    expect(EMBED_SCRIPT).toContain('message.textContent =');
    expect(EMBED_SCRIPT).not.toContain('insertAdjacentHTML');
  });

  it('says nothing on the console, whatever happens', () => {
    // 5.1.2 asks for the widget to work "without any errors", and a merchant
    // debugging their theme should not find our noise in the way.
    expect(EMBED_SCRIPT).not.toContain('console.');
  });

  it('survives a browser that refuses session storage', () => {
    expect(EMBED_SCRIPT).toContain('try { return sessionStorage.getItem(key); } catch');
  });
});

describe('the discount redirect', () => {
  it('takes the signed parameters out of the address bar on the way back', () => {
    // They are single use. Left in place they buy a replay rejection on the
    // next reload and a failure row the merchant has to explain to themselves.
    expect(EMBED_SCRIPT).toContain('encodeURIComponent(cleanTarget())');
    expect(EMBED_SCRIPT).toContain('if (isAgentParam(name.toLowerCase())) params.delete(name);');
  });

  it('applies a code once per session', () => {
    expect(EMBED_SCRIPT).toContain('if (!code || store.get(APPLIED_KEY)) return;');
  });
});
