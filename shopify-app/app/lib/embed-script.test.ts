import { runInNewContext } from 'node:vm';
import { describe, expect, it, vi } from 'vitest';
import {
  BANNER_ELEMENT_ID,
  BANNER_GUARD_INTERVAL_MS,
  BANNER_GUARD_WINDOW_MS,
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
    // Two call sites, and both replay one verdict. The pending key is written
    // in one place, after `data.allow` and a minted code; `bannerCode` is
    // assigned in one place, inside showBanner, from the argument it was
    // handed. So the restore path can only re-show a code that came through
    // the first path, and nothing re-reads storage to find one.
    expect(EMBED_SCRIPT.match(/showBanner\(/g)).toHaveLength(2);
    expect(EMBED_SCRIPT).toContain('showBanner(pending)');
    expect(EMBED_SCRIPT).toContain('showBanner(bannerCode)');
    expect(EMBED_SCRIPT.match(/^\s*bannerCode = /gm)).toHaveLength(1);
    expect(EMBED_SCRIPT).toContain('bannerCode = code;');
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

// ── A DOM to run the script in ────────────────────────────────────────────
//
// Small enough to read, and faithful in the two places the guard depends on:
// what `isConnected` means, and when an interval fires. The script runs in a
// node:vm context whose only globals are the ones below, so anything it
// reaches for that is not modelled here fails loudly instead of silently, and
// `console` genuinely does not exist in it.

type Listener = () => void;

class FakeNode {
  readonly tagName: string;
  id = '';
  type = '';
  textContent = '';
  style = { cssText: '' };
  children: FakeNode[] = [];
  parent: FakeNode | null = null;
  /** True for the body, which is what "in the document" means here. */
  attached = false;

  private readonly attrs: Record<string, string> = {};
  private readonly listeners: Record<string, Listener[]> = {};

  constructor(tagName: string) {
    this.tagName = tagName;
  }

  get isConnected(): boolean {
    let node: FakeNode = this;
    while (node.parent) node = node.parent;
    return node.attached;
  }

  appendChild(child: FakeNode): FakeNode {
    child.remove();
    child.parent = this;
    this.children.push(child);
    return child;
  }

  remove(): void {
    if (!this.parent) return;
    this.parent.children = this.parent.children.filter((c) => c !== this);
    this.parent = null;
  }

  setAttribute(name: string, value: string): void {
    this.attrs[name] = value;
  }

  getAttribute(name: string): string | null {
    return this.attrs[name] ?? null;
  }

  addEventListener(type: string, fn: Listener): void {
    (this.listeners[type] ??= []).push(fn);
  }

  dispatch(type: string): void {
    for (const fn of this.listeners[type] ?? []) fn();
  }

  descendants(): FakeNode[] {
    return this.children.flatMap((c) => [c, ...c.descendants()]);
  }
}

interface Timer {
  fn: () => void;
  every: number;
  due: number;
}

interface Harness {
  body: FakeNode;
  /** Every element on the page carrying the banner id. */
  banners: () => FakeNode[];
  banner: () => FakeNode | undefined;
  dismiss: () => void;
  /** What a DOM-morphing theme does to an element it did not render. */
  themeSweep: () => void;
  pageshow: () => void;
  advance: (ms: number) => void;
  timersRunning: () => number;
  fetch: ReturnType<typeof vi.fn>;
  session: Map<string, string>;
}

function runEmbed(options: { pending?: string; bannerSetting?: string } = {}): Harness {
  const body = new FakeNode('body');
  body.attached = true;

  const scriptTag = new FakeNode('script');
  scriptTag.setAttribute(BANNER_SETTING_ATTRIBUTE, options.bannerSetting ?? 'true');

  const session = new Map<string, string>();
  if (options.pending !== undefined) session.set('ava_pay_banner_pending', options.pending);

  let clock = 0;
  let nextId = 1;
  const timers = new Map<number, Timer>();

  const fetchMock = vi.fn(() => {
    throw new Error('the banner path must not call the verifier');
  });

  const windowListeners: Record<string, Listener[]> = {};
  const sandbox = {
    window: {
      location: { search: '', pathname: '/', href: '/' },
      addEventListener: (type: string, fn: Listener) => {
        (windowListeners[type] ??= []).push(fn);
      },
    },
    document: {
      body,
      readyState: 'complete',
      createElement: (tag: string) => new FakeNode(tag),
      getElementById: (id: string) => body.descendants().find((n) => n.id === id) ?? null,
      querySelector: (selector: string) =>
        selector === `script[${BANNER_SETTING_ATTRIBUTE}]` ? scriptTag : null,
      addEventListener: () => {},
    },
    sessionStorage: {
      getItem: (key: string) => session.get(key) ?? null,
      setItem: (key: string, value: string) => void session.set(key, String(value)),
      removeItem: (key: string) => void session.delete(key),
    },
    setInterval: (fn: () => void, every: number) => {
      const id = nextId++;
      timers.set(id, { fn, every, due: clock + every });
      return id;
    },
    clearInterval: (id: number) => void timers.delete(id),
    URLSearchParams,
    encodeURIComponent,
    fetch: fetchMock,
  };

  runInNewContext(EMBED_SCRIPT, sandbox);

  const banners = () => body.descendants().filter((n) => n.id === BANNER_ELEMENT_ID);

  return {
    body,
    banners,
    banner: () => banners()[0],
    session,
    fetch: fetchMock,
    dismiss: () => {
      const control = banners()[0]?.children.find((c) => c.tagName === 'button');
      expect(control, 'no dismiss control on the banner').toBeDefined();
      control?.dispatch('click');
    },
    // Morphing themes diff the server's markup against the live document and
    // drop what they did not render. Ours goes; the theme's own nodes stay.
    themeSweep: () => {
      for (const node of banners()) node.remove();
    },
    pageshow: () => {
      for (const fn of windowListeners['pageshow'] ?? []) fn();
    },
    timersRunning: () => timers.size,
    advance: (ms: number) => {
      const target = clock + ms;
      for (;;) {
        let due: [number, Timer] | undefined;
        for (const entry of timers) if (!due || entry[1].due < due[1].due) due = entry;
        if (!due || due[1].due > target) break;
        clock = due[1].due;
        due[1].due = clock + due[1].every;
        due[1].fn();
      }
      clock = target;
    },
  };
}

const CODE = 'AVA-7Q2M4X';

describe('surviving a theme that re-renders the page', () => {
  it('shows the banner as soon as the discount redirect lands', () => {
    const page = runEmbed({ pending: CODE });

    expect(page.banner()).toBeDefined();
    expect(page.banner()?.children[0]?.textContent).toBe(BANNER_PREFIX + CODE + BANNER_SUFFIX);
    // The verdict already happened on the load before this one.
    expect(page.fetch).not.toHaveBeenCalled();
    expect(page.session.has('ava_pay_banner_pending')).toBe(false);
  });

  it('puts the banner back when the theme sweeps it out', () => {
    // The bug this fixes: banner appears, theme hydrates, banner gone.
    const page = runEmbed({ pending: CODE });
    const original = page.banner();

    page.themeSweep();
    expect(page.banner()).toBeUndefined();

    page.advance(BANNER_GUARD_INTERVAL_MS);
    expect(page.banner()).toBe(original);
  });

  it('keeps putting it back for as long as the guard runs', () => {
    // A theme can re-render more than once while it settles.
    const page = runEmbed({ pending: CODE });

    for (let i = 0; i < 5; i++) {
      page.themeSweep();
      page.advance(BANNER_GUARD_INTERVAL_MS);
      expect(page.banner(), `sweep ${i + 1}`).toBeDefined();
    }
  });

  it('never leaves two banners on the page', () => {
    const page = runEmbed({ pending: CODE });

    page.advance(BANNER_GUARD_INTERVAL_MS * 4);
    expect(page.banners()).toHaveLength(1);
  });

  it('leaves a copy the theme made of it alone', () => {
    // Morphing can also clone a node rather than drop it. One banner carrying
    // the id is a banner on the page, whoever put it there.
    const page = runEmbed({ pending: CODE });
    const ours = page.banner();

    const copy = new FakeNode('div');
    copy.id = BANNER_ELEMENT_ID;
    page.body.appendChild(copy);
    ours?.remove();

    page.advance(BANNER_GUARD_INTERVAL_MS);
    expect(page.banners()).toEqual([copy]);
  });
});

describe('dismissing the banner', () => {
  it('takes it off the page', () => {
    const page = runEmbed({ pending: CODE });
    page.dismiss();

    expect(page.banner()).toBeUndefined();
  });

  it('stops the guard there and then, not on its next tick', () => {
    // No clock advance between the click and the assertion: dismissing leaves
    // nothing of ours running on the page at all.
    const page = runEmbed({ pending: CODE });
    expect(page.timersRunning()).toBe(1);

    page.dismiss();
    expect(page.timersRunning()).toBe(0);
  });

  it('stops the guard putting it back', () => {
    const page = runEmbed({ pending: CODE });
    page.dismiss();

    page.advance(BANNER_GUARD_WINDOW_MS * 2);
    expect(page.banner()).toBeUndefined();
    expect(page.timersRunning()).toBe(0);
  });

  it('survives a page restore, which must not resurrect it', () => {
    const page = runEmbed({ pending: CODE });
    page.dismiss();

    page.pageshow();
    expect(page.banner()).toBeUndefined();
  });
});

describe('the guard window', () => {
  it('stops on its own, and leaves the page alone afterwards', () => {
    // Hydration settles in the first second or two. A guard that ran forever
    // would be a script fighting the theme rather than recovering from it.
    const page = runEmbed({ pending: CODE });

    page.advance(BANNER_GUARD_WINDOW_MS + BANNER_GUARD_INTERVAL_MS);
    expect(page.timersRunning()).toBe(0);

    page.themeSweep();
    page.advance(BANNER_GUARD_WINDOW_MS);
    expect(page.banner()).toBeUndefined();
  });

  it('is still watching part way through', () => {
    const page = runEmbed({ pending: CODE });

    page.advance(BANNER_GUARD_WINDOW_MS / 2);
    page.themeSweep();
    page.advance(BANNER_GUARD_INTERVAL_MS);
    expect(page.banner()).toBeDefined();
  });
});

describe('a page restored from the back/forward cache', () => {
  it('shows the banner again from the code it was already holding', () => {
    // Nothing in the script runs again on a restore, and the pending key was
    // cleared when it was used, so the held code is the only thing left.
    const page = runEmbed({ pending: CODE });
    page.advance(BANNER_GUARD_WINDOW_MS + BANNER_GUARD_INTERVAL_MS);
    page.themeSweep();

    page.pageshow();
    expect(page.banner()?.children[0]?.textContent).toBe(BANNER_PREFIX + CODE + BANNER_SUFFIX);
    expect(page.fetch).not.toHaveBeenCalled();
  });

  it('adds nothing when the restored page still has it', () => {
    const page = runEmbed({ pending: CODE });

    page.pageshow();
    expect(page.banners()).toHaveLength(1);
  });
});

describe('a page with no verdict to report', () => {
  it('shows nothing and starts no guard', () => {
    const page = runEmbed();

    expect(page.banner()).toBeUndefined();
    expect(page.timersRunning()).toBe(0);
    expect(page.fetch).not.toHaveBeenCalled();
  });

  it('shows nothing when the merchant switched the banner off', () => {
    const page = runEmbed({ pending: CODE, bannerSetting: 'false' });

    expect(page.banner()).toBeUndefined();
    expect(page.timersRunning()).toBe(0);
  });
});
