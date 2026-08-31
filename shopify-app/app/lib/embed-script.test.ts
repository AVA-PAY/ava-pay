import { runInNewContext } from 'node:vm';
import { describe, expect, it, vi } from 'vitest';
import {
  BANNER_ELEMENT_ID,
  BANNER_PREFIX,
  BANNER_RESTORE_LIMIT,
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
    // Its own element, parented above the body: it never reaches into the
    // theme, and the theme's own re-render of the body never reaches it.
    expect(EMBED_SCRIPT).toContain('document.documentElement.appendChild(banner)');
    expect(EMBED_SCRIPT).not.toContain('document.body.appendChild');
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
// Small enough to read, and faithful in the four places the guard depends on:
// what `isConnected` means, where an element is parented, which childList
// changes an observer is told about, and that those callbacks arrive after the
// change rather than during it. The script runs in a node:vm context whose only
// globals are the ones below, so anything it reaches for that is not modelled
// here fails loudly instead of silently, `console` genuinely does not exist in
// it, and neither does any timer: the guard cannot quietly go back to polling.

type Listener = () => void;

class FakeNode {
  readonly tagName: string;
  id = '';
  type = '';
  textContent = '';
  style = { cssText: '' };
  children: FakeNode[] = [];
  parent: FakeNode | null = null;
  /** True for the document element, which is what "in the document" means. */
  attached = false;
  /** Observers watching this node's own child list. */
  readonly watchers = new Set<{ record: () => void }>();

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
    this.notify();
    return child;
  }

  remove(): void {
    const parent = this.parent;
    if (!parent) return;
    parent.children = parent.children.filter((c) => c !== this);
    this.parent = null;
    parent.notify();
  }

  /** A childList change is reported to whoever is watching this parent. */
  private notify(): void {
    for (const watcher of Array.from(this.watchers)) watcher.record();
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

/**
 * A MutationObserver with childList and nothing else, and with the delivery
 * order that matters here: callbacks are queued and run after the change that
 * queued them, never inside it, and a disconnected observer's queued callback
 * never runs. Mutations made from a callback queue further callbacks, which is
 * how a theme and this script can trade removals, so the drain counts its own
 * rounds and fails the test rather than hanging if nothing ever stops.
 */
function createObserverRuntime() {
  const queue: FakeObserver[] = [];
  const connected = new Set<FakeObserver>();

  class FakeObserver {
    private readonly targets: FakeNode[] = [];
    private live = false;
    private queued = false;

    constructor(private readonly callback: () => void) {}

    observe(target: FakeNode, options: { childList?: boolean; subtree?: boolean }): void {
      expect(options.childList, 'only childList is modelled').toBe(true);
      expect(options.subtree, 'a subtree observer would be a different guard').toBeUndefined();
      this.live = true;
      connected.add(this);
      this.targets.push(target);
      target.watchers.add(this);
    }

    disconnect(): void {
      this.live = false;
      this.queued = false;
      connected.delete(this);
      for (const target of this.targets) target.watchers.delete(this);
      this.targets.length = 0;
    }

    record(): void {
      if (!this.live || this.queued) return;
      this.queued = true;
      queue.push(this);
    }

    run(): void {
      this.queued = false;
      if (this.live) this.callback();
    }
  }

  const flush = () => {
    for (let round = 0; queue.length > 0; round++) {
      expect(round, 'the observers never stopped trading removals').toBeLessThan(1000);
      queue.shift()?.run();
    }
  };

  return { FakeObserver, flush, running: () => connected.size };
}

interface Harness {
  documentElement: FakeNode;
  body: FakeNode;
  /** Every element on the page carrying the banner id. */
  banners: () => FakeNode[];
  banner: () => FakeNode | undefined;
  dismiss: () => void;
  /** What a DOM-morphing theme does to an element it did not render. */
  themeSweep: () => void;
  /** What that theme does to the body: everything inside it is replaced. */
  bodySweep: () => void;
  /** Morphing can re-parent as well as remove. */
  moveBannerIntoBody: () => void;
  /** A theme runtime of the test's own, watching the document element. */
  watchDocument: (fn: () => void) => void;
  pageshow: () => void;
  /** Deliver whatever the test's own DOM changes queued. */
  flush: () => void;
  guardsRunning: () => number;
  fetch: ReturnType<typeof vi.fn>;
  session: Map<string, string>;
}

function runEmbed(
  options: { pending?: string; bannerSetting?: string; mutationObserver?: boolean } = {},
): Harness {
  const documentElement = new FakeNode('html');
  documentElement.attached = true;
  const body = documentElement.appendChild(new FakeNode('body'));

  const scriptTag = new FakeNode('script');
  scriptTag.setAttribute(BANNER_SETTING_ATTRIBUTE, options.bannerSetting ?? 'true');

  const session = new Map<string, string>();
  if (options.pending !== undefined) session.set('ava_pay_banner_pending', options.pending);

  const observers = createObserverRuntime();

  const fetchMock = vi.fn(() => {
    throw new Error('the banner path must not call the verifier');
  });

  const windowListeners: Record<string, Listener[]> = {};
  const sandbox: Record<string, unknown> = {
    window: {
      location: { search: '', pathname: '/', href: '/' },
      addEventListener: (type: string, fn: Listener) => {
        (windowListeners[type] ??= []).push(fn);
      },
    },
    document: {
      documentElement,
      body,
      readyState: 'complete',
      createElement: (tag: string) => new FakeNode(tag),
      getElementById: (id: string) =>
        documentElement.descendants().find((n) => n.id === id) ?? null,
      querySelector: (selector: string) =>
        selector === `script[${BANNER_SETTING_ATTRIBUTE}]` ? scriptTag : null,
      addEventListener: () => {},
    },
    sessionStorage: {
      getItem: (key: string) => session.get(key) ?? null,
      setItem: (key: string, value: string) => void session.set(key, String(value)),
      removeItem: (key: string) => void session.delete(key),
    },
    URLSearchParams,
    encodeURIComponent,
    fetch: fetchMock,
  };
  // A browser too old for the guard still has to get the banner itself.
  if (options.mutationObserver !== false) sandbox.MutationObserver = observers.FakeObserver;

  runInNewContext(EMBED_SCRIPT, sandbox);
  observers.flush();

  const banners = () => documentElement.descendants().filter((n) => n.id === BANNER_ELEMENT_ID);
  const act = (change: () => void) => {
    change();
    observers.flush();
  };

  return {
    documentElement,
    body,
    banners,
    banner: () => banners()[0],
    session,
    fetch: fetchMock,
    flush: observers.flush,
    guardsRunning: observers.running,
    // No flush: a click is its own task, and what the click itself does is
    // exactly what these tests are about.
    dismiss: () => {
      const control = banners()[0]?.children.find((c) => c.tagName === 'button');
      expect(control, 'no dismiss control on the banner').toBeDefined();
      control?.dispatch('click');
    },
    // Morphing themes diff their own markup against the live document and drop
    // what they did not render. Ours goes; the theme's own nodes stay.
    themeSweep: () =>
      act(() => {
        for (const node of banners()) node.remove();
      }),
    bodySweep: () =>
      act(() => {
        for (const node of Array.from(body.children)) node.remove();
        body.appendChild(new FakeNode('main'));
      }),
    moveBannerIntoBody: () =>
      act(() => {
        const ours = banners()[0];
        expect(ours, 'no banner to move').toBeDefined();
        if (ours) body.appendChild(ours);
      }),
    watchDocument: (fn: () => void) => {
      const observer = new observers.FakeObserver(fn);
      observer.observe(documentElement, { childList: true });
    },
    pageshow: () =>
      act(() => {
        for (const fn of windowListeners['pageshow'] ?? []) fn();
      }),
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

  it('sits outside the body, where a morphing diff never looks', () => {
    const page = runEmbed({ pending: CODE });

    expect(page.banner()?.parent).toBe(page.documentElement);
  });

  it('is left alone when the theme replaces everything in the body', () => {
    // No guard at all in this browser, so nothing can put the banner back: it
    // survives because of where it is parented, not because it was restored.
    const page = runEmbed({ pending: CODE, mutationObserver: false });
    const original = page.banner();
    expect(page.guardsRunning()).toBe(0);

    page.bodySweep();
    expect(page.banner()).toBe(original);
  });

  it('puts the banner back when the theme reaches it anyway', () => {
    // The bug this fixes: banner appears, theme re-renders, banner gone.
    const page = runEmbed({ pending: CODE });
    const original = page.banner();

    page.themeSweep();
    expect(page.banner()).toBe(original);
  });

  it('keeps putting it back for as long as the page lives', () => {
    // A hot-reload runtime re-renders continuously, not only while it settles.
    // Nothing here advances a clock, because the guard no longer has one: it is
    // still watching at the tenth sweep for the same reason it was at the first.
    const page = runEmbed({ pending: CODE });

    for (let i = 0; i < 10; i++) {
      page.themeSweep();
      expect(page.banner(), `sweep ${i + 1}`).toBeDefined();
    }
    expect(page.guardsRunning()).toBe(1);
  });

  it('sees a removal from the body after the theme moved our element into it', () => {
    // Morphing re-parents as well as removes. Once our element is inside the
    // body, only the body's own child list reports it going: the document
    // element saw it leave already, with the element still connected.
    const page = runEmbed({ pending: CODE });
    const ours = page.banner();

    page.moveBannerIntoBody();
    expect(page.banner()).toBe(ours);
    expect(ours?.parent).toBe(page.body);

    page.bodySweep();
    expect(page.banner()).toBe(ours);
    expect(ours?.parent).toBe(page.documentElement);
  });

  it('never leaves two banners on the page', () => {
    const page = runEmbed({ pending: CODE });

    page.themeSweep();
    page.themeSweep();
    expect(page.banners()).toHaveLength(1);
  });

  it('leaves a copy the theme made of it alone', () => {
    // Morphing can also clone a node rather than drop it. One element carrying
    // the id is a banner on the page, whoever put it there.
    const page = runEmbed({ pending: CODE });
    const ours = page.banner();

    const copy = new FakeNode('div');
    copy.id = BANNER_ELEMENT_ID;
    page.body.appendChild(copy);
    ours?.remove();
    page.flush();

    expect(page.banners()).toEqual([copy]);
  });

  it('stops trading removals with a theme that will not have it', () => {
    // The pathological case the cap exists for: a runtime that removes the
    // banner every time it appears. We answer a bounded number of times and
    // then concede the page rather than loop on it for as long as it is open.
    const page = runEmbed({ pending: CODE });
    let removals = 0;
    page.watchDocument(() => {
      for (const node of page.banners()) {
        node.remove();
        removals += 1;
      }
    });

    page.themeSweep();

    expect(removals).toBe(BANNER_RESTORE_LIMIT);
    expect(page.banner()).toBeUndefined();
    expect(page.guardsRunning()).toBe(1); // the test's runtime, not ours
  });
});

describe('dismissing the banner', () => {
  it('takes it off the page', () => {
    const page = runEmbed({ pending: CODE });
    page.dismiss();

    expect(page.banner()).toBeUndefined();
  });

  it('disconnects the guard in the click itself, not on some later delivery', () => {
    // Nothing is delivered between the click and the assertion: dismissing
    // leaves nothing of ours watching the page at all.
    const page = runEmbed({ pending: CODE });
    expect(page.guardsRunning()).toBe(1);

    page.dismiss();
    expect(page.guardsRunning()).toBe(0);
  });

  it('stops the guard putting it back, however long the page stays open', () => {
    const page = runEmbed({ pending: CODE });
    page.dismiss();

    page.themeSweep();
    page.bodySweep();
    expect(page.banner()).toBeUndefined();
    expect(page.guardsRunning()).toBe(0);
  });

  it('survives a page restore, which must not resurrect it', () => {
    const page = runEmbed({ pending: CODE });
    page.dismiss();

    page.pageshow();
    expect(page.banner()).toBeUndefined();
    expect(page.guardsRunning()).toBe(0);
  });
});

describe('a page restored from the back/forward cache', () => {
  it('shows the banner again from the code it was already holding', () => {
    // Nothing in the script runs again on a restore, and the pending key was
    // cleared when it was used, so the held code is the only thing left. The
    // browser here has no observer, so the restore is doing all of the work.
    const page = runEmbed({ pending: CODE, mutationObserver: false });
    page.themeSweep();
    expect(page.banner()).toBeUndefined();

    page.pageshow();
    expect(page.banner()?.children[0]?.textContent).toBe(BANNER_PREFIX + CODE + BANNER_SUFFIX);
    expect(page.banner()?.parent).toBe(page.documentElement);
    expect(page.fetch).not.toHaveBeenCalled();
  });

  it('adds nothing when the restored page still has it', () => {
    const page = runEmbed({ pending: CODE });

    page.pageshow();
    expect(page.banners()).toHaveLength(1);
    expect(page.guardsRunning()).toBe(1);
  });
});

describe('a page with no verdict to report', () => {
  it('shows nothing and starts no guard', () => {
    const page = runEmbed();

    expect(page.banner()).toBeUndefined();
    expect(page.guardsRunning()).toBe(0);
    expect(page.fetch).not.toHaveBeenCalled();
  });

  it('shows nothing when the merchant switched the banner off', () => {
    const page = runEmbed({ pending: CODE, bannerSetting: 'false' });

    expect(page.banner()).toBeUndefined();
    expect(page.guardsRunning()).toBe(0);
  });
});
