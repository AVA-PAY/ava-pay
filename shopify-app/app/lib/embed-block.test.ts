import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { BANNER_SETTING_ATTRIBUTE } from './embed-script.js';

/**
 * The app embed block is the half of the storefront widget an app review sees
 * in the theme editor. Two things about it have to hold no matter what anyone
 * edits later: the sample banner cannot escape design mode onto a real
 * storefront, and it cannot carry our name in front of a shopper.
 *
 * Asserted against the liquid source, because there is no way to render a theme
 * app extension in a unit test and the properties are structural anyway.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const BLOCK = readFileSync(
  join(HERE, '..', '..', 'extensions', 'ava-pay-embed', 'blocks', 'ava-pay-embed.liquid'),
  'utf-8',
);

const schema = (): { name: string; target: string; settings: Array<Record<string, unknown>> } =>
  JSON.parse(BLOCK.split('{% schema %}')[1]!.split('{% endschema %}')[0]!);

/** The markup between {% if request.design_mode %} and its {% endif %}. */
function designModeMarkup(): string {
  const opened = BLOCK.indexOf('{% if request.design_mode %}');
  expect(opened).toBeGreaterThan(-1);
  const closed = BLOCK.lastIndexOf('{% endif %}');
  expect(closed).toBeGreaterThan(opened);
  return BLOCK.slice(opened, closed);
}

describe('the app embed block', () => {
  it('renders into the body, because it renders visible markup', () => {
    // A head-targeted block that emits an element closes the document head
    // early and pushes the theme's own head content into the body.
    expect(schema().target).toBe('body');
  });

  it('loads the storefront script through the app proxy, asynchronously', () => {
    expect(BLOCK).toContain('src="{{ shop.url }}/apps/ava-pay/embed.js"');
    expect(BLOCK).toContain('async');
  });

  it('hands the merchant banner setting to the script', () => {
    const checkbox = schema().settings.find((s) => s.id === 'banner_enabled');
    expect(checkbox?.type).toBe('checkbox');
    expect(checkbox?.default).toBe(true);
    expect(BLOCK).toContain(`${BANNER_SETTING_ATTRIBUTE}="{% if block.settings.banner_enabled %}`);
  });

  it('keeps its settings down to the one a merchant has a decision to make about', () => {
    const settable = schema().settings.filter((s) => s.type !== 'paragraph');
    expect(settable).toHaveLength(1);
  });
});

describe('the theme editor preview', () => {
  it('exists, so switching the embed on visibly changes the editor preview', () => {
    expect(designModeMarkup()).toContain('This AI agent visit was verified.');
    expect(designModeMarkup()).toContain('Preview:');
  });

  it('is the only markup in the file that is not the script tag', () => {
    // Everything a shopper could see has to be inside the design_mode guard.
    // request.design_mode is false on every live storefront page, so this is
    // what makes the sample unreachable from the online store.
    const outsideDesignMode = BLOCK.replace(designModeMarkup(), '');
    expect(outsideDesignMode).not.toContain('<div');
    expect(outsideDesignMode).not.toContain('<span');
  });

  it('is pure liquid, with no script of its own', () => {
    expect(designModeMarkup()).not.toContain('<script');
    expect(designModeMarkup()).not.toContain('javascript:');
  });

  it('carries no app or company name, the same as the real banner', () => {
    const lowered = designModeMarkup().toLowerCase();
    for (const forbidden of ['ava pay', 'avalayer', 'powered by']) {
      expect(lowered, forbidden).not.toContain(forbidden);
    }
  });

  it('shows an obviously fake code, so nobody reads it as one to use', () => {
    expect(designModeMarkup()).toContain('SAMPLE-1234');
    // Not the AVA- prefix real codes carry, which would be both a live-looking
    // code and our name in front of a shopper.
    expect(designModeMarkup()).not.toContain('AVA-');
  });

  it('still explains itself when the merchant has switched the banner off', () => {
    expect(designModeMarkup()).toContain('{% else %}');
    expect(designModeMarkup()).toContain('switched off');
  });
});
