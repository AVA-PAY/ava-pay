import { describe, expect, it } from 'vitest';
import { findAvaDiscountCode, hasVerifiedNoteAttribute, toMinorUnits } from './commerce.js';

describe('findAvaDiscountCode', () => {
  it('returns the first AVA-prefixed code', () => {
    expect(
      findAvaDiscountCode([{ code: 'SUMMER10' }, { code: 'AVA-ABCD2345' }, { code: 'AVA-ZZZZ9999' }]),
    ).toBe('AVA-ABCD2345');
  });

  it('returns null when no AVA code is present', () => {
    expect(findAvaDiscountCode([{ code: 'SUMMER10' }])).toBeNull();
    expect(findAvaDiscountCode([])).toBeNull();
    expect(findAvaDiscountCode(undefined)).toBeNull();
  });

  it('ignores malformed entries', () => {
    expect(findAvaDiscountCode([{}, { code: undefined }, { code: 'AVA-OK' }])).toBe('AVA-OK');
  });
});

describe('hasVerifiedNoteAttribute', () => {
  it('detects the ava_pay_verified attribute', () => {
    expect(hasVerifiedNoteAttribute([{ name: 'ava_pay_verified', value: 'true' }])).toBe(true);
  });
  it('rejects other values and missing attrs', () => {
    expect(hasVerifiedNoteAttribute([{ name: 'ava_pay_verified', value: 'false' }])).toBe(false);
    expect(hasVerifiedNoteAttribute([])).toBe(false);
    expect(hasVerifiedNoteAttribute(undefined)).toBe(false);
  });
});

describe('toMinorUnits', () => {
  it('converts Shopify decimal strings to cents', () => {
    expect(toMinorUnits('123.45')).toBe(12_345);
    expect(toMinorUnits('0.10')).toBe(10);
    expect(toMinorUnits('1000')).toBe(100_000);
  });
  it('handles numbers and rounds fractional cents', () => {
    expect(toMinorUnits(19.999)).toBe(2_000);
  });
  it('returns null for absent or malformed values (never NaN)', () => {
    expect(toMinorUnits(undefined)).toBeNull();
    expect(toMinorUnits(null)).toBeNull();
    expect(toMinorUnits('')).toBeNull();
    expect(toMinorUnits('not-a-price')).toBeNull();
  });
});
