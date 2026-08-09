import { describe, expect, it } from 'vitest';
import {
  extractReasonsFromText,
  extractReasons,
  findSyncProblems,
  MIN_REASONS,
  type Section,
} from '../scripts/check-type-sync.js';

/**
 * Regression tests for the type-sync guardrail itself. The bug these pin down:
 * the old regex reader truncated the union at the first ";" it saw, including
 * one inside a comment, and captured quoted words from comments as phantom
 * reasons. Because both mirrored files carried the same comment, the two
 * truncated lists still matched and the checker reported "in sync" (the real
 * count fell 31 -> 9 unnoticed).
 */
describe('check-type-sync extraction (AST based)', () => {
  it('captures every union member even when a comment holds a semicolon and a quoted word', () => {
    // The comment below contains a ";", an unpaired apostrophe, and a 'quoted'
    // token. A regex slice would stop at the ";" (dropping gamma/delta) and
    // capture 'quoted' as a reason. The AST walk does neither.
    const fixture = `
export type VerificationFailureReason =
  | 'alpha'
  | 'beta'
  // Reachable but not listed; this comment's 'quoted' word must be ignored.
  | 'gamma'
  | 'delta';
`;
    expect(extractReasonsFromText(fixture, 'fixture.ts')).toEqual([
      'alpha',
      'beta',
      'delta',
      'gamma',
    ]);
  });

  it('throws when the type alias is absent instead of silently returning nothing', () => {
    expect(() => extractReasonsFromText('export type Other = string;', 'x.ts')).toThrow(
      /VerificationFailureReason type alias not found/,
    );
  });
});

describe('check-type-sync problem detection', () => {
  it('flags a synchronized truncation via the floor even when both files match (the 31 -> 9 case)', () => {
    // Both files agree, so the cross-file compare sees nothing wrong. The floor
    // is the only thing that catches it. This is the exact failure the old
    // checker missed.
    const truncated = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i']; // 9, matching
    const sections: Section[] = [
      { file: 'a.ts', reasons: truncated },
      { file: 'b.ts', reasons: truncated },
    ];
    const problems = findSyncProblems(sections, 31);
    expect(problems.some((p) => p.kind === 'floor')).toBe(true);
    // Both files are below the floor, so both are reported.
    expect(problems.filter((p) => p.kind === 'floor')).toHaveLength(2);
    expect(problems.some((p) => p.kind === 'drift')).toBe(false);
  });

  it('flags cross-file drift with the offending reason named', () => {
    const above = (extra: string[]) =>
      Array.from({ length: 31 }, (_, i) => `r${i}`).concat(extra);
    const sections: Section[] = [
      { file: 'a.ts', reasons: above(['only_in_a']).sort() },
      { file: 'b.ts', reasons: above([]).sort() },
    ];
    const problems = findSyncProblems(sections, 31);
    const drift = problems.find((p) => p.kind === 'drift');
    expect(drift).toBeDefined();
    expect(drift!.message).toContain('only_in_a');
  });

  it('returns no problems when both files agree and clear the floor', () => {
    const reasons = Array.from({ length: 31 }, (_, i) => `r${i}`).sort();
    const sections: Section[] = [
      { file: 'a.ts', reasons },
      { file: 'b.ts', reasons },
    ];
    expect(findSyncProblems(sections, 31)).toEqual([]);
  });
});

describe('check-type-sync against the real contract files', () => {
  it('extracts identical unions from both mirrored files, at or above the floor', () => {
    const api = extractReasons('packages/agent-sdk/src/types.ts');
    const shopify = extractReasons('shopify-app/app/lib/ava-types.ts');
    expect(api).toEqual(shopify);
    expect(api.length).toBeGreaterThanOrEqual(MIN_REASONS);
    // directory_unavailable (step 2) is present in the live contract.
    expect(api).toContain('directory_unavailable');
  });
});
