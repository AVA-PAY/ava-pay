import { describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  extractReasonsFromText,
  extractReasons,
  extractInterfacePropertiesFromText,
  findInterfaceDrift,
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

/**
 * The interface half of the guardrail, which VerificationFailureReason had and the mirrored
 * interfaces did not. A field added to one file's OperatorRecord and forgotten in the other compiles
 * cleanly in both and silently means two different things to two consumers of the same JSON.
 */
describe('mirrored interface extraction', () => {
  const SOURCE = `
    /** A doc comment with a ; semicolon and a 'quoted' word, to make sure neither is read as a field. */
    export interface OperatorRecord {
      origin: string;
      operator: string;
      /** optional; note the semicolon in this comment */
      abuseContact?: string;
      network?: OperatorNetworkBlock;
    }
    export interface Unrelated { ignored: string }
  `;

  it('reads every declared property and nothing from the comments', () => {
    expect(extractInterfacePropertiesFromText(SOURCE, 'sample.ts', 'OperatorRecord'))
      .toEqual(['abuseContact?', 'network?', 'operator', 'origin']);
  });

  it('records optionality as part of the shape', () => {
    // One file making a field required while the other leaves it optional is drift: a consumer of the
    // stricter copy will assume a value is always present.
    const required = SOURCE.replace('abuseContact?:', 'abuseContact:');
    expect(extractInterfacePropertiesFromText(required, 'sample.ts', 'OperatorRecord'))
      .toContain('abuseContact');
    expect(extractInterfacePropertiesFromText(required, 'sample.ts', 'OperatorRecord'))
      .not.toContain('abuseContact?');
  });

  it('throws rather than silently passing when the interface is not there at all', () => {
    // The failure mode of the reader this replaced: an empty result read as "in sync".
    expect(() => extractInterfacePropertiesFromText(SOURCE, 'sample.ts', 'NotDeclared'))
      .toThrow(/NotDeclared not found/);
  });

  it('is order-insensitive, because declaration order is not part of the contract', () => {
    const reordered = `export interface OperatorRecord {
      operator: string; origin: string; network?: OperatorNetworkBlock; abuseContact?: string;
    }`;
    expect(extractInterfacePropertiesFromText(reordered, 'sample.ts', 'OperatorRecord'))
      .toEqual(extractInterfacePropertiesFromText(SOURCE, 'sample.ts', 'OperatorRecord'));
  });
});

/**
 * The function that actually decides pass or fail. Extraction was tested and this was not, which is
 * the more important half: a reader of the suite would conclude drift is caught when only the reading
 * of the interface had ever been exercised.
 *
 * These write real files, because findInterfaceDrift resolves paths relative to the repo root, and a
 * test that stubbed that away would be testing the stub.
 */
describe('findInterfaceDrift', () => {
  const RECORD = (extra: string) => `export interface OperatorRecord {
  origin: string;
  operator: string;${extra}
}
export interface OperatorNetworkBlock {
  organisation?: string;
}
`;

  /**
   * Write two twins to a temp dir and report the drift between them.
   *
   * Absolute paths, because `resolve(ROOT, '/abs/path')` returns the absolute path unchanged, so
   * findInterfaceDrift already accepts them. Nothing is written inside the repo.
   */
  function driftBetween(a: string, b: string): string[] {
    const dir = mkdtempSync(join(tmpdir(), 'type-sync-'));
    try {
      const twinA = join(dir, 'twinA.ts');
      const twinB = join(dir, 'twinB.ts');
      writeFileSync(twinA, a);
      writeFileSync(twinB, b);
      // No floors: these fixtures exercise the cross-file compare, not the completeness ratchet.
      return findInterfaceDrift([twinA, twinB], {}).map((problem) => problem.message);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it('reports nothing when the twins agree', () => {
    expect(driftBetween(RECORD('\n  network?: OperatorNetworkBlock;'),
      RECORD('\n  network?: OperatorNetworkBlock;'))).toEqual([]);
  });

  it('names the field and the file when one twin gains a field', () => {
    // The exact defect this exists for: a field added to the SDK copy and forgotten in the app copy
    // compiles cleanly in both and silently means two different things to two consumers of one JSON.
    const messages = driftBetween(RECORD('\n  addedHere?: string;'), RECORD(''));
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain('OperatorRecord drifted');
    expect(messages[0]).toContain('addedHere?');
    expect(messages[0]).toContain('twinA.ts');
  });

  it('reports drift in BOTH directions, not just additions to the first file', () => {
    const messages = driftBetween(RECORD(''), RECORD('\n  onlyInB?: string;'));
    expect(messages[0]).toContain('onlyInB?');
  });

  it('treats a field made required in one twin as drift', () => {
    // Optionality is part of the shape: a consumer of the stricter copy assumes a value is always
    // there. Same name, different contract, so it has to fail.
    const messages = driftBetween(RECORD('\n  maybe?: string;'), RECORD('\n  maybe: string;'));
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/maybe\?|maybe/);
  });

  it('checks EVERY mirrored interface, not only the first', () => {
    const a = RECORD('') + 'export interface Extra { x: string }\n';
    const b = RECORD('').replace('  organisation?: string;', '  organisation?: string;\n  drifted?: string;');
    const messages = driftBetween(a, b);
    expect(messages.some((m) => m.includes('OperatorNetworkBlock drifted'))).toBe(true);
  });
});

/**
 * The floor, which answers the question the cross-file compare cannot.
 *
 * Agreement is strictly weaker than completeness: a field dropped from both twins in one edit leaves
 * them in perfect agreement. That is also the LIKELY failure, because the same person edits both copies
 * in the same sitting with the same misunderstanding, and it happened once already, with the checker
 * reporting "in sync" while three fields were missing from both.
 */
describe('the mirrored-interface floor', () => {
  const RECORD = (fields: readonly string[]) => `export interface OperatorRecord {
${fields.map((f) => `  ${f}`).join('\n')}
}
export interface OperatorNetworkBlock {
${Array.from({ length: 10 }, (_, i) => `  f${i}?: string;`).join('\n')}
}
`;
  const SIXTEEN = Array.from({ length: 16 }, (_, i) => `f${i}?: string;`);

  function problemsFor(a: string, b: string): string[] {
    const dir = mkdtempSync(join(tmpdir(), 'type-floor-'));
    try {
      const twinA = join(dir, 'a.ts');
      const twinB = join(dir, 'b.ts');
      writeFileSync(twinA, a);
      writeFileSync(twinB, b);
      return findInterfaceDrift([twinA, twinB], { OperatorRecord: 16, OperatorNetworkBlock: 10 })
        .map((p) => p.message);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it('passes when both twins carry the full set', () => {
    const full = RECORD(SIXTEEN);
    expect(problemsFor(full, full)).toEqual([]);
  });

  it('fails when a field is dropped from BOTH twins, which agreement alone cannot catch', () => {
    const short = RECORD(SIXTEEN.slice(0, 15));
    const problems = problemsFor(short, short);
    // Both copies agree perfectly, so the drift half is silent. Only the floor speaks.
    expect(problems.filter((m) => m.includes('drifted'))).toEqual([]);
    expect(problems.some((m) => m.includes('below the floor of 16'))).toBe(true);
    // Named per file, so an operator knows which copy to look at even when both are short.
    expect(problems.filter((m) => m.includes('below the floor'))).toHaveLength(2);
  });

  it('says what to do when the removal was deliberate', () => {
    const short = RECORD(SIXTEEN.slice(0, 15));
    expect(problemsFor(short, short).find((m) => m.includes('below the floor')))
      .toContain('Raise the floor deliberately if the removal is intended');
  });
});
