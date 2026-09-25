import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  COULD_NOT_CHECK_REASONS,
  REASON_CONCLUSIVE,
  rejection,
  type VerificationFailureReason,
} from '../src/types.js';
import { REASON_CONCLUSIVE as SHOPIFY_REASON_CONCLUSIVE } from '../shopify-app/app/lib/ava-types.js';
import {
  extractConclusiveTable,
  extractConclusiveTableFromText,
  extractReasons,
  findSyncProblems,
  type Section,
} from '../scripts/check-type-sync.js';

/**
 * The outcome/reason pairing is enforced, not maintained by hand. A reason's
 * conclusive flag is whatever REASON_CONCLUSIVE says, every verifier builds
 * its failures through rejection(), and check:type-sync reads the table.
 */

const SDK_TYPES = 'packages/agent-sdk/src/types.ts';

describe('REASON_CONCLUSIVE', () => {
  it('lists every member of the reason union exactly once', () => {
    const union = extractReasons(SDK_TYPES);
    const entries = extractConclusiveTable(SDK_TYPES);
    expect(entries.map(([key]) => key).sort()).toEqual(union);
    expect(new Set(entries.map(([key]) => key)).size).toBe(entries.length);
    // And the runtime object is the table the source declares.
    expect(Object.keys(REASON_CONCLUSIVE).sort()).toEqual(union);
  });

  it('names exactly the could-not-check reasons', () => {
    expect([...COULD_NOT_CHECK_REASONS].sort()).toEqual([
      'directory_unavailable',
      'key_directory_redirected',
      'key_directory_unavailable',
      'key_directory_unsupported_media_type',
    ]);
  });

  it('is mirrored value for value in the Shopify types', () => {
    expect(SHOPIFY_REASON_CONCLUSIVE).toEqual(REASON_CONCLUSIVE);
  });
});

describe('rejection()', () => {
  it('emits the table flag for every reason, with trusted false', () => {
    for (const reason of Object.keys(REASON_CONCLUSIVE) as VerificationFailureReason[]) {
      expect(rejection(reason, 'm')).toEqual({
        trusted: false,
        reason,
        message: 'm',
        conclusive: REASON_CONCLUSIVE[reason],
      });
    }
  });

  it('never reports a reason the table does not know as a definite rejection', () => {
    const result = rejection('not_a_reason' as VerificationFailureReason, 'm');
    expect(result.trusted).toBe(false);
    expect(result.conclusive).toBe(false);
  });
});

describe('verifiers build failures only through rejection()', () => {
  // A trusted:false literal, or a conclusive argument, would be a second place
  // the outcome is decided. This keeps the table the only one.
  const dir = resolve(import.meta.dirname, '../src/verifier');
  const files = readdirSync(dir).filter((f) => f.endsWith('.ts'));

  it.each(files)('%s constructs no trusted:false object by hand', (file) => {
    const code = stripComments(readFileSync(resolve(dir, file), 'utf-8'));
    expect(code).not.toMatch(/trusted:\s*false/);
    expect(code).not.toMatch(/conclusive\s*=\s*(true|false)/);
    expect(code).not.toMatch(/conclusive:\s*false/);
  });
});

describe('check:type-sync table checks', () => {
  const union = ['a_reason', 'b_reason', 'c_reason'];
  const table = (entries: Array<[string, boolean]>): Section => ({ file: 'x.ts', reasons: union, table: entries });

  it('passes a complete table', () => {
    const complete = table([['a_reason', true], ['b_reason', false], ['c_reason', true]]);
    expect(findSyncProblems([complete, { ...complete, file: 'y.ts' }], 3)).toEqual([]);
  });

  it('flags a reason added to the union with no table entry (the silent-default case)', () => {
    const problems = findSyncProblems([table([['a_reason', true], ['b_reason', false]])], 3);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatchObject({ kind: 'table' });
    expect(problems[0]!.message).toContain('Missing: c_reason');
  });

  it('flags a duplicated entry and an entry outside the union', () => {
    const problems = findSyncProblems(
      [table([['a_reason', true], ['a_reason', true], ['b_reason', false], ['c_reason', true], ['z_reason', true]])],
      3,
    );
    expect(problems[0]!.message).toContain('Listed more than once: a_reason');
    expect(problems[0]!.message).toContain('Not in the union: z_reason');
  });

  it('flags the two files disagreeing about an outcome', () => {
    const sdk = table([['a_reason', true], ['b_reason', false], ['c_reason', true]]);
    const mirror: Section = { ...sdk, file: 'y.ts', table: [['a_reason', true], ['b_reason', true], ['c_reason', true]] };
    const problems = findSyncProblems([sdk, mirror], 3);
    expect(problems).toHaveLength(1);
    expect(problems[0]!.message).toContain('b_reason (x.ts: false, y.ts: true)');
  });

  it('reads the table from source and refuses a computed value', () => {
    expect(
      extractConclusiveTableFromText(
        'export const REASON_CONCLUSIVE = { a: true, b: false } as const satisfies Record<R, boolean>;',
        't.ts',
      ),
    ).toEqual([['a', true], ['b', false]]);
    expect(() =>
      extractConclusiveTableFromText('export const REASON_CONCLUSIVE = { a: !false };', 't.ts'),
    ).toThrow(/literal true or false/);
    expect(() => extractConclusiveTableFromText('export const OTHER = {};', 't.ts')).toThrow(/not found/);
  });
});

function stripComments(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}
