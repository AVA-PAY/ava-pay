/**
 * CI guardrail: ensure VerificationFailureReason in the API and the Shopify
 * plugin haven't drifted, and that REASON_CONCLUSIVE, the table fixing each
 * reason's outcome (invalid or could-not-check), lists every reason exactly
 * once in both files with the same value.
 *
 * The two files (packages/agent-sdk/src/types.ts and
 * shopify-app/app/lib/ava-types.ts) hand-mirror each other today. A real
 * workspace setup would make this unnecessary; until then this check is a cheap
 * insurance policy. Add it to CI; if it fails, sync the union literal in both
 * files and run again.
 *
 * Extraction uses the TypeScript compiler AST, not a text/regex slice. An
 * earlier regex reader sliced from the type name to the first ";" and pulled
 * every quoted token: a stray ";" inside a comment truncated the list, and a
 * quoted word inside a comment was captured as a phantom reason. Because both
 * files shared such a comment, the two truncated lists still MATCHED and the
 * check reported "in sync" while comparing only a fraction of the union. The
 * AST walk ignores comments entirely, and the ratchet floor below fails loudly
 * on any synchronized truncation the cross-file compare cannot see.
 */

import * as ts from 'typescript';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(import.meta.dirname, '..');

/**
 * Ratchet floor: the union must never contain FEWER than this many reasons.
 * A synchronized extraction failure (or a reason removed from both files at
 * once) keeps the two lists equal, so the cross-file compare cannot catch it;
 * this floor can. Bump it UP whenever you intentionally add reasons. Only lower
 * it as a deliberate, reviewed act of removing a reason from the contract.
 */
export const MIN_REASONS = 48;

const FILES = [
  'packages/agent-sdk/src/types.ts',
  'shopify-app/app/lib/ava-types.ts',
];

export interface Section {
  file: string;
  reasons: string[];
  /**
   * REASON_CONCLUSIVE entries in source order, duplicates kept so they can be
   * reported. Optional so the union-only checks can be exercised alone.
   */
  table?: Array<[string, boolean]>;
}

export interface SyncProblem {
  kind: 'floor' | 'drift' | 'table';
  message: string;
}

/**
 * Collect the string-literal members of the `VerificationFailureReason` union
 * from TypeScript source text. Comments are not part of the AST, so nothing in
 * a comment can be captured or can truncate the result. Returns the members
 * sorted for stable comparison.
 */
export function extractReasonsFromText(text: string, label: string): string[] {
  const sourceFile = ts.createSourceFile(label, text, ts.ScriptTarget.Latest, false);

  const collectStringLiterals = (node: ts.Node, out: string[]): void => {
    if (ts.isLiteralTypeNode(node) && ts.isStringLiteral(node.literal)) {
      out.push(node.literal.text);
      return;
    }
    ts.forEachChild(node, (child) => collectStringLiterals(child, out));
  };

  let found: string[] | null = null;
  const visit = (node: ts.Node): void => {
    if (ts.isTypeAliasDeclaration(node) && node.name.text === 'VerificationFailureReason') {
      const out: string[] = [];
      collectStringLiterals(node.type, out);
      found = out;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  if (found === null) {
    throw new Error(`${label}: VerificationFailureReason type alias not found`);
  }
  if ((found as string[]).length === 0) {
    throw new Error(`${label}: VerificationFailureReason has no string-literal members`);
  }
  return [...(found as string[])].sort();
}

/**
 * Read the REASON_CONCLUSIVE object literal from source text via the AST.
 * Entries come back in source order with duplicates preserved (the compiler
 * rejects a duplicate key, but this check must not depend on the file having
 * been compiled). A value that is not a literal true/false is an error: the
 * table exists to state each outcome, not compute it.
 */
export function extractConclusiveTableFromText(text: string, label: string): Array<[string, boolean]> {
  const sourceFile = ts.createSourceFile(label, text, ts.ScriptTarget.Latest, false);

  let found: Array<[string, boolean]> | null = null;
  const unwrap = (expr: ts.Expression): ts.Expression => {
    let e = expr;
    while (ts.isSatisfiesExpression(e) || ts.isAsExpression(e) || ts.isParenthesizedExpression(e)) {
      e = e.expression;
    }
    return e;
  };
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === 'REASON_CONCLUSIVE' &&
      node.initializer
    ) {
      const literal = unwrap(node.initializer);
      if (!ts.isObjectLiteralExpression(literal)) {
        throw new Error(`${label}: REASON_CONCLUSIVE is not an object literal`);
      }
      const out: Array<[string, boolean]> = [];
      for (const prop of literal.properties) {
        if (!ts.isPropertyAssignment(prop)) {
          throw new Error(`${label}: REASON_CONCLUSIVE may hold only plain key: true|false entries`);
        }
        const key = ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name) ? prop.name.text : null;
        const kind = prop.initializer.kind;
        if (key === null || (kind !== ts.SyntaxKind.TrueKeyword && kind !== ts.SyntaxKind.FalseKeyword)) {
          throw new Error(`${label}: REASON_CONCLUSIVE entry must be a named key with a literal true or false`);
        }
        out.push([key, kind === ts.SyntaxKind.TrueKeyword]);
      }
      found = out;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  if (found === null) throw new Error(`${label}: REASON_CONCLUSIVE table not found`);
  return found;
}

export function extractConclusiveTable(file: string): Array<[string, boolean]> {
  return extractConclusiveTableFromText(readFileSync(resolve(ROOT, file), 'utf-8'), file);
}

export function extractReasons(file: string): string[] {
  return extractReasonsFromText(readFileSync(resolve(ROOT, file), 'utf-8'), file);
}

/**
 * Return every problem found across the sections: floor violations (count below
 * MIN_REASONS, which catches synchronized truncation) and cross-file drift.
 * Pure and side-effect free so it can be unit tested with fixtures.
 */
export function findSyncProblems(sections: Section[], minReasons: number): SyncProblem[] {
  const problems: SyncProblem[] = [];

  for (const section of sections) {
    if (section.reasons.length < minReasons) {
      problems.push({
        kind: 'floor',
        message:
          `${section.file}: extracted ${section.reasons.length} reasons, below the ` +
          `floor of ${minReasons}. Extraction was truncated, or a reason was ` +
          `removed. If the removal is intentional, lower MIN_REASONS deliberately; ` +
          `otherwise fix the source.`,
      });
    }
  }

  const [a, b] = sections;
  if (a && b) {
    const drifted =
      a.reasons.length !== b.reasons.length || a.reasons.some((r, i) => r !== b.reasons[i]);
    if (drifted) {
      const onlyA = a.reasons.filter((r) => !b.reasons.includes(r));
      const onlyB = b.reasons.filter((r) => !a.reasons.includes(r));
      let message = `VerificationFailureReason drifted between ${a.file} and ${b.file}.`;
      if (onlyA.length) message += ` Only in ${a.file}: ${onlyA.join(', ')}.`;
      if (onlyB.length) message += ` Only in ${b.file}: ${onlyB.join(', ')}.`;
      problems.push({ kind: 'drift', message });
    }
  }

  // REASON_CONCLUSIVE: within each file, exactly one entry per union member.
  for (const section of sections) {
    if (!section.table) continue;
    const counts = new Map<string, number>();
    for (const [key] of section.table) counts.set(key, (counts.get(key) ?? 0) + 1);
    const duplicated = [...counts].filter(([, n]) => n > 1).map(([key]) => key);
    const missing = section.reasons.filter((r) => !counts.has(r));
    const extra = [...counts.keys()].filter((key) => !section.reasons.includes(key));
    if (duplicated.length || missing.length || extra.length) {
      let message = `${section.file}: REASON_CONCLUSIVE must list every reason exactly once.`;
      if (missing.length) message += ` Missing: ${missing.join(', ')}.`;
      if (duplicated.length) message += ` Listed more than once: ${duplicated.join(', ')}.`;
      if (extra.length) message += ` Not in the union: ${extra.join(', ')}.`;
      problems.push({ kind: 'table', message });
    }
  }

  // And the two tables agree on every outcome.
  if (a?.table && b?.table) {
    const valuesA = new Map(a.table);
    const valuesB = new Map(b.table);
    const differ = [...valuesA]
      .filter(([key, value]) => valuesB.has(key) && valuesB.get(key) !== value)
      .map(([key, value]) => `${key} (${a.file}: ${value}, ${b.file}: ${valuesB.get(key)})`);
    if (differ.length) {
      problems.push({
        kind: 'table',
        message: `REASON_CONCLUSIVE disagrees between the files on: ${differ.join('; ')}.`,
      });
    }
  }

  return problems;
}

export function main(): void {
  const sections: Section[] = FILES.map((file) => ({
    file,
    reasons: extractReasons(file),
    table: extractConclusiveTable(file),
  }));
  const problems = findSyncProblems(sections, MIN_REASONS);

  if (problems.length > 0) {
    console.error('VerificationFailureReason sync check FAILED:');
    for (const problem of problems) console.error(`  x ${problem.message}`);
    for (const section of sections) {
      console.error(`  ${section.file} (${section.reasons.length}):`);
      for (const reason of section.reasons) console.error(`    ${reason}`);
    }
    process.exit(1);
  }

  const count = sections[0]!.reasons.length;
  const couldNotCheck = sections[0]!.table!.filter(([, conclusive]) => !conclusive).map(([key]) => key);
  console.log(
    `✓ VerificationFailureReason in sync across ${sections.length} files ` +
      `(${count} reasons, floor ${MIN_REASONS}). REASON_CONCLUSIVE covers all ${count} in both, ` +
      `${couldNotCheck.length} could-not-check: ${couldNotCheck.join(', ')}.`,
  );
}

// Run only when invoked directly (tsx scripts/check-type-sync.ts), never when
// imported by a test. process.argv[1] is the test runner under vitest.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
