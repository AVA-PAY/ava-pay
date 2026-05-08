/**
 * CI guardrail: ensure VerificationFailureReason in the API and the Shopify
 * plugin haven't drifted.
 *
 * The two files (src/types.ts and shopify-app/app/lib/ava-types.ts) hand-mirror
 * each other today. A real workspace setup would make this unnecessary; until
 * then this check is a cheap insurance policy. Add it to CI; if it fails,
 * sync the union literal in both files and run again.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');

interface Section {
  file: string;
  reasons: string[];
}

function extractReasons(file: string): string[] {
  const path = resolve(ROOT, file);
  const text = readFileSync(path, 'utf-8');
  const start = text.indexOf('export type VerificationFailureReason');
  if (start === -1) {
    throw new Error(`${file}: VerificationFailureReason not found`);
  }
  const semi = text.indexOf(';', start);
  if (semi === -1) {
    throw new Error(`${file}: VerificationFailureReason has no terminator`);
  }
  const block = text.slice(start, semi);
  const re = /'([^']+)'/g;
  const reasons: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(block)) !== null) reasons.push(m[1]!);
  return reasons.sort();
}

const sections: Section[] = [
  { file: 'packages/agent-sdk/src/types.ts', reasons: extractReasons('packages/agent-sdk/src/types.ts') },
  { file: 'shopify-app/app/lib/ava-types.ts', reasons: extractReasons('shopify-app/app/lib/ava-types.ts') },
];

const [a, b] = sections;
if (!a || !b) {
  throw new Error('expected exactly two type files to compare');
}

if (a.reasons.length !== b.reasons.length || a.reasons.some((r, i) => r !== b.reasons[i])) {
  console.error('VerificationFailureReason has drifted between files:');
  console.error(`  ${a.file}:`);
  for (const r of a.reasons) console.error(`    ${r}`);
  console.error(`  ${b.file}:`);
  for (const r of b.reasons) console.error(`    ${r}`);
  const onlyA = a.reasons.filter((r) => !b.reasons.includes(r));
  const onlyB = b.reasons.filter((r) => !a.reasons.includes(r));
  if (onlyA.length) console.error(`  Only in ${a.file}: ${onlyA.join(', ')}`);
  if (onlyB.length) console.error(`  Only in ${b.file}: ${onlyB.join(', ')}`);
  process.exit(1);
}

console.log(`✓ VerificationFailureReason in sync across both files (${a.reasons.length} reasons).`);
