/**
 * Golden-file generator for TS↔PHP policy parity.
 *
 * Runs the REAL Shopify-app decision logic (applyMerchantPolicy +
 * validateAgentPolicy/resolveRule) over a broad case matrix and writes the
 * inputs + outputs to tests/fixtures/policy-golden.json. The PHP test suite
 * replays every case through the PHP port and asserts identical output —
 * decision-semantics parity is enforced mechanically, not by review.
 *
 * Regenerate after any change to shopify-app/app/lib/policy.ts or
 * agent-policy.ts:
 *
 *   npx tsx woocommerce-plugin/scripts/generate-policy-golden.ts
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyMerchantPolicy } from '../../shopify-app/app/lib/policy.js';
import { parseAgentPolicy, resolveRule } from '../../shopify-app/app/lib/agent-policy.js';
import type { VerificationResult } from '../../shopify-app/app/lib/ava-types.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'tests', 'fixtures', 'policy-golden.json');

const mandate = (maxAmountMinor: number) => ({
  id: 'mandate_golden',
  iat: 1_700_000_000,
  exp: 1_700_000_600,
  maxAmountMinor,
  currency: 'USD',
  allowedMerchants: ['demo-store.example'],
});

const results: Record<string, VerificationResult> = {
  untrusted: { trusted: false, reason: 'invalid_signature', message: 'nope' },
  identity_only: { trusted: true, ttlSeconds: 300 },
  identity_only_with_hint: { trusted: true, discount: 0.15, ttlSeconds: 300 },
  mandate_backed: { trusted: true, mandate: mandate(50_000), ttlSeconds: 300 },
  mandate_with_hint: { trusted: true, mandate: mandate(50_000), discount: 0.15, ttlSeconds: 300 },
  mandate_with_zero_hint: { trusted: true, mandate: mandate(50_000), discount: 0, ttlSeconds: 300 },
  mandate_large_spend: { trusted: true, mandate: mandate(100_000), ttlSeconds: 300 },
};

const policies: Record<string, string | null> = {
  none: null,
  allow_with_offer_and_cap: JSON.stringify({
    version: 1,
    rules: [
      {
        platform: 'https://chatgpt.com',
        action: 'allow',
        maxDiscountPct: 12,
        offerDiscountPct: 8,
      },
    ],
  }),
  challenge_platform: JSON.stringify({
    version: 1,
    rules: [{ platform: 'https://chatgpt.com', action: 'challenge' }],
  }),
  block_platform: JSON.stringify({
    version: 1,
    rules: [{ platform: 'https://chatgpt.com', action: 'block' }],
  }),
  spend_capped: JSON.stringify({
    version: 1,
    rules: [{ platform: 'https://chatgpt.com', action: 'allow', maxSpendMinor: 60_000 }],
  }),
  default_rule_challenge: JSON.stringify({
    version: 1,
    rules: [{ platform: 'https://chatgpt.com', action: 'allow', offerDiscountPct: 15 }],
    defaultRule: { action: 'challenge' },
  }),
  synthesis_mixed: JSON.stringify({
    version: 1,
    rules: [
      { platform: 'https://chatgpt.com', action: 'allow', maxDiscountPct: 5, offerDiscountPct: 5 },
      { platform: 'https://agents.visa.com', action: 'challenge', maxSpendMinor: 30_000 },
    ],
  }),
};

const settingsVariants: Record<
  string,
  { acceptVerifiedAgents: boolean; defaultDiscountPct: number; maxDiscountPct: number; identityOnlyDiscountPct: number }
> = {
  defaults: { acceptVerifiedAgents: true, defaultDiscountPct: 10, maxDiscountPct: 20, identityOnlyDiscountPct: 0 },
  identity_tier_5: { acceptVerifiedAgents: true, defaultDiscountPct: 10, maxDiscountPct: 20, identityOnlyDiscountPct: 5 },
  identity_tier_above_cap: { acceptVerifiedAgents: true, defaultDiscountPct: 10, maxDiscountPct: 20, identityOnlyDiscountPct: 30 },
  low_max: { acceptVerifiedAgents: true, defaultDiscountPct: 10, maxDiscountPct: 5, identityOnlyDiscountPct: 3 },
  disabled: { acceptVerifiedAgents: false, defaultDiscountPct: 10, maxDiscountPct: 20, identityOnlyDiscountPct: 5 },
};

const platforms = [null, 'https://chatgpt.com', 'HTTPS://CHATGPT.COM', 'https://unknown-agent.example'];

interface DecisionCase {
  name: string;
  settings: (typeof settingsVariants)[string] & { policyJson: string | null };
  result: VerificationResult;
  platform: string | null;
  expected: unknown;
}

const decisionCases: DecisionCase[] = [];
for (const [sName, sBase] of Object.entries(settingsVariants)) {
  for (const [pName, policyJson] of Object.entries(policies)) {
    const parsed = policyJson ? parseAgentPolicy(policyJson) : null;
    if (parsed && !parsed.ok) throw new Error(`golden policy ${pName} invalid: ${parsed.error}`);
    for (const [rName, result] of Object.entries(results)) {
      for (const platform of platforms) {
        const settings = { ...sBase, policy: parsed && parsed.ok ? parsed.policy : null };
        decisionCases.push({
          name: `${sName}__${pName}__${rName}__${platform ?? 'no-platform'}`,
          settings: { ...sBase, policyJson },
          result,
          platform,
          expected: applyMerchantPolicy(settings, result, platform),
        });
      }
    }
  }
}

// Validation parity: raw JSON in, {ok, policy|error} out.
const validationInputs: Record<string, string> = {
  valid_minimal: '{"version":1,"rules":[{"platform":"https://chatgpt.com","action":"allow"}]}',
  valid_default_rule_only: '{"version":1,"rules":[],"defaultRule":{"action":"block"}}',
  valid_float_int: '{"version":1,"rules":[{"platform":"a","action":"allow","maxDiscountPct":5.0}]}',
  valid_trims_platform: '{"version":1,"rules":[{"platform":"  https://x.example  ","action":"allow"}]}',
  invalid_json: '{nope',
  not_object: '[1,2]',
  bad_version: '{"version":2,"rules":[]}',
  version_string: '{"version":"1","rules":[]}',
  rules_not_array: '{"version":1,"rules":{}}',
  empty_policy: '{"version":1,"rules":[]}',
  rule_not_object: '{"version":1,"rules":["x"]}',
  missing_platform: '{"version":1,"rules":[{"action":"allow"}]}',
  empty_platform: '{"version":1,"rules":[{"platform":"  ","action":"allow"}]}',
  duplicate_platform:
    '{"version":1,"rules":[{"platform":"https://a.example","action":"allow"},{"platform":"HTTPS://A.EXAMPLE","action":"block"}]}',
  bad_action: '{"version":1,"rules":[{"platform":"a","action":"maybe"}]}',
  pct_out_of_range: '{"version":1,"rules":[{"platform":"a","action":"allow","maxDiscountPct":101}]}',
  pct_not_integer: '{"version":1,"rules":[{"platform":"a","action":"allow","offerDiscountPct":5.5}]}',
  pct_boolean: '{"version":1,"rules":[{"platform":"a","action":"allow","maxDiscountPct":true}]}',
  negative_spend: '{"version":1,"rules":[{"platform":"a","action":"allow","maxSpendMinor":-1}]}',
  bad_default_rule: '{"version":1,"rules":[],"defaultRule":{"action":"nah"}}',
  default_rule_array: '{"version":1,"rules":[],"defaultRule":[]}',
};

const validationCases = Object.entries(validationInputs).map(([name, json]) => ({
  name,
  json,
  expected: parseAgentPolicy(json),
}));

// resolveRule parity on the trickier lookups.
const resolvePolicy = parseAgentPolicy(policies.synthesis_mixed!);
if (!resolvePolicy.ok) throw new Error('unreachable');
const resolveCases = platforms.map((platform) => ({
  name: `synthesis_mixed__${platform ?? 'no-platform'}`,
  policyJson: policies.synthesis_mixed,
  platform,
  expected: resolveRule(resolvePolicy.policy, platform),
}));

const golden = {
  generatedBy: 'woocommerce-plugin/scripts/generate-policy-golden.ts',
  source: 'shopify-app/app/lib/policy.ts + agent-policy.ts',
  decisionCases,
  validationCases,
  resolveCases,
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(golden, null, 2) + '\n');
console.log(
  `wrote ${OUT}: ${decisionCases.length} decision, ${validationCases.length} validation, ${resolveCases.length} resolve cases`,
);
