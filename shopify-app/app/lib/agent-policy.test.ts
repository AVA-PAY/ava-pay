import { describe, expect, it } from 'vitest';
import {
  mostRestrictiveRule,
  parseAgentPolicy,
  resolveRule,
  serializeAgentPolicy,
  validateAgentPolicy,
  type AgentPolicy,
} from './agent-policy.js';
import { applyMerchantPolicy, type MerchantPolicyInput } from './policy.js';
import type { VerificationResult } from './ava-types.js';

const mandateBacked: VerificationResult = {
  trusted: true,
  protocol: 'visa-tap',
  buyerInfo: { buyerId: 'b1' },
  mandate: {
    id: 'm',
    iat: 0,
    exp: 9_999_999,
    maxAmountMinor: 50_00,
    currency: 'USD',
    allowedMerchants: ['*'],
  },
  ttlSeconds: 60,
};

const identityOnly: VerificationResult = {
  trusted: true,
  protocol: 'web-bot-auth',
  agent: { id: 'https://chatgpt.com', protocol: 'web-bot-auth' },
  ttlSeconds: 60,
};

function settings(overrides: Partial<MerchantPolicyInput> = {}): MerchantPolicyInput {
  return {
    acceptVerifiedAgents: true,
    defaultDiscountPct: 10,
    maxDiscountPct: 20,
    identityOnlyDiscountPct: 0,
    ...overrides,
  };
}

function policy(p: Partial<AgentPolicy> = {}): AgentPolicy {
  return {
    version: 1,
    rules: [{ platform: 'https://chatgpt.com', action: 'allow' }],
    ...p,
  };
}

describe('parseAgentPolicy / validateAgentPolicy', () => {
  it('round-trips a valid policy through serialize/parse', () => {
    const p: AgentPolicy = {
      version: 1,
      defaultRule: { action: 'challenge', maxDiscountPct: 5 },
      rules: [
        { platform: 'https://chatgpt.com', action: 'allow', maxDiscountPct: 15, offerDiscountPct: 12 },
        { platform: 'agent_visa_demo', action: 'allow', maxSpendMinor: 100_00 },
      ],
    };
    const parsed = parseAgentPolicy(serializeAgentPolicy(p));
    expect(parsed).toEqual({ ok: true, policy: p });
  });

  it('rejects malformed JSON, wrong versions, and bad shapes', () => {
    expect(parseAgentPolicy('{nope').ok).toBe(false);
    expect(validateAgentPolicy({ version: 2, rules: [] }).ok).toBe(false);
    expect(validateAgentPolicy({ version: 1 }).ok).toBe(false);
    expect(validateAgentPolicy([]).ok).toBe(false);
    expect(validateAgentPolicy('str').ok).toBe(false);
  });

  it('rejects an empty policy (no rules, no defaultRule) — undefined behavior', () => {
    const r = validateAgentPolicy({ version: 1, rules: [] });
    expect(r.ok).toBe(false);
  });

  it('accepts a defaultRule-only policy', () => {
    const r = validateAgentPolicy({ version: 1, rules: [], defaultRule: { action: 'block' } });
    expect(r.ok).toBe(true);
  });

  it('rejects invalid actions, out-of-range percentages, and negative spend', () => {
    expect(
      validateAgentPolicy({ version: 1, rules: [{ platform: 'x', action: 'nuke' }] }).ok,
    ).toBe(false);
    expect(
      validateAgentPolicy({
        version: 1,
        rules: [{ platform: 'x', action: 'allow', maxDiscountPct: 101 }],
      }).ok,
    ).toBe(false);
    expect(
      validateAgentPolicy({
        version: 1,
        rules: [{ platform: 'x', action: 'allow', offerDiscountPct: -1 }],
      }).ok,
    ).toBe(false);
    expect(
      validateAgentPolicy({
        version: 1,
        rules: [{ platform: 'x', action: 'allow', maxSpendMinor: -5 }],
      }).ok,
    ).toBe(false);
    expect(
      validateAgentPolicy({
        version: 1,
        rules: [{ platform: 'x', action: 'allow', maxSpendMinor: 10.5 }],
      }).ok,
    ).toBe(false);
  });

  it('rejects duplicate platforms case-insensitively', () => {
    const r = validateAgentPolicy({
      version: 1,
      rules: [
        { platform: 'https://ChatGPT.com', action: 'allow' },
        { platform: 'https://chatgpt.com', action: 'block' },
      ],
    });
    expect(r.ok).toBe(false);
  });
});

describe('resolveRule / mostRestrictiveRule', () => {
  const p: AgentPolicy = {
    version: 1,
    rules: [
      { platform: 'https://chatgpt.com', action: 'allow', maxDiscountPct: 15, offerDiscountPct: 12 },
      { platform: 'https://perplexity.ai', action: 'challenge', maxDiscountPct: 5, maxSpendMinor: 200_00 },
    ],
  };

  it('matches platforms case-insensitively', () => {
    expect(resolveRule(p, 'HTTPS://CHATGPT.COM').action).toBe('allow');
  });

  it('unknown platform → most restrictive synthesis (harshest action, lowest caps, no offers)', () => {
    const rule = resolveRule(p, 'https://evil.example');
    expect(rule).toEqual({ action: 'challenge', maxDiscountPct: 5, maxSpendMinor: 200_00 });
    expect(mostRestrictiveRule(p).action).toBe('challenge');
  });

  it('any block rule makes unknown platforms blocked', () => {
    const withBlock: AgentPolicy = {
      version: 1,
      rules: [...p.rules, { platform: 'https://bad.example', action: 'block' }],
    };
    expect(resolveRule(withBlock, 'https://new.example').action).toBe('block');
    expect(resolveRule(withBlock, null).action).toBe('block');
  });

  it('an explicit defaultRule beats the synthesis', () => {
    const withDefault: AgentPolicy = { ...p, defaultRule: { action: 'allow', maxDiscountPct: 2 } };
    expect(resolveRule(withDefault, 'https://new.example')).toEqual({
      action: 'allow',
      maxDiscountPct: 2,
    });
  });
});

describe('applyMerchantPolicy with a policy document', () => {
  it('no policy → behavior identical to the legacy path', () => {
    expect(applyMerchantPolicy(settings(), mandateBacked, 'https://chatgpt.com')).toEqual({
      allow: true,
      reason: 'verified',
      discountPct: 10,
    });
    expect(applyMerchantPolicy(settings({ policy: null }), identityOnly, 'https://chatgpt.com')).toEqual({
      allow: true,
      reason: 'verified',
      discountPct: 0,
    });
  });

  it('block rule rejects even mandate-backed traffic', () => {
    const s = settings({
      policy: policy({ rules: [{ platform: 'https://chatgpt.com', action: 'block' }] }),
    });
    expect(applyMerchantPolicy(s, mandateBacked, 'https://chatgpt.com')).toEqual({
      allow: false,
      reason: 'blocked_by_policy',
    });
  });

  it('challenge admits mandate-backed traffic but rejects identity-only with a retry hint', () => {
    const s = settings({
      policy: policy({ rules: [{ platform: 'https://chatgpt.com', action: 'challenge' }] }),
    });
    expect(applyMerchantPolicy(s, mandateBacked, 'https://chatgpt.com').allow).toBe(true);
    expect(applyMerchantPolicy(s, identityOnly, 'https://chatgpt.com')).toEqual({
      allow: false,
      reason: 'challenge_required',
    });
  });

  it('spend rule rejects mandates above the cap and passes at the cap', () => {
    const s = settings({
      policy: policy({
        rules: [{ platform: 'https://chatgpt.com', action: 'allow', maxSpendMinor: 50_00 }],
      }),
    });
    expect(applyMerchantPolicy(s, mandateBacked, 'https://chatgpt.com').allow).toBe(true); // 50_00 ≤ 50_00
    const bigger = {
      ...mandateBacked,
      mandate: { ...mandateBacked.mandate!, maxAmountMinor: 50_01 },
    };
    expect(applyMerchantPolicy(s, bigger, 'https://chatgpt.com')).toEqual({
      allow: false,
      reason: 'spend_limit_exceeded',
    });
  });

  it('rule discount cap intersects the global cap (never exceeds either)', () => {
    const s = settings({
      maxDiscountPct: 20,
      policy: policy({
        rules: [{ platform: 'https://chatgpt.com', action: 'allow', maxDiscountPct: 8 }],
      }),
    });
    expect(applyMerchantPolicy(s, { ...mandateBacked, discount: 0.5 }, 'https://chatgpt.com')).toEqual(
      { allow: true, reason: 'verified', discountPct: 8 },
    );

    const ruleAboveGlobal = settings({
      maxDiscountPct: 10,
      policy: policy({
        rules: [{ platform: 'https://chatgpt.com', action: 'allow', maxDiscountPct: 50 }],
      }),
    });
    expect(
      applyMerchantPolicy(ruleAboveGlobal, { ...mandateBacked, discount: 0.5 }, 'https://chatgpt.com'),
    ).toEqual({ allow: true, reason: 'verified', discountPct: 10 });
  });

  it('platform offer applies to mandate-backed traffic, capped', () => {
    const s = settings({
      policy: policy({
        rules: [
          { platform: 'https://chatgpt.com', action: 'allow', offerDiscountPct: 15 },
          { platform: 'https://capped.example', action: 'allow', offerDiscountPct: 50, maxDiscountPct: 12 },
        ],
      }),
    });
    expect(applyMerchantPolicy(s, mandateBacked, 'https://chatgpt.com')).toEqual({
      allow: true,
      reason: 'verified',
      discountPct: 15,
    });
    expect(applyMerchantPolicy(s, mandateBacked, 'https://capped.example')).toEqual({
      allow: true,
      reason: 'verified',
      discountPct: 12,
    });
  });

  it('INVARIANT: offers never leak onto identity-only traffic', () => {
    const s = settings({
      identityOnlyDiscountPct: 0,
      policy: policy({
        rules: [{ platform: 'https://chatgpt.com', action: 'allow', offerDiscountPct: 25 }],
      }),
    });
    expect(applyMerchantPolicy(s, identityOnly, 'https://chatgpt.com')).toEqual({
      allow: true,
      reason: 'verified',
      discountPct: 0,
    });
  });

  it('INVARIANT: identity-only discount stays opt-in under a policy, and rule caps still bind it', () => {
    const optedIn = settings({
      identityOnlyDiscountPct: 10,
      policy: policy({
        rules: [{ platform: 'https://chatgpt.com', action: 'allow', maxDiscountPct: 4 }],
      }),
    });
    expect(applyMerchantPolicy(optedIn, identityOnly, 'https://chatgpt.com')).toEqual({
      allow: true,
      reason: 'verified',
      discountPct: 4,
    });
  });

  it('unknown platform under a policy gets the most restrictive treatment', () => {
    const s = settings({
      policy: policy({
        rules: [
          { platform: 'https://chatgpt.com', action: 'allow' },
          { platform: 'https://bad.example', action: 'block' },
        ],
      }),
    });
    expect(applyMerchantPolicy(s, mandateBacked, 'https://unknown.example')).toEqual({
      allow: false,
      reason: 'blocked_by_policy',
    });
    expect(applyMerchantPolicy(s, mandateBacked, null)).toEqual({
      allow: false,
      reason: 'blocked_by_policy',
    });
  });

  it('master toggle off still blocks everything, policy or not', () => {
    const s = settings({ acceptVerifiedAgents: false, policy: policy() });
    expect(applyMerchantPolicy(s, mandateBacked, 'https://chatgpt.com')).toEqual({
      allow: false,
      reason: 'merchant_disabled',
    });
  });

  it('untrusted results never reach policy evaluation', () => {
    const s = settings({
      policy: policy({
        rules: [{ platform: 'https://chatgpt.com', action: 'allow', offerDiscountPct: 15 }],
      }),
    });
    const blocked: VerificationResult = { trusted: false, reason: 'invalid_signature', message: 'x' };
    expect(applyMerchantPolicy(s, blocked, 'https://chatgpt.com')).toEqual({
      allow: false,
      reason: 'agent_blocked',
    });
  });
});
