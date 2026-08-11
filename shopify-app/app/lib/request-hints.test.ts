import { describe, expect, it } from 'vitest';
import { extractAgentIdHint, sniffProtocolHint } from './request-hints.js';

const sigInput = (params: string) => `sig1=("@method" "@target-uri")${params}`;

describe('sniffProtocolHint', () => {
  it('reads Web Bot Auth from the tag', () => {
    expect(
      sniffProtocolHint({
        signature: 'sig1=:x:',
        'signature-input': sigInput(';created=1;keyid="k";tag="web-bot-auth"'),
      }),
    ).toBe('web-bot-auth');
  });

  it('reads Web Bot Auth from Signature-Agent even without the tag', () => {
    expect(
      sniffProtocolHint({
        signature: 'sig1=:x:',
        'signature-input': sigInput(';created=1;keyid="k"'),
        'signature-agent': '"https://chatgpt.com"',
      }),
    ).toBe('web-bot-auth');
  });

  it('reads real Visa TAP from either of its tags', () => {
    for (const tag of ['agent-browser-auth', 'agent-payer-auth']) {
      expect(
        sniffProtocolHint({
          signature: 'sig1=:x:',
          'signature-input': sigInput(`;created=1;keyid="k";tag="${tag}"`),
        }),
      ).toBe('visa-tap');
    }
  });

  it("treats an untagged signature as AVA's own profile", () => {
    expect(
      sniffProtocolHint({
        signature: 'sig1=:x:',
        'signature-input': sigInput(';created=1;keyid="agent_demo_public"'),
        'x-ava-mandate': 'eyJ',
      }),
    ).toBe('ava-tap');
  });

  it('reads AP2 from its mandate headers, including the legacy one', () => {
    expect(sniffProtocolHint({ 'ap2-checkout-mandate': 'chain' })).toBe('ap2');
    expect(sniffProtocolHint({ 'ap2-attestation': 'legacy' })).toBe('ap2');
  });

  // The verifier rejects two protocols in one request as ambiguous rather than
  // choosing, so claiming one here would contradict the verdict.
  it('claims nothing when a request carries two protocols', () => {
    expect(
      sniffProtocolHint({
        signature: 'sig1=:x:',
        'signature-input': sigInput(';created=1;keyid="k"'),
        'ap2-checkout-mandate': 'chain',
      }),
    ).toBeNull();
  });

  it('claims nothing for an unsigned request, or a half-signed one', () => {
    expect(sniffProtocolHint({})).toBeNull();
    expect(sniffProtocolHint({ 'signature-input': sigInput(';created=1') })).toBeNull();
    expect(sniffProtocolHint({ signature: 'sig1=:x:' })).toBeNull();
  });
});

describe('extractAgentIdHint', () => {
  it('prefers the Signature-Agent origin, normalised', () => {
    expect(
      extractAgentIdHint({
        'signature-agent': 'sig1="https://ChatGPT.com/some/path"',
        'signature-input': sigInput(';keyid="thumbprint"'),
      }),
    ).toBe('https://chatgpt.com');
  });

  it('falls back to keyid when Signature-Agent is unusable', () => {
    expect(
      extractAgentIdHint({
        'signature-agent': 'not-a-url',
        'signature-input': sigInput(';keyid="agent_demo_public"'),
      }),
    ).toBe('agent_demo_public');
  });

  it('falls back to keyid when there is no Signature-Agent', () => {
    expect(extractAgentIdHint({ 'signature-input': sigInput(';keyid="agent_x"') })).toBe('agent_x');
  });

  it('claims nothing when there is nothing to read', () => {
    expect(extractAgentIdHint({})).toBeNull();
    expect(extractAgentIdHint({ 'signature-input': sigInput(';created=1') })).toBeNull();
  });
});
