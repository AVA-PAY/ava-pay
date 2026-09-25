/**
 * Golden-file generator for TS to PHP parity of the forwarded header set.
 *
 * Runs the REAL Shopify-app minimizer (shopify-app/app/lib/forwarded-headers.ts,
 * which reads Signature-Input with the SDK's own parseSignatureInput) over a
 * case matrix and writes inputs + outputs to tests/fixtures/forwarding-golden.json.
 * The PHP suite replays every case through AVA_Pay_Forwarded_Headers and
 * asserts identical output.
 *
 * Regenerate after any change to forwarded-headers.ts or to the SDK's
 * Signature-Input parser:
 *
 *   npx tsx woocommerce-plugin/scripts/generate-forwarding-golden.ts
 *
 * Every input is a literal, so the output is byte-stable and CI can diff it.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  coveredHeaderFields,
  minimizeForwardedHeaders,
  splitDictionaryMembers,
} from '../../shopify-app/app/lib/forwarded-headers.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'tests', 'fixtures', 'forwarding-golden.json');

const P = ';created=1790345533;keyid="k1";alg="ed25519";nonce="n1"';

/** Signature-Input values, readable and not, for the covered-field reader. */
const signatureInputs: Record<string, string> = {
  wba_keyed: `sig1=("@authority" "signature-agent";key="sig1")${P};tag="web-bot-auth"`,
  wba_unkeyed: `sig1=("@authority" "@method" "@path" "signature-agent")${P};tag="web-bot-auth"`,
  ava_tap: `sig1=("@method" "@target-uri" "host" "content-digest" "x-ava-mandate")${P}`,
  visa_tap: `sig2=("@authority" "@path");created=1790345533;expires=1790346013;keyId="k1";alg="ed25519";nonce="n1";tag="agent-browser-auth"`,
  body_components: `sig1=("@authority" "content-digest" "content-type")${P}`,
  custom_header: `sig1=("@authority" "x-example")${P}`,
  upper_case_names: `sig1=("@Authority" "Content-Digest" "X-Example")${P}`,
  component_params: `sig1=("content-digest";sf "x-a";bs "x-b";req "x-c";key="m" "x-d";tr)${P}`,
  same_name_two_keys: `sig1=("signature-agent";key="a" "signature-agent";key="b")${P}`,
  duplicate_identifier: `sig1=("x-a" "x-a")${P}`,
  derived_only: `sig1=("@authority" "@method" "@path" "@query")${P}`,
  multi_member: `sig1=("@authority" "x-a")${P}, sig2=("x-b" "content-digest")${P}`,
  multi_member_overlap: `sig1=("x-a" "x-b")${P},sig2=("x-b" "x-c")${P}`,
  comma_in_quoted_param: `sig1=("x-a")${P};tag="a,b"`,
  paren_in_quoted_param: `sig1=("x-a")${P};tag="a)b"`,
  escaped_quote_in_param: `sig1=("x-a")${P};tag="a\\"b"`,
  escaped_quote_then_comma: `sig1=("x-a")${P};tag="a\\",b"`,
  quoted_key_with_comma: `sig1=("signature-agent";key="a,b")${P}`,
  whitespace_padding: `  sig1=(  "x-a"   "x-b"  )${P}  `,
  no_params: `sig1=("x-a")`,
  params_without_semicolon: `sig1=("x-a")garbage`,
  covers_credentials: `sig1=("@authority" "cookie" "authorization" "proxy-authorization" "x-wp-nonce" "x-a")${P}`,
  created_hex: `sig1=("x-a");created=0x10`,
  created_exponent: `sig1=("x-a");created=1e3`,
  created_quoted: `sig1=("x-a");created="1790345533"`,
  created_empty: `sig1=("x-a");created=`,
  created_not_a_number: `sig1=("x-a");created=soon`,
  created_infinity: `sig1=("x-a");created=Infinity`,
  created_overflow: `sig1=("x-a");created=1e999`,
  expires_bad: `sig1=("x-a");created=1;expires=later`,
  unterminated_list: `sig1=("x-a" "x-b"`,
  unterminated_string: `sig1=("x-a)`,
  unbalanced_close: `sig1=("x-a"))`,
  not_an_inner_list: `sig1="x-a"`,
  no_label: `("x-a")${P}`,
  empty_list: `sig1=()${P}`,
  empty_component: `sig1=("" "x-a")${P}`,
  junk_between_components: `sig1=("x-a" junk "x-b")${P}`,
  unquoted_component: `sig1=(x-a)${P}`,
  trailing_comma: `sig1=("x-a")${P},`,
  leading_comma: `,sig1=("x-a")${P}`,
  one_bad_member: `sig1=("x-a")${P}, sig2=("x-b"`,
  empty: '',
  whitespace_only: '   ',
};

/** Header maps for the minimizer, including the realistic proxied request. */
const PROXY_NOISE: Record<string, string> = {
  'x-forwarded-for': '203.0.113.7, 10.0.0.1',
  'x-forwarded-proto': 'https',
  'user-agent': 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36',
  cookie: 'wordpress_logged_in_x=abc',
  authorization: 'Basic abc',
  'x-wp-nonce': 'abc123',
  accept: 'application/json',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, br',
  'x-request-id': 'req-1',
  'x-ava-agent-id': 'claimed-agent',
  'x-ava-signature': 'claimed',
  'x-ava-mock-discount': '0.9',
};

const HOST = 'demo-store.example';
const SIG = 'sig1=:AAAA:';

const minimizeCases: Array<{ name: string; headers: Record<string, string>; hasBody: boolean }> = [
  {
    name: 'wba_behind_proxy',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.wba_keyed as string,
      'signature-agent': 'sig1="https://agent.example"',
    },
  },
  {
    name: 'wba_body_covered',
    hasBody: true,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.body_components as string,
      'content-digest': 'sha-256=:abc=:',
      'content-type': 'application/json',
    },
  },
  {
    name: 'custom_header_covered',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.custom_header as string,
      'x-example': 'kept',
    },
  },
  {
    name: 'user_agent_covered',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': `sig1=("@authority" "user-agent")${P}`,
    },
  },
  {
    name: 'ava_tap_with_body',
    hasBody: true,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.ava_tap as string,
      'content-digest': 'sha-256=:abc=:',
      'content-type': 'application/json',
      'x-ava-mandate': 'e30=',
      'x-ava-discount-hint': '0.1',
    },
  },
  {
    name: 'content_type_without_body',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.custom_header as string,
      'content-digest': 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
      'content-type': 'application/json',
    },
  },
  {
    name: 'ap2_chains',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      'ap2-checkout-mandate': 'a~b~c',
      'ap2-payment-mandate': 'd~e~f',
    },
  },
  {
    name: 'ap2_v01',
    hasBody: false,
    headers: { ...PROXY_NOISE, host: HOST, 'ap2-attestation': 'x.y.z', 'ap2-cart-mandate': 'x.y.z' },
  },
  {
    name: 'unreadable_signature_input',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.unterminated_list as string,
      'x-a': 'dropped',
      'x-ava-mandate': 'e30=',
    },
  },
  {
    name: 'no_signature_input',
    hasBody: false,
    headers: { ...PROXY_NOISE, host: HOST },
  },
  {
    name: 'multi_member_union',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.multi_member_overlap as string,
      'x-a': '1',
      'x-b': '2',
      'x-c': '3',
      'x-d': 'dropped',
    },
  },
  {
    name: 'covered_but_absent',
    hasBody: false,
    headers: {
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.custom_header as string,
    },
  },
  {
    name: 'covered_cookie_and_authorization',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': `sig1=("@authority" "cookie" "authorization")${P}`,
    },
  },
  {
    name: 'covered_credentials_all',
    hasBody: false,
    headers: {
      ...PROXY_NOISE,
      host: HOST,
      signature: SIG,
      'signature-input': signatureInputs.covers_credentials as string,
      'proxy-authorization': 'Basic xyz',
      'x-a': 'kept',
    },
  },
  {
    name: 'mixed_case_names',
    hasBody: false,
    headers: {
      Host: HOST,
      Signature: SIG,
      'Signature-Input': signatureInputs.upper_case_names as string,
      'X-Example': 'kept',
      'User-Agent': 'dropped',
    },
  },
];

const golden = {
  generatedBy: 'woocommerce-plugin/scripts/generate-forwarding-golden.ts',
  note: 'Do not edit by hand. Regenerate from the TypeScript reference.',
  coveredCases: Object.entries(signatureInputs).map(([name, value]) => ({
    name,
    signatureInput: value,
    members: splitDictionaryMembers(value),
    expected: coveredHeaderFields(value),
  })),
  minimizeCases: minimizeCases.map((c) => ({
    ...c,
    expected: minimizeForwardedHeaders(c.headers, { hasBody: c.hasBody }),
  })),
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, `${JSON.stringify(golden, null, 2)}\n`);
// eslint-disable-next-line no-console
console.log(
  `wrote ${golden.coveredCases.length} covered-field cases and ${golden.minimizeCases.length} minimize cases to ${OUT}`,
);
