#!/usr/bin/env node
/**
 * Simulate one verified AI shopping agent visiting a store running AVA Pay.
 *
 *   node simulate-verified-agent.mjs your-store.myshopify.com
 *
 * Development stores keep their storefront password on and cannot turn it off,
 * and Shopify redirects app proxy requests to the password page until a client
 * has cleared it. Pass the storefront password when the store has one:
 *
 *   node simulate-verified-agent.mjs your-store.myshopify.com --password hunter2
 *   AVA_STOREFRONT_PASSWORD=hunter2 node simulate-verified-agent.mjs your-store.myshopify.com
 *
 * The script also prompts for it if it hits the password page without one, so
 * the password never has to appear in shell history.
 *
 * Signs an RFC 9421 request with AVA Pay's public demo credential and sends it
 * to the store's App Proxy endpoint, exactly as a real Visa Trusted Agent
 * Protocol agent would. The store's AVA Pay install verifies the signature
 * through the hosted API, applies the merchant's policy, and records one
 * verified event on the app's Traffic page.
 *
 * Requires Node 18 or newer. No installation, no dependencies.
 *
 * About the credential: the private key below is public on purpose. It belongs
 * to the demo agent seeded in AVA Pay's directory (`agent_demo_public`) and
 * carries no authority beyond being verifiable, which is what makes a
 * self-contained demo possible. Real agents hold keys nobody else has.
 *
 * Maintainers: this file deliberately has no imports from @ava-pay/agent so a
 * reviewer can run it against nothing but Node. tests/simulate-script.test.ts
 * feeds its output to the real VisaAgentVerifier, so the duplicated signing
 * cannot drift from the SDK without a test failing.
 */

import { createHash, createPrivateKey, randomBytes, randomUUID, sign as edSign } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DEMO_AGENT_ID = 'agent_demo_public';
const DEMO_PRIVATE_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  d: 'RfgxZQvu3WXbskCO0QZlhSOjguLIuTz8ANz0x3uCvRo',
  x: 'yKCkvxtkVtmYT1xK0FFuvQPFAQqQ_z6Zg9q6VKsJTU4',
};

/**
 * The origin the --web-bot-auth probe claims to be. It deliberately publishes
 * no key directory (the name does not resolve at all), which is the whole
 * point: see buildWebBotAuthRequest.
 */
export const PROBE_SIGNATURE_AGENT = 'https://directory-test.avalayer.com';

/** `sha-256=:<base64>:` over the exact request body. */
export function contentDigest(body) {
  return `sha-256=:${createHash('sha256').update(body ?? '').digest('base64')}:`;
}

/**
 * Build the signed request an agent would send to
 * https://{shop}/apps/ava-pay/verify. Returns { method, url, headers, body },
 * the same envelope shape AVA Pay's /verify endpoint accepts.
 */
export function buildSignedAgentRequest(shop, options = {}) {
  const now = options.created ?? Math.floor(Date.now() / 1000);
  const url = `https://${shop}/apps/ava-pay/verify`;
  const body = options.body ?? JSON.stringify({
    cart: [{ sku: 'DEMO-1234', qty: 1, price_minor: 4999 }],
  });

  // A buyer mandate: what the shopper authorised this agent to spend. Scoped
  // to this store and expiring in ten minutes.
  const mandate = {
    id: `mandate_${now}`,
    iat: now - 5,
    exp: now + 600,
    maxAmountMinor: 50_000,
    currency: 'USD',
    allowedMerchants: [shop],
    buyer: { buyerId: 'buyer_demo_001', country: 'US', displayName: 'Demo Shopper' },
  };

  const headers = {
    host: shop,
    'content-digest': contentDigest(body),
    'x-ava-mandate': Buffer.from(JSON.stringify(mandate), 'utf-8').toString('base64'),
    'content-type': 'application/json',
  };

  const components = ['@method', '@target-uri', 'host', 'content-digest', 'x-ava-mandate'];
  const nonce = options.nonce ?? randomUUID();
  const params =
    `;created=${now};expires=${now + 60};keyid="${DEMO_AGENT_ID}"` +
    `;alg="ed25519";nonce="${nonce}"`;
  const sigInputValue = `(${components.map((c) => `"${c}"`).join(' ')})${params}`;

  const base = [
    ...components.map((c) => {
      if (c === '@method') return `"${c}": POST`;
      if (c === '@target-uri') return `"${c}": ${url}`;
      return `"${c}": ${headers[c]}`;
    }),
    `"@signature-params": ${sigInputValue}`,
  ].join('\n');

  const key = createPrivateKey({ key: DEMO_PRIVATE_JWK, format: 'jwk' });
  const signature = edSign(null, Buffer.from(base), key).toString('base64');

  return {
    method: 'POST',
    url,
    headers: {
      ...headers,
      'signature-input': `sig1=${sigInputValue}`,
      signature: `sig1=:${signature}:`,
    },
    body,
  };
}

/**
 * RFC 7638 JWK SHA-256 thumbprint of an Ed25519 public key, in the RFC 8037
 * Appendix A.3 form. Web Bot Auth uses this as the signature `keyid`: the
 * verifier looks the key up in the agent's published directory by thumbprint
 * rather than by a name the agent chose for itself.
 */
export function ed25519JwkThumbprint(x) {
  return createHash('sha256')
    .update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`, 'utf-8')
    .digest('base64url');
}

/**
 * Build a Web Bot Auth request (the IETF scheme real ChatGPT-style agents use)
 * signed as an agent whose key directory cannot be reached.
 *
 * This exists to demonstrate the honest-failure path end to end. AVA Pay
 * discovers a Web Bot Auth agent's keys at
 * https://{signature-agent}/.well-known/http-message-signatures-directory, so
 * naming an origin that publishes nothing means there is no key to verify
 * against and the signature below is never checked either way. That is the
 * state worth proving: the verdict has to come back "could not check"
 * (verification_unavailable, recorded as Could not check on the Traffic page),
 * never "checked and rejected". Both fail closed; only the claim differs, and
 * telling a merchant we blocked an agent when we never reached a trust root is
 * a claim we cannot support.
 *
 * Shape follows draft -02: tag="web-bot-auth", a Signature-Agent header in the
 * dictionary form signers MUST send, and covered components ("@method"
 * "@authority" "@path" "signature-agent";key="sig1"), plus content-digest,
 * since this request carries a cart body and a body that travels unsigned is a
 * body anyone can swap. Section 5.2.1 requires the keyed member rather than the
 * whole field, so the base carries the member value alone, exactly as the
 * Appendix E vectors show.
 */
export function buildWebBotAuthRequest(shop, options = {}) {
  const now = options.created ?? Math.floor(Date.now() / 1000);
  const url = `https://${shop}/apps/ava-pay/verify`;
  const target = new URL(url);
  const body = options.body ?? JSON.stringify({
    cart: [{ sku: 'DEMO-1234', qty: 1, price_minor: 4999 }],
  });
  const signatureAgent = options.signatureAgent ?? PROBE_SIGNATURE_AGENT;
  const label = 'sig1';

  // No x-ava-mandate: Web Bot Auth proves who the agent is, never what a buyer
  // authorised it to spend. Identity only, by design.
  // The dictionary member on its own: what a keyed component covers.
  const signatureAgentMember = `"${signatureAgent}"`;
  const headers = {
    host: shop,
    'content-digest': contentDigest(body),
    'signature-agent': `${label}=${signatureAgentMember}`,
    'content-type': 'application/json',
  };

  const components = ['@method', '@authority', '@path', 'signature-agent', 'content-digest'];
  /** Component identifier as it appears in Signature-Input and in the base. */
  const identifier = (c) => (c === 'signature-agent' ? `"${c}";key="${label}"` : `"${c}"`);
  // base64url, which -02 no longer constrains: Section 5.2.3 defers nonce
  // handling entirely to RFC 9421 Section 7.2.2.
  const nonce = options.nonce ?? randomBytes(16).toString('base64url');
  const keyid = options.keyid ?? ed25519JwkThumbprint(DEMO_PRIVATE_JWK.x);
  const params =
    `;created=${now};expires=${now + 60};keyid="${keyid}"` +
    `;alg="ed25519";nonce="${nonce}";tag="web-bot-auth"`;
  const sigInputValue = `(${components.map(identifier).join(' ')})${params}`;

  const base = [
    ...components.map((c) => {
      if (c === '@method') return `${identifier(c)}: POST`;
      if (c === '@authority') return `${identifier(c)}: ${target.host}`;
      if (c === '@path') return `${identifier(c)}: ${target.pathname}`;
      // A keyed identifier covers the member's value, not the whole field.
      if (c === 'signature-agent') return `${identifier(c)}: ${signatureAgentMember}`;
      return `${identifier(c)}: ${headers[c]}`;
    }),
    `"@signature-params": ${sigInputValue}`,
  ].join('\n');

  const key = createPrivateKey({ key: DEMO_PRIVATE_JWK, format: 'jwk' });
  const signature = edSign(null, Buffer.from(base), key).toString('base64');

  return {
    method: 'POST',
    url,
    headers: {
      ...headers,
      'signature-input': `${label}=${sigInputValue}`,
      signature: `${label}=:${signature}:`,
    },
    body,
  };
}

/**
 * Minimal cookie jar. Node's fetch does not keep cookies, and the storefront
 * password gate needs a session cookie carried from the form GET through to
 * the proxy request.
 */
function makeJar() {
  const jar = new Map();
  return {
    absorb(res) {
      // getSetCookie landed in Node 19.7; fall back for Node 18.
      const all = res.headers.getSetCookie?.() ?? [res.headers.get('set-cookie')].filter(Boolean);
      for (const raw of all) {
        const [pair] = raw.split(';');
        const eq = pair.indexOf('=');
        if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
      }
    },
    header() {
      return [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    },
  };
}

function decodeEntities(value) {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

/**
 * Every hidden field on the password form, submitted back verbatim. Shopify's
 * form carries an `authenticity_token` CSRF field bound to the session cookie,
 * and themes vary in what else they include, so this copies the form rather
 * than hardcoding field names.
 */
function hiddenFields(html) {
  const fields = {};
  for (const [tag] of html.matchAll(/<input[^>]*type=["']hidden["'][^>]*>/gi)) {
    const name = tag.match(/name=["']([^"']+)["']/i)?.[1];
    if (!name) continue;
    fields[name] = decodeEntities(tag.match(/value=["']([^"']*)["']/i)?.[1] ?? '');
  }
  return fields;
}

/**
 * Ask on the terminal without echoing keystrokes, so the password stays off the
 * screen and out of shell history. Returns '' when there is no terminal to
 * prompt on (piped input, CI), and the caller then names the flag to use.
 */
async function promptSecret(label) {
  if (!process.stdin.isTTY) return '';
  const { createInterface } = await import('node:readline');
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  // Suppress echo: write the prompt itself, swallow every keystroke redraw.
  rl._writeToOutput = (chunk) => {
    if (chunk.includes(label)) rl.output.write(label);
  };
  const answer = await new Promise((resolve) => rl.question(label, resolve));
  rl.close();
  process.stdout.write('\n');
  return answer.trim();
}

/**
 * Clear the storefront password gate, exactly as a browser does: fetch the
 * form for its session cookie and CSRF token, post the form back with the
 * password, and keep every cookie the store hands out along the way.
 *
 * Development stores cannot switch this gate off, so a reviewer's store will
 * normally need it. Whether the password was right is not judged here: a wrong
 * one re-renders the page with HTTP 200 rather than signalling failure, so the
 * caller decides based on whether the proxy request still lands on /password.
 */
async function clearStorefrontPassword(shop, password, jar) {
  const form = await fetch(`https://${shop}/password`, {
    headers: { cookie: jar.header() },
    redirect: 'manual',
  });
  jar.absorb(form);
  const html = await form.text();

  const res = await fetch(`https://${shop}/password`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: jar.header(),
      referer: `https://${shop}/password`,
    },
    body: new URLSearchParams({ ...hiddenFields(html), password }).toString(),
    redirect: 'manual',
  });
  jar.absorb(res);
}

const HELP = `Simulate one AI shopping agent visiting a store running AVA Pay.

Usage: node simulate-verified-agent.mjs your-store.myshopify.com [options]

Options:
  --password <storefront password>
        Clear the storefront password gate. Development stores always have
        one and cannot turn it off. The script prompts for it if it hits the
        gate without one, so it need never appear in shell history.
        AVA_STOREFRONT_PASSWORD is read as a fallback.

  --web-bot-auth
        Send a Web Bot Auth request instead of the default Visa-profile one,
        signed as an agent at
        ${PROBE_SIGNATURE_AGENT}, an origin that publishes
        no key directory. With no key to check the signature against, the
        verifier cannot reach a verdict, and the expected answer is HTTP 200
        with allow:false and reason verification_unavailable, listed on the
        Traffic page as "Could not check" rather than as a rejection. Exits 0
        on that outcome, 1 on any other.

  --help, -h
        Show this message.

With no options the script sends AVA Pay's public demo credential as a
verified Visa Trusted Agent Protocol agent, and the store should answer
HTTP 200 with allow:true, reason verified, and a one-time discount code.
`;

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    console.log(HELP);
    return;
  }
  const probe = args.includes('--web-bot-auth');
  const input = args.find((a) => !a.startsWith('--'));
  if (!input) {
    console.error(
      'Usage: node simulate-verified-agent.mjs your-store.myshopify.com [--password <storefront password>]',
    );
    process.exit(2);
  }
  // Accept a bare domain or a pasted URL.
  const shop = input.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

  const flagIndex = args.indexOf('--password');
  let password =
    (flagIndex !== -1 ? args[flagIndex + 1] : undefined) ??
    process.env.AVA_STOREFRONT_PASSWORD ??
    '';

  if (probe) {
    console.log('Web Bot Auth probe: signing as an agent whose key directory does not');
    console.log(`resolve (${PROBE_SIGNATURE_AGENT}), so the verifier`);
    console.log('cannot reach a verdict either way.\n');
  }
  console.log(`Sending a signed agent request to https://${shop}/apps/ava-pay/verify\n`);

  const jar = makeJar();
  // Sign immediately before each send, never once up front. Signatures carry a
  // created/expires window and the verifier enforces a maximum age, so a
  // request signed before the password prompt would age out while the human
  // types and come back signature_expired. Re-signing also gives each attempt
  // a fresh nonce, which the single-use replay guard requires.
  const build = probe ? buildWebBotAuthRequest : buildSignedAgentRequest;
  const send = () => {
    const signed = build(shop);
    const cookie = jar.header();
    return fetch(signed.url, {
      method: signed.method,
      headers: cookie ? { ...signed.headers, cookie } : signed.headers,
      body: signed.body,
      redirect: 'manual',
    });
  };
  const hitPasswordGate = (r) =>
    r.status >= 300 && r.status < 400 && /\/password/.test(r.headers.get('location') ?? '');

  let res;
  try {
    if (password) await clearStorefrontPassword(shop, password, jar);
    res = await send();

    // Still gated: either no password was supplied, or the one supplied was
    // wrong. Ask for it once and retry.
    if (hitPasswordGate(res)) {
      if (password) {
        console.error('That storefront password was not accepted by the store.');
        process.exit(1);
      }
      console.log('This store is password protected, which development stores always are.');
      password = await promptSecret('Storefront password: ');
      if (!password) {
        console.error(
          'No password given. Re-run with --password <storefront password>, or set\n' +
            'AVA_STOREFRONT_PASSWORD. Find it in the store admin under Online Store,\n' +
            'Preferences, Password protection.',
        );
        process.exit(1);
      }
      await clearStorefrontPassword(shop, password, jar);
      res = await send();
      if (hitPasswordGate(res)) {
        console.error('That storefront password was not accepted by the store.');
        process.exit(1);
      }
    }
  } catch (err) {
    console.error(`Could not reach ${shop}: ${err.message}`);
    process.exit(1);
  }

  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }

  console.log(`HTTP ${res.status}`);
  console.log(parsed ? JSON.stringify(parsed, null, 2) : text.slice(0, 500));
  console.log();

  // The probe is asking a different question, so it grades a different answer:
  // an inconclusive verdict is the success condition, and anything else,
  // including a verified one, means the path under test was not exercised.
  if (probe) {
    if (parsed?.allow === false && parsed.reason === 'verification_unavailable') {
      console.log('Could not check, and said so. There was no reachable directory to');
      console.log('resolve the agent key from, so nothing was proved either way. The');
      console.log('request still failed closed, but AVA Pay did not claim to have');
      console.log('blocked an agent it never managed to check.');
      console.log('');
      console.log('Open the AVA Pay app in the store admin and click Traffic: this');
      console.log('visit is listed as "Could not check" and is counted apart from');
      console.log('rejected requests.');
      return;
    }
    console.error('Expected allow:false with reason verification_unavailable.');
    if (parsed?.reason === 'agent_blocked') {
      console.error('agent_blocked means the verdict came back conclusive: the request');
      console.error('was rejected on its merits rather than left unchecked. Check that');
      console.error(`${PROBE_SIGNATURE_AGENT} is still admitted by the`);
      console.error('API allowlist, since an origin outside it is rejected, not fetched.');
    }
    process.exit(1);
  }

  if (parsed?.allow === true) {
    console.log('Verified. Open the AVA Pay app in the store admin and click');
    console.log('Traffic: this visit is listed with its protocol, agent identity');
    console.log('and verdict.');
    if (parsed.discount) {
      console.log(
        `\nThe merchant's policy also minted a one-time discount code: ` +
          `${parsed.discount.code} (${parsed.discount.percentage}%).`,
      );
    }
    return;
  }

  if (parsed && parsed.allow === false) {
    console.log('The request reached AVA Pay and was recorded on the Traffic page,');
    console.log(`but it was not admitted. Reason: ${parsed.reason}`);
    if (parsed.reason === 'no_session') {
      console.log('That reason means AVA Pay is not installed on this store.');
    }
    process.exit(1);
  }

  console.log('That response did not come from AVA Pay. If it is a redirect to');
  console.log('/password, the storefront password gate was not cleared: re-run with');
  console.log('--password <storefront password>. Otherwise check that AVA Pay is');
  console.log('installed on this store.');
  process.exit(1);
}

// Only run when executed directly, so tests can import the builder. Compared
// through realpath rather than by string: a file:// URL percent-encodes spaces,
// so the naive comparison silently skips main() from a path like
// "/Users/me/My Projects/".
function runningDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (runningDirectly()) {
  await main();
}
