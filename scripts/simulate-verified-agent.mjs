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

import { createHash, createPrivateKey, randomUUID, sign as edSign } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DEMO_AGENT_ID = 'agent_demo_public';
const DEMO_PRIVATE_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  d: 'RfgxZQvu3WXbskCO0QZlhSOjguLIuTz8ANz0x3uCvRo',
  x: 'yKCkvxtkVtmYT1xK0FFuvQPFAQqQ_z6Zg9q6VKsJTU4',
};

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

async function main() {
  const args = process.argv.slice(2);
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

  console.log(`Sending a signed agent request to https://${shop}/apps/ava-pay/verify\n`);

  const jar = makeJar();
  // Sign immediately before each send, never once up front. Signatures carry a
  // created/expires window and the verifier enforces a maximum age, so a
  // request signed before the password prompt would age out while the human
  // types and come back signature_expired. Re-signing also gives each attempt
  // a fresh nonce, which the single-use replay guard requires.
  const send = () => {
    const signed = buildSignedAgentRequest(shop);
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
