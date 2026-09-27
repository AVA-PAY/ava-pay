/**
 * AVA Pay landing-page demo.
 *
 * Browser-side: imports the bundled public demo agent's private key, then
 * signs a real Visa TAP-style (RFC 9421) request, POSTs it to /verify, and
 * renders the verdict.
 *
 * The verifier deliberately demotes this agent: the verdict is trusted (the
 * point of the demo) but flagged demo, with no mandate and no discount,
 * because the private key below is public and anything it signs is
 * self-attested. The mandate shown under the verdict is therefore the one
 * THIS PAGE signed, labelled as such, not something the verifier vouched for.
 *
 * The AP2 demo was removed with the demo-agent demotion: it still signed the
 * retired v0.1 wire format, and a faithful v0.2 dSD-JWT chain would mean
 * duplicating the SDK's chain builder in this dependency-free file. The API
 * test suite proves the demo key can produce a valid v0.2 chain server side.
 *
 * The demo agent is pre-seeded into the hosted directory at server boot
 * (see src/directory/seed-demo.ts). Both halves of the keypair are public:
 * the agent has no real authority and only exists so the demo can show
 * end-to-end signature verification without exposing /directory/agents POST
 * to anonymous writers in production.
 *
 * If you fork this and stand up your own instance, regenerate the keypair
 * and update the JWKs here AND in src/directory/seed-demo.ts.
 *
 * Every byte signed and verified is real cryptography. Web Crypto Ed25519
 * has been widely supported across Chrome, Firefox, and Safari since 2024.
 */

// Bundled demo keypair. The corresponding public key is written to the
// hosted directory at server boot. The agent_id below must match
// DEMO_AGENT_ID in src/directory/seed-demo.ts.
const DEMO_AGENT_ID = 'agent_demo_public';
const DEMO_PRIVATE_JWK = {
  crv: 'Ed25519',
  d: 'RfgxZQvu3WXbskCO0QZlhSOjguLIuTz8ANz0x3uCvRo',
  x: 'yKCkvxtkVtmYT1xK0FFuvQPFAQqQ_z6Zg9q6VKsJTU4',
  kty: 'OKP',
};

const $ = (sel) => document.querySelector(sel);
const MERCHANT_HOST = window.location.host;
const MERCHANT_URL = `${window.location.protocol}//${MERCHANT_HOST}/cart`;

// Lazy-imported private key handle; first click pays the import cost.
let _demoPrivateKey = null;
async function getDemoPrivateKey() {
  if (_demoPrivateKey) return _demoPrivateKey;
  _demoPrivateKey = await crypto.subtle.importKey(
    'jwk',
    DEMO_PRIVATE_JWK,
    { name: 'Ed25519' },
    false,
    ['sign'],
  );
  return _demoPrivateKey;
}

document.addEventListener('DOMContentLoaded', () => {
  $('#runDemo').addEventListener('click', runDemo);
  loadDirectory();
});

async function loadDirectory() {
  const list = $('#directoryList');
  try {
    const res = await fetch('/directory/agents');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    if (!body.agents || body.agents.length === 0) {
      list.innerHTML = `<p class="lede" style="grid-column:1/-1;padding:24px">No agents registered yet. Register the demo agent below to see it appear here.</p>`;
      return;
    }
    list.innerHTML = body.agents
      .map((a) => `
        <div class="dir-card">
          <h4>${escapeHtml(a.issuer)}</h4>
          <div class="agent-id">${escapeHtml(a.agentId)}</div>
          <div class="protos">${(a.keys?.[0]?.protocols ?? []).map((p) => `<span>${p.toUpperCase()}</span>`).join('')}</div>
        </div>
      `)
      .join('');
  } catch (err) {
    list.innerHTML = `<p class="lede" style="grid-column:1/-1;padding:24px">Couldn't load directory: ${escapeHtml(err.message)}</p>`;
  }
}

async function runDemo() {
  const buyerName = $('#buyerName').value.trim() || 'Alex';
  const spendCap = Math.max(1, Number($('#spendCap').value));
  const cartTotal = Math.max(0.01, Number($('#cartTotal').value));

  const out = $('#demoOutput');
  const signedOut = $('#signedOut');
  const verdictOut = $('#verdictOut');
  out.hidden = false;
  signedOut.textContent = 'Loading demo agent key…';
  verdictOut.textContent = '';

  try {
    // 1. Import the bundled demo agent's private key.
    const privateKey = await getDemoPrivateKey();

    // 2. Sign a real RFC 9421 request. Keep the mandate the page created so
    // the verdict can show it labelled as page-signed input, never as
    // something the verifier vouched for.
    signedOut.textContent = 'Signing request…';
    const { request, mandate } = await signVisa({ privateKey, buyerName, spendCap, cartTotal });
    signedOut.textContent = formatSigned(request);

    // 3. POST it to /verify and render the verdict.
    verdictOut.textContent = 'Calling /verify…';
    const verifyRes = await fetch('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    });
    const verdict = await verifyRes.json();
    verdictOut.innerHTML = formatVerdict(verifyRes.status, verdict, mandate);

    // Refresh the directory view to confirm the demo agent is registered.
    loadDirectory();
  } catch (err) {
    verdictOut.textContent = `error: ${err.message}`;
  }
}

// ─── Visa TAP (RFC 9421) ────────────────────────────────────────────────────

async function signVisa({ privateKey, buyerName, spendCap, cartTotal }) {
  const totalMinor = Math.round(cartTotal * 100);
  const body = JSON.stringify({
    cart: [{ sku: 'TOOL-1234', qty: 1, price_minor: totalMinor }],
    total_minor: totalMinor,
    currency: 'USD',
  });
  const now = Math.floor(Date.now() / 1000);

  const mandate = {
    id: `mandate_${Date.now()}`,
    iat: now - 5,
    exp: now + 600,
    maxAmountMinor: spendCap * 100,
    currency: 'USD',
    allowedMerchants: [MERCHANT_HOST],
    buyer: { buyerId: 'buyer_browser_demo', country: 'US', displayName: buyerName },
  };
  const mandateB64 = btoa(JSON.stringify(mandate));
  const contentDigest = await sha256ContentDigest(body);

  const components = ['@method', '@target-uri', 'host', 'content-digest', 'x-ava-mandate'];
  const componentList = components.map((c) => `"${c}"`).join(' ');
  const created = now;
  const expires = now + 60;
  const nonce = crypto.randomUUID();
  const sigInputValue = `(${componentList});created=${created};expires=${expires};keyid="${DEMO_AGENT_ID}";alg="ed25519";nonce="${nonce}"`;
  const headerMap = {
    host: MERCHANT_HOST,
    'content-digest': contentDigest,
    'x-ava-mandate': mandateB64,
  };

  const lines = [];
  for (const comp of components) {
    let v;
    if (comp === '@method') v = 'POST';
    else if (comp === '@target-uri') v = MERCHANT_URL;
    else v = headerMap[comp];
    lines.push(`"${comp}": ${v}`);
  }
  lines.push(`"@signature-params": ${sigInputValue}`);
  const signatureBase = lines.join('\n');

  const sigBytes = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    new TextEncoder().encode(signatureBase),
  );
  const sigB64 = arrayBufferToBase64(sigBytes);

  return {
    request: {
      method: 'POST',
      url: MERCHANT_URL,
      headers: {
        ...headerMap,
        'signature-input': `sig1=${sigInputValue}`,
        signature: `sig1=:${sigB64}:`,
      },
      body,
    },
    mandate,
  };
}

async function sha256ContentDigest(body) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
  return `sha-256=:${arrayBufferToBase64(buf)}:`;
}

// ─── helpers ────────────────────────────────────────────────────────────────

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function formatSigned(signed) {
  const lines = [`${signed.method} ${signed.url}`];
  for (const [k, v] of Object.entries(signed.headers)) {
    const display = v.length > 110 ? `${v.slice(0, 100)}…` : v;
    lines.push(`  ${k}: ${display}`);
  }
  if (signed.body) {
    lines.push('');
    lines.push(`body: ${signed.body}`);
  }
  return lines.join('\n');
}

/**
 * Render the verifier's verdict, without letting the page's own input pass as
 * the verifier's word. The verifier strips the mandate from demo results (the
 * demo key is public, so its mandates are self-made), so the mandate printed
 * here is the one THIS PAGE signed, labelled as exactly that.
 */
function formatVerdict(status, body, signedMandate) {
  const lines = [];
  if (body.trusted) {
    lines.push(`<span class="verdict-good">HTTP ${status} ✓ trusted</span>`);
    if (body.agent && body.agent.id) lines.push(`agent: ${escapeHtml(body.agent.id)}`);
    if (body.protocol) lines.push(`protocol: ${escapeHtml(body.protocol)}`);
    if (signedMandate) {
      lines.push(
        `mandate signed by this page (demo input, not verifier output): ` +
        `${escapeHtml(signedMandate.id)} (cap $${signedMandate.maxAmountMinor / 100} ${escapeHtml(signedMandate.currency)})`,
      );
    }
    lines.push(`decision ttl: ${body.ttlSeconds}s`);
    if (body.demo) {
      lines.push('Demo agent: verified, but demo visits never earn a discount.');
    }
  } else {
    lines.push(`<span class="verdict-bad">HTTP ${status} ✗ blocked</span>`);
    lines.push(`reason: ${escapeHtml(body.reason)}`);
    lines.push(escapeHtml(body.message));
  }
  return lines.join('\n');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
