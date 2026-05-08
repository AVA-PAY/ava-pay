/**
 * AVA Pay landing-page demo.
 *
 * Browser-side: generates a real Ed25519 keypair via Web Crypto, exports the
 * public JWK, registers it with the directory, then either signs a Visa TAP
 * request (RFC 9421) or builds an AP2 mandate chain (compact JWS), POSTs to
 * /verify, and renders the verdict.
 *
 * No simulation; every byte is real cryptography. Web Crypto Ed25519 has been
 * widely supported across Chrome, Firefox, and Safari since 2024-2025.
 */

const $ = (sel) => document.querySelector(sel);
// Unique per page load so concurrent visitors don't collide and the verifier's
// directory cache always has a fresh-key entry to find.
const DEMO_AGENT_ID = `agent_demo_browser_${Math.random().toString(36).slice(2, 10)}`;
const MERCHANT_HOST = window.location.host;
const MERCHANT_URL = `${window.location.protocol}//${MERCHANT_HOST}/cart`;

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
      list.innerHTML = `<p class="section-lede">No agents registered yet — register the demo agent below to see it appear here.</p>`;
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
    list.innerHTML = `<p class="section-lede">Couldn't load directory: ${escapeHtml(err.message)}</p>`;
  }
}

async function runDemo() {
  const protocol = document.querySelector('input[name="protocol"]:checked').value;
  const buyerName = $('#buyerName').value.trim() || 'Alex';
  const spendCap = Math.max(1, Number($('#spendCap').value));
  const cartTotal = Math.max(0.01, Number($('#cartTotal').value));

  const out = $('#demoOutput');
  const signedOut = $('#signedOut');
  const verdictOut = $('#verdictOut');
  out.hidden = false;
  signedOut.textContent = 'Generating keypair…';
  verdictOut.textContent = '';

  try {
    // 1. Fresh keypair via Web Crypto.
    const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);

    // 2. Register with the hosted directory (open POST in dev; bearer-token-protected in prod).
    signedOut.textContent = 'Registering with the AVA Agent Directory…';
    const reg = await fetch('/directory/agents', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        agentId: DEMO_AGENT_ID,
        issuer: 'Browser Demo',
        url: window.location.origin,
        keys: [{ alg: 'ed25519', jwk: publicJwk, protocols: ['visa', 'ap2'] }],
      }),
    });
    if (!reg.ok && reg.status !== 401) {
      throw new Error(`Directory registration returned ${reg.status}`);
    }
    if (reg.status === 401) {
      signedOut.textContent =
        'Directory registration is gated on this instance (DIRECTORY_REGISTRATION_TOKEN is set).\n' +
        'The verification step below will return unknown_agent unless this agent\'s key is preloaded.';
    }

    // 3. Sign + verify in the chosen protocol.
    let signed;
    if (protocol === 'visa') {
      signed = await signVisa({ keys, buyerName, spendCap, cartTotal });
    } else {
      signed = await signAp2({ keys, buyerName, spendCap, cartTotal });
    }
    signedOut.textContent = formatSigned(signed);

    verdictOut.textContent = 'Calling /verify…';
    const verifyRes = await fetch('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(signed),
    });
    const verdict = await verifyRes.json();
    verdictOut.innerHTML = formatVerdict(verifyRes.status, verdict);

    // Refresh the directory view.
    loadDirectory();
  } catch (err) {
    verdictOut.textContent = `error: ${err.message}`;
  }
}

// ─── Visa TAP (RFC 9421) ────────────────────────────────────────────────────

async function signVisa({ keys, buyerName, spendCap, cartTotal }) {
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
  const sigInputValue = `(${componentList});created=${created};expires=${expires};keyid="${DEMO_AGENT_ID}";alg="ed25519"`;
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
    keys.privateKey,
    new TextEncoder().encode(signatureBase),
  );
  const sigB64 = arrayBufferToBase64(sigBytes);

  return {
    method: 'POST',
    url: MERCHANT_URL,
    headers: {
      ...headerMap,
      'signature-input': `sig1=${sigInputValue}`,
      signature: `sig1=:${sigB64}:`,
    },
    body,
  };
}

async function sha256ContentDigest(body) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
  return `sha-256=:${arrayBufferToBase64(buf)}:`;
}

// ─── AP2 (compact JWS) ──────────────────────────────────────────────────────

async function signAp2({ keys, buyerName, spendCap, cartTotal }) {
  const now = Math.floor(Date.now() / 1000);
  const totalMinor = Math.round(cartTotal * 100);
  const intentJti = `intent_${Date.now()}`;

  const intentClaims = {
    iss: DEMO_AGENT_ID,
    iat: now - 5,
    exp: now + 600,
    jti: intentJti,
    ap2: {
      type: 'intent',
      sub: 'buyer_browser_demo',
      spend_limit: { value: spendCap * 100, currency: 'USD' },
      allowed_merchants: [MERCHANT_HOST],
    },
  };
  const cartClaims = {
    iss: DEMO_AGENT_ID,
    iat: now - 1,
    exp: now + 60,
    jti: `cart_${Date.now()}`,
    ap2: {
      type: 'cart',
      intent_ref: intentJti,
      merchant: MERCHANT_HOST,
      items: [{ sku: 'TOOL-1234', qty: 1, price: totalMinor }],
      total: { value: totalMinor, currency: 'USD' },
    },
  };

  const intentJws = await signCompactJws(intentClaims, keys.privateKey);
  const cartJws = await signCompactJws(cartClaims, keys.privateKey);

  return {
    method: 'POST',
    url: MERCHANT_URL,
    headers: {
      host: MERCHANT_HOST,
      'ap2-attestation': intentJws,
      'ap2-cart-mandate': cartJws,
    },
    body: '',
  };
}

async function signCompactJws(payload, privateKey) {
  const header = { alg: 'EdDSA', typ: 'JWT', kid: DEMO_AGENT_ID };
  const headerB64 = b64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = b64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${b64UrlEncode(new Uint8Array(sig))}`;
}

// ─── helpers ────────────────────────────────────────────────────────────────

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64UrlEncode(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
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

function formatVerdict(status, body) {
  const lines = [];
  if (body.trusted) {
    lines.push(`<span class="verdict-good">HTTP ${status} ✓ trusted</span>`);
    lines.push(`buyer: ${escapeHtml(body.buyerInfo.displayName ?? body.buyerInfo.buyerId)}`);
    lines.push(`mandate: ${escapeHtml(body.mandate.id)} (cap $${body.mandate.maxAmountMinor / 100} ${escapeHtml(body.mandate.currency)})`);
    if (body.discount !== undefined) lines.push(`discount hint: ${(body.discount * 100).toFixed(1)}%`);
    lines.push(`decision ttl: ${body.ttlSeconds}s`);
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
