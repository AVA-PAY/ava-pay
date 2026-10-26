/**
 * Generate tests/fixtures/es256-web-bot-auth-2026-10-26.json: a frozen
 * ES256 (ecdsa-p256-sha256) Web Bot Auth exchange (key directory body, its
 * Appendix B response proof, and a signed request), all made with the RFC 9421
 * Appendix B.1.3 test key (test-key-ecc-p256), whose RFC 7638 thumbprint is
 * the pinned vector in tests/web-bot-auth.test.ts.
 *
 * ECDSA signing is randomized, so regenerating produces different (equally
 * valid) signature bytes: the committed fixture is frozen on purpose and only
 * needs regenerating if the signed SHAPES change. Build the SDK first
 * (`npm run build -w @ava-pay/agent`), then:
 *
 *   node scripts/generate-es256-wba-fixture.mjs
 *
 * The clock is pinned (CREATED/now in the fixture), so the fixture does not
 * age.
 */
import { createPrivateKey } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  ecP256JwkThumbprint,
  signDirectoryResponse,
} from '../packages/agent-sdk/dist/protocol/web-bot-auth/index.js';
import { signWithWebBotAuth } from '../packages/agent-sdk/dist/index.js';

// RFC 9421 Appendix B.1.3 test-key-ecc-p256 (public test material).
const JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA',
  y: 'Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0',
  d: 'UpuF81l-kOxbjf7T4mNSv0r5tN67Gim7rnf6EFpcYDs',
};

const ORIGIN = 'https://agent-es256.example';
const CREATED = 1_761_480_000; // 2026-10-26, pinned
const EXPIRES = CREATED + 120;

const privateKey = createPrivateKey({ key: JWK, format: 'jwk' });
const thumbprint = ecP256JwkThumbprint(JWK.x, JWK.y);

const { d: _d, ...publicJwk } = JWK;
const body = JSON.stringify({ keys: [{ ...publicJwk, kid: thumbprint, alg: 'ES256', use: 'sig' }] });

const proof = signDirectoryResponse({
  signers: [{ privateKey, keyid: thumbprint }],
  authority: new URL(ORIGIN).host,
  body,
  created: CREATED,
  expires: CREATED + 3600,
});

const request = signWithWebBotAuth({
  method: 'GET',
  url: 'https://shop.example.com/products/tool-1234',
  signatureAgent: ORIGIN,
  privateKey,
  created: CREATED,
  expires: EXPIRES,
  signatureAgentFormat: 'dictionary',
  nonce: 'ZXMyNTYtZml4dHVyZS1ub25jZQ',
});

const fixture = {
  note: 'ES256 Web Bot Auth fixture, RFC 9421 B.1.3 test key. See the generator script header.',
  origin: ORIGIN,
  now: CREATED + 5,
  thumbprint,
  directory: {
    body,
    headers: {
      'content-type': 'application/http-message-signatures-directory+json',
      'content-digest': proof['content-digest'],
      'signature-input': proof['signature-input'],
      signature: proof.signature,
    },
  },
  request: { method: request.method, url: request.url, headers: request.headers },
};

const out = fileURLToPath(new URL('../tests/fixtures/es256-web-bot-auth-2026-10-26.json', import.meta.url));
writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`wrote ${out}`);
