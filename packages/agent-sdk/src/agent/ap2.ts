import { createHash, randomBytes, sign as nodeSign, type KeyObject } from 'node:crypto';
import {
  computeCheckoutHash,
  VCT_CHECKOUT,
  VCT_OPEN_CHECKOUT,
  VCT_OPEN_PAYMENT,
  VCT_PAYMENT,
  type Checkout,
  type PaymentMandate,
} from '../protocol/ap2/mandates.js';

/**
 * AP2 v0.2 — agent-side mandate creation (dSD-JWT chains).
 *
 * CLEAN BREAK from v0.1: the Intent/Cart mandate API (signIntentMandate,
 * signCartMandate, buildAp2Headers) is gone, replaced by the Checkout/Payment
 * mandate chain model of AP2 v0.2.0 (github.com/google-agentic-commerce/AP2).
 * @ava-pay/agent has not shipped a 0.2.0 release, so no published API breaks.
 *
 * Wire form mirrors the reference MandateClient:
 *   - root SD-JWT (user-signed open mandate):
 *       header {alg, kid}; payload { delegate_payload: [{"...": digest}],
 *       _sd_alg: "sha-256" }; one array-element disclosure carrying the
 *       mandate object; compact form `jwt~disclosure~`.
 *   - KB hop (holder-signed closed mandate): header {alg, typ: "kb+sd-jwt"};
 *       payload additionally carries iat/aud/nonce + sd_hash binding to the
 *       previous token; joined `prev~~hop`.
 *
 * AVA's HTTP binding of AP2 v0.2 (AP2 itself defines A2A message transport,
 * not HTTP headers):
 *   Ap2-Checkout-Mandate: <open>~~<closed>   (dSD-JWT chain)
 *   Ap2-Payment-Mandate:  <open>~~<closed>   (optional second chain)
 * aud = merchant origin (https://host); nonce = single-use random value the
 * verifier deduplicates.
 */

export interface Ap2KeyRef {
  privateKey: KeyObject;
  /** kid resolvable by the merchant's federated directory (root keys only). */
  kid?: string;
}

function b64u(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

function signCompactJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: KeyObject,
): string {
  const signingInput = `${b64u(header)}.${b64u(payload)}`;
  const alg = key.asymmetricKeyType;
  let sig: Buffer;
  if (alg === 'ed25519') {
    sig = nodeSign(null, Buffer.from(signingInput), key);
  } else if (alg === 'ec') {
    sig = nodeSign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' });
  } else {
    throw new Error(`unsupported AP2 signing key type: ${alg}`);
  }
  return `${signingInput}.${sig.toString('base64url')}`;
}

function jwsAlgOf(key: KeyObject): string {
  return key.asymmetricKeyType === 'ed25519' ? 'EdDSA' : 'ES256';
}

/** One array-element disclosure ([salt, value]) + its sha-256 digest. */
function makeDisclosure(value: Record<string, unknown>): { disclosure: string; digest: string } {
  const salt = randomBytes(16).toString('base64url');
  const disclosure = Buffer.from(JSON.stringify([salt, value])).toString('base64url');
  const digest = createHash('sha256').update(disclosure, 'ascii').digest('base64url');
  return { disclosure, digest };
}

/** Sign a root SD-JWT whose delegate payload is `mandate`. Returns `jwt~disclosure~`. */
export function createRootMandate(mandate: Record<string, unknown>, issuer: Ap2KeyRef): string {
  const { disclosure, digest } = makeDisclosure(mandate);
  const header: Record<string, unknown> = {
    alg: jwsAlgOf(issuer.privateKey),
    ...(issuer.kid !== undefined ? { kid: issuer.kid } : {}),
  };
  const payload = { delegate_payload: [{ '...': digest }], _sd_alg: 'sha-256' };
  return `${signCompactJwt(header, payload, issuer.privateKey)}~${disclosure}~`;
}

export interface PresentMandateInput {
  /** The preceding token (`...~` form or full chain). */
  prevToken: string;
  /** This hop's signing key — must be the previous hop's cnf key. */
  holderKey: KeyObject;
  /** The mandate object this hop discloses (terminal unless it carries cnf). */
  mandate: Record<string, unknown>;
  /** Merchant origin, e.g. "https://shop.example.com". */
  aud: string;
  /** Single-use nonce; the verifier deduplicates it. */
  nonce: string;
  iat?: number;
}

/** Append one KB hop to `prevToken`. Returns the `~~`-joined chain. */
export function presentMandate(input: PresentMandateInput): string {
  const prevSegments = input.prevToken.split('~~');
  const prevLast = prevSegments[prevSegments.length - 1]!;
  const prevForBinding = prevLast.endsWith('~') ? prevLast : `${prevLast}~`;
  const sdHash = createHash('sha256').update(prevForBinding, 'ascii').digest('base64url');

  const terminal = !('cnf' in input.mandate);
  const { disclosure, digest } = makeDisclosure(input.mandate);
  const header = {
    alg: jwsAlgOf(input.holderKey),
    typ: terminal ? 'kb+sd-jwt' : 'kb+sd-jwt+kb',
  };
  const payload = {
    delegate_payload: [{ '...': digest }],
    _sd_alg: 'sha-256',
    iat: input.iat ?? Math.floor(Date.now() / 1000),
    aud: input.aud,
    nonce: input.nonce,
    sd_hash: sdHash,
  };
  const hop = `${signCompactJwt(header, payload, input.holderKey)}~${disclosure}~`;

  const prevJoined = input.prevToken.endsWith('~')
    ? input.prevToken.slice(0, -1)
    : input.prevToken;
  return `${prevJoined}~~${hop}`;
}

// ─── High-level helpers (demo + tests) ──────────────────────────────────────

/** Merchant-signed checkout JWT (the artifact the closed mandate commits to). */
export function makeCheckoutJwt(checkout: Checkout, merchantKey: KeyObject, kid?: string): string {
  return signCompactJwt(
    { alg: jwsAlgOf(merchantKey), typ: 'JWT', ...(kid !== undefined ? { kid } : {}) },
    checkout as unknown as Record<string, unknown>,
    merchantKey,
  );
}

export interface CheckoutChainInput {
  /** Root issuer (the user / credential provider); kid must resolve in the directory. */
  user: Required<Ap2KeyRef>;
  /** The agent the open mandate delegates to (its public key becomes cnf.jwk). */
  agentPrivateKey: KeyObject;
  agentPublicKey: KeyObject;
  /** Open-mandate constraints (checkout.allowed_merchants / checkout.line_items / custom). */
  constraints: Array<Record<string, unknown>>;
  /** The merchant-signed checkout JWT this chain closes over. */
  checkoutJwt: string;
  aud: string;
  nonce: string;
  iat?: number;
  exp?: number;
}

/** Build a complete v0.2 Checkout Mandate chain: open (user) ~~ closed (agent). */
export function buildCheckoutMandateChain(input: CheckoutChainInput): string {
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const open = createRootMandate(
    {
      vct: VCT_OPEN_CHECKOUT,
      constraints: input.constraints,
      cnf: { jwk: input.agentPublicKey.export({ format: 'jwk' }) },
      iat,
      exp: input.exp ?? iat + 3600,
    },
    input.user,
  );
  return presentMandate({
    prevToken: open,
    holderKey: input.agentPrivateKey,
    mandate: {
      vct: VCT_CHECKOUT,
      checkout_jwt: input.checkoutJwt,
      checkout_hash: computeCheckoutHash(input.checkoutJwt),
      iat,
      exp: input.exp ?? iat + 600,
    },
    aud: input.aud,
    nonce: input.nonce,
    iat,
  });
}

export interface PaymentChainInput {
  user: Required<Ap2KeyRef>;
  agentPrivateKey: KeyObject;
  agentPublicKey: KeyObject;
  constraints: Array<Record<string, unknown>>;
  /** The closed payment mandate (transaction_id must be the checkout hash). */
  payment: Omit<PaymentMandate, 'vct' | 'iat' | 'exp'>;
  aud: string;
  nonce: string;
  iat?: number;
  exp?: number;
}

/** Build a v0.2 Payment Mandate chain: open (user) ~~ closed (agent). */
export function buildPaymentMandateChain(input: PaymentChainInput): string {
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const open = createRootMandate(
    {
      vct: VCT_OPEN_PAYMENT,
      constraints: input.constraints,
      cnf: { jwk: input.agentPublicKey.export({ format: 'jwk' }) },
      iat,
      exp: input.exp ?? iat + 3600,
    },
    input.user,
  );
  return presentMandate({
    prevToken: open,
    holderKey: input.agentPrivateKey,
    mandate: { vct: VCT_PAYMENT, ...input.payment, iat, exp: input.exp ?? iat + 600 },
    aud: input.aud,
    nonce: input.nonce,
    iat,
  });
}
