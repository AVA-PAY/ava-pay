import { constants, randomUUID, sign as nodeSign, type KeyObject } from 'node:crypto';
import {
  buildTapObjectSignatureBase,
  TAP_BROWSER_TAG,
  type TapSignedObject,
  type TapTag,
} from '../protocol/visa-tap/index.js';
import type { SignedRequest } from './visa.js';

/**
 * Visa Trusted Agent Protocol — agent-side signing, real wire format.
 *
 * Byte-compatible with the tap-agent in github.com/visa/trusted-agent-protocol:
 * label sig2, covered components ("@authority" "@path"), `; `-separated
 * parameters, `keyId` spelling, tags agent-browser-auth / agent-payer-auth,
 * algorithms ed25519 or rsa-pss-sha256 (Python-style PSS MAX_LENGTH salt).
 */

export interface VisaTapSignInput {
  url: string;
  /** "GET" etc. — not covered by the TAP base but kept on the request. */
  method?: string;
  privateKey: KeyObject;
  /** Key identifier resolvable by the merchant (agent directory / Visa registry). */
  keyid: string;
  /** "ed25519" (default for ed25519 keys) or "rsa-pss-sha256" (default for RSA keys). */
  alg?: 'ed25519' | 'rsa-pss-sha256';
  tag?: TapTag;
  /** Defaults to now (seconds). */
  created?: number;
  /** Defaults to created + 480 (the spec's 8-minute maximum window). */
  expires?: number;
  nonce?: string;
  /** Defaults to "sig2" (what the sample emits). */
  label?: string;
  /** Parameter spelling: sample uses "keyId", spec text uses "keyid". Default "keyId". */
  keyParamName?: 'keyId' | 'keyid';
  extraHeaders?: Record<string, string>;
  body?: string;
}

export function signWithVisaTap(input: VisaTapSignInput): SignedRequest {
  const url = new URL(input.url);
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const expires = input.expires ?? created + 480;
  const nonce = input.nonce ?? randomUUID();
  const tag = input.tag ?? TAP_BROWSER_TAG;
  const label = input.label ?? 'sig2';
  const keyParamName = input.keyParamName ?? 'keyId';
  const alg =
    input.alg ?? (input.privateKey.asymmetricKeyType === 'ed25519' ? 'ed25519' : 'rsa-pss-sha256');

  // Exact sample-implementation parameter order and `; ` separators.
  const params =
    `("@authority" "@path"); created=${created}; expires=${expires}; ` +
    `${keyParamName}="${input.keyid}"; alg="${alg}"; nonce="${nonce}"; tag="${tag}"`;

  const signatureBase = [
    `"@authority": ${url.host}`,
    `"@path": ${url.pathname}`,
    `"@signature-params": ${params}`,
  ].join('\n');

  const signature = tapSign(alg, input.privateKey, Buffer.from(signatureBase, 'utf-8'));

  return {
    method: input.method ?? 'GET',
    url: input.url,
    headers: {
      host: url.host,
      ...(input.extraHeaders ?? {}),
      'signature-input': `${label}=${params}`,
      signature: `${label}=:${signature.toString('base64')}:`,
    },
    ...(input.body !== undefined ? { body: input.body } : { body: undefined }),
  };
}

/**
 * Sign a TAP body object (agenticConsumer / agenticPaymentContainer): appends
 * the `signature` field over buildTapObjectSignatureBase of the given fields,
 * in their insertion order. `nonce`, `kid`, `alg` must already be present and
 * `kid`/`alg`/key must match the message signature per spec.
 */
export function signTapObject(
  fields: Omit<TapSignedObject, 'signature'>,
  privateKey: KeyObject,
): TapSignedObject {
  const base = buildTapObjectSignatureBase(fields);
  const signature = tapSign(String(fields.alg), privateKey, Buffer.from(base, 'utf-8'));
  return { ...fields, signature: signature.toString('base64url') } as TapSignedObject;
}

function tapSign(alg: string, key: KeyObject, data: Buffer): Buffer {
  const lower = alg.toLowerCase();
  if (lower === 'ed25519') return nodeSign(null, data, key);
  if (lower === 'rsa-pss-sha256' || lower === 'ps256') {
    return nodeSign('sha256', data, {
      key,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength:
        lower === 'ps256' ? constants.RSA_PSS_SALTLEN_DIGEST : constants.RSA_PSS_SALTLEN_MAX_SIGN,
    });
  }
  throw new Error(`unsupported TAP signing algorithm: ${alg}`);
}
