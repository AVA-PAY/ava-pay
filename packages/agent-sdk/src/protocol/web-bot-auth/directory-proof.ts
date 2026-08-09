import { sign as nodeSign, type KeyObject } from 'node:crypto';
import { computeContentDigest, verifyEd25519 } from '../visa/http-signatures.js';
import type { WebBotAuthKey } from './index.js';

/**
 * Appendix B directory proof-of-possession (draft-meunier-webbotauth-httpsig).
 *
 * The directory server signs its RESPONSE, once per published key, with an HTTP
 * Message Signature made BY that key. A verifier that checks the proof learns
 * the directory actually holds the private half of each key it publishes, not
 * just that it can serve a JSON blob over TLS.
 *
 * The covered set is fixed by the draft: `@authority;req` (the authority of the
 * request that fetched the directory, so the proof is bound to the host that
 * served it) and `content-digest` (over the response body, so the key list
 * cannot be swapped under a captured signature). Parameters carry
 * created/expires, keyid = the key's RFC 7638 thumbprint, and
 * tag="http-message-signatures-directory".
 *
 * No live directory serves these as of 2026-08-09 (checked chatgpt.com and
 * www.shopify.com), so the exact base construction here is our documented
 * interpretation, mirroring how buildTapObjectSignatureBase pins the Visa TAP
 * base. It is the single place to change if the WG publishes a normative
 * example.
 */

export const DIRECTORY_PROOF_TAG = 'http-message-signatures-directory';

/**
 * Per-key proof outcome. `absent` = the directory offered no proof for this key
 * (tolerated under grace, dropped without it). `invalid` = a proof was offered
 * and failed verification (a bad window, a wrong key, or a broken signature);
 * never tolerated. `valid` = a proof was offered and verified.
 */
export type KeyProofStatus = 'valid' | 'invalid' | 'absent';

/** Build the RFC 9421 signature base for one directory proof signature. */
export function buildDirectoryProofBase(params: {
  authority: string;
  contentDigest: string;
  created: number;
  expires: number;
  keyid: string;
}): string {
  const sigParams =
    `("@authority";req "content-digest")` +
    `;created=${params.created};expires=${params.expires}` +
    `;keyid="${params.keyid}";tag="${DIRECTORY_PROOF_TAG}"`;
  return [
    `"@authority";req: ${params.authority}`,
    `"content-digest": ${params.contentDigest}`,
    `"@signature-params": ${sigParams}`,
  ].join('\n');
}

export interface DirectoryProofSigner {
  privateKey: KeyObject;
  /** The key's RFC 7638 thumbprint, used as the signature keyid. */
  keyid: string;
}

/**
 * Produce Appendix B response headers for a directory body. Test/tooling side:
 * signs one proof per signer, all bound to `authority` and the body digest.
 */
export function signDirectoryResponse(params: {
  signers: DirectoryProofSigner[];
  authority: string;
  body: string;
  created: number;
  expires: number;
}): { 'content-digest': string; 'signature-input': string; signature: string } {
  const contentDigest = computeContentDigest(params.body);
  const inputs: string[] = [];
  const sigs: string[] = [];
  params.signers.forEach((signer, i) => {
    const label = `binding${i}`;
    const base = buildDirectoryProofBase({
      authority: params.authority,
      contentDigest,
      created: params.created,
      expires: params.expires,
      keyid: signer.keyid,
    });
    const sig = nodeSign(null, Buffer.from(base), signer.privateKey);
    const sigParams =
      `("@authority";req "content-digest")` +
      `;created=${params.created};expires=${params.expires}` +
      `;keyid="${signer.keyid}";tag="${DIRECTORY_PROOF_TAG}"`;
    inputs.push(`${label}=${sigParams}`);
    sigs.push(`${label}=:${sig.toString('base64')}:`);
  });
  return {
    'content-digest': contentDigest,
    'signature-input': inputs.join(', '),
    signature: sigs.join(', '),
  };
}

interface ProofInput {
  label: string;
  keyid?: string;
  tag?: string;
  created?: number;
  expires?: number;
}

/** Parse the response Signature-Input dictionary into per-label proof params. */
function parseProofInputs(signatureInput: string): ProofInput[] {
  const memberRe = /([A-Za-z0-9_-]+)=\([^)]*\)((?:;[a-z]+(?:="[^"]*"|=[^;,\s]+)?)*)/g;
  const out: ProofInput[] = [];
  let m: RegExpExecArray | null;
  while ((m = memberRe.exec(signatureInput)) !== null) {
    const params = m[2] ?? '';
    const num = (name: string): number | undefined => {
      const found = params.match(new RegExp(`;${name}=([0-9]+)`));
      return found ? Number(found[1]) : undefined;
    };
    const str = (name: string): string | undefined => {
      const found = params.match(new RegExp(`;${name}="([^"]*)"`));
      return found ? found[1] : undefined;
    };
    out.push({
      label: m[1]!,
      keyid: str('keyid'),
      tag: str('tag'),
      created: num('created'),
      expires: num('expires'),
    });
  }
  return out;
}

/** Parse the response Signature dictionary into label -> signature bytes. */
function parseProofSignatures(signature: string): Map<string, Buffer> {
  const memberRe = /([A-Za-z0-9_-]+)=:([^:]*):/g;
  const out = new Map<string, Buffer>();
  let m: RegExpExecArray | null;
  while ((m = memberRe.exec(signature)) !== null) {
    out.set(m[1]!, Buffer.from(m[2]!, 'base64'));
  }
  return out;
}

/**
 * Classify every key in `keys` by its Appendix B proof. A key with no matching
 * proof signature is `absent`; a key whose proof is present but fails the
 * window, is missing its signature bytes, or does not verify is `invalid`; a
 * key whose proof verifies is `valid`. Proof signatures for keyids not in the
 * directory are ignored.
 */
export function verifyDirectoryProofs(params: {
  authority: string;
  body: string;
  signatureInput: string | undefined;
  signature: string | undefined;
  now: number;
  skewSeconds: number;
  keys: WebBotAuthKey[];
}): Map<string, KeyProofStatus> {
  const status = new Map<string, KeyProofStatus>();
  for (const key of params.keys) status.set(key.thumbprint, 'absent');

  if (!params.signatureInput || !params.signature) return status;

  const contentDigest = computeContentDigest(params.body);
  const keyByThumbprint = new Map(params.keys.map((key) => [key.thumbprint, key]));
  const signatures = parseProofSignatures(params.signature);

  for (const input of parseProofInputs(params.signatureInput)) {
    if (input.tag !== DIRECTORY_PROOF_TAG) continue; // not a directory proof
    if (input.keyid === undefined) continue;
    const key = keyByThumbprint.get(input.keyid);
    if (!key) continue; // a proof for a key not in this directory: ignore it

    // From here the proof is "offered" for a known key: any failure is invalid,
    // never absent, so it can never be tolerated under grace.
    const sig = signatures.get(input.label);
    if (!sig || input.created === undefined || input.expires === undefined) {
      status.set(key.thumbprint, 'invalid');
      continue;
    }
    if (
      input.created > params.now + params.skewSeconds ||
      input.expires + params.skewSeconds < params.now
    ) {
      status.set(key.thumbprint, 'invalid');
      continue;
    }
    const base = buildDirectoryProofBase({
      authority: params.authority,
      contentDigest,
      created: input.created,
      expires: input.expires,
      keyid: input.keyid,
    });
    let ok = false;
    try {
      ok = verifyEd25519({ kty: 'OKP', crv: 'Ed25519', x: key.x }, base, sig);
    } catch {
      ok = false;
    }
    status.set(key.thumbprint, ok ? 'valid' : 'invalid');
  }

  return status;
}
