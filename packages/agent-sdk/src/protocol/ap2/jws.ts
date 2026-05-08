import { sign as nodeSign, verify as nodeVerify, type KeyObject } from 'node:crypto';
import type { JwsHeader } from './types.js';

/**
 * Minimal compact-JWS implementation for AP2 mandates.
 *
 * Compact JWS form is `<base64url(header)>.<base64url(payload)>.<base64url(signature)>`.
 * Signing input is the concatenation `<header>.<payload>` as ASCII bytes.
 *
 * Supports EdDSA (Ed25519) and ES256 (P-256). No JWE, no JWS-JSON, no RS256.
 *
 * Reference: RFC 7515 (JWS), RFC 8037 (EdDSA in JOSE).
 */

export class JwsParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JwsParseError';
  }
}

const ALLOWED_ALGS = new Set(['EdDSA', 'ES256']);

export interface ParsedJws<TPayload = unknown> {
  header: JwsHeader;
  payload: TPayload;
  signingInput: Buffer;
  signature: Buffer;
}

export function parseJws<TPayload = unknown>(token: string): ParsedJws<TPayload> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new JwsParseError('JWS must have exactly three dot-separated segments.');
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];

  let header: JwsHeader;
  let payload: TPayload;
  try {
    header = JSON.parse(b64UrlDecode(headerB64).toString('utf-8')) as JwsHeader;
  } catch {
    throw new JwsParseError('JWS header is not valid base64url JSON.');
  }
  try {
    payload = JSON.parse(b64UrlDecode(payloadB64).toString('utf-8')) as TPayload;
  } catch {
    throw new JwsParseError('JWS payload is not valid base64url JSON.');
  }

  if (!header.alg || !ALLOWED_ALGS.has(header.alg)) {
    throw new JwsParseError(`Unsupported alg: ${header.alg ?? '(missing)'}`);
  }
  if (typeof header.kid !== 'string' || header.kid.length === 0) {
    throw new JwsParseError('JWS header missing kid.');
  }

  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf-8');
  const signature = b64UrlDecode(sigB64);

  return { header, payload, signingInput, signature };
}

export function verifyJws(parsed: ParsedJws<unknown>, publicKey: KeyObject): boolean {
  try {
    if (parsed.header.alg === 'EdDSA') {
      return nodeVerify(null, parsed.signingInput, publicKey, parsed.signature);
    }
    if (parsed.header.alg === 'ES256') {
      return nodeVerify('sha256', parsed.signingInput, publicKey, parsed.signature);
    }
    return false;
  } catch {
    return false;
  }
}

export function signJws(
  header: JwsHeader,
  payload: unknown,
  privateKey: KeyObject,
): string {
  const headerB64 = b64UrlEncode(Buffer.from(JSON.stringify(header), 'utf-8'));
  const payloadB64 = b64UrlEncode(Buffer.from(JSON.stringify(payload), 'utf-8'));
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf-8');

  let signature: Buffer;
  if (header.alg === 'EdDSA') {
    signature = nodeSign(null, signingInput, privateKey);
  } else if (header.alg === 'ES256') {
    signature = nodeSign('sha256', signingInput, privateKey);
  } else {
    throw new Error(`Unsupported alg: ${header.alg as string}`);
  }

  return `${headerB64}.${payloadB64}.${b64UrlEncode(signature)}`;
}

function b64UrlDecode(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function b64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
