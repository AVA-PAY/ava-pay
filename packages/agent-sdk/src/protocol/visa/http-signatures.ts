import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';

type JsonWebKeyLike = { kty: string; [k: string]: unknown };

/**
 * Minimal RFC 9421 (HTTP Message Signatures) primitives.
 *
 * Scope intentionally narrow — one signature label per request, ed25519 only,
 * derived components (`@method`, `@target-uri`, `@authority`) plus arbitrary
 * lowercase header references. Structured-field rendering of header values is
 * not applied; values are taken as-is, which matches real-world Visa TAP
 * signers.
 *
 * Reference: https://www.rfc-editor.org/rfc/rfc9421
 */

export class SignatureParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SignatureParseError';
  }
}

export interface ParsedSignatureInput {
  label: string;
  components: string[];
  rawValue: string;
  parameters: {
    keyid?: string;
    created?: number;
    expires?: number;
    alg?: string;
    nonce?: string;
  };
}

export function parseSignatureInput(headerValue: string): ParsedSignatureInput {
  const value = headerValue.trim();
  rejectIfMultiDictionary(value, 'signature-input');

  const eq = value.indexOf('=');
  if (eq === -1) throw new SignatureParseError('Signature-Input missing `label=`');
  const label = value.slice(0, eq).trim();
  const rest = value.slice(eq + 1).trim();
  if (!rest.startsWith('(')) {
    throw new SignatureParseError('Signature-Input components must be a parenthesized list');
  }
  const close = rest.indexOf(')');
  if (close === -1) {
    throw new SignatureParseError('Signature-Input has unterminated component list');
  }
  const componentsRaw = rest.slice(1, close).trim();
  const paramsRaw = rest.slice(close + 1);

  const components: string[] = [];
  const re = /"([^"]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(componentsRaw)) !== null) {
    const name = m[1];
    if (name === undefined || name === '') {
      throw new SignatureParseError('Empty component in Signature-Input');
    }
    components.push(name);
  }
  if (components.length === 0) {
    throw new SignatureParseError('Signature-Input has no covered components');
  }

  const parameters: ParsedSignatureInput['parameters'] = {};
  if (paramsRaw.trim().startsWith(';')) {
    const segs = paramsRaw.trim().slice(1).split(';');
    for (const seg of segs) {
      const idx = seg.indexOf('=');
      if (idx === -1) continue;
      const name = seg.slice(0, idx).trim();
      let raw = seg.slice(idx + 1).trim();
      if (raw.startsWith('"') && raw.endsWith('"')) raw = raw.slice(1, -1);
      switch (name) {
        case 'keyid':
          parameters.keyid = raw;
          break;
        case 'created':
        case 'expires': {
          const n = Number(raw);
          if (!Number.isFinite(n)) {
            throw new SignatureParseError(`Signature-Input ${name} is not a number`);
          }
          parameters[name] = n;
          break;
        }
        case 'alg':
          parameters.alg = raw;
          break;
        case 'nonce':
          parameters.nonce = raw;
          break;
        default:
          break;
      }
    }
  }

  return { label, components, rawValue: rest, parameters };
}

export function parseSignature(headerValue: string, expectedLabel: string): Buffer {
  const value = headerValue.trim();
  rejectIfMultiDictionary(value, 'signature');

  const eq = value.indexOf('=');
  if (eq === -1) throw new SignatureParseError('Signature header missing `label=`');
  const label = value.slice(0, eq).trim();
  if (label !== expectedLabel) {
    throw new SignatureParseError(
      `Signature label "${label}" does not match Signature-Input label "${expectedLabel}"`,
    );
  }
  const rest = value.slice(eq + 1).trim();
  if (!(rest.startsWith(':') && rest.endsWith(':'))) {
    throw new SignatureParseError('Signature value must be wrapped in colons (byte sequence)');
  }
  const b64 = rest.slice(1, -1);
  let buf: Buffer;
  try {
    buf = Buffer.from(b64, 'base64');
  } catch {
    throw new SignatureParseError('Signature value is not valid base64');
  }
  if (buf.length !== 64) {
    throw new SignatureParseError(`Ed25519 signature must be 64 bytes, got ${buf.length}`);
  }
  return buf;
}

export interface SignatureBaseInputs {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export function buildSignatureBase(
  parsed: ParsedSignatureInput,
  inputs: SignatureBaseInputs,
): string {
  const lines: string[] = [];
  for (const comp of parsed.components) {
    lines.push(`"${comp}": ${resolveComponent(comp, inputs)}`);
  }
  lines.push(`"@signature-params": ${parsed.rawValue}`);
  return lines.join('\n');
}

function resolveComponent(name: string, inputs: SignatureBaseInputs): string {
  if (name === '@method') return inputs.method.toUpperCase();
  if (name === '@target-uri') return inputs.url;
  if (name === '@authority') {
    try {
      return new URL(inputs.url).host;
    } catch {
      throw new SignatureParseError(`@authority requires a valid URL, got: ${inputs.url}`);
    }
  }
  if (name.startsWith('@')) {
    throw new SignatureParseError(`Unsupported derived component: ${name}`);
  }
  const lower = name.toLowerCase();
  const v = inputs.headers[lower];
  if (v === undefined) {
    throw new SignatureParseError(`Covered header missing from request: ${name}`);
  }
  return v;
}

export function verifyEd25519(
  publicKey: KeyObject | string | object,
  signatureBase: string,
  signature: Buffer,
): boolean {
  const key =
    typeof publicKey === 'string'
      ? createPublicKey(publicKey)
      : publicKey instanceof Object && 'asymmetricKeyType' in (publicKey as KeyObject)
        ? (publicKey as KeyObject)
        : createPublicKey({ key: publicKey as JsonWebKeyLike, format: 'jwk' });
  return cryptoVerify(null, Buffer.from(signatureBase), key, signature);
}

/**
 * Compute the canonical Content-Digest header value for a request body, per
 * RFC 9530 (Digest Fields).
 */
export function computeContentDigest(body: string | undefined): string {
  const data = body ?? '';
  const hash = createHash('sha256').update(data).digest('base64');
  return `sha-256=:${hash}:`;
}

function rejectIfMultiDictionary(value: string, name: string): void {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '"') inString = !inString;
    else if (!inString && c === '(') depth++;
    else if (!inString && c === ')') depth--;
    else if (!inString && depth === 0 && c === ',') {
      throw new SignatureParseError(
        `Multiple ${name} entries are not supported (only one signature per request).`,
      );
    }
  }
}
