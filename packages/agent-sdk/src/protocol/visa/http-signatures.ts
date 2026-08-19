import { createHash, createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';

type JsonWebKeyLike = { kty: string; [k: string]: unknown };

/**
 * Minimal RFC 9421 (HTTP Message Signatures) primitives.
 *
 * Scope intentionally narrow: one signature label per request, ed25519 only,
 * derived components (`@method`, `@target-uri`, `@authority`, `@path`,
 * `@query`) plus arbitrary lowercase header references. Structured-field
 * rendering of header values is not applied; values are taken as-is, which
 * matches real-world Visa TAP and Web Bot Auth signers.
 *
 * ONE exception to "values as-is": a component identifier carrying the RFC 9421
 * Section 2.1 `key` parameter selects a single member out of a Dictionary
 * header, so that member's value is what goes in the base. Web Bot Auth -02
 * Section 5.2.1 requires exactly this for Signature-Agent
 * (`"signature-agent";key="sig1"`), and its Appendix E vectors are signed that
 * way. Component parameters are preserved verbatim from Signature-Input, since
 * the identifier is reproduced in the base byte for byte.
 *
 * Despite living under protocol/visa (its first consumer), this is the
 * generic RFC 9421 core — the Web Bot Auth verifier imports it too.
 *
 * Reference: https://www.rfc-editor.org/rfc/rfc9421
 */

export class SignatureParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SignatureParseError';
  }
}

/**
 * One covered component identifier, split into the parts the signature base
 * needs. `params` is kept verbatim because the identifier is reproduced in the
 * base exactly as the signer wrote it; re-serializing it would change signed
 * bytes.
 */
export interface SignatureComponentId {
  /** Bare component name, e.g. `@authority` or `signature-agent`. */
  name: string;
  /** Raw parameter text as it appeared, e.g. `;key="sig1"`. Empty when none. */
  params: string;
  /**
   * RFC 9421 Section 2.1 `key` parameter. Selects one member out of a
   * Dictionary header, which is what Web Bot Auth -02 Section 5.2.1 requires
   * for Signature-Agent.
   */
  key?: string;
}

export interface ParsedSignatureInput {
  label: string;
  /**
   * Bare component names, in order. Parameters are stripped here so existing
   * `components.includes('@authority')` style checks read the same whether or
   * not the signer used a keyed identifier.
   */
  components: string[];
  /** The same components with their parameters, in the same order. */
  componentIds: SignatureComponentId[];
  rawValue: string;
  parameters: {
    keyid?: string;
    created?: number;
    expires?: number;
    alg?: string;
    nonce?: string;
    tag?: string;
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

  // A component identifier is a quoted name optionally followed by parameters.
  // Matching the parameters here (rather than scanning for quoted strings) is
  // what keeps a `key="sig1"` parameter from being read as a component of its
  // own: that misparse turned the Web Bot Auth -02 form
  // ("@authority" "signature-agent";key="sig1") into three components and then
  // failed to build a base at all.
  const componentIds: SignatureComponentId[] = [];
  const components: string[] = [];
  const re = /"([^"]*)"((?:;[A-Za-z0-9_-]+(?:=(?:"[^"]*"|[^;"\s)]*))?)*)/g;
  let m: RegExpExecArray | null;
  let consumed = 0;
  while ((m = re.exec(componentsRaw)) !== null) {
    const name = m[1];
    if (name === undefined || name === '') {
      throw new SignatureParseError('Empty component in Signature-Input');
    }
    const params = m[2] ?? '';
    const keyMatch = params.match(/;key="([^"]*)"/);
    const id: SignatureComponentId = { name, params };
    if (keyMatch) id.key = keyMatch[1] as string;
    componentIds.push(id);
    components.push(name);
    consumed += m[0].length;
  }
  if (components.length === 0) {
    throw new SignatureParseError('Signature-Input has no covered components');
  }
  // Anything in the list that is not a component identifier or separating
  // whitespace means we did not understand the list, so refuse it rather than
  // silently signing over a subset of what the signer covered.
  if (componentsRaw.replace(/\s+/g, '').length !== consumed) {
    throw new SignatureParseError('Signature-Input has an unparseable covered component list');
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
        // Visa's TAP sample implementation emits `keyId` (RFC 8941 keys are
        // lowercase-only, but real traffic wins — the raw header string still
        // feeds the signature base, so tolerance here cannot affect crypto).
        case 'keyId':
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
        case 'tag':
          parameters.tag = raw;
          break;
        default:
          break;
      }
    }
  }

  return { label, components, componentIds, rawValue: rest, parameters };
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
  for (const comp of parsed.componentIds) {
    // The identifier is reproduced with its parameters, exactly as the signer
    // wrote it: `"signature-agent";key="sig1": "https://agent.example"`.
    lines.push(`"${comp.name}"${comp.params}: ${resolveComponent(comp, inputs)}`);
  }
  lines.push(`"@signature-params": ${parsed.rawValue}`);
  return lines.join('\n');
}

function resolveComponent(comp: SignatureComponentId, inputs: SignatureBaseInputs): string {
  const { name } = comp;
  if (name === '@method') return inputs.method.toUpperCase();
  if (name === '@target-uri') return inputs.url;
  if (name === '@authority' || name === '@path' || name === '@query') {
    let u: URL;
    try {
      u = new URL(inputs.url);
    } catch {
      throw new SignatureParseError(`${name} requires a valid URL, got: ${inputs.url}`);
    }
    if (name === '@authority') return u.host;
    if (name === '@path') return u.pathname;
    // RFC 9421 §2.2.7: @query is the query string with its leading "?";
    // when the target has no query, the component value is "?".
    return u.search === '' ? '?' : u.search;
  }
  if (name.startsWith('@')) {
    throw new SignatureParseError(`Unsupported derived component: ${name}`);
  }
  const lower = name.toLowerCase();
  const v = inputs.headers[lower];
  if (v === undefined) {
    throw new SignatureParseError(`Covered header missing from request: ${name}`);
  }
  if (comp.key === undefined) return v;
  // RFC 9421 Section 2.1: a `key` parameter names one member of a Dictionary
  // header, and the component value is that member's value, not the whole
  // field. Covering a member that is not there is a signer error, not a
  // verifier tolerance: the base cannot be built.
  const member = dictionaryMemberValue(v, comp.key);
  if (member === undefined) {
    throw new SignatureParseError(
      `Covered header ${name} has no dictionary member "${comp.key}"`,
    );
  }
  return member;
}

/**
 * Return the serialized value of one member of a Structured Field Dictionary,
 * taken verbatim from the header text (parameters included) so the bytes match
 * what the signer covered. Quoted strings are respected, so a comma inside a
 * String Item cannot split a member. Returns undefined when the member is
 * absent or the field does not read as a dictionary.
 */
function dictionaryMemberValue(headerValue: string, key: string): string | undefined {
  let i = 0;
  while (i < headerValue.length) {
    while (i < headerValue.length && /[\s,]/.test(headerValue[i] as string)) i++;
    const keyStart = i;
    while (i < headerValue.length && /[A-Za-z0-9_.*-]/.test(headerValue[i] as string)) i++;
    const memberKey = headerValue.slice(keyStart, i);
    if (memberKey === '') return undefined;
    let value: string;
    if (headerValue[i] === '=') {
      i++;
      const valueStart = i;
      let inQuotes = false;
      while (i < headerValue.length) {
        const ch = headerValue[i] as string;
        if (inQuotes) {
          if (ch === '\\') { i += 2; continue; }
          if (ch === '"') inQuotes = false;
        } else if (ch === '"') {
          inQuotes = true;
        } else if (ch === ',') {
          break;
        }
        i++;
      }
      value = headerValue.slice(valueStart, i).trim();
    } else {
      // A member with no "=" carries Boolean true, serialized as ?1.
      while (i < headerValue.length && headerValue[i] !== ',') i++;
      value = '?1';
    }
    if (memberKey === key) return value;
    if (headerValue[i] === ',') i++;
  }
  return undefined;
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
