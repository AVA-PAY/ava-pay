import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  parseKeyDirectory,
  verifyDirectoryProofs,
} from '@ava-pay/agent/protocol/web-bot-auth';

/**
 * The IETF possession-proof test vectors: the directory set merged as -02
 * Appendix E.2.3 (issue #120) and the `jwks_uri` set that shows the same proof
 * on a response that is neither served from the well-known path nor typed as a
 * directory (offered on-list 2026-08-25, PR #131).
 *
 * Two things are being defended here.
 *
 * 1. The merged E.2.3 bytes are frozen. They are published in someone else's
 *    document; a silent change to our generator would desynchronize us from an
 *    IETF draft that third parties have already reproduced. Every published
 *    value is pinned as a literal below, so the generator cannot move them
 *    without this file failing.
 * 2. The `jwks_uri` set verifies under the SAME code path, with the shipped
 *    verifyDirectoryProofs unchanged. That is the whole public claim: the
 *    possession proof never consumed a directory-format field, so it is not
 *    directory-specific. If this file ever needs a verifier change to pass, the
 *    claim was wrong and we need to know before the draft-repo PR opens.
 */

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const VECTOR_DIR = new URL('../vectors/', import.meta.url);

interface Negative {
  id: string;
  expect: string;
  authority: string;
  body: string;
  contentDigest: string;
}

interface Vector {
  request: { method: string; path: string; authority: string };
  body: string;
  contentDigest: string;
  created: number;
  expires: number;
  keyid: string;
  label: string;
  signatureInput: string;
  signature: string;
  id: string;
  mediaType: string;
  negatives: Negative[];
}

const readVector = (file: string): Vector =>
  JSON.parse(readFileSync(new URL(file, VECTOR_DIR), 'utf8')) as Vector;

const directory = readVector('directory-proof-e2-3.json');
const jwksUri = readVector('jwks-uri-proof.json');

/** Inside the vectors' created..expires window, and fixed so nothing ages. */
const NOW = 1_750_000_000;

function classify(params: {
  authority: string;
  body: string;
  vector: Vector;
}): string | undefined {
  const keys = parseKeyDirectory(JSON.parse(params.body));
  const status = verifyDirectoryProofs({
    authority: params.authority,
    body: params.body,
    signatureInput: params.vector.signatureInput,
    signature: params.vector.signature,
    now: NOW,
    skewSeconds: 0,
    keys,
  });
  return status.get(params.vector.keyid);
}

describe('published possession-proof vectors', () => {
  it('regenerates byte-identically from the generator', () => {
    const out = execFileSync(
      process.execPath,
      ['scripts/generate-directory-proof-vectors.mjs', '--set', 'all', '--json'],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    );
    const { vectors } = JSON.parse(out) as { vectors: Vector[] };
    expect(vectors).toEqual([directory, jwksUri]);
  });

  it('holds the merged Appendix E.2.3 bytes frozen', () => {
    // Pinned against the -02 text. Nothing here may change without a
    // corresponding change to a published IETF draft.
    expect(directory.request.authority).toBe('signature-agent.test');
    expect(directory.request.path).toBe('/.well-known/http-message-signatures-directory');
    expect(directory.body).toBe(
      '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",' +
        '"x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}',
    );
    expect(directory.contentDigest).toBe('sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:');
    expect(directory.created).toBe(1735689600);
    expect(directory.expires).toBe(4889289600);
    expect(directory.keyid).toBe('poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U');
    expect(directory.signatureInput).toBe(
      'binding=("@authority";req "content-digest");created=1735689600;expires=4889289600;' +
        'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";tag="http-message-signatures-directory"',
    );
    expect(directory.signature).toBe(
      'binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:',
    );
  });

  it('serves the jwks_uri set from an ordinary path under a second authority', () => {
    expect(jwksUri.request.authority).toBe('keys.example.net');
    expect(jwksUri.request.path).toBe('/tenants/acme/jwks.json');
    expect(jwksUri.mediaType).toBe('application/jwk-set+json');
    // Same key, same thumbprint keyid, so a reader can cross-check one value
    // across both sets. Same body bytes, so the only line of the signature base
    // that moves is "@authority";req.
    expect(jwksUri.keyid).toBe(directory.keyid);
    expect(jwksUri.body).toBe(directory.body);
    expect(jwksUri.contentDigest).toBe(directory.contentDigest);
    expect(jwksUri.signature).not.toBe(directory.signature);
  });

  it('parses the jwks_uri body as a plain key set', () => {
    const keys = parseKeyDirectory(JSON.parse(jwksUri.body));
    expect(keys).toHaveLength(1);
    expect(keys[0]?.thumbprint).toBe(jwksUri.keyid);
  });
});

describe('possession-proof vectors under the shipped verifier', () => {
  // No argument to verifyDirectoryProofs describes the response type, the
  // request path or the media type. That is the point being demonstrated, and
  // these tests are the executable form of it.
  it.each([
    ['directory', directory],
    ['jwks_uri', jwksUri],
  ])('verifies the %s positive vector with no verifier change', (_name, vector) => {
    expect(classify({ authority: vector.request.authority, body: vector.body, vector })).toBe(
      'valid',
    );
  });

  it.each([
    ['directory', directory],
    ['jwks_uri', jwksUri],
  ])('rejects every published %s negative', (_name, vector) => {
    expect(vector.negatives).toHaveLength(2);
    for (const negative of vector.negatives) {
      expect(
        classify({ authority: negative.authority, body: negative.body, vector }),
        negative.id,
      ).toBe('invalid');
    }
  });

  it('does not let either signature stand in for the other', () => {
    // Identical bytes served by two hosts: the proof binds to the authority
    // that served it and to nothing else about how it was served.
    expect(
      classify({ authority: jwksUri.request.authority, body: directory.body, vector: directory }),
    ).toBe('invalid');
    expect(
      classify({ authority: directory.request.authority, body: jwksUri.body, vector: jwksUri }),
    ).toBe('invalid');
  });

  it('rejects a proof outside its window at either end', () => {
    const outside = (now: number): string | undefined => {
      const keys = parseKeyDirectory(JSON.parse(jwksUri.body));
      return verifyDirectoryProofs({
        authority: jwksUri.request.authority,
        body: jwksUri.body,
        signatureInput: jwksUri.signatureInput,
        signature: jwksUri.signature,
        now,
        skewSeconds: 0,
        keys,
      }).get(jwksUri.keyid);
    };
    expect(outside(jwksUri.created - 1)).toBe('invalid');
    expect(outside(jwksUri.expires + 1)).toBe('invalid');
    expect(outside(jwksUri.created)).toBe('valid');
  });
});

describe('the independent verifier script', () => {
  it('passes over every checked-in vector, negatives included', () => {
    const out = execFileSync(
      process.execPath,
      ['scripts/verify-directory-proof-vectors.mjs', '--all', '--now', String(NOW)],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    );
    expect(out).toContain('ALL CHECKS PASSED');
    expect(out).not.toContain('FAIL');
  });
});
