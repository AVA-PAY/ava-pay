/**
 * Generate the signed-response possession-proof test vectors contributed to
 * draft-meunier-webbotauth-httpsig-protocol.
 *
 * Two sets, one mechanism:
 *
 *   --set directory  the vector merged as -02 Appendix E.2.3 "Signed directory
 *                    response" (issue #120). Its published bytes are frozen:
 *                    nothing in this script may change them.
 *   --set jwks       the same possession proof on a `jwks_uri` response, served
 *                    from an ordinary https path under a different authority,
 *                    as application/jwk-set+json. It exists to show that the
 *                    proof is type-generic: neither the well-known path nor the
 *                    directory media type takes part in the signature.
 *
 * Every byte published in the draft comes out of this script. Nothing in the
 * vector is hand written. The signing path is the shipped SDK
 * (`signDirectoryResponse`), so the vectors are exactly what our verifier
 * produces and consumes; an implementer who matches them interoperates with a
 * running verifier, not with a document.
 *
 * Key material is RFC 9421 Appendix B.1.4, the same Ed25519 test key the draft
 * already uses in Appendix E. No key is generated here, ever. Both sets use it,
 * so a reader can cross-check one thumbprint across both.
 *
 * Usage:
 *   node scripts/generate-directory-proof-vectors.mjs                  # draft markdown, directory set
 *   node scripts/generate-directory-proof-vectors.mjs --set jwks       # draft markdown, jwks_uri set
 *   node scripts/generate-directory-proof-vectors.mjs --json           # machine readable, one set
 *   node scripts/generate-directory-proof-vectors.mjs --set all --json # machine readable, both
 *   node scripts/generate-directory-proof-vectors.mjs --write          # refresh vectors/*.json
 *
 * Verify the output with scripts/verify-directory-proof-vectors.mjs, which
 * shares no base-construction code with the signer.
 */
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  DIRECTORY_PROOF_TAG,
  signDirectoryResponse,
} from '../packages/agent-sdk/dist/protocol/web-bot-auth/index.js';

/** RFC 9421 Appendix B.1.4, test-key-ed25519. Published test key, not a secret. */
const RFC9421_ED25519_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`;

/**
 * Fixed constants, chosen so the example never ages.
 *   created: 2025-01-01T00:00:00Z, the value Appendix E already uses
 *   expires: 2124-12-31T00:00:00Z, likewise. A long expires is what the draft's
 *            own Directory Response Signature Lifetimes guidance asks for.
 * Both sets share them: the only value that changes between the two is the
 * authority, which is the point of the second set.
 */
const CREATED = 1735689600;
const EXPIRES = 4889289600;
const LABEL = 'binding';

/**
 * The tag is a single value today and the same value applies to both sets: the
 * proof is one mechanism, and a `jwks_uri` response carries no separate one to
 * name. If the text that separates the possession proof from the domain binding
 * (PR #131) ends up defining a SECOND tag value for the type-generic proof,
 * this constant and DIRECTORY_PROOF_TAG in
 * packages/agent-sdk/src/protocol/web-bot-auth/directory-proof.ts both change
 * and every vector is regenerated. That is why the draft-repo PR waits for the
 * merge rather than going out ahead of it.
 */
const TAG = 'http-message-signatures-directory';
if (TAG !== DIRECTORY_PROOF_TAG) {
  throw new Error(
    `tag is "${TAG}" here and "${DIRECTORY_PROOF_TAG}" in the SDK signer: ` +
      'change both, or the published vector will not be the one the signer produced',
  );
}

const privateKey = createPrivateKey(RFC9421_ED25519_PRIVATE_PEM);
const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });

/** JWK Thumbprint, RFC 7638 Section 3.2 with the OKP members of RFC 8037 A.3. */
function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return createHash('sha256').update(canonical).digest('base64url');
}

const keyid = thumbprint(publicJwk);

// Member order follows the Directory format example in the draft. Compact, so
// the bytes under the content digest are unambiguous. The `jwks_uri` set serves
// the SAME bytes: a redistributed key set is the same key set, and holding the
// body constant leaves the authority as the only difference between the two
// signature bases.
const body = JSON.stringify({
  keys: [
    {
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      kid: keyid,
      x: publicJwk.x,
      use: 'sig',
    },
  ],
});

/**
 * A body modified after signing. The added top-level member is ignored by every
 * key-set parser, including ours, so the key set a verifier ends up with is
 * unchanged: the only thing that catches this is the covered content-digest.
 */
const tamperedBody = body.replace(/^\{/, '{"signature_agent":"https://attacker.example",');

const digestOf = (bytes) => `sha-256=:${createHash('sha256').update(bytes, 'utf8').digest('base64')}:`;

const SETS = {
  directory: {
    id: 'directory',
    heading: 'Signed Directory Response',
    authority: 'signature-agent.test',
    path: '/.well-known/http-message-signatures-directory',
    mediaType: 'application/http-message-signatures-directory+json',
    file: 'vectors/directory-proof-e2-3.json',
  },
  jwks: {
    id: 'jwks-uri',
    heading: 'Signed jwks_uri Response',
    authority: 'keys.example.net',
    path: '/tenants/acme/jwks.json',
    mediaType: 'application/jwk-set+json',
    file: 'vectors/jwks-uri-proof.json',
  },
};

const sigParamsFor = (kid) =>
  `("@authority";req "content-digest")` +
  `;created=${CREATED};expires=${EXPIRES}` +
  `;keyid="${kid}";tag="${TAG}"`;

function buildVector(set, otherAuthority) {
  const signed = signDirectoryResponse({
    signers: [{ privateKey, keyid }],
    authority: set.authority,
    body,
    created: CREATED,
    expires: EXPIRES,
  });

  // The SDK labels signatures binding0, binding1, ... by signer index. The label
  // is a dictionary key only: it is not part of the signature base, so renaming
  // it cannot change a signed byte. Rename the single signature to `binding` for
  // the draft, then let the independent verifier check the renamed output.
  const rename = (field) => field.replace(/\bbinding0=/g, `${LABEL}=`);

  return {
    request: {
      method: 'GET',
      path: set.path,
      authority: set.authority,
    },
    body,
    contentDigest: signed['content-digest'],
    created: CREATED,
    expires: EXPIRES,
    keyid,
    label: LABEL,
    signatureInput: rename(signed['signature-input']),
    signature: rename(signed.signature),
    id: set.id,
    mediaType: set.mediaType,
    // Negatives are published alongside the positive so an implementer can
    // check that their verifier REJECTS, not only that it accepts. Each one
    // reuses the positive's signature unchanged: only the inputs move.
    negatives: [
      {
        id: `${set.id}-tampered-body`,
        expect: 'content-digest mismatch',
        note: 'the signed key set with a top-level member added after signing',
        authority: set.authority,
        body: tamperedBody,
        contentDigest: digestOf(tamperedBody),
      },
      {
        id: `${set.id}-wrong-authority`,
        expect: '@authority mismatch',
        note: `the same response re-served under ${otherAuthority}`,
        authority: otherAuthority,
        body,
        contentDigest: signed['content-digest'],
      },
    ],
  };
}

const vectors = {
  directory: buildVector(SETS.directory, SETS.jwks.authority),
  jwks: buildVector(SETS.jwks, SETS.directory.authority),
};

/** Fold one long line per RFC 8792 '\' strategy: continuations carry one space. */
function fold(line, width = 66) {
  const out = [];
  let rest = line;
  while (rest.length > width) {
    out.push(rest.slice(0, width) + '\\');
    rest = ' ' + rest.slice(width);
  }
  out.push(rest);
  return out.join('\n');
}

/**
 * Present @signature-params the way Appendix E does: the covered component list
 * stays whole on the first line, then one parameter per line. Splitting on every
 * ';' would break the list at the `;req` flag.
 */
function foldParams(prefix, params) {
  const [, components, tail] = /^(\([^)]*\))(.*)$/.exec(params);
  const rest = tail.split(';').filter(Boolean);
  return [prefix + components, ...rest.map((p) => ' ;' + p)].join('\\\n');
}

const NOTE = "NOTE: '\\' line wrapping per RFC 8792";

/**
 * Re-wrap prose to the draft source's line width. The vectors themselves are
 * never touched by this: interpolated authorities and thumbprints would
 * otherwise leave the paragraphs around them raggedly wrapped, and a hand
 * rewrap is one more thing that can drift from the values it describes.
 */
function para(text, width = 78, indent = '') {
  const words = text.split(/\s+/).filter(Boolean);
  const lines = [];
  let line = '';
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (line && (indent + candidate).length > width) {
      lines.push(indent + line);
      line = word;
    } else {
      line = candidate;
    }
  }
  if (line) lines.push(indent + line);
  return lines.join('\n');
}

/** One list item: "* " on the first line, two spaces of hanging indent after. */
function bullet(text, width = 78) {
  return '* ' + para(text, width, '  ').trimStart();
}

function directoryMarkdown(vector) {
  const sigParams = sigParamsFor(vector.keyid);
  return `### ${SETS.directory.heading}

This example presents the possession proof described in
{{origin-binding-appendix}}, using the ed25519 algorithm. The directory server
signs its own response with the key it publishes. The signature covers
\`@authority\` from the request that fetched the directory, so the key set cannot
be re-served under another authority, and \`content-digest\` over the response
body, so the key set cannot be swapped under a captured signature.

The proof is bound to the request that fetched the directory:

~~~
GET ${vector.request.path} HTTP/1.1
Host: ${vector.request.authority}
Accept: ${SETS.directory.mediaType}
~~~

The response body is the following JSON Web Key Set, signed exactly as shown,
with no trailing newline:

~~~
${NOTE}

${fold(vector.body)}
~~~

Those bytes give the following \`Content-Digest\` field value:

~~~
Content-Digest: ${vector.contentDigest}
~~~

The corresponding signature base is:

~~~
${NOTE}

"@authority";req: ${vector.request.authority}
"content-digest": ${vector.contentDigest}
${foldParams('"@signature-params": ', sigParams)}
~~~

This results in the following Content-Digest, Signature-Input and Signature
header fields being added to the response under the label \`${vector.label}\`:

~~~
${NOTE}

Content-Digest: ${vector.contentDigest}
${foldParams(`Signature-Input: ${vector.label}=`, sigParams)}
Signature: ${vector.signature}
~~~`;
}

function jwksMarkdown(vector) {
  const sigParams = sigParamsFor(vector.keyid);
  const other = SETS.directory;
  const intro = para(
    `This example presents the same possession proof as {{possession-proof}},
     using the ed25519 algorithm, on a response served under the \`jwks_uri\`
     type. The key set is served from an ordinary https path as
     \`${SETS.jwks.mediaType}\`, so neither the well-known path nor the directory
     media type takes part in the proof. The covered components are unchanged:
     \`@authority\` from the request that fetched the key set, and
     \`content-digest\` over the response body.`,
  );
  const bodyIntro = para(
    `The response body is the following JSON Web Key Set, signed exactly as
     shown, with no trailing newline. It is byte-identical to the key set served
     in {{signed-directory-response}}, the same key redistributed under a second
     identifier:`,
  );
  const notes = [
    bullet(
      `The key is the RFC 9421 test key used throughout this appendix, so the
       keyid is the same thumbprint, \`${vector.keyid}\`.`,
    ),
    bullet(
      `Only the \`@authority\` line of the signature base differs from
       {{signed-directory-response}}. The request path, the request method and
       the response media type are not covered components and cannot change a
       signed byte.`,
    ),
    bullet(
      `The two signatures are therefore not interchangeable. The signature above
       does not verify for \`${other.authority}\`, and the one in
       {{signed-directory-response}} does not verify for
       \`${vector.request.authority}\`, even though the bytes being served are
       the same. A verifier should likewise reject this response with any byte
       of the body changed, which fails on \`content-digest\`.`,
    ),
    bullet(
      `The signer is the holder of the key. Where a host serves a key set whose
       private half it does not hold, the proof for that host's authority and
       response bytes can only be produced by the key holder.`,
    ),
  ].join('\n');

  return `### ${SETS.jwks.heading}

${intro}

The proof is bound to the request that fetched the key set:

~~~
GET ${vector.request.path} HTTP/1.1
Host: ${vector.request.authority}
Accept: ${SETS.jwks.mediaType}
~~~

${bodyIntro}

~~~
${NOTE}

${fold(vector.body)}
~~~

Those bytes give the same \`Content-Digest\` field value as
{{signed-directory-response}}:

~~~
Content-Digest: ${vector.contentDigest}
~~~

The corresponding signature base is:

~~~
${NOTE}

"@authority";req: ${vector.request.authority}
"content-digest": ${vector.contentDigest}
${foldParams('"@signature-params": ', sigParams)}
~~~

This results in the following Content-Digest, Signature-Input and Signature
header fields being added to the response under the label \`${vector.label}\`:

~~~
${NOTE}

Content-Digest: ${vector.contentDigest}
${foldParams(`Signature-Input: ${vector.label}=`, sigParams)}
Signature: ${vector.signature}
~~~

Notes for implementers:

${notes}`;
}

const MARKDOWN = { directory: directoryMarkdown, jwks: jwksMarkdown };

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const setArg = flag('--set') ?? 'directory';
if (!['directory', 'jwks', 'all'].includes(setArg)) {
  console.error(`unknown --set ${setArg}: expected directory, jwks or all`);
  process.exit(2);
}
const selected = setArg === 'all' ? ['directory', 'jwks'] : [setArg];

if (argv.includes('--write')) {
  const root = fileURLToPath(new URL('..', import.meta.url));
  for (const name of ['directory', 'jwks']) {
    const path = root + SETS[name].file;
    writeFileSync(path, JSON.stringify(vectors[name], null, 2) + '\n');
    console.log(`wrote ${SETS[name].file}`);
  }
  process.exit(0);
}

if (argv.includes('--json')) {
  const payload =
    setArg === 'all' ? { vectors: selected.map((n) => vectors[n]) } : vectors[selected[0]];
  console.log(JSON.stringify(payload, null, 2));
  process.exit(0);
}

console.log(selected.map((name) => MARKDOWN[name](vectors[name])).join('\n\n'));
