/**
 * Generate the Appendix B.1 signed-directory-response test vectors contributed
 * to draft-meunier-webbotauth-httpsig-protocol, issue #120.
 *
 * Every byte published in the draft comes out of this script. Nothing in the
 * vector is hand written. The signing path is the shipped SDK
 * (`signDirectoryResponse`), so the vectors are exactly what our verifier
 * produces and consumes; an implementer who matches them interoperates with a
 * running verifier, not with a document.
 *
 * Key material is RFC 9421 Appendix B.1.4, the same Ed25519 test key the draft
 * already uses in Appendix E. No key is generated here, ever.
 *
 * Usage:
 *   node scripts/generate-directory-proof-vectors.mjs            # draft markdown
 *   node scripts/generate-directory-proof-vectors.mjs --json     # machine readable
 *
 * Verify the output with scripts/verify-directory-proof-vectors.mjs, which
 * shares no base-construction code with the signer.
 */
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
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
 * The authority is the agent's directory origin, the host that served the keys.
 */
const CREATED = 1735689600;
const EXPIRES = 4889289600;
const AUTHORITY = 'signature-agent.test';
const LABEL = 'binding';

const privateKey = createPrivateKey(RFC9421_ED25519_PRIVATE_PEM);
const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' });

/** JWK Thumbprint, RFC 7638 Section 3.2 with the OKP members of RFC 8037 A.3. */
function thumbprint(jwk) {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return createHash('sha256').update(canonical).digest('base64url');
}

const keyid = thumbprint(publicJwk);

// Member order follows the Directory format example in the draft. Compact, so
// the bytes under the content digest are unambiguous.
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

const signed = signDirectoryResponse({
  signers: [{ privateKey, keyid }],
  authority: AUTHORITY,
  body,
  created: CREATED,
  expires: EXPIRES,
});

// The SDK labels signatures binding0, binding1, ... by signer index. The label is
// a dictionary key only: it is not part of the signature base, so renaming it
// cannot change a signed byte. Rename the single signature to `binding` for the
// draft, then let the independent verifier check the renamed output.
const rename = (field) => field.replace(/\bbinding0=/g, `${LABEL}=`);
const signatureInput = rename(signed['signature-input']);
const signature = rename(signed.signature);
const contentDigest = signed['content-digest'];

const sigParams =
  `("@authority";req "content-digest")` +
  `;created=${CREATED};expires=${EXPIRES}` +
  `;keyid="${keyid}";tag="${DIRECTORY_PROOF_TAG}"`;

const vector = {
  request: {
    method: 'GET',
    path: '/.well-known/http-message-signatures-directory',
    authority: AUTHORITY,
  },
  body,
  contentDigest,
  created: CREATED,
  expires: EXPIRES,
  keyid,
  label: LABEL,
  signatureInput,
  signature,
};

if (process.argv.includes('--json')) {
  console.log(JSON.stringify(vector, null, 2));
  process.exit(0);
}

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

console.log(`### Signed directory response

This example presents the possession proof described in
{{origin-binding-appendix}}, using the ed25519 algorithm. The directory server
signs its own response with the key it publishes. The signature covers
\`@authority\` from the request that fetched the directory, so the key set cannot
be re-served under another authority, and \`content-digest\` over the response
body, so the key set cannot be swapped under a captured signature.

The proof is bound to the request that fetched the directory:

~~~
GET ${vector.request.path} HTTP/1.1
Host: ${AUTHORITY}
Accept: application/http-message-signatures-directory+json
~~~

The response body is the following JSON Web Key Set, signed exactly as shown,
with no trailing newline:

~~~
${NOTE}

${fold(body)}
~~~

Those bytes give the following \`Content-Digest\` field value:

~~~
Content-Digest: ${contentDigest}
~~~

The corresponding signature base is:

~~~
${NOTE}

"@authority";req: ${AUTHORITY}
"content-digest": ${contentDigest}
${foldParams('"@signature-params": ', sigParams)}
~~~

This results in the following Content-Digest, Signature-Input and Signature
header fields being added to the response under the label \`${LABEL}\`:

~~~
${NOTE}

Content-Digest: ${contentDigest}
${foldParams(`Signature-Input: ${LABEL}=`, sigParams)}
Signature: ${signature}
~~~`);
