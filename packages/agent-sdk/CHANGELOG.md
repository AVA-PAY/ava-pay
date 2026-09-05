# Changelog

All notable changes to `@ava-pay/agent`.

This package is a pre-1.0 developer preview, so a minor version may tighten
verification behaviour. Type-level changes are called out as additive or
breaking on each entry.

## [0.3.0] - 2026-09-04

Everything below has accumulated since 0.2.0 (published 2026-07-12). The type
surface is additive: nothing exported by 0.2.0 was removed or changed shape.
Verification behaviour is deliberately stricter, and the Security section lists
inputs that 0.2.x accepted and 0.3.0 refuses.

### Security

Three parser fixes, all found by the negative test vectors
[ParallaxGrain publishes](https://github.com/ParallaxGrain/webbotauth-negative-vectors)
and cross-checked against our verifier in PR #27. Two of the three let a request
that must never verify come back `trusted: true`, so anyone building a verifier
on these primitives should treat 0.3.0 as the floor. Credit to ParallaxGrain for
the vectors and for the write-ups that made each fault reproducible.

- **A signature base may not cover one component identifier twice** (NV-19).
  `parseSignatureInput` never checked for repeats, so a `Signature-Input`
  covering `"@authority"` twice built a base with the component twice, and a
  signature made over exactly that base verified. RFC 9421 Section 2.5 step 2.1:
  "If the component identifier (including its parameters) has already been added
  to the signature base, produce an error." A repeated identifier now throws
  `SignatureParseError`.

  The parenthetical is load-bearing, so the check keys on name **plus**
  parameters. `"signature-agent";key="a"` and `"signature-agent";key="b"` are two
  different identifiers and both stay legal; a name-only check would have
  rejected the draft's own keyed-member form.

- **Signature-Agent members are no longer attributed by header order** (NV-13).
  Given several `Signature-Agent` members, none keyed to the signature label, and
  an unkeyed whole-field component, `parseSignatureAgent` fell back to the first
  usable member and reported the request as that agent. Draft Section 5.2.2:
  "Each signer MUST provide a Signature-Agent member for its label. A verifier
  MUST NOT attribute a signature to a member that signature does not cover."

  Exploitable as written: name a reputable origin first and your own second, and
  attribution went to whichever came first, provided the first origin's directory
  published the signing key. The unlabeled fallback now applies only when exactly
  one member survives type filtering. Several usable members with no label match
  is an error. The single-member fallback is kept and separately tested, because
  the draft's own Appendix E.2.1 vector needs it (signature `sig2`, member
  `agent2`) and so does deployed bare-string traffic.

- **A `directory`-type member must be a bare origin** (NV-17). A value carrying a
  path had its path discarded via `url.origin`, and the well-known directory was
  fetched from the surviving origin and reported with `binding: "domain"`, the
  strongest binding claim, for a member the draft says to ignore. Section 5.5:
  "The member value MUST be the ASCII serialization of an origin as defined in
  Section 6.2 of ORIGIN, and a verifier MUST ignore a member carrying anything
  else (an empty path / MAY be accepted though)." A `directory`-type member with
  a path, query or fragment is now refused.

  `jwks_uri` and `cimd` point at a file, so a path is correct there and the rule
  does not apply. A bare origin parses to pathname `/`, which Section 5.5
  exempts, and that is tested.

  One previously accepted input changes with it: `https://agent.example/jwks.json`
  with no `type` parameter used to parse as type `directory`. It is now refused.
  The invariant that guarded it is intact, in that the type is still never
  inferred from the path shape; the value is refused rather than accepted.

### Added

- **Draft -02 keyed Signature-Agent signer.** Section 5.2.1 requires signers to
  send the dictionary `Signature-Agent` form and to cover the member keyed to
  their own label. `signWithWebBotAuth` gains three options:
  - `signatureAgentFormat: 'item' | 'dictionary'`, where `'item'` (the bare
    quoted string deployed agents send today) stays the default and
    `'dictionary'` emits the label-keyed form;
  - `keyedSignatureAgentComponent`, which covers `"signature-agent";key="<label>"`
    rather than the whole field and puts that member's value in the base. It
    defaults to true for the dictionary form and false for the bare-string form,
    which has no members to key;
  - `signatureAgentType`, emitted as a `;type=` parameter on the dictionary
    member.

  The draft's Appendix E.2.1 vector now verifies end to end and is a test.

- **RFC 9421 keyed component identifiers.** The component parser read the `key`
  parameter as a component of its own, turning `("@authority" "signature-agent";
  key="sig1")` into three components and then failing to build a base, so a fully
  conformant -02 signer was rejected outright. Component identifiers now keep
  their parameters, and a keyed identifier resolves the named Dictionary member
  rather than the whole field. `ParsedSignatureInput` gains `componentIds`
  (`SignatureComponentId[]`, name plus raw parameter text plus the parsed `key`)
  alongside the existing `components`, which still holds bare names in order so
  `components.includes('@authority')` style checks read the same either way.

- **Five failure reasons** on the exported `VerificationFailureReason` union:
  - `key_directory_redirected`, for a Signature-Agent URL that answered with a
    redirect. Section 5.5 of -02 requires discovery to be served with 200 and
    forbids following redirects, so there is no key material to check and no
    identity to attribute. Kept distinct from `key_directory_unavailable`
    because the operator fix differs: the directory is reachable and
    misconfigured, not down.
  - `missing_signature_agent`, for a signed request carrying no
    `Signature-Agent` header, which Section 5.2.1 requires on every signed
    request. Previously reported under the same reason as "no signature was
    offered at all".
  - `directory_unavailable`, for an agent directory that could not be reached or
    parsed. Distinct from `unknown_agent`, which is a reachable directory that
    does not list the agent.
  - `unsigned_key` and `key_proof_invalid`, the two Appendix B outcomes.
    `unsigned_key` is "no proof offered" and is tolerated under a per-source
    grace flag; `key_proof_invalid` is "proof offered and failed verification"
    and is never tolerated at any grace setting.

- **`conclusive?: boolean` on `VerificationResult`**, present on both the
  `trusted: true` and `trusted: false` branches so callers can read
  `result.conclusive` without first narrowing. False only on could-not-check
  paths; `trusted` stays false there, so fail-closed behaviour is unchanged.
  Additive and non-breaking: an absent value should be read as conclusive.

- **`binding?: 'domain' | 'url-only'` on `VerifiedAgentIdentity`.** `domain` when
  the key was discovered through the reserved well-known directory path, which
  ties the key to the origin; `url-only` when the Signature-Agent declared a
  `jwks_uri` or `cimd` type, which proves key continuity at an arbitrary URL with
  no origin association.

- **Appendix B directory proof-of-possession**, exported from
  `@ava-pay/agent/protocol/web-bot-auth`: `DIRECTORY_PROOF_TAG`,
  `buildDirectoryProofBase`, `signDirectoryResponse`, `verifyDirectoryProofs`,
  and the `KeyProofStatus` / `DirectoryProofSigner` types. The covered set is
  `@authority;req` and `content-digest`, under tag
  `http-message-signatures-directory`. The base construction is no longer an
  interpretation: the working group published our contributed vector as -02
  Appendix E.2.3.

- **Section 5.5 discovery types.** `SignatureAgentType` (`'directory' |
  'jwks_uri' | 'cimd'`) is parsed off the dictionary member's `;type=` parameter.
  `directory` is the default only when no `type` parameter is present. An
  unrecognized type is refused fail-closed: it is never upgraded to `directory`
  and never inferred from the path shape.

- **`parseSignatureAgent` takes an `options: { strict?: boolean }` third
  argument.** With `strict` on, a `label` that names no member is an error rather
  than a fallback, for callers that know the signature covers one named member.

- **jwks_uri possession-proof vectors.** Appendix B holds two separable
  properties: the domain binding is directory-only, because the well-known URI is
  reserved and an arbitrary path is not, while the possession proof covers
  `@authority;req` and `content-digest` and depends on neither. A second vector
  set was built for a `application/jwk-set+json` response served from a
  `jwks_uri` path, byte-identical in body to E.2.3 so that only the
  `"@authority";req` line of the base moves, plus negatives on each side.

  The load-bearing result for this package: **`verifyDirectoryProofs` needed no
  change**. It never took a response type, a path or a media type as an argument,
  and the body it takes is opaque bytes under the digest, so there was nothing to
  relax. Both vector sets run through the shipped function. The vectors and their
  generator/verifier scripts live in the repository, not in this tarball.

### Changed

- **Key directory parsing accepts more real-world shapes.** `parseKeyDirectory`
  takes both the canonical `{ "keys": [ ... ] }` wrapper and a bare single JWK,
  which is what www.shopify.com served as of 2026-08-09. A key whose `kid` is
  present but does not equal its computed RFC 7638 thumbprint is still dropped.
  `alg` handling relaxed: the registry name `ed25519`, the JOSE spelling `EdDSA`,
  and an absent `alg` are all accepted, because stock WebCrypto rejects
  `alg: "ed25519"` on import and directories have good reason to omit it or send
  the JOSE name.

- **Web Bot Auth identity is the resolved Signature-Agent URL.** `keyid` only
  selects the key within the resolved directory; it is not an identity of its
  own.

- **Draft citations now name `draft-ietf-webbotauth-httpsig-protocol-00`**
  (adopted 2026-09-01, content-identical to
  `draft-meunier-webbotauth-httpsig-protocol-02`). The old name is kept in
  parentheses for this release and will be dropped in the next one. Section
  numbers are unchanged.

## [0.2.0] - 2026-07-12

Breaking release. The AP2 v0.1 Intent/Cart API (`buildAp2Headers`,
`signIntentMandate`, `signCartMandate`) was removed in favour of AP2 v0.2 dSD-JWT
mandate chains (`createRootMandate`, `presentMandate`,
`buildCheckoutMandateChain`, `buildPaymentMandateChain`, `makeCheckoutJwt`,
`computeCheckoutHash`).

Added the real Visa Trusted Agent Protocol wire format (`signWithVisaTap`,
`signTapObject`, and the `@ava-pay/agent/protocol/visa-tap` primitives) alongside
AVA's TAP-style profile, and IETF Web Bot Auth signing (`signWithWebBotAuth`,
`webBotAuthKeyId`, and the `@ava-pay/agent/protocol/web-bot-auth` primitives).

## [0.1.0] - 2026-07-12

Initial developer preview, superseded by 0.2.0 the same day.
