/**
 * Hosted AVA Agent Directory — public registry of agent identities.
 *
 * The strategic role: be the single place agent issuers (Anthropic, OpenAI,
 * indie agent devs) register, so every AVA Pay merchant can trust them
 * without bilateral integration. Mirror Visa's directory and Google's
 * directory under the hood once those open up; until then we ARE the
 * directory of record for agents not yet enrolled in the big networks.
 *
 * A single record can carry both a Visa TAP key (Ed25519) and an AP2 key
 * (Ed25519 today, ES256 later) so an agent appears once in the registry but
 * works with either protocol.
 */

export interface DirectoryAgentKey {
  /** Signing algorithm this key is used with. */
  alg: 'ed25519' | 'es256' | 'ps256';
  /** JWK encoding of the public key. */
  jwk: { kty: string; crv?: string; x?: string; y?: string; n?: string; e?: string; [k: string]: unknown };
  /** What protocols this key is valid for ("visa", "ap2", or both). */
  protocols: ReadonlyArray<'visa' | 'ap2'>;
  /**
   * Optional key identifier for kid-aware resolution (e.g. an RFC 7638
   * thumbprint). Lets one agent register several keys and have verifiers
   * pick the exact one the request was signed with.
   */
  kid?: string;
}

export interface DirectoryAgentRecord {
  agentId: string;
  /** Human-friendly issuer name, e.g. "Anthropic", "Acme Shopping Bots". */
  issuer: string;
  /** Optional homepage / contact URL for this agent. */
  url?: string;
  /** One or more public keys this agent uses. Multi-protocol support is the point. */
  keys: DirectoryAgentKey[];
  revoked: boolean;
  /** Server-set ISO timestamps. */
  registeredAt: string;
  updatedAt: string;
}

export interface DirectoryListing {
  service: 'ava-agent-directory';
  version: number;
  /** ISO timestamp of the last successful registration. */
  generatedAt: string;
  /** Total number of registered (including revoked) agents. */
  count: number;
}
