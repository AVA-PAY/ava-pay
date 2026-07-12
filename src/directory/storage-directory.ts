import { createPublicKey, type KeyObject } from 'node:crypto';
import type { AgentDirectory, AgentRecord, ResolveHints } from '../verifier/agent-directory.js';
import type { DirectoryAgentKey } from './types.js';
import type { DirectoryStorage } from './storage.js';

/**
 * Adapter: the hosted directory's storage layer ↔ the verifier's
 * AgentDirectory contract.
 *
 * When AVA runs both the directory routes AND the verifier in the same
 * process, this is what the verifier resolves through — registrations are
 * visible to verifications immediately.
 *
 * Key selection is kid-, protocol-, and algorithm-aware (this replaced the
 * old `keys[0]` shortcut): an explicit kid hint picks the exact key; else
 * candidates are narrowed by the protocol the request arrived on and the
 * wire algorithm; the first surviving key wins. A record whose keys all
 * fail the hints resolves to null — fail closed, not fall back to a key
 * the request could never have been signed with.
 */
export class StorageBackedAgentDirectory implements AgentDirectory {
  constructor(private readonly storage: DirectoryStorage) {}

  async resolve(agentId: string, hints?: ResolveHints): Promise<AgentRecord | null> {
    const record = await this.storage.get(agentId);
    if (!record || record.keys.length === 0) return null;

    const keyEntry = selectKey(record.keys, hints);
    if (!keyEntry) return null;

    let publicKey: KeyObject;
    try {
      publicKey = createPublicKey({
        // Node accepts a structural JWK here; `as never` sidesteps the union
        // narrowing since we don't have lib.dom's JsonWebKey in scope.
        key: keyEntry.jwk as never,
        format: 'jwk',
      });
    } catch {
      return null;
    }
    return { agentId: record.agentId, publicKey, revoked: record.revoked, source: 'hosted-directory' };
  }
}

function selectKey(
  keys: DirectoryAgentKey[],
  hints?: ResolveHints,
): DirectoryAgentKey | undefined {
  if (hints?.kid !== undefined) {
    const exact = keys.find((k) => k.kid === hints.kid);
    if (exact) return exact;
    // An explicit kid that matches no registered key is a definitive miss
    // ONLY if any key carries a kid; legacy records without kids fall through
    // to protocol/alg narrowing so pre-kid registrations keep working.
    if (keys.some((k) => k.kid !== undefined)) return undefined;
  }
  let candidates = keys;
  if (hints?.protocol) {
    candidates = candidates.filter((k) => k.protocols.includes(hints.protocol!));
  }
  if (hints?.alg) {
    const want = normalizeAlg(hints.alg);
    candidates = candidates.filter((k) => k.alg === want);
  }
  return candidates[0];
}

/** Map wire algorithm names onto the directory's key-alg vocabulary. */
function normalizeAlg(alg: string): DirectoryAgentKey['alg'] | undefined {
  const lower = alg.toLowerCase();
  if (lower === 'ed25519' || lower === 'eddsa') return 'ed25519';
  if (lower === 'es256') return 'es256';
  if (lower === 'ps256' || lower === 'rsa-pss-sha256') return 'ps256';
  return undefined;
}
