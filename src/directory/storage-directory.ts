import { createPublicKey, type KeyObject } from 'node:crypto';
import type { AgentDirectory, AgentRecord } from '../verifier/agent-directory.js';
import type { DirectoryStorage } from './storage.js';

/**
 * Adapter: the hosted directory's storage layer ↔ the verifier's
 * AgentDirectory contract.
 *
 * When AVA runs both the directory routes AND the verifier in the same
 * process, this is what the verifier resolves through — registrations are
 * visible to verifications immediately.
 *
 * Multi-key per agent: we pick the first key whose `protocols` includes
 * either "visa" or "ap2". The verifier doesn't know which protocol it'll be
 * called with at lookup time, so we need *some* key. If an agent registers
 * a Visa-only key and an AP2-only key, both verifiers attempt against the
 * same KeyObject, and only the matching protocol succeeds.
 *
 * Future: split into per-protocol resolution so we can pick the exact key
 * for the protocol the request came in on. For now, agents typically use
 * one key for both protocols.
 */
export class StorageBackedAgentDirectory implements AgentDirectory {
  constructor(private readonly storage: DirectoryStorage) {}

  async resolve(agentId: string): Promise<AgentRecord | null> {
    const record = await this.storage.get(agentId);
    if (!record || record.keys.length === 0) return null;
    const keyEntry = record.keys[0]!;
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
    return { agentId: record.agentId, publicKey, revoked: record.revoked };
  }
}
