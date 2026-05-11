/**
 * Pre-seeded public demo agent.
 *
 * The landing page at `/` ships a fixed Ed25519 keypair. The PUBLIC half of
 * that pair is written here, into the hosted directory on server boot, so
 * that visitor browsers can sign a real request and have `/verify` accept it
 * even when `DIRECTORY_REGISTRATION_TOKEN` is set in production (i.e., random
 * visitors cannot self-register).
 *
 * The corresponding PRIVATE half is bundled into `public/app.js` so the
 * browser can sign. This is intentional: the demo agent has no real
 * authority, the private key being public is a feature, not a leak. If you
 * fork this and stand up your own instance, regenerate the keypair via:
 *
 *   node -e "const c=require('crypto');const{publicKey,privateKey}=c.generateKeyPairSync('ed25519');console.log(JSON.stringify({pub:publicKey.export({format:'jwk'}),priv:privateKey.export({format:'jwk'})},null,2))"
 *
 * Replace DEMO_AGENT_PUBLIC_JWK here AND DEMO_PRIVATE_JWK in public/app.js.
 *
 * This seed is idempotent: if a record with `DEMO_AGENT_ID` already exists,
 * its public key is updated to the current one (so rotating the demo key
 * just requires changing this file) but registeredAt is preserved.
 */

import type { DirectoryStorage } from './storage.js';
import type { DirectoryAgentRecord } from './types.js';

export const DEMO_AGENT_ID = 'agent_demo_public';

/**
 * Public half of the demo keypair. The private half lives in
 * public/app.js. Both MUST be regenerated together (see header comment).
 */
export const DEMO_AGENT_PUBLIC_JWK = {
  crv: 'Ed25519',
  x: 'yKCkvxtkVtmYT1xK0FFuvQPFAQqQ_z6Zg9q6VKsJTU4',
  kty: 'OKP',
} as const;

export async function seedDemoAgent(storage: DirectoryStorage): Promise<void> {
  const existing = await storage.get(DEMO_AGENT_ID);
  const now = new Date().toISOString();
  const record: DirectoryAgentRecord = {
    agentId: DEMO_AGENT_ID,
    issuer: 'AVA Pay Public Demo',
    keys: [
      {
        alg: 'ed25519',
        jwk: { ...DEMO_AGENT_PUBLIC_JWK },
        protocols: ['visa', 'ap2'],
      },
    ],
    revoked: false,
    registeredAt: existing?.registeredAt ?? now,
    updatedAt: now,
  };
  await storage.put(record);
}
