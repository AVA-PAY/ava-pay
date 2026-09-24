import type { OperatorRecord } from '../types.js';

/**
 * OperatorSource: accountability provenance for an already-verified origin.
 *
 * This is deliberately a SECOND interface, not another FederatedSource. Keys
 * and accountability are different questions and one must never shadow the
 * other:
 *
 *   - A FederatedSource answers "which key belongs to this identifier?" Its
 *     answer decides whether a request verifies at all, so it runs inside the
 *     trust decision and a wrong answer is a security failure.
 *   - An OperatorSource answers "who is accountable for this origin, and which
 *     registry says so?" It runs AFTER key resolution, only for a result that
 *     already verified, and its answer is attached as provenance. A registry
 *     that is down, wrong, or silent must never turn a verified request into an
 *     unverified one, and a registry that names a reputable operator must never
 *     rescue a request whose signature did not verify.
 *
 * So the contract is narrow on purpose:
 *   - describe() is called ONLY for `trusted: true` results.
 *   - Its answer is attached at `result.operator` and changes nothing else.
 *     `trusted`, `conclusive`, `reason`, `discount` and `ttlSeconds` are the
 *     verifier's alone.
 *   - `null` means "no record" and leaves the result exactly as it was.
 *   - A throw is swallowed and leaves the result exactly as it was. An operator
 *     lookup is never on the critical path, so its outage is not a merchant's
 *     outage. This is NOT a weakened fail-closed default: the fail-closed
 *     decision was already made upstream and is not revisited here.
 *
 * The first real implementation is expected to be registry-anchored: an RDAP
 * lookup for the registrable domain plus a DNSSEC-validated key-to-name
 * binding. See docs/RESOLVER-SOURCES.md for what such an implementation owes
 * its caller.
 */
export interface OperatorSource {
  /** Short provenance label, e.g. "rdap". Mirrors FederatedSource.name. */
  name: string;
  /**
   * Describe who operates `origin` (an https origin, e.g.
   * "https://www.shopify.com"). Return null when the source has no record for
   * this origin, including when the origin is not its shape.
   */
  describe(origin: string): Promise<OperatorRecord | null>;
}

/**
 * The wire shape an OperatorSource produces. Declared in the SDK
 * (packages/agent-sdk/src/types.ts) because it travels to merchants on
 * VerificationResult, and re-exported here so an implementer imports the record
 * and the interface from one place. Never fork it.
 */
export type { OperatorRecord };

/**
 * Run an operator source over a verified result and attach its answer.
 *
 * Every rule above lives in this one function so no caller can get it subtly
 * wrong: not verified, no source, a null answer, or a throw all return the
 * input result unchanged and untouched.
 */
export async function annotateWithOperator<T extends { trusted: boolean }>(
  result: T,
  source: OperatorSource | undefined,
  origin: string | undefined,
): Promise<T> {
  if (!source || !origin) return result;
  if (result.trusted !== true) return result;
  let record: OperatorRecord | null;
  try {
    record = await source.describe(origin);
  } catch {
    return result; // a registry outage is provenance we lack, not a trust change
  }
  if (!record) return result;
  return { ...result, operator: record };
}
