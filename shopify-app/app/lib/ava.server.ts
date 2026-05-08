import type { IncomingRequest, VerificationResult } from './ava-types.js';

/**
 * Thin client around the AVA Pay /verify endpoint.
 *
 * Why a wrapper at all:
 *   - centralizes the AVA_PAY_API_URL config
 *   - handles network/timeout failures with a typed result instead of throws,
 *     so the proxy route never crashes the storefront when AVA is briefly down
 *   - pinned timeout keeps us inside Shopify's app proxy budget
 *
 * The mock verifier is on the API side; this client is identical regardless
 * of whether we're talking to the mock or the real Visa-backed implementation.
 */

export interface AvaPayClientOptions {
  baseUrl: string;
  /** Hard cap on how long we'll wait for /verify before failing closed. */
  timeoutMs?: number;
  /** Optional fetch override (useful for tests). */
  fetcher?: typeof fetch;
}

export type AvaCallResult =
  | { ok: true; result: VerificationResult }
  | { ok: false; error: 'timeout' | 'network' | 'bad_response'; status?: number };

const DEFAULT_TIMEOUT_MS = 1_500;

export class AvaPayClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetcher: typeof fetch;

  constructor(opts: AvaPayClientOptions) {
    if (!opts.baseUrl) {
      throw new Error('AvaPayClient requires baseUrl (set AVA_PAY_API_URL).');
    }
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetcher = opts.fetcher ?? fetch;
  }

  async verify(request: IncomingRequest): Promise<AvaCallResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await this.fetcher(`${this.baseUrl}/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      // /verify returns 200 for trusted and 403 for blocked. Both have valid bodies.
      if (res.status !== 200 && res.status !== 403) {
        return { ok: false, error: 'bad_response', status: res.status };
      }

      const body = (await res.json()) as VerificationResult;
      return { ok: true, result: body };
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        return { ok: false, error: 'timeout' };
      }
      return { ok: false, error: 'network' };
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Lazy singleton; reads AVA_PAY_API_URL once. */
let cachedClient: AvaPayClient | null = null;
export function getAvaPayClient(): AvaPayClient {
  if (cachedClient) return cachedClient;
  const baseUrl = process.env.AVA_PAY_API_URL ?? 'http://localhost:3000';
  cachedClient = new AvaPayClient({ baseUrl });
  return cachedClient;
}

/** Test helper — reset the singleton between tests. */
export function __resetAvaPayClientForTests(): void {
  cachedClient = null;
}
