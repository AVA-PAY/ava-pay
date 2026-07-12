import { createHash } from 'node:crypto';
import { b64urlJson, SdJwtError } from './sdjwt.js';

/**
 * AP2 v0.2 mandate shapes + validators.
 *
 * Shapes mirror the JSON Schemas in google-agentic-commerce/AP2 v0.2.0
 * (code/sdk/schemas/ap2): a Checkout Mandate chain is an OPEN checkout
 * mandate (user→agent authorization: constraints + cnf) followed by a CLOSED
 * checkout mandate (the specific checkout, committed by checkout_hash over
 * the merchant-signed checkout_jwt). A Payment Mandate authorizes the payment
 * for that same checkout (transaction_id == checkout_hash).
 *
 * Constraint checking is a PLUGGABLE registry: evaluators are looked up by
 * the constraint's `type` field, and deployments can add/override evaluators
 * without touching the verifier. An open mandate carrying a constraint type
 * with NO registered evaluator is a violation — unknown constraints must not
 * silently pass (fail closed).
 */

export const VCT_OPEN_CHECKOUT = 'mandate.checkout.open.1';
export const VCT_CHECKOUT = 'mandate.checkout.1';
export const VCT_OPEN_PAYMENT = 'mandate.payment.open.1';
export const VCT_PAYMENT = 'mandate.payment.1';

export interface OpenCheckoutMandate {
  vct: typeof VCT_OPEN_CHECKOUT;
  constraints: Array<Record<string, unknown>>;
  cnf: Record<string, unknown>;
  iat?: number;
  exp?: number;
}

export interface CheckoutMandate {
  vct: typeof VCT_CHECKOUT;
  /** base64url-encoded serialized merchant-signed JWT of the Checkout payload. */
  checkout_jwt: string;
  /** base64url hash of checkout_jwt (sha-256 unless _sd_alg says otherwise). */
  checkout_hash: string;
  iat?: number;
  exp?: number;
}

export interface OpenPaymentMandate {
  vct: typeof VCT_OPEN_PAYMENT;
  constraints: Array<Record<string, unknown>>;
  cnf: Record<string, unknown>;
  iat?: number;
  exp?: number;
  [k: string]: unknown;
}

export interface PaymentMandate {
  vct: typeof VCT_PAYMENT;
  /** Hash of the checkout_jwt this payment realizes. */
  transaction_id: string;
  payee: Record<string, unknown>;
  payment_amount: { currency: string; amount: number };
  payment_instrument: Record<string, unknown>;
  execution_date?: string;
  risk_data?: Record<string, unknown>;
  iat?: number;
  exp?: number;
}

/** UCP Checkout object (subset we validate; extra fields are allowed). */
export interface Checkout {
  id: string;
  merchant?: { name?: string; url?: string; [k: string]: unknown };
  line_items: Array<{ item?: { id?: string; title?: string }; quantity?: number; [k: string]: unknown }>;
  status: string;
  currency: string;
  totals: Array<{ type?: string; amount?: number; [k: string]: unknown }>;
  [k: string]: unknown;
}

// ─── Shape guards ───────────────────────────────────────────────────────────

export function asOpenCheckoutMandate(p: Record<string, unknown>): OpenCheckoutMandate {
  if (p['vct'] !== VCT_OPEN_CHECKOUT) {
    throw new SdJwtError(`Open checkout mandate vct must be "${VCT_OPEN_CHECKOUT}"`);
  }
  if (!Array.isArray(p['constraints'])) {
    throw new SdJwtError('Open checkout mandate must carry a constraints array');
  }
  if (typeof p['cnf'] !== 'object' || p['cnf'] === null) {
    throw new SdJwtError('Open checkout mandate must carry a cnf claim');
  }
  return p as unknown as OpenCheckoutMandate;
}

export function asCheckoutMandate(p: Record<string, unknown>): CheckoutMandate {
  if (p['vct'] !== VCT_CHECKOUT) {
    throw new SdJwtError(`Checkout mandate vct must be "${VCT_CHECKOUT}"`);
  }
  if (typeof p['checkout_jwt'] !== 'string' || p['checkout_jwt'] === '') {
    throw new SdJwtError('Checkout mandate must carry checkout_jwt');
  }
  if (typeof p['checkout_hash'] !== 'string' || p['checkout_hash'] === '') {
    throw new SdJwtError('Checkout mandate must carry checkout_hash');
  }
  return p as unknown as CheckoutMandate;
}

export function asOpenPaymentMandate(p: Record<string, unknown>): OpenPaymentMandate {
  if (p['vct'] !== VCT_OPEN_PAYMENT) {
    throw new SdJwtError(`Open payment mandate vct must be "${VCT_OPEN_PAYMENT}"`);
  }
  if (!Array.isArray(p['constraints'])) {
    throw new SdJwtError('Open payment mandate must carry a constraints array');
  }
  if (typeof p['cnf'] !== 'object' || p['cnf'] === null) {
    throw new SdJwtError('Open payment mandate must carry a cnf claim');
  }
  return p as unknown as OpenPaymentMandate;
}

export function asPaymentMandate(p: Record<string, unknown>): PaymentMandate {
  if (p['vct'] !== VCT_PAYMENT) {
    throw new SdJwtError(`Payment mandate vct must be "${VCT_PAYMENT}"`);
  }
  for (const field of ['transaction_id', 'payee', 'payment_amount', 'payment_instrument']) {
    if (p[field] === undefined || p[field] === null) {
      throw new SdJwtError(`Payment mandate missing required field "${field}"`);
    }
  }
  const amount = p['payment_amount'] as Record<string, unknown>;
  if (typeof amount['currency'] !== 'string' || typeof amount['amount'] !== 'number') {
    throw new SdJwtError('payment_amount must carry currency + integer minor-unit amount');
  }
  return p as unknown as PaymentMandate;
}

// ─── checkout_jwt handling ──────────────────────────────────────────────────

export function computeCheckoutHash(checkoutJwt: string): string {
  return createHash('sha256').update(checkoutJwt, 'ascii').digest('base64url');
}

/** Structurally parse the merchant-signed checkout JWT's Checkout payload. */
export function parseCheckoutJwt(checkoutJwt: string): Checkout {
  const parts = checkoutJwt.split('.');
  if (parts.length !== 3) {
    throw new SdJwtError('checkout_jwt must be a compact JWT (header.payload.signature)');
  }
  const payload = b64urlJson(parts[1]!, 'checkout_jwt payload');
  for (const field of ['id', 'line_items', 'status', 'currency', 'totals']) {
    if (payload[field] === undefined) {
      throw new SdJwtError(`Checkout payload missing required field "${field}"`);
    }
  }
  return payload as unknown as Checkout;
}

// ─── Pluggable constraint evaluators ────────────────────────────────────────

/**
 * A checkout-constraint evaluator: returns human-readable violations (empty =
 * pass). Registered by the constraint object's `type` value.
 */
export type CheckoutConstraintEvaluator = (
  constraint: Record<string, unknown>,
  checkout: Checkout,
) => string[];

export function allowedMerchantsEvaluator(
  constraint: Record<string, unknown>,
  checkout: Checkout,
): string[] {
  const allowed = constraint['allowed'];
  if (!Array.isArray(allowed) || allowed.length === 0) {
    return ['checkout.allowed_merchants constraint has no allowed merchants'];
  }
  const merchant = checkout.merchant;
  if (!merchant) return ['Checkout has no merchant to test against allowed_merchants'];
  const matches = allowed.some((m) => merchantMatches(m as Record<string, unknown>, merchant));
  return matches ? [] : [`Merchant "${String(merchant.name ?? merchant.url)}" is not in allowed_merchants`];
}

/** Reference semantics: match on url when both sides have one, else on name. */
function merchantMatches(candidate: Record<string, unknown>, target: Record<string, unknown>): boolean {
  const cu = candidate['url'];
  const tu = target['url'];
  if (typeof cu === 'string' && typeof tu === 'string') {
    return normalizeUrl(cu) === normalizeUrl(tu);
  }
  const cn = candidate['name'];
  const tn = target['name'];
  return typeof cn === 'string' && typeof tn === 'string' && cn.toLowerCase() === tn.toLowerCase();
}

function normalizeUrl(u: string): string {
  try {
    const url = new URL(u);
    return `${url.origin}${url.pathname.replace(/\/$/, '')}`.toLowerCase();
  } catch {
    return u.toLowerCase();
  }
}

export function lineItemsEvaluator(
  constraint: Record<string, unknown>,
  checkout: Checkout,
): string[] {
  const requirements = constraint['items'];
  if (!Array.isArray(requirements) || requirements.length === 0) {
    return ['checkout.line_items constraint has no requirements'];
  }
  const violations: string[] = [];
  for (const req of requirements as Array<Record<string, unknown>>) {
    const acceptable = Array.isArray(req['acceptable_items'])
      ? (req['acceptable_items'] as Array<Record<string, unknown>>)
      : [];
    const wantQty = typeof req['quantity'] === 'number' ? (req['quantity'] as number) : 1;
    const matching = checkout.line_items.filter((li) =>
      acceptable.some((a) => a['id'] !== undefined && a['id'] === li.item?.id),
    );
    // "One and only one must be present in the Checkout Mandate."
    if (matching.length !== 1) {
      violations.push(
        `Line item requirement "${String(req['id'])}" matched ${matching.length} checkout items, expected exactly 1`,
      );
      continue;
    }
    const qty = matching[0]!.quantity ?? 1;
    if (qty !== wantQty) {
      violations.push(
        `Line item requirement "${String(req['id'])}" quantity ${qty} != required ${wantQty}`,
      );
    }
  }
  return violations;
}

/** Default registry. Copy + extend to plug in deployment-specific evaluators. */
export const DEFAULT_CHECKOUT_EVALUATORS: ReadonlyMap<string, CheckoutConstraintEvaluator> =
  new Map([
    ['checkout.allowed_merchants', allowedMerchantsEvaluator],
    ['checkout.line_items', lineItemsEvaluator],
  ]);

// ─── Payment constraint evaluators ──────────────────────────────────────────

/**
 * A payment-constraint evaluator, keyed by the constraint's `type`. The
 * shipped set covers the stateless reference constraints
 * (payment.amount_range, payment.allowed_payees, payment.reference); the
 * stateful ones (payment.budget, payment.agent_recurrence,
 * allowed_payment_instruments, allowed_pisps, execution_date) need
 * deployment-side state and plug into the same registry.
 */
export type PaymentConstraintEvaluator = (
  constraint: Record<string, unknown>,
  closed: PaymentMandate,
  context: { openCheckoutHash?: string },
) => string[];

export function amountRangeEvaluator(
  constraint: Record<string, unknown>,
  closed: PaymentMandate,
): string[] {
  const violations: string[] = [];
  const { currency, amount } = closed.payment_amount;
  if (typeof constraint['currency'] === 'string' && currency !== constraint['currency']) {
    violations.push(`Currency mismatch: expected ${constraint['currency']}, got ${currency}`);
  }
  if (typeof constraint['min'] === 'number' && amount < constraint['min']) {
    violations.push(`Amount ${amount} below minimum ${constraint['min']}`);
  }
  if (typeof constraint['max'] === 'number' && amount > constraint['max']) {
    violations.push(`Amount ${amount} exceeds maximum ${constraint['max']}`);
  }
  return violations;
}

export function allowedPayeesEvaluator(
  constraint: Record<string, unknown>,
  closed: PaymentMandate,
): string[] {
  const allowed = constraint['allowed'];
  if (!Array.isArray(allowed) || allowed.length === 0) {
    return ['payment.allowed_payees constraint has no allowed merchants'];
  }
  const ok = allowed.some((m) => merchantMatches(m as Record<string, unknown>, closed.payee));
  return ok ? [] : [`Payee "${String(closed.payee['name'] ?? closed.payee['url'])}" not in allowed list`];
}

export function paymentReferenceEvaluator(
  constraint: Record<string, unknown>,
  _closed: PaymentMandate,
  context: { openCheckoutHash?: string },
): string[] {
  if (!context.openCheckoutHash) {
    return ['open checkout hash is required to evaluate payment.reference constraints'];
  }
  if (context.openCheckoutHash !== constraint['conditional_transaction_id']) {
    return ['payment.reference mismatch against the checkout this payment realizes'];
  }
  return [];
}

export const DEFAULT_PAYMENT_EVALUATORS: ReadonlyMap<string, PaymentConstraintEvaluator> =
  new Map([
    ['payment.amount_range', amountRangeEvaluator],
    ['payment.allowed_payees', allowedPayeesEvaluator],
    ['payment.reference', paymentReferenceEvaluator],
  ]);

export function checkPaymentConstraints(
  open: OpenPaymentMandate,
  closed: PaymentMandate,
  context: { openCheckoutHash?: string },
  evaluators: ReadonlyMap<string, PaymentConstraintEvaluator> = DEFAULT_PAYMENT_EVALUATORS,
): string[] {
  const violations: string[] = [];
  for (const constraint of open.constraints) {
    const type = typeof constraint['type'] === 'string' ? (constraint['type'] as string) : undefined;
    const evaluator = type !== undefined ? evaluators.get(type) : undefined;
    if (!evaluator) {
      violations.push(`No evaluator registered for constraint type "${type ?? '(missing)'}"`);
      continue;
    }
    violations.push(...evaluator(constraint, closed, context));
  }
  return violations;
}

/**
 * Evaluate an open mandate's constraints against a Checkout. A constraint
 * whose `type` has no registered evaluator is itself a violation.
 */
export function checkCheckoutConstraints(
  open: OpenCheckoutMandate,
  checkout: Checkout,
  evaluators: ReadonlyMap<string, CheckoutConstraintEvaluator> = DEFAULT_CHECKOUT_EVALUATORS,
): string[] {
  const violations: string[] = [];
  for (const constraint of open.constraints) {
    const type = typeof constraint['type'] === 'string' ? (constraint['type'] as string) : undefined;
    const evaluator = type !== undefined ? evaluators.get(type) : undefined;
    if (!evaluator) {
      violations.push(`No evaluator registered for constraint type "${type ?? '(missing)'}"`);
      continue;
    }
    violations.push(...evaluator(constraint, checkout));
  }
  return violations;
}
