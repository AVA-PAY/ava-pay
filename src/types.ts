// Source of truth moved to @ava-pay/agent. This file re-exports for any
// callers still using the relative import; new code should `from '@ava-pay/agent'`.
export type {
  IncomingRequest,
  Mandate,
  BuyerInfo,
  VerificationResult,
  VerificationFailureReason,
  VerifiedProtocol,
  VerifiedAgentIdentity,
  TapVerificationDetail,
} from '@ava-pay/agent';
