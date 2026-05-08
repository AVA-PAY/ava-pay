// Tests use the public SDK directly. Keeping this file as a thin re-export
// preserves the existing test imports (and proves the SDK API is what tests
// were already exercising).
export {
  generateAgentKeyPair,
  encodeMandate,
  signRequest,
  type AgentKeyPair as KeyPair,
  type SignRequestInput,
  type SignedRequest,
} from '../src/sdk/agent.js';
