// This module has been removed.
//
// The KeyStore concept (getAgentPublicKey / isAgentRevoked / getBuyerForMandate)
// was the original mock-only abstraction. It's been superseded by AgentDirectory
// (src/verifier/agent-directory.ts), which serves both the real Visa TAP path
// and the mock path. Buyer identity now travels with the mandate, not in a
// parallel store.
//
// If you're seeing this file, delete it — it exists only because the build
// environment couldn't unlink it.
export {};
