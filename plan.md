╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
 Plan: All Audit Findings (#1–#13)

 Context

 The audit report identified 13 findings across code changes, testing, and operational categories. This plan
 covers all of them in a single implementation pass.

 ---
 Phase 1: Code Changes

 #2 (CRITICAL) — Add nonReentrant to 5 functions

 File: src/registry/CredentialRegistry.sol
 Add nonReentrant modifier to: registerCredential (line 143), renewCredential (line 207), initiateRecovery (line
 604), executeRecovery (line 670), removeExpiredCredential (line 534). The bytes-signature wrapper overloads
 (lines 113, 184, 573) don't need it since they delegate to the guarded functions.

 #6 (HIGH) — Add Pausable emergency shutdown

 File: src/registry/CredentialRegistry.sol
 - Import OpenZeppelin Pausable and add to inheritance
 - Add whenNotPaused to state-changing user functions: registerCredential, renewCredential, submitProof,
 submitProofs, initiateRecovery, executeRecovery, removeExpiredCredential
 - Add owner-only pause() and unpause() functions
 - View functions (verifyProof, verifyProofs, getScore) remain unpaused

 #7 (MEDIUM) — Extract duplicate signature unpacking

 File: src/registry/CredentialRegistry.sol
 Extract the 3 duplicate assembly blocks (lines 118–122, 189–193, 582–586) into a shared internal helper:
 _unpackSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s)

 #8 (MEDIUM) — Pin pragma

 Files: All .sol files in src/
 Change pragma solidity ^0.8.23; to pragma solidity 0.8.23;

 #11 (LOW) — DefaultScorer: Ownable → Ownable2Step

 File: src/scoring/DefaultScorer.sol
 Replace Ownable import/inheritance with Ownable2Step. Constructor already uses _transferOwnership() which is
 compatible.

 #12 (LOW) — Two-step app admin transfer

 File: src/registry/CredentialRegistry.sol
 Replace setAppAdmin() with a two-step pattern: transferAppAdmin(appId, newAdmin) sets pendingAdmin,
 acceptAppAdmin(appId) completes the transfer. Add pendingAppAdmin mapping to App struct or a separate mapping.

 #13 (LOW) — Cache array length in getAllScores()

 File: src/scoring/DefaultScorer.sol
 Cache _scoredGroupIds.length in a local variable before the loop (line 72).

 ---
 Phase 2: Testing & Config

 #3 (HIGH) — Increase fuzz runs

 File: foundry.toml
 Change [fuzz] runs = 10 to runs = 256 (both default and ci profiles).

 #4 (HIGH) — Invariant tests

 File: Create test/invariants/ with invariant tests for critical properties:
 - Registration uniqueness (cannot double-register same hash)
 - Commitment continuity (commitment never changes except via recovery)
 - Family constraint (one credential per family per app)
 - Scope binding correctness

 #9 (MEDIUM) — NatSpec on interface files

 Files: src/registry/ICredentialRegistry.sol, src/registry/Events.sol, src/registry/IScorer.sol
 Add @notice and @param NatSpec to all functions, events, and structs.

 ---
 Phase 3: Documentation (no code changes)

 #1 (CRITICAL) — Document trust assumptions for single EOA owner

 File: CLAUDE.md — add ### Trust Model & Governance under "Key design decisions"
 - Single EOA owner via Ownable2Step, operated by BringID
 - Complete list of owner powers: create/suspend/activate credential groups, add/remove verifiers, set attestation
  & validity durations, set family IDs
 - Blast radius: owner compromise = full protocol halt
 - Multisig (Gnosis Safe) + TimelockController recommended for production hardening
 - App admin and trusted verifier trust boundaries

 #5 (HIGH) + #10 (MEDIUM) — Threat model & formal specification

 File: Create docs/threat-model.md with sections:
 1. Protocol Invariants — registration uniqueness, commitment continuity, family constraint, scope binding,
 nullifier uniqueness, recovery timelock, attestation freshness, status gating
 2. Trust Assumptions — owner (single EOA, BringID), trusted verifiers, app admins, Semaphore contract, scorer
 contracts
 3. Attack Vectors & Mitigations — double-spend, cross-app/cross-caller replay, attestation replay, reentrancy,
 owner/verifier compromise, malicious scorer, family bypass, recovery double-spend
 4. Accepted Risks — removeExpiredCredential grief vector (#10): publicly callable by design, attacker cost
 ~50-150k gas, user impact ~100-300k extra gas on renewal, no security impact; attestation replay within validity
 window; no pause mechanism (now addressed by #6); single EOA owner
 5. External Dependencies — Semaphore (PSE-audited), OpenZeppelin, Solidity 0.8.23

 ---
 Files to Create/Modify

 File: src/registry/CredentialRegistry.sol
 Action: #2 nonReentrant, #6 Pausable, #7 signature helper, #8 pin pragma, #12 two-step admin
 ────────────────────────────────────────
 File: src/scoring/DefaultScorer.sol
 Action: #8 pin pragma, #11 Ownable2Step, #13 cache length
 ────────────────────────────────────────
 File: src/scoring/ScorerFactory.sol
 Action: #8 pin pragma
 ────────────────────────────────────────
 File: src/registry/ICredentialRegistry.sol
 Action: #8 pin pragma, #9 NatSpec, #12 interface updates
 ────────────────────────────────────────
 File: src/registry/IScorer.sol
 Action: #8 pin pragma, #9 NatSpec
 ────────────────────────────────────────
 File: src/registry/Events.sol
 Action: #8 pin pragma, #9 NatSpec
 ────────────────────────────────────────
 File: foundry.toml
 Action: #3 fuzz runs
 ────────────────────────────────────────
 File: test/invariants/
 Action: #4 invariant tests (new)
 ────────────────────────────────────────
 File: CLAUDE.md
 Action: #1 trust model section
 ────────────────────────────────────────
 File: docs/threat-model.md
 Action: #5 + #10 threat model (new)

 Verification

 1. FOUNDRY_PROFILE=ci forge build — compile succeeds
 2. FOUNDRY_PROFILE=ci forge test --ffi -vvv — all existing tests pass
 3. forge fmt --check — formatting clean
 4. Review new invariant tests pass
 5. Review docs for accuracy against contract code