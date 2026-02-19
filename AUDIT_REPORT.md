# Trail of Bits Code Maturity Assessment Report

**Project**: BringID Identity Registry
**Platform**: Solidity 0.8.23 / Foundry / Base (L2)
**Branch**: `refactor/registry-contract`
**Assessment Date**: 2026-02-19
**Framework**: Trail of Bits Code Maturity Evaluation v0.1.0

---

## Executive Summary

**Overall Maturity: 2.4 / 4.0 (Moderate)**

The BringID Identity Registry is a well-architected privacy-preserving credential system with strong code-level security practices. The modular design, comprehensive event coverage, and thorough test suite demonstrate mature engineering. However, significant centralization risks (single EOA owner with instant control over critical parameters) and missing operational infrastructure (monitoring, incident response, formal verification) prevent a higher rating.

### Top 3 Strengths

1. **Comprehensive Event Coverage**: All 28+ state-changing functions emit events with appropriate indexing. Centralized event definitions in `Events.sol` prevent duplication.
2. **Robust Testing Suite**: 151 test functions covering happy paths, error cases, edge cases, fuzz tests, and invariant tests with real Semaphore proof generation via FFI.
3. **Clean Modular Architecture**: 6 base modules with clear separation of concerns, low cyclomatic complexity (max ~3), and minimal code duplication.

### Top 3 Critical Gaps

1. **Single EOA Owner with No Timelock**: The owner can instantly pause the entire protocol, suspend credential groups, add/remove verifiers, and manipulate default scores with zero delay or multi-party approval.
2. **No Off-Chain Monitoring or Incident Response Plan**: Despite comprehensive events, there is no documented monitoring infrastructure, alerting, or incident response playbook.
3. **No Formal Verification or Coverage Reports**: No Certora specs, Scribble annotations, mutation testing, or code coverage reports. Static analysis tools (Slither, Mythril) are not integrated into CI.

### Priority Recommendations

1. **CRITICAL**: Transfer ownership to a Gnosis Safe multisig fronted by a `TimelockController` (as recommended in CLAUDE.md but not yet implemented).
2. **HIGH**: Integrate Slither into CI and generate coverage reports with `forge coverage`.
3. **HIGH**: Document and deploy off-chain event monitoring with alerting for critical operations (verifier changes, pauses, score modifications).

---

## Maturity Scorecard

| # | Category | Rating | Score | Key Findings |
|---|----------|--------|-------|-------------|
| 1 | Arithmetic | Satisfactory | 3 | Solidity 0.8.23 overflow checks; zero `unchecked` blocks; no division; fuzz-tested boundaries |
| 2 | Auditing | Moderate | 2 | All state changes emit events; no monitoring infra or incident response documented |
| 3 | Authentication / Access Controls | Moderate | 2 | Ownable2Step + multi-layer roles + reentrancy guards; owner is single EOA |
| 4 | Complexity Management | Satisfactory | 3 | 6 modular base contracts; max CC ~3; clear naming; minimal duplication |
| 5 | Decentralization | Weak | 1 | Single EOA owner; instant pause; no admin timelocks; limited user opt-out |
| 6 | Documentation | Satisfactory | 3 | Comprehensive CLAUDE.md + THREAT_MODEL.md + 8 docs files; missing NatSpec |
| 7 | Transaction Ordering Risks | Satisfactory | 3 | Non-DeFi; minimal MEV surface; risks documented in THREAT_MODEL.md |
| 8 | Low-Level Manipulation | Satisfactory | 3 | Single justified assembly block (signature unpacking); no delegatecall |
| 9 | Testing & Verification | Moderate | 2 | 151 tests + 4 fuzz + 4 invariant; no formal verification or coverage reports |

**Overall: 2.4 / 4.0 (Moderate)**

---

## Detailed Analysis

### 1. ARITHMETIC - Satisfactory (3/4)

**Evidence**:
- All 13 source files use `pragma solidity 0.8.23` with built-in overflow/underflow protection
- **Zero `unchecked {}` blocks** found in the entire codebase
- No division operations exist, eliminating precision loss risks entirely
- Timestamp arithmetic is the primary arithmetic concern, with 4 addition operations:
  - `src/registry/base/AttestationVerifier.sol:33` - attestation expiry check
  - `src/registry/base/CredentialManager.sol:64` - credential expiry on registration
  - `src/registry/base/CredentialManager.sol:128` - credential expiry on renewal
  - `src/registry/base/RecoveryManager.sol:89` - recovery timelock calculation
- All timestamp additions are guarded by `> 0` checks before computation
- Score accumulation in loops (`ProofVerifier.sol:55`, `ProofVerifier.sol:120`) is protected by Solidity 0.8.x
- Boundary conditions well-guarded: 9+ `require` statements checking for zero values

**Fuzz Testing for Arithmetic**:
- `testFuzzAttestationExpiry` (test/CredentialRegistry.t.sol) - fuzzes time deltas for expiry boundaries
- `testFuzzCredentialExpiry` - fuzzes credential validity duration
- `testFuzzRecoveryTimelock` - fuzzes recovery timelock enforcement

**Gaps**:
- No standalone arithmetic specification document (design rationale is inline in CLAUDE.md)
- No formal precision analysis (though no precision-sensitive operations exist)

**Actions to reach Strong (4)**:
- Create a standalone arithmetic specification document mapping formulas to code
- Add explicit documentation for all timestamp arithmetic bounds

---

### 2. AUDITING - Moderate (2/4)

**Evidence**:
- **19 event definitions** centralized in `src/registry/Events.sol` + 2 in scoring contracts
- **All 28+ state-changing functions emit events** - zero silent state mutations found
- Event indexing follows best practices: addresses, IDs, and hashes are indexed; scalar values are not
- Semaphore external state changes (9 instances) are all tracked by parent registry events
- Consistent event naming (PastTense for completions, e.g., `CredentialRegistered`, `RecoveryExecuted`)
- `BID::` error prefix convention for instant identification in transaction traces

**Missing**:
- No off-chain monitoring infrastructure documented
- No incident response plan or runbook
- No log review process documented
- OpenZeppelin `Pausable` events (`Paused`/`Unpaused`) are inherited but not explicitly overridden
- No validation failure events (uses reverts instead, which is standard)

**Actions to reach Satisfactory (3)**:
- Document and deploy event monitoring with alerts for: `TrustedVerifierUpdated`, `Paused`/`Unpaused`, `DefaultScorerUpdated`, `CredentialGroupStatusChanged`
- Create an incident response playbook covering: verifier compromise, unauthorized pause, score manipulation
- Establish a log review cadence and assign roles for incident detection

---

### 3. AUTHENTICATION / ACCESS CONTROLS - Moderate (2/4)

**Evidence**:
- **Three-tier access control**:
  - **Owner** (Ownable2Step): 12 admin functions in `RegistryAdmin.sol` (credential groups, verifiers, pause, config)
  - **App Admin** (per-app): 7 functions in `AppManager.sol` (suspend, timelock, scorer, admin transfer)
  - **Trusted Verifiers**: ECDSA attestation signing validated in `AttestationVerifier.sol:35-36`
- Two-step ownership transfer via OpenZeppelin `Ownable2Step`
- Two-step app admin transfer via `transferAppAdmin()`/`acceptAppAdmin()` (`AppManager.sol:58-73`)
- `ReentrancyGuard` on all 7 state-changing user functions
- `Pausable` with `whenNotPaused` on all state-changing functions
- Scope binding (`ProofVerifier.sol:68`) ties proofs to `msg.sender + context`
- All `require` statements use descriptive `BID::` prefixed error messages
- **90+ negative test cases** validating access control enforcement

**Gaps**:
- Owner is a **single EOA** - not a multisig or DAO
- Key compromise of owner = full protocol control (suspend all groups, add malicious verifiers, manipulate scores, pause contract)
- No role separation within owner operations (all 12 functions behind `onlyOwner`)
- Trusted verifiers can sign attestations for ANY credential group and ANY app - no per-group verifier restrictions

**Actions to reach Satisfactory (3)**:
- Transfer ownership to Gnosis Safe multisig + TimelockController
- Consider role-based access control (separate roles for verifier management vs. group management vs. emergency pause)
- Document key compromise scenarios and response procedures

---

### 4. COMPLEXITY MANAGEMENT - Satisfactory (3/4)

**Evidence**:
- **Modular architecture**: `CredentialRegistry` aggregates 6 base modules:
  - `RegistryStorage` (149 lines) - state variables and initialization
  - `RegistryAdmin` (143 lines) - owner operations
  - `AttestationVerifier` (42 lines) - signature verification
  - `CredentialManager` (184 lines) - credential lifecycle
  - `AppManager` (103 lines) - app management
  - `RecoveryManager` (133 lines) - key recovery
  - `ProofVerifier` (123 lines) - proof validation
- **Low cyclomatic complexity**: Maximum CC ~3 (loops with external calls in `ProofVerifier.sol`)
- **Two functions exceed 30 lines**: `registerCredential()` (31 lines) and `renewCredential()` (37 lines) in `CredentialManager.sol` - both are well-structured with clear validation steps
- **Code duplication minimized**: Signature unpacking extracted to `_unpackSignature()` helper (`RegistryStorage.sol:105-112`)
- **15 state variables** in `RegistryStorage` - moderate count with clear documentation
- Consistent `BID::` error prefix naming convention
- Clear struct definitions with descriptive field names in `ICredentialRegistry.sol`

**Gaps**:
- 5-layer inheritance with diamond pattern (multiple paths to `RegistryStorage`) - not problematic in Solidity's linearized MRO but adds mental overhead
- Credential state machine has 5+ transition paths with interdependent fields (`registered`, `expired`, `commitment`, `pendingRecovery`, `credentialGroupId`, `expiresAt`)

**Actions to reach Strong (4)**:
- Add a state machine diagram to documentation
- Consider splitting `renewCredential()` into smaller helper functions

---

### 5. DECENTRALIZATION - Weak (1/4)

**Evidence**:
- **Single EOA owner** controls all critical protocol parameters via `Ownable2Step`
- **Instant pause** (`RegistryAdmin.sol:16-18`) - owner can halt all operations with zero delay
- **No admin timelocks** - verifier changes, score modifications, group suspensions all execute immediately
- **No multisig** - `CLAUDE.md` recommends Gnosis Safe + TimelockController but this is not implemented
- **Limited user opt-out**: App admins can set custom scorers and timelocks for their app, but users cannot opt-out of global owner actions (pause, group suspension, verifier removal)
- **No upgrade mechanism** (positive for immutability but means bugs cannot be patched)

**Mitigating Factors**:
- Ownable2Step prevents accidental ownership transfer
- Owner cannot directly modify existing credential records or Semaphore group memberships
- Owner cannot affect per-app configurations (admin, scorer, timelock)
- Centralization risks are well-documented in CLAUDE.md "Trust Model & Governance" section

**Why WEAK**:
- Parameters changeable anytime by single entity (attestation validity, scores, verifiers)
- Single entity can halt protocol (pause) without delay
- Centralization points are documented but not visible to on-chain users
- No user exit path during a pause

**Actions to reach Moderate (2)**:
- Transfer ownership to multisig (minimum 3-of-5)
- Add TimelockController (minimum 24h delay) for non-emergency operations
- Separate emergency pause from routine admin operations
- Document user opt-out paths clearly

---

### 6. DOCUMENTATION - Satisfactory (3/4)

**Evidence**:
- **CLAUDE.md** (208 lines): Comprehensive project guide covering architecture, build commands, deployment, design decisions, trust model, error conventions, and CI configuration
- **THREAT_MODEL.md** (68 lines): Detailed analysis of Merkle tree duration, stale root window, recovery threat model, and residual risks
- **docs/ directory** (8 files): App manager specs, nullifier design, key recovery, credential groups, scoring API, migration guides
- **Events.sol**: Centralized event declarations with descriptive names
- **ICredentialRegistry.sol** (318 lines): Full interface with struct definitions and function signatures
- **Error message convention**: All `require` strings use `BID::` prefix with descriptive messages
- Inline comments explain design decisions (e.g., commitment persistence, family enforcement, timelock rationale)

**Gaps**:
- **No NatSpec documentation** on most functions (no `@notice`, `@param`, `@return` annotations)
- No architecture diagrams (text descriptions only)
- No formal user stories document
- No domain glossary (terms like "family", "commitment", "scope" are explained inline but not centralized)

**Actions to reach Strong (4)**:
- Add NatSpec to all public/external functions
- Create visual architecture diagrams (inheritance, state machine, credential lifecycle)
- Compile a domain glossary
- Write formal user stories for each credential operation

---

### 7. TRANSACTION ORDERING RISKS - Satisfactory (3/4)

**Evidence**:
- **Not a DeFi protocol** - no swaps, AMMs, liquidity pools, or price-dependent logic
- **No oracle dependencies** - scores are deterministic, set by owner/admin
- **Scope binding** (`ProofVerifier.sol:68`) prevents proof replay across callers
- **Per-app Semaphore groups** prevent cross-app proof replay naturally
- **THREAT_MODEL.md** documents the stale root window risk and its acceptability
- **Recovery timelock** has minimal MEV surface - `executeRecovery()` is permissionless, so front-running it has no value (anyone can execute, only the credential holder benefits)
- `removeExpiredCredential()` is public but non-destructive - front-running has no meaningful impact

**Identified Risks (documented)**:
- `block.timestamp` manipulation (~15s window on L2) affects expiry and timelock checks
- Stale Merkle root window (5 min default) allows proofs against pre-removal roots
- Both risks are documented and accepted in THREAT_MODEL.md with justification

**Actions to reach Strong (4)**:
- Add explicit MEV analysis section to documentation
- Add test cases that specifically demonstrate ordering attack resilience
- Document the `block.timestamp` manipulation impact quantitatively

---

### 8. LOW-LEVEL MANIPULATION - Satisfactory (3/4)

**Evidence**:
- **Single assembly block** in `RegistryStorage.sol:107-111` for ECDSA signature unpacking (`r`, `s`, `v` extraction)
  - This is a well-known, standard pattern used across the Solidity ecosystem
  - Input validated before assembly: `require(signature_.length == 65)` at line 106
  - Returns are used directly in `ECDSA.recover()` (OpenZeppelin)
- **No `delegatecall`** anywhere in the codebase
- **No low-level `.call()` or `.staticcall()`** - all external interactions use typed interface calls
- **No `abi.encodePacked()`** - only `abi.encode()` is used, avoiding hash collision risks
- **5 instances of `abi.encode()`** - all with properly typed parameters for attestation hashing, scope binding, and registration hash computation
- Two-slot encoding scheme (`RegistryStorage.sol:124-126`) explicitly prevents hash collisions between family and standalone groups

**Gaps**:
- Assembly block lacks inline comments explaining each operation
- No high-level reference implementation for the signature unpacking
- No differential testing between assembly and a pure-Solidity equivalent

**Actions to reach Strong (4)**:
- Add inline comments to the assembly block explaining each `mload` operation
- Consider replacing with OpenZeppelin's signature parsing utilities (if available)
- Add a differential fuzz test comparing assembly output against a Solidity reference

---

### 9. TESTING & VERIFICATION - Moderate (2/4)

**Evidence**:
- **151 test functions** in `CredentialRegistry.t.sol` (2,749 lines)
- **4 fuzz tests** with 256 runs each: attestation expiry, credential expiry, recovery timelock boundaries
- **4 invariant tests** with handler-based fuzzing (64 runs, depth 32): registration uniqueness, commitment non-zero, family constraint, credential group ID consistency
- **90+ negative test cases** with `expectRevert` validations
- **50+ event emission checks** with `vm.expectEmit`
- **FFI-based ZK proof generation** using real Semaphore library via Node.js (`test/semaphore-js/`)
- **CI/CD pipeline** (`.github/workflows/test.yml`): format check, build, via-ir build, tests with FFI
- **Mock contracts**: `MockScorer` and `ReentrantAttacker` for isolated testing
- **Edge case testing**: 9 expiry+recovery interaction tests, 8 family constraint tests
- Integration tests cover full credential lifecycle: register -> renew -> expire -> recover -> prove

**Gaps**:
- **No formal verification** (no Certora, Scribble, or symbolic execution)
- **No coverage reports** (`forge coverage` not integrated into CI)
- **No mutation testing**
- **No static analysis in CI** (no Slither, Mythril, or Semgrep integration)
- **No pause/unpause tests** found
- **No gas optimization tests**
- Fuzz test count (4) is low relative to the number of state-changing functions (28+)
- Invariant test depth (32) and runs (64) are relatively low

**Actions to reach Satisfactory (3)**:
- Integrate `forge coverage` into CI and track coverage percentage
- Add Slither to CI pipeline
- Add tests for `pause()`/`unpause()` functionality
- Increase fuzz test count to cover all time-dependent and arithmetic operations
- Increase invariant test runs (256+) and depth (64+)
- Add formal invariant specifications (Certora or Scribble)

---

## Improvement Roadmap

### CRITICAL (Immediate)

| # | Recommendation | Category | Effort | Impact |
|---|---------------|----------|--------|--------|
| 1 | **Transfer ownership to Gnosis Safe multisig + TimelockController** | Decentralization | Medium (1-2 weeks) | Eliminates single point of failure for all admin operations |
| 2 | **Add Slither to CI pipeline** | Testing | Low (1-2 days) | Catches common vulnerability patterns automatically on every PR |
| 3 | **Add tests for pause/unpause** | Testing | Low (1 day) | Validates emergency control mechanism that protects entire protocol |

### HIGH (1-2 Months)

| # | Recommendation | Category | Effort | Impact |
|---|---------------|----------|--------|--------|
| 4 | **Deploy off-chain event monitoring + alerting** | Auditing | Medium (2-3 weeks) | Enables real-time detection of suspicious admin actions (verifier changes, pauses, score modifications) |
| 5 | **Create incident response playbook** | Auditing | Low (1 week) | Defines response procedures for verifier compromise, unauthorized pause, score manipulation |
| 6 | **Integrate `forge coverage` into CI** | Testing | Low (1-2 days) | Tracks and enforces minimum coverage thresholds |
| 7 | **Add NatSpec to all public functions** | Documentation | Medium (1-2 weeks) | Improves developer experience and enables auto-generated documentation |
| 8 | **Separate emergency pause from routine admin** | Decentralization | Medium (1-2 weeks) | Allows instant pause while requiring timelock for routine changes |
| 9 | **Increase fuzz/invariant test depth** | Testing | Low (2-3 days) | More fuzz tests (cover all time-dependent ops) + higher invariant runs (256+) and depth (64+) |

### MEDIUM (2-4 Months)

| # | Recommendation | Category | Effort | Impact |
|---|---------------|----------|--------|--------|
| 10 | **Add Certora formal verification specs** | Testing | High (4-6 weeks) | Proves critical invariants (commitment continuity, family uniqueness, nullifier binding) hold under all conditions |
| 11 | **Create architecture diagrams** | Documentation | Low (1 week) | Visual inheritance tree, state machine diagram, credential lifecycle flowchart |
| 12 | **Add inline comments to assembly block** | Low-Level | Low (1 hour) | Documents signature unpacking logic in `RegistryStorage.sol:107-111` |
| 13 | **Consider per-group verifier restrictions** | Access Control | Medium (2-3 weeks) | Limits blast radius of verifier compromise to specific credential groups |
| 14 | **Create domain glossary** | Documentation | Low (2-3 days) | Centralizes definitions for family, commitment, scope, attestation, etc. |
| 15 | **Add MEV analysis section to documentation** | Transaction Ordering | Low (2-3 days) | Quantifies `block.timestamp` manipulation impact and documents all ordering-sensitive operations |

---

## Appendix: File Reference Summary

### Source Contracts (13 files, ~1,504 lines)
- `src/registry/CredentialRegistry.sol` (41 lines) - Main contract
- `src/registry/ICredentialRegistry.sol` (318 lines) - Interface
- `src/registry/IScorer.sol` (22 lines) - Scorer interface
- `src/registry/Events.sol` (149 lines) - Event definitions
- `src/registry/base/RegistryStorage.sol` (149 lines) - State & storage
- `src/registry/base/RegistryAdmin.sol` (143 lines) - Owner operations
- `src/registry/base/AttestationVerifier.sol` (42 lines) - Signature verification
- `src/registry/base/CredentialManager.sol` (184 lines) - Credential lifecycle
- `src/registry/base/AppManager.sol` (103 lines) - App management
- `src/registry/base/RecoveryManager.sol` (133 lines) - Key recovery
- `src/registry/base/ProofVerifier.sol` (123 lines) - Proof validation
- `src/scoring/DefaultScorer.sol` (77 lines) - Default scorer
- `src/scoring/ScorerFactory.sol` (20 lines) - Scorer factory

### Test Files (4 files, ~3,020 lines)
- `test/CredentialRegistry.t.sol` (2,749 lines) - 151 test functions
- `test/TestUtils.sol` (36 lines) - FFI utilities
- `test/invariants/InvariantRegistry.t.sol` (105 lines) - 4 invariants
- `test/invariants/RegistryHandler.sol` (130 lines) - Fuzz handler

### Key Security Documentation
- `CLAUDE.md` - Trust model, design decisions, architecture
- `THREAT_MODEL.md` - Merkle tree duration, stale root analysis
- `docs/` - 8 specification and migration documents

---

## Appendix B: Slither Static Analysis Results

### Summary

**Tool**: Slither v0.10.x with Foundry integration
**Target**: `src/registry/CredentialRegistry.sol` (21 contracts, 101 detectors)
**Filters**: Excluded `node_modules/` and `lib/`
**Results**: 27 findings (0 high, 9 medium, 16 low, 2 informational)

### DefaultScorer: 0 findings (clean)

### CredentialRegistry Findings by Detector

#### Reentrancy (no-eth) - 8 findings | Severity: Medium | Triaged: FALSE POSITIVES

All 8 reentrancy findings involve state writes after external calls to the `SEMAPHORE` contract. These are **false positives** because:

1. **All affected functions are protected by `nonReentrant` modifier** (OpenZeppelin ReentrancyGuard):
   - `registerCredential()` (`CredentialManager.sol:45`)
   - `renewCredential()` (`CredentialManager.sol:105`)
   - `removeExpiredCredential()` (`CredentialManager.sol:162`)
   - `initiateRecovery()` (`RecoveryManager.sol:50`)
   - `executeRecovery()` (`RecoveryManager.sol:110`)

2. **The `SEMAPHORE` contract is immutable** (`ISemaphore public immutable SEMAPHORE` at `RegistryStorage.sol:16`) and deployed by a trusted party. It is not attacker-controlled.

3. **`_ensureAppSemaphoreGroup()` is an internal function** (`RegistryStorage.sol:133-148`) only called from within `nonReentrant`-protected external functions.

**Recommendation**: No code changes needed. Add Slither triage annotations or a `slither.config.json` to suppress these false positives in CI.

#### Uninitialized Local Variables - 2 findings | Severity: Medium | Triaged: FALSE POSITIVES

```
CredentialManager.registerCredential().expiresAt (line 62)
CredentialManager.renewCredential().expiresAt (line 126)
```

Both `expiresAt` variables default to `0` (Solidity's default for `uint256`), which is intentional. They are only set when `validityDuration > 0`:
```solidity
uint256 expiresAt;  // defaults to 0
if (validityDuration > 0) {
    expiresAt = block.timestamp + validityDuration;
    cred.expiresAt = expiresAt;
}
```

A `0` value in the emitted event correctly indicates "no expiry". **False positive** - the default behavior is by design.

#### Calls Inside Loops - 6 findings | Severity: Low | Triaged: ACCEPTABLE RISK

External calls inside loops in:
- `AppManager.setAppMerkleTreeDuration()` (line 98): `SEMAPHORE.updateGroupMerkleTreeDuration()` - iterates over app's Semaphore groups
- `ProofVerifier.submitProofs()` / `verifyProofs()` / `getScore()`: Loop over proof array calling `SEMAPHORE.validateProof()`, `SEMAPHORE.verifyProof()`, and `IScorer.getScore()`

**Risk**: Gas exhaustion with large arrays. **Mitigation**: The number of credential groups and proofs per submission is bounded by practical limits (15 credential groups exist). The Semaphore contract is immutable and trusted. App admins control their own scorer contracts.

**Recommendation**: Consider adding explicit array length bounds (e.g., `require(proofs_.length <= MAX_PROOFS)`) as a defense-in-depth measure.

#### Reentrancy (benign) - 1 finding | Severity: Informational

`_ensureAppSemaphoreGroup()` writes `_appSemaphoreGroupIds` and `appSemaphoreGroups` after `SEMAPHORE.createGroup()`. Same triage as above - internal function, immutable Semaphore, called within `nonReentrant` context.

#### Reentrancy (events) - 3 findings | Severity: Informational

Events emitted after external calls in `_ensureAppSemaphoreGroup()`, `_executeInitiateRecovery()`, and `setAppMerkleTreeDuration()`. Standard pattern - events after external calls are not exploitable.

#### Timestamp Comparisons - 6 findings | Severity: Low | Triaged: ACCEPTABLE RISK

All `block.timestamp` comparisons are documented in `THREAT_MODEL.md`:
- `AttestationVerifier.sol:32-33` - attestation validity window
- `CredentialManager.sol:171` - credential expiry check
- `RecoveryManager.sol:114` - recovery timelock check

**Mitigation**: Protocol operates on Base L2 (~2s block time), limiting miner manipulation to ~15 seconds. The attestation validity window (30 minutes) and credential durations (30-180 days) make this negligible.

#### Assembly Usage - 1 finding | Severity: Informational

`RegistryStorage._unpackSignature()` (line 107-111): Standard ECDSA signature unpacking. Input length validated at line 106. Well-known pattern.

#### Naming Convention - 1 finding | Severity: Informational

`SEMAPHORE` constant uses UPPER_CASE instead of mixedCase. This is **intentional** - `immutable` variables are conventionally named in UPPER_CASE to signal their immutability.

---

## Appendix C: Secure Development Workflow Checklist

### Step 1: Static Analysis (Slither) - COMPLETED
- [x] Slither scan executed (27 findings)
- [x] All findings triaged (0 true positives requiring code changes)
- [x] False positives documented with justification
- [ ] Slither integrated into CI pipeline (RECOMMENDED)

### Step 2: Special Feature Checks - COMPLETED
- [x] **Upgradeability**: No proxies or upgrade patterns detected (N/A)
- [x] **ERC conformance**: No ERC token implementations (N/A)
- [x] **Token integration**: No token transfers or balances (N/A)

### Step 3: Visual Security Inspection - COMPLETED
- [x] Human summary generated (715 SLOC in source, 535 in deps)
- [x] Function summary: 105 functions in CredentialRegistry, all CC <= 3
- [x] Variables and authorization: State variable access mapped to msg.sender conditions
- [x] Confirmed: All app admin functions require `apps[appId_].admin == msg.sender`
- [x] Confirmed: Owner functions use `onlyOwner` modifier

### Step 4: Security Properties - PARTIALLY COMPLETED
- [x] 4 invariant tests document critical properties (registration uniqueness, commitment non-zero, family constraint, credential group ID consistency)
- [x] Handler-based fuzzing with bounded inputs
- [ ] Formal verification specs (Certora/Scribble) NOT implemented
- [ ] Echidna/Manticore NOT configured
- [ ] Additional invariants needed: commitment continuity through renewal, scope binding correctness, recovery timelock ordering

### Step 5: Manual Review Areas - COMPLETED
- [x] **Privacy**: Semaphore ZK proofs provide membership privacy; commitments are public but not linkable
- [x] **Front-running**: Minimal MEV surface; recovery execution is permissionless; no value extraction possible
- [x] **Cryptography**: ECDSA via OpenZeppelin (audited); Semaphore proof verification via trusted library; no custom crypto
- [x] **Signature replay**: Prevented by per-registration hash deduplication and attestation expiry
- [x] **External interactions**: All calls to trusted, immutable contracts (Semaphore); scorer calls to admin-controlled addresses
