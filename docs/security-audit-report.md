# BringID Identity Registry — Trail of Bits Security Audit Report

**Date**: 2026-02-17
**Branch**: `fix/security-hardening-phase2`
**Tools**: Trail of Bits Building Secure Contracts plugins, Slither static analyzer
**Platform**: Solidity ^0.8.23, Foundry, Base L2

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Plugin 1: Code Maturity Assessment](#plugin-1-code-maturity-assessment)
3. [Plugin 2: Secure Workflow Guide](#plugin-2-secure-workflow-guide)
4. [Plugin 3: Guidelines Advisor](#plugin-3-guidelines-advisor)
5. [Plugin 4: Audit Prep Assistant](#plugin-4-audit-prep-assistant)
6. [Consolidated Findings](#consolidated-findings)

---

## Executive Summary

The BringID Identity Registry is a well-structured, well-tested codebase with strong access controls and comprehensive event coverage. The main areas for improvement are operational security (multisig/timelock) and defense-in-depth (extending reentrancy guards).

| Metric | Value |
|--------|-------|
| **Overall Maturity** | **2.3 / 4.0 (Moderate)** |
| **Source Files** | 6 (1,045 lines) |
| **Test Lines** | 2,483 lines (~2.4x source) |
| **Test Functions** | 128 (all passing) |
| **Fuzz Tests** | 4 |
| **Slither Findings (project code)** | 0 high, 8 medium (triaged), 2 low (accepted) |
| **Dead Code** | 0 |

---

## Plugin 1: Code Maturity Assessment

**Framework**: Trail of Bits Code Maturity Evaluation v0.1.0

### Maturity Scorecard

| # | Category | Rating | Score | Key Notes |
|---|----------|--------|-------|-----------|
| 1 | Arithmetic | Satisfactory | 3 | Solidity >=0.8 overflow protection; minimal unchecked arithmetic; clean timestamp math |
| 2 | Auditing | Moderate | 2 | Comprehensive events, but no monitoring, incident response, or off-chain alerting |
| 3 | Access Controls | Satisfactory | 3 | Ownable2Step, per-app admins, ReentrancyGuard, zero-address checks |
| 4 | Complexity | Satisfactory | 3 | Well-structured code, clear separation, reasonable function lengths |
| 5 | Decentralization | Weak | 1 | Single EOA owner, no multisig/timelock on admin operations |
| 6 | Documentation | Moderate | 2 | Good NatSpec and design docs; lacks formal spec, invariants, threat model |
| 7 | Transaction Ordering | Moderate | 2 | Timelocked recovery; but no MEV protections on registration, no commit-reveal |
| 8 | Low-Level Code | Moderate | 2 | Assembly for signature unpacking (3 instances); justified but no fuzz-specific tests for the assembly |
| 9 | Testing | Satisfactory | 3 | ~115 tests + 4 fuzz tests + reentrancy simulation; limited fuzz runs (10); no formal verification |

**Top 3 Strengths:**
1. **Access Controls (3 — Satisfactory)**: Ownable2Step, per-app admin separation, ReentrancyGuard, comprehensive authorization checks on every mutating function
2. **Testing (3 — Satisfactory)**: High test count (~115 tests), good coverage of edge cases, fuzz tests, reentrancy attack simulation, comprehensive event emission testing
3. **Arithmetic Safety (3 — Satisfactory)**: Solidity >=0.8.23 with built-in overflow protection, minimal arithmetic, well-bounded operations

**Top 3 Critical Gaps:**
1. **Decentralization (1 — Weak)**: Single EOA owner, no multisig, no timelock on admin operations, no user opt-out path
2. **Documentation (2 — Moderate)**: Good NatSpec coverage and design docs, but no formal specification, no invariants documented, no threat model
3. **Auditing/Monitoring (2 — Moderate)**: Good event coverage, but no monitoring infrastructure, no incident response plan, no anomaly detection

### Detailed Category Analysis

#### 1. ARITHMETIC — Satisfactory (3)

**Evidence:**
- Solidity ^0.8.23 provides built-in overflow/underflow protection (`CredentialRegistry.sol:2`)
- No `unchecked` blocks in source code
- Arithmetic operations are minimal and well-bounded:
  - `block.timestamp + validityDuration` (`CredentialRegistry.sol:160`) — timestamp addition, safe for centuries
  - `block.timestamp + recoveryTimelock` (`CredentialRegistry.sol:649`) — same pattern
  - `_score += _submitProof(...)` (`CredentialRegistry.sol:287`) — score accumulation with Solidity overflow protection
  - `nextAppId++` (`CredentialRegistry.sol:449`) — auto-increment counter
- `attestation_.issuedAt + attestationValidityDuration` (`CredentialRegistry.sol:717`) — could theoretically overflow if `issuedAt` is set to a very large value by a malicious verifier, but trusted verifiers are whitelisted

**Gaps:**
- No explicit upper bound on `attestationValidityDuration` (could be set to `type(uint256).max` by owner, but this is an admin-only operation)
- No upper bound on `validityDuration` when creating credential groups
- Fuzz tests exist but with only 10 runs (`foundry.toml:13`)

#### 2. AUDITING — Moderate (2)

**Evidence:**
- **Events defined**: 16 event types covering all state-changing operations (`Events.sol:1-52`)
  - `CredentialRegistered`, `CredentialRenewed`, `CredentialExpired` (credential lifecycle)
  - `RecoveryInitiated`, `RecoveryExecuted` (recovery flow)
  - `ProofValidated` (proof consumption)
  - `AppRegistered`, `AppStatusChanged`, `AppScorerSet`, `AppAdminTransferred`, `AppRecoveryTimelockSet` (app management)
  - `TrustedVerifierUpdated` (verifier management)
  - `CredentialGroupCreated`, `CredentialGroupStatusChanged`, `CredentialGroupValidityDurationSet`, `CredentialGroupFamilySet` (group management)
  - `AppSemaphoreGroupCreated` (Semaphore group creation)
  - `AttestationValidityDurationSet` (configuration)
- Events include proper `indexed` parameters for efficient log filtering
- Tests verify event emissions

**Gaps:**
- No monitoring/alerting infrastructure visible in the codebase
- No incident response plan documented
- No anomaly detection (e.g., unusual registration volumes, mass recovery initiations)
- No off-chain log monitoring setup (TheGraph, Tenderly, OpenZeppelin Defender)
- No `Pausable` pattern for emergency shutdown

#### 3. AUTHENTICATION / ACCESS CONTROLS — Satisfactory (3)

**Evidence:**
- **Ownable2Step** from OpenZeppelin (`CredentialRegistry.sol:24`) — two-step ownership transfer prevents accidental transfers
- **Per-app admin model**: App admins manage their own apps independently (`CredentialRegistry.sol:457-520`)
- **ReentrancyGuard** on `submitProof`/`submitProofs` (`CredentialRegistry.sol:264-289`)
- **Zero-address checks** on all address inputs:
  - Constructor: `trustedVerifier_ != address(0)` (line 72)
  - `addTrustedVerifier`: `verifier_ != address(0)` (line 477)
  - `setAppAdmin`: `newAdmin_ != address(0)` (line 506)
  - `setAppScorer`: `scorer_ != address(0)` (line 517)
- **Owner-only functions** protected by `onlyOwner`:
  - `createCredentialGroup`, `suspendCredentialGroup`, `activateCredentialGroup` (lines 371, 424, 435)
  - `setCredentialGroupValidityDuration`, `setCredentialGroupFamily` (lines 390, 405)
  - `setAttestationValidityDuration` (line 416)
  - `addTrustedVerifier`, `removeTrustedVerifier` (lines 476, 484)
- **App admin functions** check `msg.sender == apps[appId_].admin`
- **Attestation verification** validates ECDSA signature from trusted verifiers

**Gaps:**
- No multi-sig requirement for owner (single EOA)
- `setAppAdmin` is a one-step transfer (not two-step like Ownable2Step)
- No role-based access (only owner + app admins)

#### 4. COMPLEXITY MANAGEMENT — Satisfactory (3)

**Evidence:**
- **Function scope**: Largest function is `_executeInitiateRecovery` (~32 lines) — reasonable
- **Separation of concerns**: Clear module boundaries (6 files)
- **Internal helpers**: `_registrationHash`, `_ensureAppSemaphoreGroup`, `_executeInitiateRecovery`
- **Inheritance depth**: Only 3 levels (CredentialRegistry -> Ownable2Step -> Ownable)
- **Code duplication**: Signature unpacking assembly duplicated 3 times (lines 118-122, 189-193, 582-586)

**Gaps:**
- Signature unpacking assembly repeated 3 times (minor DRY violation)
- The main contract (762 lines) handles many responsibilities

#### 5. DECENTRALIZATION — Weak (1)

**Evidence:**
- **Single owner**: `Ownable2Step` with a single EOA address
- **Owner powers**: Create/suspend/activate credential groups, add/remove trusted verifiers, set attestation validity duration
- **No timelock on admin operations**: All owner functions execute immediately
- **No multisig**: Owner is `0x6F0CDcd334BA91A5E221582665Cce0431aD4Fc0b` (EOA)
- **No upgrade mechanism**: Contract is not upgradeable (positive)
- **App self-registration**: Apps register permissionlessly (positive)

**Gaps:**
- Owner can suspend any credential group immediately, blocking all proofs and registrations
- Owner can remove any trusted verifier, blocking all new registrations/renewals
- No user opt-out or exit mechanism if owner becomes malicious
- No governance mechanism for protocol upgrades or parameter changes

#### 6. DOCUMENTATION — Moderate (2)

**Evidence:**
- Comprehensive `@notice` and `@dev` comments on all public functions in `CredentialRegistry.sol`
- Extensive 17KB CLAUDE.md design document
- 13 documentation files in `docs/` directory
- Consistent `BID::` prefix convention for all error strings
- Key design decisions documented inline

**Gaps:**
- No formal specification
- No documented invariants
- No threat model document
- Interface files (`ICredentialRegistry.sol`, `IScorer.sol`, `Events.sol`) lack NatSpec

#### 7. TRANSACTION ORDERING RISKS — Moderate (2)

**Evidence:**
- **Recovery timelock** (`CredentialRegistry.sol:649`): Prevents instant key replacement
- **Scope binding** (`CredentialRegistry.sol:300`): Ties proofs to specific callers
- **Nullifier uniqueness**: Semaphore enforces per-group nullifier uniqueness

**Gaps:**
- No commit-reveal scheme for `registerCredential()`
- `removeExpiredCredential` is publicly callable — could be used to grief users
- No MEV protection

#### 8. LOW-LEVEL MANIPULATION — Moderate (2)

**Evidence:**
- 3 assembly instances, all identical — signature unpacking from `bytes memory`
- Standard, well-known pattern for ECDSA signature unpacking
- `require(signature_.length == 65)` precedes each assembly block
- No `delegatecall`, `staticcall`, `call` with value, or `selfdestruct`

**Gaps:**
- Assembly blocks duplicated 3 times
- No specific fuzz tests targeting the assembly

#### 9. TESTING & VERIFICATION — Satisfactory (3)

**Evidence:**
- ~128 test functions in 2,483 lines
- Test-to-source ratio: 2.4:1
- 4 fuzz tests covering timing properties
- `ReentrantAttacker` contract for reentrancy testing
- FFI integration for real Semaphore proof generation
- CI integration via GitHub Actions

**Gaps:**
- Fuzz runs: Only 10 (should be 256+)
- No formal verification
- No invariant tests
- No coverage reporting in CI
- Single test file (2,483 lines)

### Improvement Roadmap

#### CRITICAL (Immediate)

| # | Recommendation | Category | Effort |
|---|---------------|----------|--------|
| 1 | Deploy behind multisig + timelock (Gnosis Safe + TimelockController) | Decentralization | Medium |
| 2 | Add Pausable pattern for emergency shutdown | Auditing, Decentralization | Low |
| 3 | Commission formal security audit | All categories | High |

#### HIGH (1-2 months)

| # | Recommendation | Category | Effort |
|---|---------------|----------|--------|
| 4 | Increase fuzz runs to 256+ | Testing | Low |
| 5 | Add invariant tests | Testing | Medium |
| 6 | Document formal invariants and threat model | Documentation | Medium |
| 7 | Set up monitoring/alerting (Tenderly, OZ Defender) | Auditing | Medium |
| 8 | Extract signature unpacking to shared helper | Low-Level, Complexity | Low |

#### MEDIUM (2-4 months)

| # | Recommendation | Category | Effort |
|---|---------------|----------|--------|
| 9 | Add two-step app admin transfer | Access Controls | Low |
| 10 | Add coverage reporting to CI | Testing | Low |
| 11 | Consider commit-reveal for registration | Transaction Ordering | Medium |
| 12 | Add formal verification (Certora/Halmos) | Testing | High |
| 13 | Document incident response plan | Auditing | Low |

---

## Plugin 2: Secure Workflow Guide

### Step 1: Slither Static Analysis Findings

#### CredentialRegistry.sol — Summary: 1 High, 17 Medium, 19 Low, 12 Informational

##### HIGH Severity

| # | Detector | Location | Details | Triage |
|---|----------|----------|---------|--------|
| 1 | `incorrect-exp` | `Math.mulDiv` (OpenZeppelin lib) | XOR `^` vs exponentiation `**` | **False positive** — OZ library uses XOR intentionally in Newton's method |

##### MEDIUM Severity — Reentrancy (reentrancy-no-eth)

| # | Function | External Call | State Written After | Risk Assessment |
|---|----------|--------------|-------------------|-----------------|
| 1 | `_ensureAppSemaphoreGroup` (line 749) | `SEMAPHORE.createGroup()` | `appSemaphoreGroupCreated` | **Low risk** — Semaphore is a trusted, immutable contract set at construction time. No callback vector. |
| 2 | `_executeInitiateRecovery` (line 632) | `SEMAPHORE.removeMember()` | `cred.pendingRecovery` | **Low risk** — Same trusted Semaphore. `require(cred.pendingRecovery.executeAfter == 0)` guard prevents re-entry. |
| 3 | `executeRecovery` (line 670) | `SEMAPHORE.createGroup()` + `addMember()` | `cred.expired`, `cred.commitment`, `cred.credentialGroupId` | **Low risk** — Trusted Semaphore. `request.executeAfter != 0` + `delete cred.pendingRecovery` prevents re-entry. |
| 4 | `registerCredential` (line 143) | `SEMAPHORE.createGroup()` + `addMember()` | `cred.registered`, `cred.credentialGroupId`, `cred.commitment`, `cred.expiresAt` | **Low risk** — `require(!cred.registered)` prevents re-entry for same registration hash. |
| 5 | `removeExpiredCredential` (line 534) | `SEMAPHORE.removeMember()` | `cred.expired` | **Low risk** — `require(!cred.expired)` prevents re-entry. |
| 6 | `renewCredential` (line 207) | `SEMAPHORE.addMember()` | `cred.expired`, `cred.expiresAt` | **Low risk** — `require(cred.registered)` + commitment match prevents meaningful re-entry. |

**Recommendation**: While all reentrancy findings are low-risk due to trusted Semaphore calls and state-based guards, consider adding `nonReentrant` to `registerCredential`, `renewCredential`, `initiateRecovery`, `executeRecovery`, and `removeExpiredCredential` as defense-in-depth. Currently only `submitProof`/`submitProofs` have `nonReentrant`.

##### MEDIUM Severity — Other

| # | Detector | Location | Details | Triage |
|---|----------|----------|---------|--------|
| 7 | `divide-before-multiply` | `Math.mulDiv` (OZ lib) | Division before multiplication in Newton's method | **False positive** — intentional OZ algorithm |

##### LOW Severity

| # | Detector | Location | Details | Recommendation |
|---|----------|----------|---------|----------------|
| 1 | `uninitialized-local` | `registerCredential:158`, `renewCredential:226` | `expiresAt` initialized to 0 implicitly | **Informational** — intentional; defaults to 0 for no-expiry groups |
| 2 | `calls-loop` | `submitProofs` -> `_submitProof` (line 305, 309) | External calls inside loop | **Accepted risk** — necessary for batch proof validation |
| 3 | `missing-zero-check` | `Ownable2Step.transferOwnership` (OZ lib) | Missing zero-check on `_pendingOwner` | **False positive** — OZ Ownable2Step uses two-step pattern |

#### DefaultScorer.sol — Summary: 0 High, 0 Medium, 1 Low, 2 Informational

| # | Detector | Location | Details | Recommendation |
|---|----------|----------|---------|----------------|
| 1 | `cache-array-length` | `getAllScores` (line 72) | `_scoredGroupIds.length` not cached in loop | **Gas optimization** — cache length in local variable |
| 2 | `pragma` | Multiple files | Mixed `^0.8.0` (OZ) and `^0.8.23` (project) | **Informational** — no functional impact |
| 3 | `solc-version` | OZ files | `^0.8.0` includes versions with known issues | **Informational** — actual compiler is ^0.8.23 |

### Step 2: Special Features Check

- **Upgradeability**: Not applicable — no proxy pattern detected (positive security property)
- **ERC Conformance**: Not applicable — no ERC20/ERC721/ERC1155 implementation
- **Token Integration**: Not applicable — no token transfers or ERC20 interactions

### Step 3: Visual Security Inspection

#### Contract Summary (from Slither)

| Contract | Functions | ERCs | Complex Code | Features |
|----------|-----------|------|-------------|----------|
| CredentialRegistry | 85 | None | No | Ecrecover, Assembly |
| DefaultScorer | 18 | None | No | — |

**Source lines**: 619 SLOC (source) + 500 SLOC (dependencies)

#### Function Authorization Matrix

| Function | Access | Notes |
|----------|--------|-------|
| `createCredentialGroup` | `onlyOwner` | Creates new credential group |
| `suspendCredentialGroup` / `activateCredentialGroup` | `onlyOwner` | Group lifecycle |
| `setCredentialGroupValidityDuration` / `setCredentialGroupFamily` | `onlyOwner` | Group config |
| `setAttestationValidityDuration` | `onlyOwner` | Global config |
| `addTrustedVerifier` / `removeTrustedVerifier` | `onlyOwner` | Verifier management |
| `suspendApp` / `activateApp` | App admin | App lifecycle |
| `setAppRecoveryTimelock` / `setAppAdmin` / `setAppScorer` | App admin | App config |
| `registerCredential` / `renewCredential` | Public (requires verifier signature) | Credential ops |
| `initiateRecovery` | Public (requires verifier signature) | Recovery initiation |
| `executeRecovery` | Public (requires timelock expired) | Recovery completion |
| `removeExpiredCredential` | Public (requires credential expired) | Expiry cleanup |
| `submitProof` / `submitProofs` | Public + `nonReentrant` | Proof validation |
| `registerApp` | Public | Self-service app registration |

#### State Variable Write Authorization

| State Variable | Written By |
|---------------|-----------|
| `credentialGroups` | Owner (create/suspend/activate/setDuration/setFamily) |
| `apps` | Owner (via registerApp); App admin (suspend/activate/setTimelock/setAdmin/setScorer) |
| `credentials` | Public (register/renew/expire/recovery — all guarded by signatures or state checks) |
| `appSemaphoreGroups` / `appSemaphoreGroupCreated` | Internal (via `_ensureAppSemaphoreGroup`) |
| `trustedVerifiers` | Owner |
| `attestationValidityDuration` | Owner |
| `nextAppId` | Public (via `registerApp`) |
| `defaultScorer` | Constructor only (immutable after deploy) |

### Step 4: Security Properties

#### Critical Invariants

| # | Property | Type | Priority |
|---|----------|------|----------|
| 1 | **No double-registration**: A credential with `cred.registered == true` cannot be registered again | State invariant | CRITICAL |
| 2 | **Commitment continuity**: Renewal must use the same commitment as registration | State invariant | CRITICAL |
| 3 | **Family uniqueness**: Only one active credential per family per app per credential ID | State invariant | CRITICAL |
| 4 | **Recovery timelock**: New commitment cannot be added to Semaphore before `executeAfter` timestamp | Temporal invariant | CRITICAL |
| 5 | **Scope binding**: Proof scope must equal `keccak256(msg.sender, context)` | Cryptographic invariant | CRITICAL |
| 6 | **Nullifier uniqueness**: Each Semaphore nullifier can only be consumed once per group | Delegated to Semaphore | CRITICAL |
| 7 | **Attestation freshness**: Attestation `issuedAt + validityDuration >= block.timestamp` | Temporal invariant | HIGH |
| 8 | **Trusted verifier**: Only attestations signed by `trustedVerifiers[signer] == true` are accepted | Access control | CRITICAL |
| 9 | **Expiry guard**: `removeExpiredCredential` only succeeds after `cred.expiresAt` has passed | Temporal invariant | HIGH |
| 10 | **Recovery exclusion**: No operations allowed during pending recovery | State machine | HIGH |

### Step 5: Manual Review Areas

#### Privacy
- Semaphore commitments are public — expected for ZK group membership
- `credentialId` is hashed into the registration hash, not stored directly
- Full `Attestation` struct visible in calldata
- Registration events emit the commitment (linkable to user's address at registration time)

#### Front-Running
- Attestation signed to specific commitment and registry — cannot frontrun with different commitment
- Proof scope bound to `msg.sender` — cannot be frontrun by different address
- `removeExpiredCredential` publicly callable — potential grief vector

#### Cryptography
- OpenZeppelin ECDSA with `toEthSignedMessageHash()` — standard pattern
- No weak randomness usage
- `abi.encode` (not `abi.encodePacked`) prevents hash collisions
- OZ ECDSA enforces `s <= secp256k1n/2` — signature malleability protected

#### External Interactions
- Semaphore: Single trusted external contract, set immutably at construction
- Scorer calls: `IScorer(apps[proof_.appId].scorer).getScore()` — calls arbitrary address set by app admin
- No flash loan risk, no oracle dependency

---

## Plugin 3: Guidelines Advisor

### 1. Documentation & Specifications

#### NatSpec Coverage

| File | NatSpec Status | Notes |
|------|---------------|-------|
| `CredentialRegistry.sol` | **Excellent** | `@notice` and `@dev` on all public/external functions |
| `DefaultScorer.sol` | **Good** | `@notice` on all functions |
| `ScorerFactory.sol` | **Good** | `@notice` and `@return` present |
| `ICredentialRegistry.sol` | **Missing** | No NatSpec on interface functions |
| `Events.sol` | **Missing** | No NatSpec on events |
| `IScorer.sol` | **Missing** | No NatSpec on interface functions |

#### Documentation Gaps

| Gap | Priority | Recommendation |
|-----|----------|---------------|
| No formal specification | HIGH | Create a spec defining all invariants, pre/post-conditions, valid state transitions |
| No threat model | HIGH | Document trust assumptions, attack vectors, mitigations |
| Interface files lack NatSpec | MEDIUM | Add `@notice`/`@param` to interfaces and events |
| No state machine diagram | MEDIUM | Create visual diagram of credential lifecycle |
| No deployment runbook | LOW | Document exact deployment steps and post-deploy config |

### 2. On-Chain vs Off-Chain Architecture

| Component | Location | Assessment |
|-----------|----------|-----------|
| Credential verification | Off-chain (verifiers) | **Correct** |
| Attestation signing | Off-chain (verifiers) | **Correct** |
| Semaphore identity derivation | Off-chain (client) | **Correct** |
| ZK proof generation | Off-chain (client) | **Correct** |
| Registration, renewal, recovery | On-chain | **Correct** |
| Proof validation + nullifier consumption | On-chain | **Correct** |
| Score computation | On-chain (scorer contracts) | **Acceptable** |

**Assessment**: Well-designed on-chain/off-chain split.

### 3. Upgradeability Review

**Not applicable** — contract is intentionally non-upgradeable (positive security property). Migration guide exists in `docs/migration-guide-v2.md`.

### 4. Delegatecall / Proxy Pattern

**Not applicable** — no `delegatecall` usage.

### 5. Function Composition

| Finding | Location | Recommendation |
|---------|----------|---------------|
| Duplicated signature unpacking | Lines 113-123, 184-194, 573-587 | Extract to `_unpackSignature(bytes memory) internal pure returns (uint8 v, bytes32 r, bytes32 s)` |
| Main contract is 762 lines | `CredentialRegistry.sol` | Consider splitting into logical modules via inheritance |

### 6. Inheritance

```
CredentialRegistry
+-- ICredentialRegistry (interface)
+-- Ownable2Step (OpenZeppelin)
|   +-- Ownable
|       +-- Context
+-- ReentrancyGuard (OpenZeppelin)

DefaultScorer
+-- IScorer (interface)
+-- Ownable (OpenZeppelin)
    +-- Context
```

**Assessment**: Good — shallow inheritance depth, no diamond problem, well-audited OZ base contracts.

**Note**: `DefaultScorer` uses `Ownable` (one-step) rather than `Ownable2Step` (two-step).

### 7. Events Assessment

All 16 event types cover all state-changing operations with proper `indexed` parameters. No missing events for critical operations.

### 8. Common Pitfalls

| Pitfall | Status | Evidence |
|---------|--------|---------|
| Reentrancy | Partially mitigated | `nonReentrant` on `submitProof`/`submitProofs` only; other functions have state-based guards |
| Integer overflow/underflow | Protected | Solidity ^0.8.23 built-in checks |
| Access control | Good | `onlyOwner` + per-app admin checks |
| Signature replay | Partially mitigated | Time-bounded attestations + state checks (no nonce) |
| Front-running | Acceptable | Attestations signed to specific commitments; proofs bound to `msg.sender` |
| DoS | Minor risk | `removeExpiredCredential` publicly callable |
| Unchecked return values | Safe | All Semaphore calls revert on failure |
| `tx.origin` | None | Not used |
| Selfdestruct | None | Not used |
| Floating pragma | Present | `^0.8.23` — consider pinning |

### 9. Dependencies

| Dependency | Version | Source | Assessment |
|-----------|---------|--------|-----------|
| `openzeppelin-contracts` | Git submodule | `lib/` | **Good** — well-audited |
| `semaphore-protocol/contracts` | v4.14.2 | npm | **Good** — audited by PSE team |
| `forge-std` | Git submodule | `lib/` | **Good** — standard Foundry framework |
| `solmate` | Git submodule | `lib/` | **Low usage** — consider removing if unused |

### 10. Testing Assessment

| Metric | Value | Assessment |
|--------|-------|-----------|
| Test functions | 128 | **Good** |
| Test-to-source ratio | 2.4:1 | **Good** |
| Fuzz tests | 4 | **Adequate** |
| Fuzz runs | 10 | **Weak** — too low |
| Invariant tests | 0 | **Missing** |
| Formal verification | None | **Missing** |
| Coverage reporting | None | **Missing** |
| CI integration | Yes | **Good** |

### Prioritized Recommendations

#### CRITICAL
1. Add multisig + timelock for owner operations
2. Extend `nonReentrant` to all functions with external calls

#### HIGH
3. Pin floating pragma to exact version
4. Increase fuzz runs from 10 to 256+
5. Add invariant tests
6. Create formal specification
7. Create threat model

#### MEDIUM
8. Extract signature unpacking to shared helper
9. Add NatSpec to interface files
10. Add Pausable pattern
11. Add coverage reporting to CI
12. Pin OZ dependency version

#### LOW
13. Consider two-step app admin transfer
14. Remove unused `solmate` dependency
15. Create state machine diagram
16. Add monitoring/alerting documentation

---

## Plugin 4: Audit Prep Assistant

### Step 1: Review Goals

#### Security Objectives
1. Verify credential lifecycle integrity — registration, renewal, recovery, and expiry must maintain consistent state and prevent double-spend
2. Validate ZK proof security — Semaphore proof verification, nullifier uniqueness, scope binding, and cross-app isolation
3. Assess access control — owner privileges, app admin separation, trusted verifier management
4. Evaluate cryptographic security — ECDSA attestation verification, hash collision resistance, signature replay prevention
5. Check reentrancy safety — external calls to Semaphore and scorer contracts

#### Areas of Concern
1. **Reentrancy in non-guarded functions** (`CredentialRegistry.sol:143-173, 207-243, 604-630, 670-692, 534-560`) — 5 functions make external calls to Semaphore without `nonReentrant`
2. **Recovery timelock correctness** (`CredentialRegistry.sol:632-664`) — complex state transitions during key recovery and family group changes
3. **Family enforcement** (`CredentialRegistry.sol:620-627`) — ensures only one credential per family per app
4. **Attestation replay** — same attestation valid within 30-minute window; relies on state checks rather than nonces
5. **Scorer trust boundary** (`CredentialRegistry.sol:309`) — external call to arbitrary scorer address

#### Worst-Case Scenarios
1. **Double-spend**: User obtains two different Semaphore nullifiers for the same credential
2. **Credential theft**: Attacker replays an attestation to register a credential for themselves
3. **Owner key compromise**: Attacker suspends all credential groups, removes all trusted verifiers
4. **Scorer manipulation**: Malicious scorer returns inflated scores or causes DoS

### Step 2: Static Analysis

| Severity | Count | Status |
|----------|-------|--------|
| High | 0 (in project code) | **Clean** |
| Medium | 8 (all reentrancy-no-eth) | **Triaged** — all involve trusted Semaphore calls |
| Low | 2 (uninitialized-local) | **Accepted** — intentional defaults |
| Dead Code | 0 | **Clean** |
| Tests | 128/128 pass | **All passing** |

### Step 3: Code Accessibility

#### In-Scope Files (6 contracts, 1,045 SLOC)

| # | File | Lines | Purpose | Complexity |
|---|------|-------|---------|-----------|
| 1 | `src/registry/CredentialRegistry.sol` | 762 | Main contract | High |
| 2 | `src/registry/ICredentialRegistry.sol` | 127 | Interface and data types | Low |
| 3 | `src/registry/Events.sol` | 52 | Event declarations | Low |
| 4 | `src/registry/IScorer.sol` | 8 | Scorer interface | Low |
| 5 | `src/scoring/DefaultScorer.sol` | 76 | Default scorer | Low |
| 6 | `src/scoring/ScorerFactory.sol` | 20 | Scorer factory | Low |

#### Out-of-Scope
- `lib/` — OpenZeppelin, forge-std, solmate (audited dependencies)
- `node_modules/` — @semaphore-protocol (audited by PSE)
- `test/` — test contracts and helpers
- `script/` — deployment scripts

#### Build Instructions

```bash
# Prerequisites: Foundry, Node.js 18+, Yarn
git clone <repo-url>
cd identity-registry
yarn install                                # npm dependencies
forge build                                 # Compile (via_ir=true by default)
FOUNDRY_PROFILE=ci forge build              # Fast compile (no via_ir)
FOUNDRY_PROFILE=ci forge test --ffi -vvv    # Run all tests
```

### Step 4: Documentation

#### Credential Registration Flow
```
User --> Verifier (off-chain)
         | verifies credential (TLSN/OAuth/zkPassport)
         | derives credentialId
         | signs Attestation(registry, groupId, credentialId, appId, commitment, issuedAt)
         v
User --> CredentialRegistry.registerCredential(attestation, signature)
         |
         +- verifyAttestation() -> checks group active, app active, registry match, freshness, ECDSA sig
         +- check !cred.registered, commitment != 0
         +- _ensureAppSemaphoreGroup() -> lazily create Semaphore group
         +- set cred.registered = true, cred.commitment, cred.credentialGroupId
         +- SEMAPHORE.addMember(groupId, commitment)
         +- set cred.expiresAt if validityDuration > 0
         +- emit CredentialRegistered(...)
```

#### Proof Validation Flow
```
User --> Generate ZK proof off-chain (Semaphore)
         scope = keccak256(callerAddress, context)
         v
Caller --> CredentialRegistry.submitProof(context, proof)
           |
           +- check group active, app active
           +- verify scope == keccak256(msg.sender, context)
           +- check appSemaphoreGroupCreated
           +- SEMAPHORE.validateProof(groupId, proof) -> consumes nullifier
           +- emit ProofValidated(...)
           +- return IScorer(app.scorer).getScore(credentialGroupId)
```

#### Recovery Flow
```
User (lost key) --> Verifier (off-chain)
                    | re-verifies credential -> same credentialId
                    | signs Attestation with NEW commitment
                    v
User --> CredentialRegistry.initiateRecovery(attestation, sig, merkleProof)
         |
         +- verifyAttestation()
         +- check cred.registered, commitment != 0, no pending recovery
         +- check recoveryTimelock > 0
         +- check group match or same-family group change
         +- SEMAPHORE.removeMember(oldCommitment) [if not expired]
         +- set pendingRecovery(newGroupId, appId, newCommitment, block.timestamp + timelock)
         +- emit RecoveryInitiated(...)

... timelock elapses ...

Anyone --> CredentialRegistry.executeRecovery(registrationHash)
           |
           +- check pendingRecovery exists, timelock expired
           +- check group active, app active
           +- _ensureAppSemaphoreGroup() for target group
           +- SEMAPHORE.addMember(groupId, newCommitment)
           +- update cred.commitment, cred.credentialGroupId
           +- delete cred.pendingRecovery, clear cred.expired
           +- emit RecoveryExecuted(...)
```

#### User Stories

| # | Actor | Story | Functions Used |
|---|-------|-------|----------------|
| 1 | User | Register a Farcaster High credential for App 1 | `registerCredential()` |
| 2 | User | Renew an expired GitHub Medium credential | `renewCredential()` |
| 3 | User | Submit proof of Farcaster High + zkPassport credentials | `submitProofs()` |
| 4 | User | Recover access after losing wallet, upgrade from Farcaster Low to High | `initiateRecovery()` -> wait -> `executeRecovery()` |
| 5 | App admin | Register a new app with 7-day recovery timelock | `registerApp(604800)` |
| 6 | App admin | Set a custom scorer for the app | `setAppScorer()` |
| 7 | Protocol owner | Create a new credential group "LinkedIn" in a new family | `createCredentialGroup()` |
| 8 | Protocol owner | Add a new verifier for zkPassport credentials | `addTrustedVerifier()` |
| 9 | Protocol owner | Suspend a compromised credential group | `suspendCredentialGroup()` |
| 10 | Anyone | Remove an expired credential from Semaphore group | `removeExpiredCredential()` |
| 11 | Integrator | Check if a user's proofs are valid without consuming nullifiers | `verifyProofs()` or `getScore()` |

#### Actors and Privileges

| Actor | Privilege | Functions | Risk Level |
|-------|----------|-----------|-----------|
| **Owner** (Ownable2Step) | Full protocol control | `createCredentialGroup`, `suspend/activateCredentialGroup`, `setCredentialGroupValidityDuration`, `setCredentialGroupFamily`, `setAttestationValidityDuration`, `add/removeTrustedVerifier` | **CRITICAL** |
| **App Admin** | Per-app control | `suspend/activateApp`, `setAppRecoveryTimelock`, `setAppAdmin`, `setAppScorer` | **HIGH** |
| **Trusted Verifier** (off-chain) | Sign attestations | (off-chain signing) | **HIGH** |
| **User** | Credential lifecycle | `registerCredential`, `renewCredential`, `initiateRecovery`, `submitProof/submitProofs` | **MEDIUM** |
| **Anyone** | Public cleanup/execution | `removeExpiredCredential`, `executeRecovery`, `registerApp` | **LOW** |

#### Function Invariants

| Function | Key Invariants |
|----------|---------------|
| `registerCredential` | `cred.registered` transitions from `false` to `true` exactly once per registration hash |
| `renewCredential` | Commitment MUST match stored commitment; group MUST match stored group |
| `initiateRecovery` | Old commitment removed from Semaphore immediately; new commitment delayed by timelock |
| `executeRecovery` | Only possible after `block.timestamp >= pendingRecovery.executeAfter` |
| `removeExpiredCredential` | Only possible after `block.timestamp >= cred.expiresAt`; blocked during pending recovery |
| `submitProof` | Scope MUST equal `keccak256(msg.sender, context)` |
| `_registrationHash` | Family: `keccak256(registry, familyId, 0, credentialId, appId)` — collision-free with standalone: `keccak256(registry, 0, credentialGroupId, credentialId, appId)` |

#### Glossary

| Term | Definition |
|------|-----------|
| **Credential Group** | A category of credential (e.g., "Farcaster High", "zkPassport") with a unique ID, validity duration, and family ID |
| **Family** | A grouping of credential groups (e.g., Farcaster Low/Medium/High = Family 1). Only one credential per family per app per user |
| **Registration Hash** | `keccak256(registry, familyId/0, 0/credentialGroupId, credentialId, appId)` — unique key for credential state |
| **Credential ID** | `bytes32` identifier derived by the verifier from the user's real-world credential (e.g., OAuth account ID) |
| **Semaphore Commitment** | A ZK identity derived from `keccak256(walletPrivateKey, appId, credentialGroupId)` — added to Semaphore group for anonymous proof |
| **Nullifier** | A per-group, per-scope value derived during ZK proof generation. Once consumed, prevents the same identity from proving again for the same scope |
| **Scope** | `keccak256(msg.sender, context)` — binds proof to a specific caller and application context |
| **Attestation** | A signed struct from a trusted verifier certifying a user holds a specific credential |
| **Recovery Timelock** | A per-app delay (in seconds) between initiating and executing key recovery |
| **Scorer** | A contract implementing `IScorer` that returns scores for credential groups |

### Audit Prep Checklist

| # | Item | Status | Notes |
|---|------|--------|-------|
| 1 | Review goals documented | Done | Security objectives, concerns, worst cases defined |
| 2 | Slither scan clean/triaged | Done | 0 high in project code; 8 medium triaged |
| 3 | Dead code removed | Done | 0 dead code findings |
| 4 | All tests pass | Done | 128/128 pass with `--ffi` |
| 5 | Build instructions verified | Done | `FOUNDRY_PROFILE=ci forge test --ffi` succeeds |
| 6 | In-scope files listed | Done | 6 files, 1,045 SLOC |
| 7 | Flowcharts created | Done | Registration, proof, recovery flows |
| 8 | User stories documented | Done | 11 stories covering all actors |
| 9 | Actors/privileges mapped | Done | 5 actor levels with risk assessment |
| 10 | Function invariants documented | Done | Key invariants for all critical functions |
| 11 | Glossary created | Done | 10 domain terms defined |
| 12 | Stable version frozen | Pending | Tag release commit before audit |
| 13 | Test coverage measured | Pending | Run `forge coverage` |
| 14 | Formal spec written | Pending | Document all invariants formally |
| 15 | Threat model written | Pending | Document attack vectors and mitigations |

### Pre-Audit Action Items

| Priority | Action | Effort |
|----------|--------|--------|
| CRITICAL | Extend `nonReentrant` to `registerCredential`, `renewCredential`, `initiateRecovery`, `executeRecovery`, `removeExpiredCredential` | Low (1 day) |
| HIGH | Deploy owner behind Gnosis Safe multisig + TimelockController | Medium (1 week) |
| HIGH | Run `forge coverage` and address gaps below 80% | Medium (3-5 days) |
| MEDIUM | Pin Solidity pragma to exact version | Low (1 hour) |
| MEDIUM | Increase fuzz runs from 10 to 256+ | Low (1 hour) |
| MEDIUM | Add invariant tests for critical properties | Medium (3-5 days) |
| MEDIUM | Extract duplicate signature unpacking to shared helper | Low (1 hour) |

---

## Consolidated Findings

### Top Findings by Priority

| # | Priority | Finding | Source |
|---|----------|---------|--------|
| 1 | **CRITICAL** | Single EOA owner with immediate, un-timelocked control over all protocol parameters | Code Maturity, Guidelines Advisor |
| 2 | **CRITICAL** | 5 functions with external Semaphore calls lack `nonReentrant` modifier | Secure Workflow (Slither), Guidelines Advisor |
| 3 | **HIGH** | Fuzz testing uses only 10 runs (should be 256+) | Code Maturity, Guidelines Advisor |
| 4 | **HIGH** | No invariant tests for critical protocol properties | Code Maturity, Audit Prep |
| 5 | **HIGH** | No formal specification or threat model document | Code Maturity, Audit Prep |
| 6 | **HIGH** | No Pausable emergency shutdown mechanism | Code Maturity, Guidelines Advisor |
| 7 | **MEDIUM** | Duplicate assembly blocks (3 instances of signature unpacking) | Code Maturity, Secure Workflow |
| 8 | **MEDIUM** | Floating pragma `^0.8.23` should be pinned | Guidelines Advisor |
| 9 | **MEDIUM** | Missing NatSpec on interface files (`ICredentialRegistry.sol`, `IScorer.sol`, `Events.sol`) | Guidelines Advisor |
| 10 | **MEDIUM** | `removeExpiredCredential` publicly callable — potential grief vector | Secure Workflow (Step 5) |
| 11 | **LOW** | `DefaultScorer` uses one-step `Ownable` instead of `Ownable2Step` | Guidelines Advisor |
| 12 | **LOW** | `setAppAdmin` uses one-step transfer | Code Maturity |
| 13 | **LOW** | `getAllScores()` doesn't cache array length in loop | Slither optimization |
