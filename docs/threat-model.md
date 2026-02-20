# Threat Model & Formal Specification

BringID Credential Registry — security analysis and protocol invariants.

## 1. Protocol Invariants

These properties must hold at all times. Violation of any invariant indicates a critical bug.

### Registration Uniqueness

A credential can only be registered once per registration hash. The `registerCredential()` function requires `!cred.registered` and sets `cred.registered = true` atomically. Once set, `registered` is never reset to false — it persists through expiry, removal, renewal, and recovery.

- **Family groups** (familyId > 0): registration hash = `keccak256(registry, familyId, 0, credentialId, appId)`. All groups in the same family share this hash, so a user can hold at most one credential per family per app.
- **Standalone groups** (familyId == 0): registration hash = `keccak256(registry, 0, credentialGroupId, credentialId, appId)`. Each group has its own hash.
- **Collision prevention**: the two-slot encoding (`familyId, 0` vs `0, credentialGroupId`) prevents hash collisions between family and standalone groups.

### Commitment Continuity

A credential's Semaphore identity commitment can only change through the recovery flow (`initiateRecovery` + `executeRecovery`). Specifically:

- `registerCredential()` sets `cred.commitment` on first registration.
- `renewCredential()` requires `attestation.semaphoreIdentityCommitment == cred.commitment` — the commitment cannot change.
- `removeExpiredCredential()` sets `cred.expired = true` but does NOT clear `cred.commitment`.
- `executeRecovery()` is the only function that writes a new value to `cred.commitment`.

This ensures Semaphore nullifier continuity: a user cannot obtain fresh nullifiers by changing their commitment without going through the timelocked recovery process.

### Family Constraint

Within a family (familyId > 0), a user can hold at most one active credential per app. This is enforced structurally: all groups in a family share the same registration hash, so `registerCredential()` will revert with `AlreadyRegistered()` for any second registration in the same family. Group changes within a family must go through `initiateRecovery()` / `executeRecovery()`, which enforces the recovery timelock.

### Scope Binding

Semaphore proof scopes are bound to `keccak256(abi.encode(msg.sender, context))`. This is enforced in `_submitProof()` and `verifyProof()`:

```
if (proof.semaphoreProof.scope != uint256(keccak256(abi.encode(msg.sender, context)))) revert ScopeMismatch();
```

A proof generated for one caller cannot be submitted by a different caller. A proof generated for one context cannot be reused for a different context by the same caller.

### Nullifier Uniqueness

Semaphore enforces per-group nullifier uniqueness internally via `validateProof()`. Once a nullifier is consumed for a given Semaphore group, it cannot be reused. Since each (credentialGroupId, appId) pair maps to a distinct Semaphore group, nullifiers are naturally isolated per app and per credential group.

### Recovery Timelock

Key recovery is a two-phase process with an enforced delay:

- `initiateRecovery()` immediately removes the old commitment from the Semaphore group and queues the new commitment with `executeAfter = block.timestamp + apps[appId].recoveryTimelock`.
- `executeRecovery()` requires `block.timestamp >= request.executeAfter`.
- During the timelock window, no valid commitment exists in the Semaphore group for this credential, preventing proof generation.
- Only one recovery can be pending at a time (reverts with `RecoveryAlreadyPending()`).
- Recovery is disabled when `apps[appId].recoveryTimelock == 0`.

### Attestation Freshness

Attestations include a verifier-signed `issuedAt` timestamp. The contract enforces:

```
if (block.timestamp > attestation.issuedAt + attestationValidityDuration) revert AttestationExpired();
```

Default validity is 30 minutes. The owner can adjust via `setAttestationValidityDuration()` (must be > 0).

### Status Gating

All state-changing credential operations check that both the credential group and app are ACTIVE:

- `verifyAttestation()` (used by register, renew, initiateRecovery): requires credential group ACTIVE and app ACTIVE.
- `_submitProof()`: requires credential group ACTIVE and app ACTIVE.
- `executeRecovery()`: requires credential group ACTIVE and app ACTIVE.
- `removeExpiredCredential()`: does not check status (expired credentials can be removed regardless of group/app status).

## 2. Trust Assumptions

### Owner (single EOA, BringID)

The CredentialRegistry owner is currently a single EOA controlled by BringID. The owner is trusted to:

- Create and manage credential groups honestly (not suspending groups to grief users).
- Manage trusted verifiers responsibly (not adding malicious verifiers).
- Set reasonable attestation validity durations.
- Use `pause()` only for genuine emergencies.
- Not manipulate DefaultScorer values to inflate or deflate scores unfairly.

The owner uses Ownable2Step for ownership transfer, requiring the new owner to explicitly accept. The DefaultScorer contract also uses Ownable2Step independently.

**Recommended hardening**: transfer ownership to a Gnosis Safe multisig fronted by a TimelockController.

### Trusted Verifiers

Verifiers are off-chain services that authenticate users (via TLSN, OAuth, zkPassport, zkKYC, etc.) and sign attestation structs with their ECDSA key. The protocol trusts verifiers to:

- Derive consistent `credentialId` values for the same underlying identity (prevents duplicate registrations).
- Not sign attestations for fraudulent identities.
- Set accurate `issuedAt` timestamps.
- Protect their signing keys.

Multiple verifiers are supported via the `trustedVerifiers` mapping. Each verifier can sign attestations for any credential group and any app.

### App Admins

App admins are self-appointed (whoever calls `registerApp()` becomes admin). Admin transfer uses a two-step pattern (`transferAppAdmin` + `acceptAppAdmin`). App admins are trusted to:

- Set appropriate recovery timelocks for their app.
- Choose scorer contracts that implement `IScorer` correctly.
- Not grief their own users by suspending their app without cause.

App admins cannot affect other apps or the global registry.

### Semaphore Contract

The protocol delegates all zero-knowledge proof verification and nullifier management to the external Semaphore contract (PSE-audited). The registry trusts Semaphore to:

- Correctly verify Groth16 proofs of group membership.
- Enforce per-group nullifier uniqueness via `validateProof()`.
- Correctly manage Merkle tree membership (add/remove members).
- Return accurate results from `verifyProof()` (view-only verification).

### Scorer Contracts

Each app points to a scorer contract (default: `DefaultScorer`). The registry calls `scorer.getScore(credentialGroupId)` during proof submission and score retrieval. Scorer contracts are trusted to:

- Return consistent, non-reverting score values.
- Not have side effects in `getScore()` (it is called within `nonReentrant`-guarded functions).

Custom scorers are set by app admins via `setAppScorer()`. A malicious scorer could return inflated scores, but this only affects the app that configured it.

## 3. Attack Vectors & Mitigations

### Double-Spend via Commitment Change

**Attack**: a user changes their Semaphore identity commitment to get fresh nullifiers for the same scope, effectively proving the same credential twice.

**Mitigation**: commitment continuity is enforced. `renewCredential()` requires the same commitment. `registerCredential()` rejects already-registered credentials. Only `executeRecovery()` can change the commitment, and recovery removes the old commitment from the Semaphore group immediately during `initiateRecovery()`, with a timelock before the new commitment is added. During the timelock, no valid commitment exists, so no proofs can be generated.

### Cross-App Proof Replay

**Attack**: a proof generated for app A is submitted to app B.

**Mitigation**: each (credentialGroupId, appId) pair has its own Semaphore group (created lazily via `_ensureAppSemaphoreGroup()`). Since Semaphore proofs are bound to a specific group ID, a proof for app A's group is invalid for app B's group. No additional mechanism is needed.

### Cross-Caller Proof Replay

**Attack**: Alice generates a proof and Bob submits it as his own.

**Mitigation**: scope binding. The proof's scope must equal `keccak256(abi.encode(msg.sender, context))`. Since `msg.sender` differs between Alice and Bob, a proof generated for Alice's address will fail scope verification when submitted by Bob.

### Attestation Replay

**Attack**: an attacker captures a valid attestation and replays it to register the same credential again.

**Mitigation**: `registerCredential()` sets `cred.registered = true` and rejects subsequent calls with `AlreadyRegistered()`. `renewCredential()` requires the same commitment and group — it cannot be used to create a new credential. Attestation expiry (default 30 minutes) limits the replay window. Within the validity window, replaying an attestation for an already-registered credential will revert.

### Reentrancy

**Attack**: a malicious contract triggers a callback during a state-changing operation to re-enter the registry.

**Mitigation**: `ReentrancyGuard` (OpenZeppelin) with `nonReentrant` modifier on all state-changing user functions: `registerCredential`, `renewCredential`, `submitProof`, `submitProofs`, `initiateRecovery`, `executeRecovery`, `removeExpiredCredential`. The external calls to the Semaphore contract (`addMember`, `removeMember`, `validateProof`) occur within the reentrancy guard.

### Owner Compromise

**Attack**: an attacker gains control of the owner's private key.

**Impact**: the attacker could suspend all credential groups (halting the protocol), add a malicious verifier (enabling fraudulent registrations), remove legitimate verifiers (blocking renewals), change attestation validity, pause the contract, or manipulate DefaultScorer values.

**Mitigation**: Ownable2Step prevents accidental ownership transfer. Recommended hardening: Gnosis Safe multisig + TimelockController. The `pause()` function provides an emergency stop if compromise is detected before damage is done.

**Limitations**: the attacker cannot directly modify existing credential records, Semaphore group memberships, or per-app configurations (app admin, scorer, recovery timelock).

### Verifier Compromise

**Attack**: an attacker obtains a trusted verifier's private key and signs fraudulent attestations.

**Impact**: the attacker could register credentials for any credential group and any app with arbitrary commitments. However, each registration is bound to a `credentialId` — if the attacker doesn't know the legitimate user's `credentialId`, they cannot overwrite existing registrations.

**Mitigation**: the owner can call `removeTrustedVerifier()` to immediately revoke the compromised key. Attestation expiry limits the window for using pre-signed attestations. Multiple independent verifiers can be maintained for redundancy.

### Malicious Scorer

**Attack**: an app admin sets a custom scorer that returns inflated or manipulated scores.

**Impact**: `submitProofs()` and `getScore()` would return incorrect aggregate scores for that app. Other apps are unaffected (each app has its own scorer reference).

**Mitigation**: scorer choice is per-app, set by the app admin. Users/integrators should verify which scorer an app uses before relying on its scores. The DefaultScorer (owned by BringID) serves as a trusted baseline.

### Family Bypass via Group Change

**Attack**: a user tries to hold two credentials in the same family (e.g., Farcaster Low and Farcaster High) to get two sets of nullifiers.

**Mitigation**: family groups share a registration hash. The first `registerCredential()` succeeds; the second reverts with `AlreadyRegistered()`. Group changes within a family must go through `initiateRecovery()`, which enforces `credFamilyId > 0 && credFamilyId == attestFamilyId` and uses the recovery timelock. The timelock ensures no valid commitment exists during the transition, preventing double-spend.

### Recovery Double-Spend

**Attack**: a user initiates recovery to change their commitment, then uses the old commitment to generate proofs before the timelock expires.

**Mitigation**: `initiateRecovery()` immediately removes the old commitment from the Semaphore group (via `SEMAPHORE.removeMember()`). The new commitment is not added until `executeRecovery()` after the timelock. During the timelock window, no valid commitment exists in the group. Additionally, `removeExpiredCredential()` is blocked during pending recovery (`RecoveryPending()`), preventing a race condition where expiry removal could interfere.

## 4. Accepted Risks

### removeExpiredCredential Grief Vector (Finding #10)

`removeExpiredCredential()` is publicly callable by design — anyone can call it once `block.timestamp >= cred.expiresAt`. An attacker could monitor for expired credentials and call `removeExpiredCredential()` before the credential holder does.

- **Attacker cost**: ~50,000–150,000 gas per call (Merkle proof verification + storage writes).
- **User impact**: the user must call `renewCredential()` to re-add their commitment to the Semaphore group, costing ~100,000–300,000 additional gas compared to renewing before expiry.
- **Security impact**: none. The credential remains registered (`cred.registered` stays true), the commitment is preserved (`cred.commitment` is not cleared), and renewal re-adds the same commitment. No nullifiers are lost and no double-spend is possible.
- **Design rationale**: public callability enables protocol hygiene — expired commitments can be cleaned from Semaphore groups without requiring the credential holder's participation.

### Attestation Replay Within Validity Window

A valid attestation can technically be submitted multiple times within its validity window (default 30 minutes). However, this has no security impact:

- `registerCredential()` rejects re-registration (`AlreadyRegistered()`).
- `renewCredential()` is idempotent within the same validity period (re-extending the expiry is harmless).
- `initiateRecovery()` rejects duplicate recovery initiation (`RecoveryAlreadyPending()`).

### Credential Window Between Expiry and Removal

After a credential expires (`block.timestamp >= cred.expiresAt`) but before `removeExpiredCredential()` is called, the credential's commitment remains in the Semaphore group. During this window, the user can still generate valid Semaphore proofs. This is accepted because:

- Expiry is a soft boundary — the credential was valid until recently.
- Anyone can call `removeExpiredCredential()` to close this window.
- The window creates no double-spend risk.

### Scorer Trust per App

Apps can set arbitrary scorer contracts via `setAppScorer()`. The registry does not validate scorer behavior beyond requiring a non-zero address. A malicious or buggy scorer could return incorrect scores, but this is scoped to the app that configured it.

## 5. External Dependencies

### Semaphore (PSE)

- **Contract**: `ISemaphore` interface, deployed at `0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D`.
- **Version**: @semaphore-protocol/contracts (npm).
- **Audit status**: audited by PSE (Privacy & Scaling Explorations, Ethereum Foundation).
- **Usage**: group creation (`createGroup`), member management (`addMember`, `removeMember`), proof verification (`validateProof`, `verifyProof`).
- **Trust**: the registry fully delegates zero-knowledge proof verification and nullifier tracking to Semaphore. A bug in Semaphore's proof verification could allow invalid proofs to pass.

### OpenZeppelin Contracts

- **Modules used**: `Ownable2Step` (two-step ownership), `ECDSA` (signature recovery), `Pausable` (emergency stop), `ReentrancyGuard` (reentrancy protection).
- **Version**: managed via git submodule (`lib/openzeppelin-contracts`).
- **Audit status**: extensively audited; industry standard.

### Solidity 0.8.23

- **Compiler**: pragma is pinned to `0.8.23` (not floating).
- **Overflow protection**: built-in checked arithmetic (Solidity 0.8+).
- **Known issues**: no known compiler bugs affecting the patterns used in this codebase.
