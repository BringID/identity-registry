# Migration Guide — Identity Registry v2 (PR #5)

This guide is for repos that integrate with the BringID CredentialRegistry contracts. It covers deployed addresses, new features, credential groups, default scores, and all ABI breaking changes.

## Deployed Contracts (Base Sepolia — chain ID 84532)

| Contract | Address |
|---|---|
| Semaphore | `0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D` |
| CredentialRegistry | `0x78Ce003ff79557A44eae862377a00F66df0557B2` |
| DefaultScorer | `0x68a3CA701c6f7737395561E000B5cCF4ECa5185A` |

Owner / trusted verifier: `0xc7308C53B6DD25180EcE79651Bf0b1Fd16e64452`

## Credential Groups

| ID | Credential | Group | Family | Default Score | Validity Duration |
|----|------------|-------|--------|---------------|-------------------|
| 1 | Farcaster | Low | 1 | 2 | 30 days |
| 2 | Farcaster | Medium | 1 | 5 | 60 days |
| 3 | Farcaster | High | 1 | 10 | 90 days |
| 4 | GitHub | Low | 2 | 2 | 30 days |
| 5 | GitHub | Medium | 2 | 5 | 60 days |
| 6 | GitHub | High | 2 | 10 | 90 days |
| 7 | X (Twitter) | Low | 3 | 2 | 30 days |
| 8 | X (Twitter) | Medium | 3 | 5 | 60 days |
| 9 | X (Twitter) | High | 3 | 10 | 90 days |
| 10 | zkPassport | — | 0 | 20 | 180 days |
| 11 | Self | — | 0 | 20 | 180 days |
| 12 | Uber Rides | — | 0 | 10 | 180 days |
| 13 | Apple Subs | — | 0 | 10 | 180 days |
| 14 | Binance KYC | — | 0 | 20 | 180 days |
| 15 | OKX KYC | — | 0 | 20 | 180 days |

Scores are set on the `DefaultScorer` contract. Apps can override scoring by deploying a custom `IScorer` and calling `setAppScorer()`. To check whether an app uses a custom scorer, call `apps(appId)` — the returned `scorer` field will differ from `defaultScorer()` if a custom one is set.

> **Family enforcement:** Groups in the same family (e.g. Farcaster Low/Medium/High) share a registration hash, so a user can only hold one credential per family per app. Group changes within a family go through the recovery timelock (`initiateRecovery`/`executeRecovery`). Standalone groups (family = 0) have no such constraint.

## New Features

### 1. Per-app Semaphore groups

Each `(credentialGroupId, appId)` pair now gets its own Semaphore group, created lazily on first credential registration. Since Semaphore enforces per-group nullifier uniqueness, this naturally prevents cross-app proof replay without needing a second ZK circuit.

### 2. App self-registration

Apps register themselves via `registerApp(recoveryTimelock)` — public, auto-increment ID. The caller becomes the app admin and can manage:
- Custom scorer (`setAppScorer`)
- Recovery timelock (`setAppRecoveryTimelock`)
- Admin transfer (`setAppAdmin`)

The registry owner retains `suspendApp()`.

### 3. Custom app scoring

Scores are no longer stored in `CredentialGroup`. A separate `DefaultScorer` contract (owned by BringID) holds global scores. Each app can point to a custom `IScorer` implementation via `setAppScorer()`. If no custom scorer is set, the `DefaultScorer` is used.

### 4. Per-app timelocked key recovery

Users who lose their wallet can recover credentials per-app:
1. Re-authenticate via any supported verification flow (zkTLS, OAuth, zkPassport, zkKYC, etc.) — the verifier re-derives the same `credentialId` and signs an attestation with a new commitment.
2. `initiateRecovery()` — removes the old commitment immediately and queues the new one behind the app's `recoveryTimelock`. Also supports group changes within the same family (e.g. upgrading from Farcaster Low to High).
3. `executeRecovery()` — adds the new commitment after the timelock expires and updates `credentialGroupId`.

App admins configure the timelock at `registerApp()` time. Setting `recoveryTimelock` to `0` disables recovery.

### 5. Per-credential-group expiration

Credential groups now carry a `validityDuration` (seconds, `0` = no expiry). On registration, `credentialExpiresAt` is stored. After expiry, anyone can call `removeExpiredCredential()` to evict the commitment from the Semaphore group and allow renewal.

### 6. Credential family enforcement

Credential groups can be assigned to a family (e.g. Farcaster Low/Medium/High all belong to family 1). A user can only hold **one credential per family per app**. This is enforced via the registration hash: family groups use `keccak256(registry, familyId, 0, credentialId, appId)` while standalone groups use `keccak256(registry, 0, credentialGroupId, credentialId, appId)`.

Group changes within a family (e.g. upgrading from Farcaster Low to High) go through the **recovery timelock** (`initiateRecovery`/`executeRecovery`), not renewal. This prevents double-spend — the timelock ensures no valid commitment exists during the transition. `renewCredential()` requires the same group as the original registration.

### 7. Multiple trusted verifiers

The single `TLSNVerifier` address has been replaced with a `trustedVerifiers` mapping supporting multiple signers (TLSN, OAuth, zkPassport, etc.) via `addTrustedVerifier()` / `removeTrustedVerifier()`.

### 8. Credential group enumeration

New `getCredentialGroupIds()` view returns all registered credential group IDs.

## ABI Breaking Changes

### Struct changes

**`CredentialGroup`** — fields removed and added:
```diff
 struct CredentialGroup {
-    uint256 score;
-    uint256 semaphoreGroupId;
     CredentialGroupStatus status;
+    uint256 validityDuration;
+    uint256 familyId;          // 0 = standalone, >0 = family grouping
 }
```
Score is now on `DefaultScorer`. Semaphore group IDs are managed internally via `appSemaphoreGroups[credentialGroupId][appId]`. `familyId` groups related credentials (e.g. Farcaster Low/Medium/High share family 1) — users can only hold one credential per family per app.

**`Attestation`** — renamed and added fields:
```diff
 struct Attestation {
     address registry;
     uint256 credentialGroupId;
-    bytes32 idHash;
+    bytes32 credentialId;
+    uint256 appId;
     uint256 semaphoreIdentityCommitment;
+    uint256 issuedAt;
 }
```
The `issuedAt` timestamp is signed by the verifier. The contract enforces `block.timestamp <= issuedAt + attestationValidityDuration` (default 30 minutes, configurable via `setAttestationValidityDuration()`).

**`CredentialGroupProof`** — added `appId`:
```diff
 struct CredentialGroupProof {
     uint256 credentialGroupId;
+    uint256 appId;
     ISemaphore.SemaphoreProof semaphoreProof;
 }
```

**New structs:**
- `App` — `{ AppStatus status, uint256 recoveryTimelock, address admin, address scorer }`
- `RecoveryRequest` — `{ uint256 credentialGroupId, uint256 appId, uint256 newCommitment, uint256 executeAfter }`
- `CredentialRecord` — `{ bool registered, bool expired, uint256 commitment, uint256 expiresAt, uint256 credentialGroupId, RecoveryRequest pendingRecovery }`

### Renamed / replaced functions

| v1 | v2 | Notes |
|---|---|---|
| `joinGroup(attestation, signature)` | `registerCredential(attestation, signature)` | Attestation struct now includes `appId` and `credentialId` (was `idHash`) |
| `validateProof(context, proof)` | `submitProof(context, proof)` | State-changing, consumes nullifier |
| `score(context, proofs)` | `submitProofs(context, proofs)` | State-changing, consumes nullifiers, returns aggregate score |
| `verifyProof(context, proof)` (internal) | `verifyProof(context, proof)` | Now **public view**, does not consume nullifier |
| `credentialGroupScore(id)` | Removed | Use `DefaultScorer.getScore(id)` or app's custom scorer |
| `setVerifier(address)` | `addTrustedVerifier(address)` / `removeTrustedVerifier(address)` | Multiple verifiers supported |

### New functions

| Function | Type | Description |
|---|---|---|
| `verifyProofs(context, proofs)` | view | Batch verify without consuming nullifiers |
| `getScore(context, proofs)` | view | Verify proofs and return aggregate score (no state change) |
| `registerApp(recoveryTimelock)` | write | Public app registration, returns `appId` |
| `suspendApp(appId)` | write | Owner-only |
| `setAppScorer(appId, scorer)` | write | App admin sets custom scorer |
| `setAppAdmin(appId, newAdmin)` | write | App admin transfers admin role |
| `setAppRecoveryTimelock(appId, timelock)` | write | App admin sets recovery timelock |
| `renewCredential(attestation, signature)` | write | Renew a previously-registered credential (same commitment, resets validity) |
| `initiateRecovery(attestation, signature, siblings)` | write | Start key recovery |
| `executeRecovery(registrationHash)` | write | Finalize recovery after timelock |
| `removeExpiredCredential(credentialGroupId, credentialId, appId, siblings)` | write | Evict expired credential (blocked during pending recovery) |
| `activateApp(appId)` | write | App admin reactivates a suspended app |
| `setAttestationValidityDuration(duration)` | write | Owner-only, set max attestation age |
| `createCredentialGroup(id, validityDuration, familyId)` | write | Owner-only, now takes `validityDuration` and `familyId` |
| `setCredentialGroupValidityDuration(id, duration)` | write | Owner-only, update expiry for future registrations |
| `setCredentialGroupFamily(id, familyId)` | write | Owner-only, update family assignment |
| `getCredentialGroupIds()` | view | List all credential group IDs |
| `appIsActive(appId)` | view | Check if app is active |

### Event changes

| v1 | v2 |
|---|---|
| `CredentialAdded(credentialGroupId, commitment)` | `CredentialRegistered(credentialGroupId, appId, commitment, credentialId, registrationHash, verifier)` |
| `ProofValidated(credentialGroupId)` | `ProofValidated(credentialGroupId, appId, nullifier)` |
| `TLSNVerifierSet(verifier)` | `TrustedVerifierAdded(verifier)` / `TrustedVerifierRemoved(verifier)` |

**New events:** `AppSemaphoreGroupCreated`, `AppRegistered`, `AppSuspended`, `AppActivated`, `AppScorerSet`, `AppAdminTransferred`, `AppRecoveryTimelockSet`, `RecoveryInitiated`, `RecoveryExecuted`, `CredentialRenewed`, `CredentialExpired`, `CredentialGroupValidityDurationSet`, `CredentialGroupFamilySet`, `AttestationValidityDurationSet`.

### New contracts

| Contract | Description |
|---|---|
| `DefaultScorer.sol` | Global scores per credential group. Implements `IScorer`. Owner-only `setScore()` / `setScores()`. Views: `getScore()`, `getScores()`, `getAllScores()`. |
| `IScorer.sol` | Interface: `getScore(uint256 credentialGroupId) → uint256` |

### Constructor change

```diff
- constructor(ISemaphore semaphore_, address tlsnVerifier_)
+ constructor(ISemaphore semaphore_, address trustedVerifier_)
```

The constructor now deploys a `DefaultScorer` automatically and adds the provided address as the first trusted verifier.

### Error messages

All `require` error strings now use a `BID::` prefix (e.g. `"BID::not registered"`, `"BID::app not active"`). If your integration matches on revert reason strings, update them accordingly.

## Quick Migration Checklist

- [ ] Update contract addresses to Base Sepolia values above
- [ ] Update ABI imports — `ICredentialRegistry`, events, and structs have changed
- [ ] Add `appId` and `issuedAt` to all `Attestation` structs
- [ ] Add `appId` to all `CredentialGroupProof` structs
- [ ] Rename `idHash` → `credentialId` in attestation construction
- [ ] Replace `joinGroup()` calls with `registerCredential()`
- [ ] Replace `validateProof()` with `submitProof()` or `verifyProof()` (view)
- [ ] Replace `score()` with `submitProofs()` or `getScore()` (view)
- [ ] Replace `credentialGroupScore()` with `DefaultScorer.getScore()`
- [ ] Register your app via `registerApp(recoveryTimelock)` and use the returned `appId`
- [ ] Account for `familyId` in `CredentialGroup` — groups in the same family share a registration hash
- [ ] Account for `credentialGroupId` in `CredentialRecord` — tracks which group within the family
- [ ] For group changes within a family, use `initiateRecovery`/`executeRecovery` (not `renewCredential`)
- [ ] If listening to events, update to new event names and signatures
- [ ] If matching on revert reason strings, update to `BID::` prefixed messages
