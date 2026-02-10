# Migration Guide — Identity Registry v2 (PR #5)

This guide is for repos that integrate with the BringID CredentialRegistry contracts. It covers deployed addresses, new features, credential groups, default scores, and all ABI breaking changes.

## Deployed Contracts (Base Sepolia — chain ID 84532)

| Contract | Address |
|---|---|
| Semaphore | `0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D` |
| CredentialRegistry | `0xB0e2bf7d3D6536ad4b5851533bb120C9dbF5493b` |
| DefaultScorer | `0x24EDA18506D9509F438c53496274A2fA4675888F` |

Owner / trusted verifier: `0xc7308C53B6DD25180EcE79651Bf0b1Fd16e64452`

## Credential Groups

| ID | Credential | Group | Default Score | Validity Duration |
|----|------------|-------|---------------|-------------------|
| 1 | Farcaster | Low | 2 | No expiry |
| 2 | Farcaster | Medium | 5 | No expiry |
| 3 | Farcaster | High | 10 | No expiry |
| 4 | GitHub | Low | 2 | No expiry |
| 5 | GitHub | Medium | 5 | No expiry |
| 6 | GitHub | High | 10 | No expiry |
| 7 | X (Twitter) | Low | 2 | No expiry |
| 8 | X (Twitter) | Medium | 5 | No expiry |
| 9 | X (Twitter) | High | 10 | No expiry |
| 10 | zkPassport | — | 20 | No expiry |
| 11 | Self | — | 20 | No expiry |
| 12 | Uber Rides | — | 10 | No expiry |
| 13 | Apple Subs | — | 10 | No expiry |
| 14 | Binance KYC | — | 20 | No expiry |
| 15 | OKX KYC | — | 20 | No expiry |

All groups have `validityDuration = 0` (no expiry). Scores are set on the `DefaultScorer` contract. Apps can override scoring by deploying a custom `IScorer` and calling `setAppScorer()`. To check whether an app uses a custom scorer, call `apps(appId)` — the returned `scorer` field will differ from `defaultScorer()` if a custom one is set.

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
2. `initiateRecovery()` — removes the old commitment immediately and queues the new one behind the app's `recoveryTimelock`.
3. `executeRecovery()` — adds the new commitment after the timelock expires.

App admins configure the timelock at `registerApp()` time. Setting `recoveryTimelock` to `0` disables recovery.

### 5. Per-credential-group expiration

Credential groups now carry a `validityDuration` (seconds, `0` = no expiry). On registration, `credentialExpiresAt` is stored. After expiry, anyone can call `removeExpiredCredential()` to evict the commitment from the Semaphore group and allow re-registration.

### 6. Multiple trusted verifiers

The single `TLSNVerifier` address has been replaced with a `trustedVerifiers` mapping supporting multiple signers (TLSN, OAuth, zkPassport, etc.) via `addTrustedVerifier()` / `removeTrustedVerifier()`.

### 7. Credential group enumeration

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
 }
```
Score is now on `DefaultScorer`. Semaphore group IDs are managed internally via `appSemaphoreGroups[credentialGroupId][appId]`.

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
- `CredentialRecord` — `{ bool registered, bool expired, uint256 commitment, uint256 expiresAt, RecoveryRequest pendingRecovery }`

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
| `createCredentialGroup(id, validityDuration)` | write | Owner-only, now takes `validityDuration` |
| `setCredentialGroupValidityDuration(id, duration)` | write | Owner-only, update expiry for future registrations |
| `getCredentialGroupIds()` | view | List all credential group IDs |
| `appIsActive(appId)` | view | Check if app is active |

### Event changes

| v1 | v2 |
|---|---|
| `CredentialAdded(credentialGroupId, commitment)` | `CredentialRegistered(credentialGroupId, appId, commitment, credentialId, registrationHash, verifier)` |
| `ProofValidated(credentialGroupId)` | `ProofValidated(credentialGroupId, appId, nullifier)` |
| `TLSNVerifierSet(verifier)` | `TrustedVerifierAdded(verifier)` / `TrustedVerifierRemoved(verifier)` |

**New events:** `AppSemaphoreGroupCreated`, `AppRegistered`, `AppSuspended`, `AppActivated`, `AppScorerSet`, `AppAdminTransferred`, `AppRecoveryTimelockSet`, `RecoveryInitiated`, `RecoveryExecuted`, `CredentialRenewed`, `CredentialExpired`, `CredentialGroupValidityDurationSet`, `AttestationValidityDurationSet`.

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
- [ ] If listening to events, update to new event names and signatures
- [ ] If matching on revert reason strings, update to `BID::` prefixed messages
