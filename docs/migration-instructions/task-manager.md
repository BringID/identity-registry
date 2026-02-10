# Migration Instructions — BringID Task Manager

## Overview

The Task Manager accepts, schedules, and batches verification/claim tasks before sending them to blockchain relayers. It directly constructs calldata for the CredentialRegistry contract.

## Required Changes

### 1. Verification Task API — Field Rename and Addition (CRITICAL)

**Files:** `src/controllers/task-controller.ts`, validation schemas, `src/services/task-service.ts`

The `id_hash` field must be renamed to `credential_id`, and `app_id` must be added:

```diff
  interface IAddVerificationRequest {
-   id_hash: string
+   credential_id: string
    registry: string
    credential_group_id: string
+   app_id: string
    verifier_signature: string
    identity_commitment: string
  }
```

Update Celebrate/Joi validation schemas accordingly.

### 2. Task Model — Updated Params

**File:** Task MongoDB model/schema

```diff
  interface ITaskParams {
-   idHash?: string
+   credentialId?: string
    registry?: string
    credentialGroupId?: string
+   appId?: string
    verifierSignature?: string
    identityCommitment?: string
  }
```

Update the `_flattenTask` method to map `credentialId` → `credential_id` and `appId` → `app_id` in API responses.

### 3. Task Deduplication Logic

**File:** `src/services/task-service.ts`

If deduplication checks use `id_hash`, update to `credential_id`:

```diff
- // Find existing task by id_hash and identity_commitment
- const existing = await Task.findOne({ 'params.idHash': idHash, 'params.identityCommitment': identityCommitment })
+ // Find existing task by credential_id, app_id, and identity_commitment
+ const existing = await Task.findOne({ 'params.credentialId': credentialId, 'params.appId': appId, 'params.identityCommitment': identityCommitment })
```

### 4. Relayer Calldata — registerCredential ABI (CRITICAL)

**File:** `src/services/sender-services/` (verification batch sender)

The contract function has been renamed and the Attestation struct has changed:

```diff
  // Old: joinGroup(attestation, signature)
  // New: registerCredential(attestation, signature)

  // Old Attestation: { registry, credentialGroupId, idHash, semaphoreIdentityCommitment }
  // New Attestation: { registry, credentialGroupId, credentialId, appId, semaphoreIdentityCommitment, issuedAt }
```

Update the ABI encoding to use the new function name and struct:

```diff
- const callData = registryInterface.encodeFunctionData('joinGroup', [
-   { registry, credentialGroupId, idHash, semaphoreIdentityCommitment: commitment },
+ const callData = registryInterface.encodeFunctionData('registerCredential', [
+   { registry, credentialGroupId, credentialId, appId, semaphoreIdentityCommitment: commitment, issuedAt },
    signature
  ])
```

Note: `issuedAt` is a new field included in the verifier response as `attestation.issued_at` — it must be passed through to the calldata. The contract enforces `block.timestamp <= issuedAt + attestationValidityDuration` (default 30 minutes).

### 5. Contract ABI Import

Update the CredentialRegistry ABI used for encoding calldata. Key changes:
- `joinGroup` → `registerCredential`
- Attestation struct includes `appId`, `credentialId` (was `idHash`), `issuedAt`
- New error messages prefixed with `BID::`

### 6. Credential Group ID Renumbering

All `credentialGroupId` values have been renumbered in v2:

| Credential | v1 ID | v2 ID |
|---|---|---|
| Farcaster Low | 14 | 1 |
| Farcaster Medium | 15 | 2 |
| Farcaster High | 16 | 3 |
| GitHub Low | 8 | 4 |
| GitHub Medium | 9 | 5 |
| GitHub High | 10 | 6 |
| X (Twitter) Low | 11 | 7 |
| X (Twitter) Medium | 12 | 8 |
| X (Twitter) High | 13 | 9 |
| zkPassport | 17 | 10 |
| Self | — | 11 |
| Uber Rides | 1 | 12 |
| Apple Subs | — | 13 |
| Binance KYC | — | 14 |
| OKX KYC | — | 15 |

### 7. Contract Error Handling

**File:** `src/configs/` or error handling utilities

If the task-manager parses contract error messages from relayer responses, update error matching for `BID::` prefixed error strings:

```diff
- 'not registered'
+ 'BID::not registered'
- 'already registered'
+ 'BID::already registered'
```

### 8. Conflict Error Messages

Update user-facing error messages:

```diff
- "Task already verified with this identityCommitment. Status: completed"
+ "Task already verified with this credential_id. Status: completed"
```

### 9. Environment Variables

Add or update:
- `REGISTRY_ADDRESS` — new CredentialRegistry address (current **Base Sepolia** deployment): `0x78Ce003ff79557A44eae862377a00F66df0557B2`

> **Note:** This is the current Base Sepolia (chain 84532) deployment. Base Mainnet addresses are TBD.

## No Changes Required

- Claim task endpoint and logic (uses Semaphore proofs directly, not attestations)
- Batch processing and scheduling
- MongoDB connection and general infrastructure
- Drop whitelist configuration
- Cron scheduling
- Winston logging
