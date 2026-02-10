# Migration Instructions — BringID Widget

## Overview

The widget is a Next.js embeddable iframe that handles identity verification and Semaphore ZK proof generation. It communicates with the parent website via postMessage, manages OAuth and ZK-TLS flows, and calls backend APIs (verifier, task-manager, indexer).

## Required Changes

### 1. Semaphore Identity Derivation (CRITICAL)

**File:** `src/utils/create-semaphore-identity.tsx`

The identity derivation formula has changed. It now requires `appId` in addition to the master key and credential group ID:

```diff
- const createSemaphoreIdentity = (masterKey: string, credentialGroupId: string) => {
-   const coder = new AbiCoder()
-   const encoded = coder.encode(['string', 'string'], [masterKey, credentialGroupId])
-   const identityKey = keccak256(encoded)
+ const createSemaphoreIdentity = (masterKey: string, appId: string, credentialGroupId: string) => {
+   const identityKey = keccak256(
+     solidityPacked(
+       ['bytes32', 'uint256', 'uint256'],
+       [masterKey, appId, credentialGroupId]
+     )
+   )
    const identity = new Identity(identityKey)
    return identity
  }
```

**Key differences:**
- Uses `solidityPacked` (equivalent to `abi.encodePacked`) instead of `AbiCoder.encode`
- Takes the master key as `bytes32`, `appId` as `uint256`, `credentialGroupId` as `uint256`
- The `masterKey` should be the raw wallet private key or a deterministic derivative — not the wallet signature (verify this matches your current implementation)
- `appId` is a new required parameter

All callers of `createSemaphoreIdentity` must be updated to pass `appId`.

### 2. `appId` — Provided by SDK

The widget receives `appId` from the BringID SDK (not from remote configs). The SDK passes it via the `PROOFS_REQUEST` postMessage or as an iframe URL parameter.

**Where to receive it:** `src/app/content/inner-content/index.tsx` — the postMessage handler for `PROOFS_REQUEST`.

The `appId` must flow through the entire verification pipeline:
- Semaphore identity derivation
- Verifier API requests
- Task manager API requests
- Proof generation and response

### 3. Verifier API — Updated Request and Response Format

**File:** `src/app/content/api/verifier/index.tsx`

**Request changes** — add `app_id` to both endpoints:

```diff
 // POST /verify (ZK-TLS)
 {
   tlsn_presentation: string,
   registry: string,
   credential_group_id: string,
+  app_id: string,
   semaphore_identity_commitment: string
 }

 // POST /verify/oauth
 {
   message: { domain, userId, score, timestamp },
   signature: string,
   registry: string,
   credential_group_id: string,
+  app_id: string,
   semaphore_identity_commitment: string
 }
```

**Response changes** — the response wrapper and field names have changed:

```diff
- const idHash = response.verifier_message.id_hash
- const signature = response.signature
+ const credentialId = response.attestation.credential_id
+ const appId = response.attestation.app_id
+ const issuedAt = response.attestation.issued_at
+ const signature = response.signature
```

New fields in `response.attestation`:
- `credential_id` (was `id_hash` under `verifier_message`)
- `app_id` — the app ID echoed back
- `issued_at` — unix timestamp (contract enforces 30-minute validity window)

Update all code that reads from the verifier response to use the new field names.

### 4. Task Manager API — Field Rename and Addition

**File:** `src/app/content/api/task-manager/index.tsx`

The `id_hash` field has been renamed to `credential_id` and `app_id` is required:

```diff
  {
    registry: string,
    credential_group_id: string,
-   id_hash: string,
+   credential_id: string,
+   app_id: string,
    identity_commitment: string,
    verifier_signature: string
  }
```

### 5. Indexer API — Per-App Semaphore Group IDs

**File:** `src/app/content/api/indexer/index.tsx`

Semaphore groups are now per-app. The `semaphore_group_id` values used when fetching Merkle proofs are now different (per-app group IDs from the `appSemaphoreGroups` mapping). The widget needs to either:

- Query the contract's `appSemaphoreGroups(credentialGroupId, appId)` to get the correct Semaphore group ID, **or**
- Receive the Semaphore group ID from the task-manager/verifier response after registration.

### 6. Proof Format — Add `appId`

**File:** `src/utils/prepare-proofs.tsx` and related

The `CredentialGroupProof` struct now includes `appId`:

```diff
  interface TSemaphoreProof {
    credential_group_id: string
+   app_id: string
    semaphore_proof: {
      merkle_tree_depth: number
      merkle_tree_root: string
      nullifier: string
      message: string
      scope: string
      points: number
    }
  }
```

The `PROOFS_RESPONSE` postMessage payload must include `app_id` in each proof.

### 7. Scores — Fetch from Scorer Contract

Scores are no longer hardcoded in `CredentialGroup` or in task configs. Each app has a Scorer contract (default: `DefaultScorer`) that provides scores per credential group.

The app should fetch its Scorer address from the registry and then call `getScore(credentialGroupId)` to get the score for each credential group:

```typescript
// 1. Get the app's scorer address
const app = await registry.apps(appId)
const scorerAddress = app.scorer

// 2. Fetch score for a credential group
const scorer = new Contract(scorerAddress, ['function getScore(uint256) view returns (uint256)'], provider)
const score = await scorer.getScore(credentialGroupId)
```

Remove any hardcoded `points` values from task group definitions if they exist in the widget. Scores should be fetched dynamically.

### 8. Credential Group ID Renumbering

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

If credential group IDs are loaded from the configs repo at runtime, ensure the configs repo is updated first.

### 9. Verification Status / Task Data Model

**File:** `src/app/content/store/` (Redux reducers)

If the Redux store or `TVerification` type references `id_hash`, rename to `credential_id`:

```diff
  interface TVerification {
    status: 'pending' | 'completed' | 'failed'
    scheduledTime: number
    credentialGroupId: string
+   appId: string
    batchId?: string | null
    txHash?: string
    fetched: boolean
    taskId: string
  }
```

### 10. Scope Binding Change

The scope for `submitProof` is now `keccak256(abi.encode(msg.sender, context))` where `msg.sender` is the on-chain caller (relayer). Verify that the proof generation uses the correct scope formula. If the widget generates scope client-side, ensure it matches what the contract expects.

## No Changes Required

- OAuth popup communication protocol (AUTH_SUCCESS / AUTH_ERROR)
- ZK-TLS extension communication protocol
- Theme support, URL parameters (except new `appId` if passed as URL param)
- Plausible analytics events
- General postMessage architecture
