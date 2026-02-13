# Migration Instructions — BringID SDK

## Overview

The BringID SDK (`bringid` npm package) provides `BringID` class for reputation scoring, humanity verification, and Semaphore proof verification (on-chain via Multicall3 or off-chain via API). Includes a `BringIDModal` React component.

## Required Changes

### 1. `appId` — SDK Must Accept and Provide

The SDK is the source of `appId` for the widget. Each consuming app must register on the `CredentialRegistry` contract via `registerApp()` and obtain an `appId`. The SDK then passes this to the widget.

**`BringID` constructor or `verifyHumanity()` options:**

```diff
+ // Option A: Constructor
+ const bringid = new BringID({ mode: "dev", appId: "1" });

+ // Option B: Per-call
+ const { proofs, points } = await bringid.verifyHumanity({ appId: "1" });
```

**`BringIDModal` component:**

```diff
  <BringIDModal
    address={address}
+   appId="1"
    generateSignature={(message) => walletClient.signMessage({ message })}
    mode="dev"
  />
```

The SDK must pass `appId` to the widget via the `PROOFS_REQUEST` postMessage or as an iframe URL parameter. The widget uses it for identity derivation, verifier requests, and proof construction.

### 2. Registry Contract ABI

**File:** `src/abi/registry.tsx`

The Registry contract ABI must be updated to reflect v2 changes:

- **Renamed functions:**
  - `joinGroup` → `registerCredential`
  - `validateProof` → `submitProof`
  - `score` → `submitProofs`

- **Updated function signatures:**
  - `verifyProof(uint256, CredentialGroupProof)` — now public view
  - `verifyProofs(uint256, CredentialGroupProof[])` — new batch view
  - `getScore(uint256, CredentialGroupProof[])` — new view returning score

- **Updated structs in ABI:**
  - `Attestation`: added `appId` (uint256), `issuedAt` (uint256); renamed `idHash` → `credentialId`
  - `CredentialGroupProof`: added `appId` (uint256)
  - `CredentialGroup`: removed `score`, `semaphoreGroupId`; added `validityDuration`, `familyId`

- **New structs:** `App`, `RecoveryRequest`, `CredentialRecord`

- **New events:** `CredentialRegistered`, `AppRegistered`, `RecoveryInitiated`, `RecoveryExecuted`, `CredentialRenewed`, `CredentialExpired`, etc.

### 3. On-Chain Proof Verification (Multicall3)

**File:** `src/modules/bring-id-sdk/index.ts` (verifyProofs method)

When verifying proofs on-chain with a provider, the Multicall3 call data must use the updated ABI:

- The function called on the registry changes from `validateProof` to `verifyProof` (view)
- Each proof's `CredentialGroupProof` struct now includes `appId`
- The encoding must match: `verifyProof(uint256 context, CredentialGroupProof calldata proof)`

```diff
  // Encoding each proof for Multicall3
  const callData = registryInterface.encodeFunctionData(
-   'validateProof',
-   [context, { credentialGroupId, semaphoreProof }]
+   'verifyProof',
+   [context, { credentialGroupId, appId, semaphoreProof }]
  )
```

### 4. Scores — Fetch from Scorer Contract

Scores are no longer embedded in `CredentialGroup` or task config files. Each app has a Scorer contract (default: `DefaultScorer`) that the app should query for scores.

**How to fetch scores:**

```typescript
// 1. Get the app's scorer address from the registry
const app = await registry.apps(appId)
const scorerAddress = app.scorer

// 2. Fetch scores for credential groups
const scorer = new Contract(scorerAddress, ['function getScore(uint256) view returns (uint256)'], provider)
const score = await scorer.getScore(credentialGroupId)
```

The SDK's `verifyProofs()` result should use on-chain scores (from the Scorer contract) rather than static `points` values from task config files.

If the SDK currently reads `points` from the GitHub-hosted tasks config and returns them in `TVerifyProofsResult.points.groups`, update this to use on-chain scores instead.

### 5. TSemaphoreProof Type

**File:** `src/types/`

Add `app_id` to the proof type:

```diff
  type TSemaphoreProof = {
    credential_group_id: string
+   app_id: string
    semaphore_proof: {
      merkle_tree_depth: number
      merkle_tree_root: string
      nullifier: string
      message: string
      scope: string
      points: string[]
    }
  }
```

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

If the SDK maps `credentialGroupId` from config files, ensure the configs are updated first.

### 7. verifyProofs API Endpoint

**File:** `src/api/verify-proofs/`

If the off-chain verification endpoint (`POST /v1/proofs/verify`) expects the updated proof format with `app_id`, update the request body:

```diff
  {
    proofs: [
      {
        credential_group_id: string,
+       app_id: string,
        semaphore_proof: { ... }
      }
    ],
    registry: string,
    chain_id: number
  }
```

### 8. PROOFS_REQUEST / PROOFS_RESPONSE Messages

The postMessage communication with the widget now includes `app_id` in proofs. The SDK's message validation and type definitions need updating:

**File:** `src/utils/validate-inbound-message.ts`, `src/utils/validate-outbound-message.ts`

Ensure the validators accept `app_id` in proof objects.

**PROOFS_REQUEST** — the SDK should send `appId` so the widget knows which app context to use:

```diff
  {
    type: 'PROOFS_REQUEST',
    requestId: string,
    payload: {
      scope?: string,
      message?: string,
      minPoints?: number,
+     appId?: string,
    }
  }
```

### 9. Verifier Response Type Changes

If the SDK defines types for verifier responses or attestation data, update field names:
- `verifier_message` → `attestation`
- `id_hash` → `credential_id`
- Add `app_id: string` field
- Add `issued_at: string` field

## No Changes Required

- `getAddressScore()` — address-based scoring is independent of registry changes
- `destroy()` cleanup logic
- Error classes
- Domain whitelist
- General postMessage architecture
