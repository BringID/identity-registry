# Migration Instructions — Verify Proofs API

## Overview

The Verify Proofs API verifies Semaphore proofs by simulating Multicall3 calls against the CredentialRegistry. It does not execute transactions — only simulates them.

## Required Changes

### 1. Registry ABI — Updated Function and Structs (CRITICAL)

**File:** ABI definitions used in `src/services/transaction-data-service.ts`

The Registry ABI must be updated:

- **Function name:** `verifyProof` is now a **public view** function (previously internal). Use `verifyProof` for single-proof verification or `verifyProofs` for batch.
- **`CredentialGroupProof` struct:** now includes `appId`:

```diff
  struct CredentialGroupProof {
    uint256 credentialGroupId;
+   uint256 appId;
    ISemaphore.SemaphoreProof semaphoreProof;
  }
```

Update the ABI encoding:

```diff
  const callData = registryInterface.encodeFunctionData(
    'verifyProof',
-   [context, { credentialGroupId, semaphoreProof }]
+   [context, { credentialGroupId, appId, semaphoreProof }]
  )
```

Or for batch verification:
```typescript
const callData = registryInterface.encodeFunctionData(
  'verifyProofs',
  [context, proofs.map(p => ({ credentialGroupId: p.credentialGroupId, appId: p.appId, semaphoreProof: p.semaphoreProof }))]
)
```

### 2. Request Validation — Add `app_id`

**File:** `src/utils/celebrate-builder.ts` (Joi schemas)

Add `app_id` to the proof validation schema:

```diff
  const proofSchema = Joi.object({
    credential_group_id: Joi.string().required(),
+   app_id: Joi.string().required(),
    semaphore_proof: semaphoreProofSchema.required()
  })
```

### 3. Proof Interface — Add `app_id`

**File:** `src/models/` (TypeScript interfaces)

```diff
  interface IProof {
    credential_group_id: string
+   app_id: string
    semaphore_proof: ISemaphoreProof
  }
```

### 4. Scores — Fetch from Scorer Contract

If the Verify Proofs API returns score/points information alongside verification results, scores must now come from the app's Scorer contract rather than static configuration.

Each app has a Scorer contract (default: `DefaultScorer`). To get scores:

```typescript
// 1. Get the app's scorer address from the registry
const app = await registry.apps(appId)
const scorerAddress = app.scorer

// 2. Fetch score for each credential group
const scorer = new Contract(scorerAddress, ['function getScore(uint256) view returns (uint256)'], provider)
const score = await scorer.getScore(credentialGroupId)
```

If the API currently only returns `{ verified: boolean }` without scores, this change is not needed here — but consuming services (SDK, widget) that previously read scores from configs must switch to on-chain lookup.

### 5. Chain Registries — Updated Contract Addresses

**File:** `src/configs/chain-registries.ts`

Update the registry whitelist. Contract addresses are identical on both chains (same deployer, same nonce).

```diff
  export const chainRegistries: Record<number, string[]> = {
-   84532: ['0x0b2Ab187a6FD2d2F05fACc158611838c284E3a9c'],
+   84532: ['0xfd600B14Dc5A145ec9293Fd5768ae10Ccc1E91Fe'],
+   8453: ['0xfd600B14Dc5A145ec9293Fd5768ae10Ccc1E91Fe'],
  }
```

### 6. Error Handling — BID:: Prefix

If the error parser matches on contract revert reason strings, update for the `BID::` prefix:

```diff
- 'credential group not active'
+ 'BID::credential group not active'
- 'app not active'
+ 'BID::app not active'
```

## No Changes Required

- Multicall3 aggregation pattern (same approach, just different calldata)
- Provider caching per chain ID
- General API structure and Express middleware
- Winston logging
- RPC configuration pattern
