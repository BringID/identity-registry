# Migration Instructions — BringID Relayer

## Overview

The Relayer executes blockchain operations via a relayer wallet with transaction tracking and retries. It receives pre-encoded calldata from the task-manager and sends transactions.

## Required Changes

### 1. Contract Error ABI — Updated Error Parsing

**File:** `src/utils/error-parser.js`

The error parser uses contract ABIs to decode revert reasons. Update with the new CredentialRegistry ABI:

- New error messages use `BID::` prefix (e.g. `"BID::not registered"`, `"BID::already registered"`, `"BID::app not active"`)
- New potential errors: `"BID::attestation expired"`, `"BID::invalid attestation"`, `"BID::recovery pending"`, `"BID::not expired"`, `"BID::family mismatch"`, `"BID::group mismatch"`

Update the error-to-code mapping:

```diff
+ 'BID::already registered': 'ALREADY_REGISTERED',
+ 'BID::not registered': 'NOT_REGISTERED',
+ 'BID::app not active': 'APP_NOT_ACTIVE',
+ 'BID::attestation expired': 'ATTESTATION_EXPIRED',
+ 'BID::credential group not active': 'CREDENTIAL_GROUP_NOT_ACTIVE',
+ 'BID::recovery pending': 'RECOVERY_PENDING',
+ 'BID::not expired': 'NOT_EXPIRED',
```

### 2. Error-to-Warn Configuration

**File:** `configs/error-to-warn.json`

Add new BringID error codes that should be logged as warnings (expected/non-critical):

```json
{
  "ALREADY_REGISTERED": { "warn": true },
  "ATTESTATION_EXPIRED": { "warn": true }
}
```

### 3. Simulation ABI Update

If the relayer simulates transactions before sending (for `type === 'claim'`), and if claim transactions now use the updated `submitProofs` function (renamed from `score`), the simulation ABI needs updating:

- `score(context, proofs)` → `submitProofs(context, proofs)`
- `CredentialGroupProof` struct now includes `appId`

## No Changes Required

- The relayer receives pre-encoded calldata (`data` field) from the task-manager, so most ABI changes are transparent
- Operation lifecycle and status tracking
- Transaction retry logic and gas management
- Nonce queue management
- MongoDB models and schemas
- API endpoints (`/operations/execute`, `/operations/:id/status`)
- General infrastructure (Express, MongoDB, cron)
