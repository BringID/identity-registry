# Migration Instructions — BringID Semaphore Indexer

## Overview

The Semaphore Indexer indexes Semaphore group members and returns Merkle proofs for identity commitments. It reads from a PostgreSQL database that mirrors on-chain Semaphore group state.

## Required Changes

### 1. Per-App Semaphore Group IDs (CRITICAL)

In v2, each `(credentialGroupId, appId)` pair gets its own Semaphore group, created lazily on first registration. This means:

- **Group IDs are no longer static.** The old mapping of `credentialGroupId` → single `semaphoreGroupId` no longer holds.
- **New groups are created on-chain.** The contract emits `AppSemaphoreGroupCreated(credentialGroupId, appId, semaphoreGroupId)` events when groups are created.

The indexer's database ingestion pipeline (which populates the `member` table) must index the new per-app Semaphore groups. Ensure the pipeline:
- Listens for `MemberAdded` events on the new Semaphore contract (current **Base Sepolia** deployment: `0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D`; Base Mainnet TBD)
- Indexes members for all per-app groups (not just the old static group IDs)
- Handles the `AppSemaphoreGroupCreated` event to discover new groups

### 2. Member Model — Group ID Values

**File:** `src/models/member-model.js`

The `group` column now stores per-app Semaphore group IDs (auto-incremented by the Semaphore contract). These are different from the old static `semaphoreGroupId` values. No schema change is needed, but verify the data pipeline populates with correct new group IDs.

### 3. API Consumers — New Group IDs

Clients of the indexer API (primarily the widget) will need to pass the new per-app `semaphore_group_id` values. The indexer itself doesn't need to change its API contract — it already accepts `semaphore_group_id` as a generic identifier.

### 4. Database Re-Indexing

After deploying the new contracts:
- Drop or archive old member data for the old Semaphore groups
- Re-index from the new Semaphore contract's events
- Ensure the data pipeline handles the new group creation pattern (groups created lazily, not in advance)

### 5. Contract Addresses

Update any hardcoded or configured Semaphore contract addresses.

Current **Base Sepolia** (chain 84532) deployment:
- Semaphore: `0x8A1fd199516489B0Fb7153EB5f075cDAC83c693D`

> **Note:** Base Mainnet addresses are TBD.

## No Changes Required

- API endpoint contracts (`GET /proofs`, `POST /proofs`) remain the same
- Merkle proof generation logic (uses @semaphore-protocol/group)
- Request validation schemas
- Error handling patterns
- PostgreSQL model schema (member model structure is unchanged)
- Authentication (API key validation)
