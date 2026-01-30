# zkBring Protocol

A privacy-preserving credential registry built on Semaphore for zero-knowledge identity verification with support for identity recovery.

## Overview

zkBring Protocol enables users to prove credential ownership (e.g., credit scores) without revealing their identity. The protocol uses:

- **Semaphore** for zero-knowledge group membership proofs
- **Verifier** for signed attestations of user credentials
- **Score-oriented groups** where users are organized by credential score tiers

## Architecture

### CredentialRegistryV2

The main contract combines three layers:

1. **Score Groups** - Score-based Semaphore groups (0, 10, 20, 30, etc.)
2. **Apps Layer** - Registered applications with configurable recovery delays
3. **Identity Recovery** - Timelock-protected commitment replacement

### Key Concepts

#### Blinded ID
```
blindedId = hash(idHash, domain, appId)
```
- Unique identifier per user per application
- Acts as a nullifier preventing duplicate registrations
- Computed off-chain by the verifier

#### Score-Oriented Groups
- Each score tier (0, 10, 20, 30, 40, 50) has its own Semaphore group
- Users join the group matching their verified score
- Proofs demonstrate membership in a specific score tier

#### Identity Structure
```solidity
struct Identity {
    uint256 commitment;  // Semaphore identity commitment
    uint256 score;       // Which score group the identity belongs to
}
```

## User Flows

### 1. Join a Score Group

**Prerequisites:**
- User has a Semaphore identity (commitment)
- User obtains a signed attestation proving their credential score

**Flow:**
```
User → Verifier → Signs Attestation
User → CredentialRegistryV2.joinGroup(attestation, signature)
```

The contract:
1. Verifies signature
2. Checks blindedId hasn't been used (prevents duplicate registrations)
3. Links blindedId → Identity (commitment + score)
4. Adds commitment to the appropriate Semaphore group

### 2. Prove Credential Ownership

**Flow:**
```
User → Generate Semaphore proof for score group
User → Third-party app calls validateProof(context, proof)
```

The proof demonstrates the user belongs to a specific score tier without revealing their identity.

### 3. Identity Recovery

When a user loses access to their Semaphore identity, they can recover by replacing their commitment.

**Initiate Recovery (Verifier only):**
```
Verifier → initiateRecovery(blindedId, appId, newCommitment, score)
```
- Starts a timelock based on the app's recovery delay (1-30 days)
- User must prove identity ownership again

**Cancel Recovery (Verifier only):**
```
Verifier → cancelRecovery(blindedId)
```
- Original identity owner can cancel if they still have access

**Finalize Recovery (Anyone):**
```
Anyone → finalizeRecovery(blindedId, merkleProofSiblings)
```
- After timelock expires, anyone can trigger the commitment swap
- Old commitment is replaced with new commitment in Semaphore group

## Contract Interface

### Score Groups

```solidity
// Create a score group (owner only)
createScoreGroup(uint256 score)

// Join with signed attestation
joinGroup(Attestation memory attestation, bytes memory signature)

// Verify proof (view)
verifyProof(ScoreGroupProof calldata proof) returns (bool)

// Validate proof (state-changing, prevents replay)
validateProof(uint256 context, ScoreGroupProof memory proof)
```

### Apps Management

```solidity
// Register an app (owner only)
registerApp(uint256 appId, address admin, uint256 recoveryDelay)

// Update recovery delay (app admin or owner)
updateAppRecoveryDelay(uint256 appId, uint256 newRecoveryDelay)
```

### Identity Recovery

```solidity
// Start recovery (verifier only)
initiateRecovery(bytes32 blindedId, uint256 appId, uint256 newCommitment, uint256 score)

// Cancel pending recovery (verifier only)
cancelRecovery(bytes32 blindedId)

// Complete recovery after timelock (anyone)
finalizeRecovery(bytes32 blindedId, uint256[] calldata merkleProofSiblings)

// Check if recovery is ready
isRecoveryReady(bytes32 blindedId) returns (bool)
```

## Deployment

### Prerequisites

1. Deploy Semaphore contract (or use existing deployment)
2. Set up verifier address

### Environment Variables

```bash
PRIVATE_KEY=<deployer-private-key>
VERIFIER_ADDRESS=<verifier-address>
SEMAPHORE_ADDRESS=<semaphore-contract-address>
```

### Deploy Contract

```bash
forge script script/Deploy.s.sol:Deploy --rpc-url <rpc-url> --broadcast
```

### Setup Score Groups

```bash
REGISTRY_ADDRESS=<deployed-registry> \
forge script script/Deploy.s.sol:SetupScoreGroups --rpc-url <rpc-url> --broadcast
```

This creates groups for scores: 0, 10, 20, 30, 40, 50

### Register an App

```bash
REGISTRY_ADDRESS=<deployed-registry> \
APP_ID=1 \
APP_ADMIN_ADDRESS=<admin-address> \
RECOVERY_DELAY=86400 \
forge script script/Deploy.s.sol:RegisterApp --rpc-url <rpc-url> --broadcast
```

## Development

### Install Dependencies

This project uses `yarn` to install dependencies since `soldeer` doesn't resolve them correctly.
```bash
yarn
```

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Gas Snapshots

```bash
forge snapshot
```

## Security Considerations

- **Recovery Timelock**: 1-30 days configurable per app, giving original owners time to cancel fraudulent recovery attempts
- **Verifier**: Only the trusted verifier can initiate/cancel recovery
- **Nullifier Protection**: blindedId prevents duplicate identity registrations
- **Two-Step Admin Transfer**: Uses OpenZeppelin's Ownable2Step for safe ownership transfers

## License

MIT
