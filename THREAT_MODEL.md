# Threat Model: Merkle Tree Duration & Stale Root Window

## Overview

When a member is removed from a Semaphore group (via recovery or expiry removal), the old Merkle root remains valid for `merkleTreeDuration` seconds. During this window, proofs generated against the pre-removal root can still be verified on-chain. This document explains why this is acceptable under the current threat model and how the configurable duration provides defense-in-depth.

## Recovery: Lost Keys, Not Compromised Keys

The recovery flow (`initiateRecovery` / `executeRecovery`) is designed for **lost key** scenarios, not compromised keys:

- The user loses access to their wallet and can no longer derive the Semaphore identity.
- They re-authenticate via a supported verification flow (zkTLS, OAuth, zkPassport, zkKYC, etc.).
- The verifier re-derives the same `credentialId` and signs an attestation with a new commitment.

**Key assumption**: No adversary holds the old private key during recovery. The user simply lost access. Therefore, the stale root window after `initiateRecovery` (which immediately removes the old commitment) poses no risk -- there is no one who can generate proofs with the old identity.

## submitProof() Delegates Directly to Semaphore

`submitProof()` validates the ZK proof via Semaphore's `validateProof()` and consumes the nullifier. It does **not** perform credential-level status checks (expiry, recovery state). This means:

- A credential that has expired but not been removed via `removeExpiredCredential()` can still generate valid proofs.
- During the `merkleTreeDuration` window after removal, proofs against the old root are still valid.

This is by design -- Semaphore's proof verification is the security boundary, and the Merkle tree duration controls how quickly root changes propagate.

## Why This Is Acceptable

### Recovery scenario (no adversary)

Since recovery handles lost keys, no one can exploit the stale root window. The old commitment is removed immediately on `initiateRecovery()`, and the new commitment is added only after the recovery timelock expires. During the timelock, the user has no valid commitment in the group.

### Expiry race (no incentive)

After `removeExpiredCredential()`, the credential is marked expired. The stale root window allows a brief period where the old root is still valid, but:

- The user's own credential has expired -- they gain nothing from a proof during this window that they couldn't have gotten before expiry.
- Nullifiers are still consumed, so double-proving is impossible.
- The expiry + removal is a public action (anyone can call it), so there's no information asymmetry.

## Residual Risk: Compromised Keys

If the threat model evolves to include **compromised key** recovery (where an adversary holds the old private key), the stale root window becomes a real attack surface:

- An adversary could generate proofs against the pre-removal root during the `merkleTreeDuration` window after `initiateRecovery()`.
- The recovery timelock prevents the legitimate user from re-entering the group, creating an asymmetry.

**Mitigation**: A shorter `merkleTreeDuration` reduces this window. The configurable duration (registry default + per-app override) allows tuning based on the chain's block time and the app's risk tolerance.

## Default Duration: 5 Minutes for Base

The production default is **5 minutes** (300 seconds), chosen for Base mainnet/Sepolia:

- **Block time**: Base produces blocks every ~2 seconds. 5 minutes = ~150 blocks, providing ample propagation time.
- **Sequencer delay**: Base uses a centralized sequencer. 5 minutes accommodates any reasonable sequencer delay or congestion.
- **Mempool propagation**: On L2s with a sequencer, transactions are typically included within seconds. 5 minutes is conservative.
- **Semaphore default**: Semaphore's own default is 1 hour, which is unnecessarily wide for L2 block times.

The constructor accepts `defaultMerkleTreeDuration` as a parameter, allowing different defaults for different chains (e.g., longer for L1 Ethereum with ~12s blocks).

## Configurability

Two levels of configuration:

1. **Registry default** (`defaultMerkleTreeDuration`): Set by the registry owner via `setDefaultMerkleTreeDuration()`. Affects newly created Semaphore groups. Does not propagate to existing groups.

2. **Per-app override** (`appMerkleTreeDuration`): Set by the app admin via `setAppMerkleTreeDuration()`. Overrides the registry default for that app. **Propagates to all existing Semaphore groups** for the app via `SEMAPHORE.updateGroupMerkleTreeDuration()`. Setting to 0 clears the override and propagates the registry default.

This allows apps with different security requirements to tune the window independently.

## Chain-Bound Attestations & Hash-Based App IDs

### Problem

Without chain binding, a verifier-signed attestation could be replayed on any chain where the registry is deployed at the same address (e.g. via CREATE2). Additionally, auto-incremented app IDs (1, 2, 3, ...) collide across chains by coincidence, so an attestation signed for "app 1" on Chain A would also be valid for "app 1" on Chain B if the registry address matched.

### Mitigations

1. **Chain-bound attestations**: The `Attestation` struct includes a `chainId` field validated against `block.chainid` in `verifyAttestation()`. Combined with the existing `registry` address check, this provides defense-in-depth against cross-chain replay -- both the contract address and the chain ID must match.

2. **Hash-based app IDs**: App IDs are derived from `keccak256(block.chainid, msg.sender, nonce)` instead of a simple auto-incrementing counter. This makes app IDs unpredictable and naturally chain-unique, eliminating accidental ID collisions across chains.

### Remaining attack paths

An attacker would need to compromise a trusted verifier on the target chain to produce valid attestations. The existing verifier trust boundary and attestation expiry (default 30 minutes) limit the blast radius of such a compromise.
