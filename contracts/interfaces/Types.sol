// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";

/// @notice A proof binding a Semaphore ZK proof to a specific credential group and app.
/// @param credentialGroupId The credential group being proven.
/// @param appId The app identity used (determines which per-app Semaphore group).
/// @param semaphoreProof The Semaphore zero-knowledge proof (membership + nullifier).
///        The `semaphoreProof.message` field is not validated by the registry — it is a
///        free-form field that smart contract consumers SHOULD bind to the intended
///        recipient or action to prevent mempool front-running. See `BringIDGated`.
struct CredentialProof {
    uint256 credentialGroupId;
    uint256 appId;
    ISemaphore.SemaphoreProof semaphoreProof;
}
