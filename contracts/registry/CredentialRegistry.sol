// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "@bringid/contracts/interfaces/Errors.sol";
import "@bringid/contracts/interfaces/Events.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";
import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import {AppManager} from "./base/AppManager.sol";
import {CredentialManager} from "./base/CredentialManager.sol";
import {ProofVerifier} from "./base/ProofVerifier.sol";
import {RecoveryManager} from "./base/RecoveryManager.sol";
import {RegistryAdmin} from "./base/RegistryAdmin.sol";
import {RegistryStorage} from "./base/RegistryStorage.sol";

/// @title CredentialRegistry
/// @notice Main contract for the BringID privacy-preserving credential system.
///
/// Users register credentials via verifier-signed attestations, then prove membership
/// using Semaphore zero-knowledge proofs. Each credential group carries a score;
/// the `submitProofs()` function validates proofs (consuming nullifiers) and aggregates scores.
///
/// Per-app Semaphore groups: each (credentialGroup, app) pair gets its own Semaphore
/// group, created lazily on first credential registration. Since Semaphore enforces
/// per-group nullifier uniqueness, separate groups per app naturally prevent cross-app
/// proof replay.
///
/// @dev WARNING: The `message` field of the Semaphore proof is NOT validated. Smart contract
///      callers are vulnerable to mempool front-running unless they validate `message` binding
///      themselves. See `BringIDGated` for a ready-made helper.
contract CredentialRegistry is CredentialManager, RecoveryManager, ProofVerifier, RegistryAdmin, AppManager {
    /// @param semaphore_ Address of the deployed Semaphore contract.
    /// @param trustedVerifier_ Address of the initial trusted verifier to add.
    /// @param defaultMerkleTreeDuration_ Default Merkle tree duration in seconds (must be > 0).
    constructor(ISemaphore semaphore_, address trustedVerifier_, uint256 defaultMerkleTreeDuration_)
        RegistryStorage(semaphore_)
    {
        if (trustedVerifier_ == address(0)) revert InvalidTrustedVerifier();
        if (defaultMerkleTreeDuration_ == 0) revert ZeroMerkleTreeDuration();
        trustedVerifiers[trustedVerifier_] = true;
        defaultMerkleTreeDuration = defaultMerkleTreeDuration_;
        emit TrustedVerifierUpdated(trustedVerifier_, true);

        DefaultScorer _scorer = new DefaultScorer(msg.sender);
        defaultScorer = address(_scorer);
        emit DefaultScorerUpdated(address(0), address(_scorer));
    }
}
