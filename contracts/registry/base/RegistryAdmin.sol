// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "@bringid/contracts/interfaces/Errors.sol";
import "@bringid/contracts/interfaces/Events.sol";
import {IScorer} from "@bringid/contracts/interfaces/IScorer.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {RegistryStorage} from "./RegistryStorage.sol";

/// @title RegistryAdmin
/// @notice Owner-only administration: credential group management, verifier management,
///         attestation validity, Merkle tree duration, and default scorer.
abstract contract RegistryAdmin is RegistryStorage {
    // ──────────────────────────────────────────────
    //  Owner-only administration
    // ──────────────────────────────────────────────

    /// @notice Pauses the contract, disabling all state-changing user functions.
    function pause() public onlyOwner {
        _pause();
    }

    /// @notice Unpauses the contract, re-enabling all state-changing user functions.
    function unpause() public onlyOwner {
        _unpause();
    }

    /// @notice Creates a new credential group with the given ID.
    /// @dev The credential group ID is user-defined (not auto-incremented) and must be > 0.
    ///      Per-app Semaphore groups are created lazily during credential registration.
    ///      Scores are managed separately by Scorer contracts, not by the registry.
    /// @param credentialGroupId_ The unique identifier for this credential group (must be > 0).
    /// @param validityDuration_ Duration in seconds for which credentials in this group remain valid
    ///        (0 = no expiry).
    /// @param familyId_ Family ID (0 = standalone, >0 = family grouping). Groups in the same family
    ///        share a registration hash, so only one group per family can be active per credential per app.
    function createCredentialGroup(uint256 credentialGroupId_, uint256 validityDuration_, uint256 familyId_)
        public
        onlyOwner
    {
        if (credentialGroupId_ == 0) revert ZeroCredentialGroupId();
        if (credentialGroups[credentialGroupId_].status != CredentialGroupStatus.UNDEFINED) {
            revert CredentialGroupExists();
        }
        CredentialGroup memory _credentialGroup =
            CredentialGroup(ICredentialRegistry.CredentialGroupStatus.ACTIVE, validityDuration_, familyId_);
        credentialGroups[credentialGroupId_] = _credentialGroup;
        credentialGroupIds.push(credentialGroupId_);
        emit CredentialGroupCreated(credentialGroupId_, _credentialGroup);
    }

    /// @notice Updates the validity duration for an existing credential group.
    /// @dev Only affects future registrations; existing credentials keep their original expiry.
    /// @param credentialGroupId_ The credential group ID to update.
    /// @param validityDuration_ New duration in seconds (0 = no expiry).
    function setCredentialGroupValidityDuration(uint256 credentialGroupId_, uint256 validityDuration_)
        public
        onlyOwner
    {
        if (credentialGroups[credentialGroupId_].status == CredentialGroupStatus.UNDEFINED) {
            revert CredentialGroupNotFound();
        }
        credentialGroups[credentialGroupId_].validityDuration = validityDuration_;
        emit CredentialGroupValidityDurationSet(credentialGroupId_, validityDuration_);
    }

    /// @notice Updates the global attestation validity duration.
    /// @param duration_ New duration in seconds (must be > 0).
    function setAttestationValidityDuration(uint256 duration_) public onlyOwner {
        if (duration_ == 0) revert ZeroDuration();
        attestationValidityDuration = duration_;
        emit AttestationValidityDurationSet(duration_);
    }

    /// @notice Updates the registry-level default Merkle tree duration for new Semaphore groups.
    /// @dev Does not propagate to existing groups. Only affects groups created after this call.
    /// @param duration_ New duration in seconds (must be > 0).
    function setDefaultMerkleTreeDuration(uint256 duration_) public onlyOwner {
        if (duration_ == 0) revert ZeroMerkleTreeDuration();
        defaultMerkleTreeDuration = duration_;
        emit DefaultMerkleTreeDurationSet(duration_);
    }

    /// @notice Suspends an active credential group, preventing new registrations and proof validations.
    /// @param credentialGroupId_ The credential group ID to suspend.
    function suspendCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        if (credentialGroups[credentialGroupId_].status != CredentialGroupStatus.ACTIVE) {
            revert CredentialGroupNotActive();
        }
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.SUSPENDED;
        emit CredentialGroupStatusChanged(credentialGroupId_, CredentialGroupStatus.SUSPENDED);
    }

    /// @notice Reactivates a suspended credential group.
    /// @param credentialGroupId_ The credential group ID to activate.
    function activateCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        if (credentialGroups[credentialGroupId_].status != CredentialGroupStatus.SUSPENDED) {
            revert CredentialGroupNotSuspended();
        }
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.ACTIVE;
        emit CredentialGroupStatusChanged(credentialGroupId_, CredentialGroupStatus.ACTIVE);
    }

    /// @notice Adds a trusted verifier that can sign attestations.
    /// @param verifier_ The verifier address to trust (must not be zero).
    function addTrustedVerifier(address verifier_) public onlyOwner {
        if (verifier_ == address(0)) revert InvalidVerifierAddress();
        trustedVerifiers[verifier_] = true;
        emit TrustedVerifierUpdated(verifier_, true);
    }

    /// @notice Removes a trusted verifier, revoking its ability to sign attestations.
    /// @param verifier_ The verifier address to remove (must be currently trusted).
    function removeTrustedVerifier(address verifier_) public onlyOwner {
        if (!trustedVerifiers[verifier_]) revert VerifierNotTrusted();
        trustedVerifiers[verifier_] = false;
        emit TrustedVerifierUpdated(verifier_, false);
    }

    /// @notice Updates the default scorer contract used for newly registered apps.
    /// @dev Only affects future app registrations; existing apps keep their current scorer.
    /// @param scorer_ The new default scorer address (must not be zero).
    function setDefaultScorer(address scorer_) public onlyOwner {
        if (scorer_ == address(0)) revert InvalidScorerAddress();
        if (!ERC165Checker.supportsInterface(scorer_, type(IScorer).interfaceId)) revert InvalidScorerContract();
        address oldScorer = defaultScorer;
        defaultScorer = scorer_;
        emit DefaultScorerUpdated(oldScorer, scorer_);
    }
}
