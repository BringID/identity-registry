// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "../Events.sol";
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
        require(credentialGroupId_ > 0, "BID::zero credential group ID");
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.UNDEFINED,
            "BID::credential group exists"
        );
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
        require(
            credentialGroups[credentialGroupId_].status != CredentialGroupStatus.UNDEFINED,
            "BID::credential group not found"
        );
        credentialGroups[credentialGroupId_].validityDuration = validityDuration_;
        emit CredentialGroupValidityDurationSet(credentialGroupId_, validityDuration_);
    }

    /// @notice Updates the family ID for an existing credential group.
    /// @dev Only affects future registrations; existing registrations keep their original hash.
    /// @param credentialGroupId_ The credential group ID to update.
    /// @param familyId_ New family ID (0 = standalone, >0 = family).
    function setCredentialGroupFamily(uint256 credentialGroupId_, uint256 familyId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status != CredentialGroupStatus.UNDEFINED,
            "BID::credential group not found"
        );
        credentialGroups[credentialGroupId_].familyId = familyId_;
        emit CredentialGroupFamilySet(credentialGroupId_, familyId_);
    }

    /// @notice Updates the global attestation validity duration.
    /// @param duration_ New duration in seconds (must be > 0).
    function setAttestationValidityDuration(uint256 duration_) public onlyOwner {
        require(duration_ > 0, "BID::zero duration");
        attestationValidityDuration = duration_;
        emit AttestationValidityDurationSet(duration_);
    }

    /// @notice Updates the registry-level default Merkle tree duration for new Semaphore groups.
    /// @dev Does not propagate to existing groups. Only affects groups created after this call.
    /// @param duration_ New duration in seconds (must be > 0).
    function setDefaultMerkleTreeDuration(uint256 duration_) public onlyOwner {
        require(duration_ > 0, "BID::zero merkle tree duration");
        defaultMerkleTreeDuration = duration_;
        emit DefaultMerkleTreeDurationSet(duration_);
    }

    /// @notice Suspends an active credential group, preventing new registrations and proof validations.
    /// @param credentialGroupId_ The credential group ID to suspend.
    function suspendCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE,
            "BID::credential group not active"
        );
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.SUSPENDED;
        emit CredentialGroupStatusChanged(credentialGroupId_, CredentialGroupStatus.SUSPENDED);
    }

    /// @notice Reactivates a suspended credential group.
    /// @param credentialGroupId_ The credential group ID to activate.
    function activateCredentialGroup(uint256 credentialGroupId_) public onlyOwner {
        require(
            credentialGroups[credentialGroupId_].status == CredentialGroupStatus.SUSPENDED,
            "BID::credential group not suspended"
        );
        credentialGroups[credentialGroupId_].status = CredentialGroupStatus.ACTIVE;
        emit CredentialGroupStatusChanged(credentialGroupId_, CredentialGroupStatus.ACTIVE);
    }

    /// @notice Adds a trusted verifier that can sign attestations.
    /// @param verifier_ The verifier address to trust (must not be zero).
    function addTrustedVerifier(address verifier_) public onlyOwner {
        require(verifier_ != address(0), "BID::invalid verifier address");
        trustedVerifiers[verifier_] = true;
        emit TrustedVerifierUpdated(verifier_, true);
    }

    /// @notice Removes a trusted verifier, revoking its ability to sign attestations.
    /// @param verifier_ The verifier address to remove (must be currently trusted).
    function removeTrustedVerifier(address verifier_) public onlyOwner {
        require(trustedVerifiers[verifier_], "BID::verifier not trusted");
        trustedVerifiers[verifier_] = false;
        emit TrustedVerifierUpdated(verifier_, false);
    }

    /// @notice Updates the default scorer contract used for newly registered apps.
    /// @dev Only affects future app registrations; existing apps keep their current scorer.
    /// @param scorer_ The new default scorer address (must not be zero).
    function setDefaultScorer(address scorer_) public onlyOwner {
        require(scorer_ != address(0), "BID::invalid scorer address");
        address oldScorer = defaultScorer;
        defaultScorer = scorer_;
        emit DefaultScorerUpdated(oldScorer, scorer_);
    }
}
