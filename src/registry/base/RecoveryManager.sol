// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "@bringid/contracts/Errors.sol";
import "@bringid/contracts/Events.sol";
import {AttestationVerifier} from "./AttestationVerifier.sol";

/// @title RecoveryManager
/// @notice Handles timelocked key recovery and family group changes.
abstract contract RecoveryManager is AttestationVerifier {
    // ──────────────────────────────────────────────
    //  Key recovery
    // ──────────────────────────────────────────────

    /// @notice Initiates recovery for a credential (bytes signature variant).
    /// @dev Convenience wrapper that unpacks a 65-byte signature into (v, r, s) components
    ///      and delegates to the main initiateRecovery implementation.
    /// @param attestation_ Attestation with the same credentialId but a new commitment.
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    /// @param merkleProofSiblings_ Merkle proof siblings for removing the old commitment from
    ///        the Semaphore group.
    function initiateRecovery(
        Attestation memory attestation_,
        bytes memory signature_,
        uint256[] calldata merkleProofSiblings_
    ) public {
        (uint8 v, bytes32 r, bytes32 s) = _unpackSignature(signature_);
        initiateRecovery(attestation_, v, r, s, merkleProofSiblings_);
    }

    /// @notice Initiates recovery for a credential.
    /// @dev The verifier re-derives the same credentialId from the user's OAuth
    ///      credentials and signs an attestation with a new Semaphore commitment. The old
    ///      commitment is immediately removed from the Semaphore group. The new commitment
    ///      is queued with the app's timelock and can be finalized via executeRecovery().
    ///
    ///      During the timelock period the user has no valid commitment in the group
    ///      (intentional — prevents use of a compromised identity).
    /// @param attestation_ Attestation with the same credentialId but a new semaphoreIdentityCommitment.
    ///        The appId field determines which app's recovery timelock governs this recovery.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    /// @param merkleProofSiblings_ Merkle proof siblings for the old commitment in the Semaphore group.
    function initiateRecovery(
        Attestation memory attestation_,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256[] calldata merkleProofSiblings_
    ) public nonReentrant whenNotPaused {
        (, bytes32 registrationHash) = verifyAttestation(attestation_, v, r, s);
        CredentialRecord storage cred = credentials[registrationHash];

        if (!cred.registered) revert NotRegistered();
        if (attestation_.semaphoreIdentityCommitment == 0) revert InvalidCommitment();
        if (cred.pendingRecovery.executeAfter != 0) revert RecoveryAlreadyPending();
        if (apps[attestation_.appId].recoveryTimelock == 0) revert RecoveryDisabled();

        // Allow same group (key recovery) or different group within the same family (group change).
        // Both go through the recovery timelock to prevent double-spend with different nullifiers.
        uint256 credFamilyId = credentialGroups[cred.credentialGroupId].familyId;
        uint256 attestFamilyId = credentialGroups[attestation_.credentialGroupId].familyId;
        if (
            attestation_.credentialGroupId != cred.credentialGroupId
                && !(credFamilyId > 0 && credFamilyId == attestFamilyId)
        ) {
            revert GroupMismatch();
        }

        _executeInitiateRecovery(attestation_, registrationHash, merkleProofSiblings_);
    }

    function _executeInitiateRecovery(
        Attestation memory attestation_,
        bytes32 registrationHash,
        uint256[] calldata merkleProofSiblings_
    ) internal {
        CredentialRecord storage cred = credentials[registrationHash];
        uint256 oldCommitment = cred.commitment;

        // Only remove from Semaphore if the credential hasn't been expired and removed.
        // After removeExpiredCredential, the commitment is already gone from Semaphore.
        // Use cred.credentialGroupId (not attestation) for removal — the attestation may
        // target a different group within the same family (group change).
        if (!cred.expired) {
            uint256 semaphoreGroupId = appSemaphoreGroups[cred.credentialGroupId][attestation_.appId];
            SEMAPHORE.removeMember(semaphoreGroupId, oldCommitment, merkleProofSiblings_);
        }

        uint256 executeAfter = block.timestamp + apps[attestation_.appId].recoveryTimelock;
        cred.pendingRecovery = RecoveryRequest({
            credentialGroupId: attestation_.credentialGroupId,
            appId: attestation_.appId,
            newCommitment: attestation_.semaphoreIdentityCommitment,
            executeAfter: executeAfter
        });

        emit RecoveryInitiated(
            registrationHash,
            attestation_.credentialGroupId,
            oldCommitment,
            attestation_.semaphoreIdentityCommitment,
            executeAfter
        );
    }

    /// @notice Finalizes a pending recovery after the timelock has expired.
    /// @dev Adds the new commitment to the Semaphore group, updates the stored commitment,
    ///      and clears the pending recovery. Can be called by anyone once the timelock expires.
    /// @param registrationHash_ The registration hash identifying the credential being recovered.
    function executeRecovery(bytes32 registrationHash_) public nonReentrant whenNotPaused {
        CredentialRecord storage cred = credentials[registrationHash_];
        RecoveryRequest memory request = cred.pendingRecovery;
        if (request.executeAfter == 0) revert NoPendingRecovery();
        if (block.timestamp < request.executeAfter) revert RecoveryTimelockNotExpired();

        if (credentialGroups[request.credentialGroupId].status != CredentialGroupStatus.ACTIVE) {
            revert CredentialGroupInactive();
        }
        if (apps[request.appId].status != AppStatus.ACTIVE) revert AppNotActive();

        // Use _ensureAppSemaphoreGroup because the target group may not have a
        // Semaphore group yet (group change within a family to a never-used group).
        uint256 semaphoreGroupId = _ensureAppSemaphoreGroup(request.credentialGroupId, request.appId);
        SEMAPHORE.addMember(semaphoreGroupId, request.newCommitment);
        cred.expired = false;
        cred.commitment = request.newCommitment;
        cred.credentialGroupId = request.credentialGroupId;
        delete cred.pendingRecovery;

        emit RecoveryExecuted(registrationHash_, request.newCommitment);
    }
}
