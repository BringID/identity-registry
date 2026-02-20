// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "@bringid/contracts/Errors.sol";
import "@bringid/contracts/Events.sol";
import {AttestationVerifier} from "./AttestationVerifier.sol";

/// @title CredentialManager
/// @notice Handles credential registration, renewal, and expiry removal.
abstract contract CredentialManager is AttestationVerifier {
    // ──────────────────────────────────────────────
    //  Credential registration
    // ──────────────────────────────────────────────

    /// @notice Register a credential using a verifier-signed attestation (bytes signature variant).
    /// @dev Convenience wrapper that unpacks a 65-byte signature into (v, r, s) components
    ///      and delegates to the main registerCredential implementation.
    ///      The signature is chain-bound — it includes the chain ID and registry address.
    /// @param attestation_ The attestation containing credential details and Semaphore commitment.
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    function registerCredential(Attestation memory attestation_, bytes memory signature_) public {
        (uint8 v, bytes32 r, bytes32 s) = _unpackSignature(signature_);
        registerCredential(attestation_, v, r, s);
    }

    /// @notice Register a credential using a verifier-signed attestation.
    /// @dev Validates the attestation and adds the user's Semaphore commitment to the
    ///      per-app Semaphore group. The flow:
    ///      1. Compute registration hash from (registry, credentialGroupId, credentialId, appId).
    ///      2. Verify the credential group and app are active.
    ///      3. Verify the attestation was signed by a trusted verifier.
    ///      4. Lazily create the per-app Semaphore group if needed.
    ///      5. Mark the credential as registered and add the commitment to the Semaphore group.
    /// @param attestation_ The attestation struct containing:
    ///        - registry: must match this contract's address
    ///        - credentialGroupId: the group to join
    ///        - credentialId: app-specific credential identity (used for dedup)
    ///        - appId: the app this credential is for
    ///        - semaphoreIdentityCommitment: the Semaphore identity commitment to register
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function registerCredential(Attestation memory attestation_, uint8 v, bytes32 r, bytes32 s)
        public
        nonReentrant
        whenNotPaused
    {
        (address signer, bytes32 registrationHash) = verifyAttestation(attestation_, v, r, s);
        CredentialRecord storage cred = credentials[registrationHash];
        if (cred.registered) revert AlreadyRegistered();
        if (attestation_.semaphoreIdentityCommitment == 0) revert InvalidCommitment();

        // Lazily create the per-app Semaphore group
        uint256 semaphoreGroupId = _ensureAppSemaphoreGroup(attestation_.credentialGroupId, attestation_.appId);

        cred.registered = true;
        cred.credentialGroupId = attestation_.credentialGroupId;
        cred.commitment = attestation_.semaphoreIdentityCommitment;
        SEMAPHORE.addMember(semaphoreGroupId, attestation_.semaphoreIdentityCommitment);

        uint256 validityDuration = credentialGroups[attestation_.credentialGroupId].validityDuration;
        uint256 expiresAt;
        if (validityDuration > 0) {
            expiresAt = block.timestamp + validityDuration;
            cred.expiresAt = expiresAt;
        }

        emit CredentialRegistered(
            attestation_.credentialGroupId,
            attestation_.appId,
            attestation_.semaphoreIdentityCommitment,
            attestation_.credentialId,
            registrationHash,
            signer,
            expiresAt
        );
    }

    // ──────────────────────────────────────────────
    //  Credential renewal
    // ──────────────────────────────────────────────

    /// @notice Renew a previously-registered credential (bytes signature variant).
    /// @dev Convenience wrapper that unpacks a 65-byte signature into (v, r, s) components
    ///      and delegates to the main renewCredential implementation.
    /// @param attestation_ The attestation (commitment must match the stored one).
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    function renewCredential(Attestation memory attestation_, bytes memory signature_) public {
        (uint8 v, bytes32 r, bytes32 s) = _unpackSignature(signature_);
        renewCredential(attestation_, v, r, s);
    }

    /// @notice Renew a previously-registered credential.
    /// @dev Re-activates an expired/removed credential or extends an active one.
    ///      The identity commitment must remain the same (preserving nullifier continuity).
    ///      If the credential was removed from the Semaphore group, it is re-added.
    ///      The validity duration is always reset from the current block timestamp.
    /// @param attestation_ The attestation struct. The semaphoreIdentityCommitment must match
    ///        the stored commitment from the original registration.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function renewCredential(Attestation memory attestation_, uint8 v, bytes32 r, bytes32 s)
        public
        nonReentrant
        whenNotPaused
    {
        (address signer, bytes32 registrationHash) = verifyAttestation(attestation_, v, r, s);
        CredentialRecord storage cred = credentials[registrationHash];
        if (!cred.registered) revert NotRegistered();
        if (attestation_.semaphoreIdentityCommitment == 0) revert InvalidCommitment();
        if (attestation_.semaphoreIdentityCommitment != cred.commitment) revert CommitmentMismatch();
        if (cred.pendingRecovery.executeAfter != 0) revert RecoveryPending();

        if (attestation_.credentialGroupId != cred.credentialGroupId) revert GroupMismatch();

        // Re-add to Semaphore if credential was expired and removed
        if (cred.expired) {
            uint256 semaphoreGroupId = appSemaphoreGroups[attestation_.credentialGroupId][attestation_.appId];
            SEMAPHORE.addMember(semaphoreGroupId, cred.commitment);
            cred.expired = false;
        }

        // Reset validity duration
        uint256 validityDuration = credentialGroups[attestation_.credentialGroupId].validityDuration;
        uint256 expiresAt;
        if (validityDuration > 0) {
            expiresAt = block.timestamp + validityDuration;
            cred.expiresAt = expiresAt;
        } else {
            cred.expiresAt = 0;
        }

        emit CredentialRenewed(
            attestation_.credentialGroupId,
            attestation_.appId,
            cred.commitment,
            attestation_.credentialId,
            registrationHash,
            signer,
            expiresAt
        );
    }

    // ──────────────────────────────────────────────
    //  Credential expiry
    // ──────────────────────────────────────────────

    /// @notice Removes an expired credential from its per-app Semaphore group.
    /// @dev Anyone can call this once a credential has expired. Clears registration state
    ///      so the user can re-register with a fresh attestation. Also clears any pending
    ///      recovery to avoid orphaned state.
    /// @param credentialGroupId_ The credential group the credential belongs to.
    /// @param credentialId_ The credential identity (from the attestation).
    /// @param appId_ The app the credential was registered for.
    /// @param merkleProofSiblings_ Merkle proof siblings for removing the commitment from the Semaphore group.
    function removeExpiredCredential(
        uint256 credentialGroupId_,
        bytes32 credentialId_,
        uint256 appId_,
        uint256[] calldata merkleProofSiblings_
    ) public nonReentrant whenNotPaused {
        uint256 familyId = credentialGroups[credentialGroupId_].familyId;
        bytes32 registrationHash = _registrationHash(familyId, credentialGroupId_, credentialId_, appId_);
        CredentialRecord storage cred = credentials[registrationHash];
        if (!cred.registered) revert NotRegistered();
        if (cred.expired) revert AlreadyExpired();
        if (credentialGroupId_ != cred.credentialGroupId) revert GroupMismatch();
        if (cred.pendingRecovery.executeAfter != 0) revert RecoveryPending();
        if (cred.expiresAt == 0) revert NoExpirySet();
        if (block.timestamp < cred.expiresAt) revert NotYetExpired();

        uint256 semaphoreGroupId = appSemaphoreGroups[credentialGroupId_][appId_];
        SEMAPHORE.removeMember(semaphoreGroupId, cred.commitment, merkleProofSiblings_);

        cred.expired = true;
        // NOTE: cred.commitment is intentionally NOT cleared.
        // This forces renewal to use the same identity commitment,
        // preserving Semaphore nullifier continuity and preventing double-spend.
        delete cred.pendingRecovery;

        emit CredentialExpired(credentialGroupId_, appId_, credentialId_, registrationHash);
    }
}
