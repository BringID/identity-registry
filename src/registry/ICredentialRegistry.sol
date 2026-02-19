// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";

/// @title ICredentialRegistry
/// @notice Interface for the BringID Credential Registry — a privacy-preserving credential
///         system where users register credentials via verifier-signed attestations and prove
///         membership using Semaphore zero-knowledge proofs.
interface ICredentialRegistry {
    /// @notice Status of a credential group.
    /// @dev UNDEFINED = not created, ACTIVE = accepting registrations/proofs, SUSPENDED = paused.
    enum CredentialGroupStatus {
        UNDEFINED,
        ACTIVE,
        SUSPENDED
    }

    /// @notice Status of an app.
    /// @dev UNDEFINED = not registered, ACTIVE = operational, SUSPENDED = paused by admin.
    enum AppStatus {
        UNDEFINED,
        ACTIVE,
        SUSPENDED
    }

    /// @notice Configuration for a credential group.
    /// @param status Current status of the credential group.
    /// @param validityDuration Seconds until a registered credential expires (0 = no expiry).
    /// @param familyId Family grouping ID. 0 = standalone (no family constraint),
    ///        >0 = family grouping where only one group per family per credential per app is allowed.
    struct CredentialGroup {
        CredentialGroupStatus status;
        uint256 validityDuration;
        uint256 familyId;
    }

    /// @notice Configuration for a registered app.
    /// @param status Current status of the app.
    /// @param recoveryTimelock Duration in seconds for key recovery timelock (0 = recovery disabled).
    /// @param admin Address of the app administrator.
    /// @param scorer Address of the scorer contract used for this app's score lookups.
    struct App {
        AppStatus status;
        uint256 recoveryTimelock;
        address admin;
        address scorer;
    }

    /// @notice A pending key recovery request queued behind the app's timelock.
    /// @param credentialGroupId The target credential group (may differ from original for family upgrades).
    /// @param appId The app this recovery applies to.
    /// @param newCommitment The new Semaphore identity commitment to replace the old one.
    /// @param executeAfter Timestamp after which executeRecovery() can be called (0 = no pending request).
    struct RecoveryRequest {
        uint256 credentialGroupId;
        uint256 appId;
        uint256 newCommitment;
        uint256 executeAfter;
    }

    /// @notice Per-credential state stored in the registry, keyed by registration hash.
    /// @param registered True once a credential is first registered (stays true even after expiry).
    /// @param expired True after removeExpiredCredential() is called; cleared on renewal/recovery.
    /// @param commitment The Semaphore identity commitment (persists across expiry for nullifier continuity).
    /// @param expiresAt Timestamp when the credential expires (0 = no expiry).
    /// @param credentialGroupId The credential group this credential belongs to.
    /// @param pendingRecovery The in-flight recovery request, if any.
    struct CredentialRecord {
        bool registered;
        bool expired;
        uint256 commitment;
        uint256 expiresAt;
        uint256 credentialGroupId;
        RecoveryRequest pendingRecovery;
    }

    /// @notice A proof binding a Semaphore ZK proof to a specific credential group and app.
    /// @param credentialGroupId The credential group being proven.
    /// @param appId The app identity used (determines which per-app Semaphore group).
    /// @param semaphoreProof The Semaphore zero-knowledge proof (membership + nullifier).
    struct CredentialGroupProof {
        uint256 credentialGroupId;
        uint256 appId;
        ISemaphore.SemaphoreProof semaphoreProof;
    }

    /// @notice A verifier-signed attestation authorizing a credential operation.
    /// @param registry Address of the CredentialRegistry contract (prevents cross-chain replay).
    /// @param credentialGroupId The credential group to register/renew/recover into.
    /// @param credentialId Application-specific credential identity derived by the verifier.
    /// @param appId The app this attestation is scoped to.
    /// @param semaphoreIdentityCommitment The user's Semaphore identity commitment.
    /// @param issuedAt Timestamp when the verifier created this attestation (for freshness checks).
    struct Attestation {
        address registry;
        uint256 credentialGroupId;
        bytes32 credentialId;
        uint256 appId;
        uint256 semaphoreIdentityCommitment;
        uint256 issuedAt;
    }

    // ── View helpers ──────────────────────────────

    /// @notice Checks whether a credential group is currently active.
    /// @param credentialGroupId_ The credential group ID to check.
    /// @return True if the credential group status is ACTIVE.
    function credentialGroupIsActive(uint256 credentialGroupId_) external view returns (bool);

    /// @notice Checks whether an app is currently active.
    /// @param appId_ The app ID to check.
    /// @return True if the app status is ACTIVE.
    function appIsActive(uint256 appId_) external view returns (bool);

    /// @notice Returns all registered credential group IDs.
    /// @return Array of credential group IDs.
    function getCredentialGroupIds() external view returns (uint256[] memory);
    function getAppSemaphoreGroupIds(uint256 appId_) external view returns (uint256[] memory);

    /// @notice Verifies an attestation's validity and recovers the signer.
    /// @dev Checks: credential group active, app active, registry address match, attestation
    ///      freshness, and ECDSA signature from a trusted verifier.
    /// @param attestation_ The attestation to verify.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    /// @return signer The recovered signer address (must be a trusted verifier).
    /// @return registrationHash The computed registration hash for the credential.
    function verifyAttestation(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s)
        external
        view
        returns (address signer, bytes32 registrationHash);

    // ── Credential registration ─────────────────

    /// @notice Registers a credential using a packed 65-byte ECDSA signature.
    /// @param attestation_ The verifier-signed attestation with credential details.
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    function registerCredential(Attestation calldata attestation_, bytes calldata signature_) external;

    /// @notice Registers a credential using split ECDSA signature components.
    /// @param attestation_ The verifier-signed attestation with credential details.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function registerCredential(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s) external;

    // ── Credential renewal ──────────────────────

    /// @notice Renews a previously-registered credential using a packed 65-byte ECDSA signature.
    /// @param attestation_ The attestation (commitment must match the stored one).
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    function renewCredential(Attestation calldata attestation_, bytes calldata signature_) external;

    /// @notice Renews a previously-registered credential using split ECDSA signature components.
    /// @param attestation_ The attestation (commitment must match the stored one).
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function renewCredential(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s) external;

    // ── Proof validation ────────────────────────

    /// @notice Submits a single ZK proof, consuming the Semaphore nullifier, and returns the score.
    /// @param context_ Application-defined context value combined with msg.sender to form the scope.
    /// @param proof The credential group proof to validate.
    /// @return The credential group's score from the app's scorer.
    function submitProof(uint256 context_, CredentialGroupProof calldata proof) external returns (uint256);

    /// @notice Submits multiple ZK proofs, consuming nullifiers, and returns the aggregate score.
    /// @param context_ Application-defined context value combined with msg.sender to form the scope.
    /// @param proofs Array of credential group proofs to validate.
    /// @return The total score across all validated credential groups.
    function submitProofs(uint256 context_, CredentialGroupProof[] calldata proofs) external returns (uint256);

    /// @notice Verifies a single ZK proof without consuming the nullifier (view-only).
    /// @param context_ Application-defined context value combined with msg.sender to form the scope.
    /// @param proof The credential group proof to verify.
    /// @return True if the proof is valid.
    function verifyProof(uint256 context_, CredentialGroupProof calldata proof) external view returns (bool);

    /// @notice Verifies multiple ZK proofs without consuming nullifiers (view-only).
    /// @param context_ Application-defined context value combined with msg.sender to form the scope.
    /// @param proofs Array of credential group proofs to verify.
    /// @return True if all proofs are valid.
    function verifyProofs(uint256 context_, CredentialGroupProof[] calldata proofs) external view returns (bool);

    /// @notice Verifies multiple proofs and returns the aggregate score (view-only).
    /// @param context_ Application-defined context value combined with msg.sender to form the scope.
    /// @param proofs Array of credential group proofs to verify and score.
    /// @return The total score across all verified credential groups.
    function getScore(uint256 context_, CredentialGroupProof[] calldata proofs) external view returns (uint256);

    // ── Credential expiry ───────────────────────

    /// @notice Removes an expired credential from its per-app Semaphore group.
    /// @dev Publicly callable once a credential has passed its expiresAt timestamp.
    ///      Sets expired=true but preserves the commitment for renewal continuity.
    /// @param credentialGroupId_ The credential group the credential belongs to.
    /// @param credentialId_ The credential identity from the original attestation.
    /// @param appId_ The app the credential was registered for.
    /// @param merkleProofSiblings_ Merkle proof siblings for Semaphore group member removal.
    function removeExpiredCredential(
        uint256 credentialGroupId_,
        bytes32 credentialId_,
        uint256 appId_,
        uint256[] calldata merkleProofSiblings_
    ) external;

    // ── Recovery ────────────────────────────────

    /// @notice Initiates key recovery using a packed 65-byte ECDSA signature.
    /// @param attestation_ Attestation with the same credentialId but a new commitment.
    /// @param signature_ 65-byte ECDSA signature (r || s || v).
    /// @param merkleProofSiblings_ Merkle proof siblings for removing the old commitment.
    function initiateRecovery(
        Attestation calldata attestation_,
        bytes calldata signature_,
        uint256[] calldata merkleProofSiblings_
    ) external;

    /// @notice Initiates key recovery using split ECDSA signature components.
    /// @param attestation_ Attestation with the same credentialId but a new commitment.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    /// @param merkleProofSiblings_ Merkle proof siblings for removing the old commitment.
    function initiateRecovery(
        Attestation calldata attestation_,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256[] calldata merkleProofSiblings_
    ) external;

    /// @notice Finalizes a pending recovery after the timelock has expired.
    /// @param registrationHash_ The registration hash identifying the credential being recovered.
    function executeRecovery(bytes32 registrationHash_) external;

    // ── Owner administration ────────────────────

    /// @notice Creates a new credential group.
    /// @param credentialGroupId_ Unique identifier for the group (must be > 0, must not already exist).
    /// @param validityDuration_ Duration in seconds for credential validity (0 = no expiry).
    /// @param familyId_ Family grouping ID (0 = standalone, >0 = family constraint).
    function createCredentialGroup(uint256 credentialGroupId_, uint256 validityDuration_, uint256 familyId_) external;

    /// @notice Updates the validity duration for an existing credential group.
    /// @param credentialGroupId_ The credential group ID to update.
    /// @param validityDuration_ New validity duration in seconds (0 = no expiry).
    function setCredentialGroupValidityDuration(uint256 credentialGroupId_, uint256 validityDuration_) external;

    /// @notice Updates the family ID for an existing credential group.
    /// @param credentialGroupId_ The credential group ID to update.
    /// @param familyId_ New family ID (0 = standalone, >0 = family grouping).
    function setCredentialGroupFamily(uint256 credentialGroupId_, uint256 familyId_) external;

    /// @notice Updates the global attestation validity duration.
    /// @param duration_ New duration in seconds (must be > 0).
    function setAttestationValidityDuration(uint256 duration_) external;

    /// @notice Suspends an active credential group.
    /// @param credentialGroupId_ The credential group ID to suspend.
    function suspendCredentialGroup(uint256 credentialGroupId_) external;

    /// @notice Reactivates a suspended credential group.
    /// @param credentialGroupId_ The credential group ID to activate.
    function activateCredentialGroup(uint256 credentialGroupId_) external;

    /// @notice Adds a trusted attestation verifier.
    /// @param verifier_ The verifier address to add (must not be zero).
    function addTrustedVerifier(address verifier_) external;

    /// @notice Removes a trusted attestation verifier.
    /// @param verifier_ The verifier address to remove.
    function removeTrustedVerifier(address verifier_) external;
    function setDefaultMerkleTreeDuration(uint256 duration_) external;

    // ── App management ──────────────────────────

    /// @notice Registers a new app. Caller becomes admin. Uses DefaultScorer by default.
    /// @param recoveryTimelock_ Recovery timelock in seconds (0 to disable recovery).
    /// @return The newly assigned auto-incremented app ID.
    function registerApp(uint256 recoveryTimelock_) external returns (uint256);

    /// @notice Suspends an active app. Only callable by the app admin.
    /// @param appId_ The app ID to suspend.
    function suspendApp(uint256 appId_) external;

    /// @notice Reactivates a suspended app. Only callable by the app admin.
    /// @param appId_ The app ID to activate.
    function activateApp(uint256 appId_) external;

    /// @notice Sets the recovery timelock for an app. Only callable by the app admin.
    /// @param appId_ The app ID to configure.
    /// @param recoveryTimelock_ New timelock duration in seconds (0 to disable).
    function setAppRecoveryTimelock(uint256 appId_, uint256 recoveryTimelock_) external;

    /// @notice Initiates a two-step app admin transfer. Only callable by the current admin.
    /// @param appId_ The app ID.
    /// @param newAdmin_ The proposed new admin address.
    function transferAppAdmin(uint256 appId_, address newAdmin_) external;

    /// @notice Completes a two-step app admin transfer. Must be called by the pending admin.
    /// @param appId_ The app ID.
    function acceptAppAdmin(uint256 appId_) external;

    /// @notice Updates the default scorer contract used for newly registered apps.
    /// @param scorer_ The new default scorer address (must not be zero).
    function setDefaultScorer(address scorer_) external;

    /// @notice Sets a custom scorer contract for an app. Only callable by the app admin.
    /// @param appId_ The app ID.
    /// @param scorer_ The scorer contract address.
    function setAppScorer(uint256 appId_, address scorer_) external;
    function setAppMerkleTreeDuration(uint256 appId_, uint256 merkleTreeDuration_) external;
}
