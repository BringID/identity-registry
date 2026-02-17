// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";

/// @title ICredentialRegistry
/// @notice Interface for the BringID Credential Registry — a privacy-preserving credential
///         system where users register credentials via verifier-signed attestations and prove
///         membership using Semaphore zero-knowledge proofs.
interface ICredentialRegistry {
    /// @notice Status lifecycle for credential groups.
    /// @dev UNDEFINED is the default (group does not exist), ACTIVE allows operations,
    ///      SUSPENDED blocks new registrations and proof validations.
    enum CredentialGroupStatus {
        UNDEFINED,
        ACTIVE,
        SUSPENDED
    }

    /// @notice Status lifecycle for apps.
    /// @dev UNDEFINED is the default (app does not exist), ACTIVE allows operations,
    ///      SUSPENDED blocks credential operations for this app.
    enum AppStatus {
        UNDEFINED,
        ACTIVE,
        SUSPENDED
    }

    /// @notice Configuration for a credential group.
    /// @param status Current lifecycle status of the group.
    /// @param validityDuration Duration in seconds credentials remain valid (0 = no expiry).
    /// @param familyId Family grouping identifier. Groups with the same familyId (> 0) share
    ///        a registration hash, enforcing one credential per family per app. 0 = standalone.
    struct CredentialGroup {
        CredentialGroupStatus status;
        uint256 validityDuration;
        uint256 familyId;
    }

    /// @notice Configuration for a registered app.
    /// @param status Current lifecycle status of the app.
    /// @param recoveryTimelock Duration in seconds for the recovery timelock (0 = recovery disabled).
    /// @param admin Address authorized to manage this app.
    /// @param scorer Address of the scorer contract used to evaluate credential group scores.
    struct App {
        AppStatus status;
        uint256 recoveryTimelock;
        address admin;
        address scorer;
    }

    /// @notice Pending recovery request for a credential.
    /// @param credentialGroupId Target credential group (may differ from current for family group changes).
    /// @param appId The app this recovery is scoped to.
    /// @param newCommitment The new Semaphore identity commitment to install after the timelock.
    /// @param executeAfter Timestamp after which executeRecovery() can be called (0 = no pending recovery).
    struct RecoveryRequest {
        uint256 credentialGroupId;
        uint256 appId;
        uint256 newCommitment;
        uint256 executeAfter;
    }

    /// @notice On-chain record for a registered credential.
    /// @param registered True once the credential has been registered (persists across expiry).
    /// @param expired True after removeExpiredCredential() is called; cleared on renewal/recovery.
    /// @param commitment Semaphore identity commitment. Persists across expiry for nullifier continuity;
    ///        only changes via recovery.
    /// @param expiresAt Timestamp when the credential expires (0 = no expiry).
    /// @param credentialGroupId The credential group this credential belongs to.
    /// @param pendingRecovery In-flight recovery request, if any.
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
    /// @param appId The app the proof is scoped to.
    /// @param semaphoreProof The underlying Semaphore proof (membership + nullifier).
    struct CredentialGroupProof {
        uint256 credentialGroupId;
        uint256 appId;
        ISemaphore.SemaphoreProof semaphoreProof;
    }

    /// @notice Verifier-signed attestation authorizing a credential operation.
    /// @param registry Address of the CredentialRegistry (prevents cross-registry replay).
    /// @param credentialGroupId The credential group the attestation targets.
    /// @param credentialId Unique identifier for the credential (e.g., hashed OAuth sub),
    ///        used for deduplication within a group or family.
    /// @param appId The app this attestation is scoped to.
    /// @param semaphoreIdentityCommitment The user's Semaphore identity commitment.
    /// @param issuedAt Timestamp when the verifier created this attestation. The registry
    ///        enforces `block.timestamp <= issuedAt + attestationValidityDuration`.
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
    /// @return True if the group status is ACTIVE.
    function credentialGroupIsActive(uint256 credentialGroupId_) external view returns (bool);

    /// @notice Checks whether an app is currently active.
    /// @param appId_ The app ID to check.
    /// @return True if the app status is ACTIVE.
    function appIsActive(uint256 appId_) external view returns (bool);

    /// @notice Returns all registered credential group IDs.
    /// @return Array of credential group IDs that have been created.
    function getCredentialGroupIds() external view returns (uint256[] memory);

    /// @notice Verifies an attestation's validity and recovers the signer address.
    /// @dev Checks credential group and app are active, registry address matches,
    ///      attestation is not expired, and the ECDSA signature is from a trusted verifier.
    /// @param attestation_ The attestation to verify.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    /// @return signer The recovered trusted verifier address.
    /// @return registrationHash The computed registration hash for the credential.
    function verifyAttestation(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s)
        external
        view
        returns (address signer, bytes32 registrationHash);

    // ── Credential registration ─────────────────

    /// @notice Registers a new credential using a packed bytes signature.
    /// @dev Unpacks the 65-byte signature (r || s || v) and delegates to the (v, r, s) overload.
    /// @param attestation_ The verifier-signed attestation with credential details.
    /// @param signature_ 65-byte ECDSA signature.
    function registerCredential(Attestation calldata attestation_, bytes calldata signature_) external;

    /// @notice Registers a new credential using split ECDSA signature components.
    /// @dev Creates a per-app Semaphore group lazily if needed, validates the attestation,
    ///      and adds the user's commitment to the Semaphore group. Reverts if already registered.
    /// @param attestation_ The verifier-signed attestation with credential details.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function registerCredential(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s) external;

    // ── Credential renewal ──────────────────────

    /// @notice Renews a previously-registered credential using a packed bytes signature.
    /// @dev Unpacks the 65-byte signature and delegates to the (v, r, s) overload.
    /// @param attestation_ The attestation; commitment must match the stored one.
    /// @param signature_ 65-byte ECDSA signature.
    function renewCredential(Attestation calldata attestation_, bytes calldata signature_) external;

    /// @notice Renews a previously-registered credential using split ECDSA signature components.
    /// @dev Re-activates an expired credential or extends an active one. The commitment must
    ///      remain unchanged (preserving nullifier continuity). If expired, re-adds commitment
    ///      to the Semaphore group.
    /// @param attestation_ The attestation; commitment must match the originally registered one.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    function renewCredential(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s) external;

    // ── Proof validation ────────────────────────

    /// @notice Submits a single credential group proof, consuming the Semaphore nullifier.
    /// @dev Validates scope binding (scope == keccak256(msg.sender, context)), verifies the
    ///      Semaphore proof, and returns the credential group's score from the app's scorer.
    /// @param context_ Application-defined context value combined with msg.sender for scope.
    /// @param proof The credential group proof containing group ID, app ID, and Semaphore proof.
    /// @return The score for the proven credential group.
    function submitProof(uint256 context_, CredentialGroupProof calldata proof) external returns (uint256);

    /// @notice Submits multiple credential group proofs, consuming nullifiers, and returns the total score.
    /// @dev Iterates over each proof, validates and consumes nullifiers, and sums scores.
    ///      Reverts if any proof is invalid.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs Array of credential group proofs to submit.
    /// @return The aggregate score across all validated credential groups.
    function submitProofs(uint256 context_, CredentialGroupProof[] calldata proofs) external returns (uint256);

    /// @notice Verifies a single credential group proof without consuming the nullifier.
    /// @dev View-only counterpart to submitProof(). Uses Semaphore's verifyProof() instead of
    ///      validateProof(), so the proof can still be submitted later.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proof The credential group proof to verify.
    /// @return True if the proof is valid.
    function verifyProof(uint256 context_, CredentialGroupProof calldata proof) external view returns (bool);

    /// @notice Verifies multiple credential group proofs without consuming nullifiers.
    /// @dev View-only counterpart to submitProofs(). Returns false if any proof is invalid.
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs Array of credential group proofs to verify.
    /// @return True if all proofs are valid.
    function verifyProofs(uint256 context_, CredentialGroupProof[] calldata proofs) external view returns (bool);

    /// @notice Verifies multiple proofs and returns the aggregate score without consuming nullifiers.
    /// @dev Reverts if any proof is invalid (unlike verifyProofs which returns false).
    /// @param context_ Application-defined context value (see submitProof).
    /// @param proofs Array of credential group proofs to verify and score.
    /// @return The total score across all verified credential groups.
    function getScore(uint256 context_, CredentialGroupProof[] calldata proofs) external view returns (uint256);

    // ── Credential expiry ───────────────────────

    /// @notice Removes an expired credential from its per-app Semaphore group.
    /// @dev Publicly callable once a credential has expired. Sets cred.expired = true but
    ///      preserves cred.registered and cred.commitment for renewal and recovery continuity.
    ///      Blocked if a recovery is pending to prevent double-removal from the Semaphore group.
    /// @param credentialGroupId_ The credential group the credential belongs to.
    /// @param credentialId_ The credential identity (from the attestation).
    /// @param appId_ The app the credential was registered for.
    /// @param merkleProofSiblings_ Merkle proof siblings for removing the commitment from the Semaphore group.
    function removeExpiredCredential(
        uint256 credentialGroupId_,
        bytes32 credentialId_,
        uint256 appId_,
        uint256[] calldata merkleProofSiblings_
    ) external;

    // ── Recovery ────────────────────────────────

    /// @notice Initiates recovery for a credential using a packed bytes signature.
    /// @dev Unpacks the 65-byte signature and delegates to the (v, r, s) overload.
    /// @param attestation_ Attestation with the same credentialId but a new commitment.
    /// @param signature_ 65-byte ECDSA signature.
    /// @param merkleProofSiblings_ Merkle proof siblings for the old commitment in the Semaphore group.
    function initiateRecovery(
        Attestation calldata attestation_,
        bytes calldata signature_,
        uint256[] calldata merkleProofSiblings_
    ) external;

    /// @notice Initiates recovery for a credential using split ECDSA signature components.
    /// @dev Removes the old commitment from the Semaphore group immediately and queues the new
    ///      commitment behind the app's recovery timelock. Supports group changes within the
    ///      same family (e.g., upgrading from Low to High tier).
    /// @param attestation_ Attestation with the same credentialId but a new commitment.
    /// @param v ECDSA recovery parameter.
    /// @param r ECDSA signature component.
    /// @param s ECDSA signature component.
    /// @param merkleProofSiblings_ Merkle proof siblings for the old commitment in the Semaphore group.
    function initiateRecovery(
        Attestation calldata attestation_,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256[] calldata merkleProofSiblings_
    ) external;

    /// @notice Finalizes a pending recovery after the timelock has expired.
    /// @dev Adds the new commitment to the Semaphore group, updates the stored commitment
    ///      and credential group ID, and clears the pending recovery. Callable by anyone
    ///      once the timelock expires.
    /// @param registrationHash_ The registration hash identifying the credential being recovered.
    function executeRecovery(bytes32 registrationHash_) external;

    // ── Owner administration ────────────────────

    /// @notice Creates a new credential group.
    /// @dev Group IDs are user-defined (not auto-incremented) and must be > 0.
    ///      Per-app Semaphore groups are created lazily during credential registration.
    /// @param credentialGroupId_ Unique identifier for the group (must be > 0, must not exist).
    /// @param validityDuration_ Duration in seconds for credential validity (0 = no expiry).
    /// @param familyId_ Family grouping ID (0 = standalone, >0 = family). Same-family groups
    ///        share a registration hash, preventing double registration.
    function createCredentialGroup(uint256 credentialGroupId_, uint256 validityDuration_, uint256 familyId_) external;

    /// @notice Updates the validity duration for a credential group.
    /// @dev Only affects future registrations/renewals; existing credentials keep their expiry.
    /// @param credentialGroupId_ The credential group to update.
    /// @param validityDuration_ New duration in seconds (0 = no expiry).
    function setCredentialGroupValidityDuration(uint256 credentialGroupId_, uint256 validityDuration_) external;

    /// @notice Updates the family ID for a credential group.
    /// @dev Only affects future registrations; existing registrations keep their hash.
    /// @param credentialGroupId_ The credential group to update.
    /// @param familyId_ New family ID (0 = standalone, >0 = family).
    function setCredentialGroupFamily(uint256 credentialGroupId_, uint256 familyId_) external;

    /// @notice Updates the global attestation validity duration.
    /// @param duration_ New duration in seconds (must be > 0).
    function setAttestationValidityDuration(uint256 duration_) external;

    /// @notice Suspends an active credential group, blocking registrations and proofs.
    /// @param credentialGroupId_ The credential group to suspend.
    function suspendCredentialGroup(uint256 credentialGroupId_) external;

    /// @notice Reactivates a suspended credential group.
    /// @param credentialGroupId_ The credential group to reactivate.
    function activateCredentialGroup(uint256 credentialGroupId_) external;

    /// @notice Adds a trusted verifier that can sign attestations.
    /// @param verifier_ The verifier address to trust (must not be zero).
    function addTrustedVerifier(address verifier_) external;

    /// @notice Removes a trusted verifier, revoking attestation signing authority.
    /// @param verifier_ The verifier address to remove.
    function removeTrustedVerifier(address verifier_) external;

    // ── App management ──────────────────────────

    /// @notice Registers a new app. The caller becomes the app admin.
    /// @dev App IDs are auto-incremented. The app uses the default scorer initially.
    /// @param recoveryTimelock_ Recovery timelock duration in seconds (0 = recovery disabled).
    /// @return The newly assigned app ID.
    function registerApp(uint256 recoveryTimelock_) external returns (uint256);

    /// @notice Suspends an active app. Only callable by the app admin.
    /// @param appId_ The app to suspend.
    function suspendApp(uint256 appId_) external;

    /// @notice Reactivates a suspended app. Only callable by the app admin.
    /// @param appId_ The app to reactivate.
    function activateApp(uint256 appId_) external;

    /// @notice Sets the recovery timelock for an app. Only callable by the app admin.
    /// @param appId_ The app to configure.
    /// @param recoveryTimelock_ Timelock duration in seconds (0 = disable recovery).
    function setAppRecoveryTimelock(uint256 appId_, uint256 recoveryTimelock_) external;

    /// @notice Transfers app admin to a new address. Only callable by the current admin.
    /// @param appId_ The app to transfer.
    /// @param newAdmin_ The new admin address (must not be zero).
    function setAppAdmin(uint256 appId_, address newAdmin_) external;

    /// @notice Sets a custom scorer contract for an app. Only callable by the app admin.
    /// @param appId_ The app to configure.
    /// @param scorer_ The scorer contract address (must not be zero).
    function setAppScorer(uint256 appId_, address scorer_) external;
}
