// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";

/// @notice Emitted when a new credential group is created by the owner.
/// @param credentialGroupId The unique ID assigned to the credential group.
/// @param credentialGroup The full configuration of the newly created group.
event CredentialGroupCreated(uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroup credentialGroup);

/// @notice Emitted when a per-app Semaphore group is lazily created for a (credentialGroup, app) pair.
/// @param credentialGroupId The credential group the Semaphore group belongs to.
/// @param appId The app the Semaphore group belongs to.
/// @param semaphoreGroupId The ID of the newly created Semaphore group.
event AppSemaphoreGroupCreated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 semaphoreGroupId);

/// @notice Emitted when a credential is successfully registered for the first time.
/// @param credentialGroupId The credential group the credential was registered in.
/// @param appId The app the credential was registered for.
/// @param commitment The Semaphore identity commitment that was added to the group.
/// @param credentialId The unique credential identifier (e.g., hashed OAuth sub).
/// @param registrationHash The computed registration hash for this credential.
/// @param verifier The trusted verifier address that signed the attestation.
/// @param expiresAt The timestamp when the credential expires (0 if no expiry).
event CredentialRegistered(
    uint256 indexed credentialGroupId,
    uint256 indexed appId,
    uint256 indexed commitment,
    bytes32 credentialId,
    bytes32 registrationHash,
    address verifier,
    uint256 expiresAt
);

/// @notice Emitted when a Semaphore proof is validated and its nullifier consumed.
/// @param credentialGroupId The credential group the proof was submitted for.
/// @param appId The app the proof was submitted for.
/// @param nullifier The Semaphore nullifier that was consumed.
event ProofValidated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 nullifier);

/// @notice Emitted when a trusted verifier is added or removed.
/// @param verifier The verifier address that was updated.
/// @param trusted True if added, false if removed.
event TrustedVerifierUpdated(address indexed verifier, bool trusted);

/// @notice Emitted when a new app is registered.
/// @param appId The auto-incremented ID assigned to the app.
/// @param admin The address that registered the app and became its admin.
/// @param recoveryTimelock The initial recovery timelock duration in seconds.
event AppRegistered(uint256 indexed appId, address indexed admin, uint256 recoveryTimelock);

/// @notice Emitted when an app's status changes (suspended or reactivated).
/// @param appId The app whose status changed.
/// @param status The new status of the app.
event AppStatusChanged(uint256 indexed appId, ICredentialRegistry.AppStatus status);

/// @notice Emitted when an app's scorer contract is updated.
/// @param appId The app whose scorer was changed.
/// @param scorer The new scorer contract address.
event AppScorerSet(uint256 indexed appId, address indexed scorer);

/// @notice Emitted when an app's admin is transferred to a new address.
/// @param appId The app whose admin was transferred.
/// @param oldAdmin The previous admin address.
/// @param newAdmin The new admin address.
event AppAdminTransferred(uint256 indexed appId, address indexed oldAdmin, address indexed newAdmin);

/// @notice Emitted when an app's recovery timelock is updated.
/// @param appId The app whose timelock was changed.
/// @param timelock The new recovery timelock duration in seconds.
event AppRecoveryTimelockSet(uint256 indexed appId, uint256 timelock);

/// @notice Emitted when credential recovery is initiated.
/// @param registrationHash The registration hash identifying the credential.
/// @param credentialGroupId The target credential group (may differ for family group changes).
/// @param oldCommitment The Semaphore commitment being replaced (removed from group immediately).
/// @param newCommitment The new Semaphore commitment (queued behind timelock).
/// @param executeAfter The timestamp after which executeRecovery() can be called.
event RecoveryInitiated(
    bytes32 indexed registrationHash,
    uint256 indexed credentialGroupId,
    uint256 oldCommitment,
    uint256 newCommitment,
    uint256 executeAfter
);

/// @notice Emitted when a pending recovery is finalized.
/// @param registrationHash The registration hash identifying the recovered credential.
/// @param newCommitment The new Semaphore commitment that was added to the group.
event RecoveryExecuted(bytes32 indexed registrationHash, uint256 newCommitment);

/// @notice Emitted when a credential is renewed (re-activated or extended).
/// @param credentialGroupId The credential group of the renewed credential.
/// @param appId The app the credential was renewed for.
/// @param commitment The Semaphore identity commitment (unchanged from registration).
/// @param credentialId The unique credential identifier.
/// @param registrationHash The registration hash for this credential.
/// @param verifier The trusted verifier that signed the renewal attestation.
/// @param expiresAt The new expiry timestamp after renewal (0 if no expiry).
event CredentialRenewed(
    uint256 indexed credentialGroupId,
    uint256 indexed appId,
    uint256 indexed commitment,
    bytes32 credentialId,
    bytes32 registrationHash,
    address verifier,
    uint256 expiresAt
);

/// @notice Emitted when an expired credential is removed from its Semaphore group.
/// @param credentialGroupId The credential group of the expired credential.
/// @param appId The app the credential was registered for.
/// @param credentialId The unique credential identifier.
/// @param registrationHash The registration hash for this credential.
event CredentialExpired(
    uint256 indexed credentialGroupId, uint256 indexed appId, bytes32 credentialId, bytes32 registrationHash
);

/// @notice Emitted when a credential group's validity duration is updated.
/// @param credentialGroupId The credential group that was updated.
/// @param validityDuration The new validity duration in seconds.
event CredentialGroupValidityDurationSet(uint256 indexed credentialGroupId, uint256 validityDuration);

/// @notice Emitted when a credential group's family ID is updated.
/// @param credentialGroupId The credential group that was updated.
/// @param familyId The new family ID.
event CredentialGroupFamilySet(uint256 indexed credentialGroupId, uint256 familyId);

/// @notice Emitted when the global attestation validity duration is updated.
/// @param duration The new attestation validity duration in seconds.
event AttestationValidityDurationSet(uint256 duration);

/// @notice Emitted when a credential group's status changes (suspended or reactivated).
/// @param credentialGroupId The credential group whose status changed.
/// @param status The new status of the credential group.
event CredentialGroupStatusChanged(uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroupStatus status);
