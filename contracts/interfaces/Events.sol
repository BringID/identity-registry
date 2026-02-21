// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";

/// @notice Emitted when a new credential group is created by the owner.
/// @param credentialGroupId The unique identifier of the new credential group.
/// @param credentialGroup The credential group configuration (status, validityDuration, familyId).
event CredentialGroupCreated(uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroup credentialGroup);

/// @notice Emitted when a per-app Semaphore group is lazily created for a (credentialGroup, app) pair.
/// @param credentialGroupId The credential group ID.
/// @param appId The app ID.
/// @param semaphoreGroupId The Semaphore group ID assigned to this pair.
event AppSemaphoreGroupCreated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 semaphoreGroupId);

/// @notice Emitted when a credential is registered for the first time.
/// @param credentialGroupId The credential group the credential was registered to.
/// @param appId The app the credential was registered for.
/// @param commitment The Semaphore identity commitment added to the group.
/// @param credentialId The application-specific credential identity.
/// @param registrationHash The computed registration hash for this credential.
/// @param verifier The trusted verifier address that signed the attestation.
/// @param expiresAt Timestamp when the credential expires (0 if no expiry).
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
/// @param credentialGroupId The credential group the proof was for.
/// @param appId The app the proof was submitted against.
/// @param nullifier The Semaphore nullifier that was consumed.
event ProofValidated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 nullifier);

/// @notice Emitted when a trusted verifier is added or removed.
/// @param verifier The verifier address.
/// @param trusted True if added, false if removed.
event TrustedVerifierUpdated(address indexed verifier, bool trusted);

/// @notice Emitted when a new app is registered.
/// @param appId The auto-incremented app ID assigned.
/// @param admin The address that registered the app (becomes admin).
/// @param recoveryTimelock The recovery timelock duration set for this app.
event AppRegistered(uint256 indexed appId, address indexed admin, uint256 recoveryTimelock);

/// @notice Emitted when an app's status changes (suspended or activated).
/// @param appId The app ID.
/// @param status The new app status.
event AppStatusChanged(uint256 indexed appId, ICredentialRegistry.AppStatus status);

/// @notice Emitted when an app's scorer contract is changed.
/// @param appId The app ID.
/// @param scorer The new scorer contract address.
event AppScorerSet(uint256 indexed appId, address indexed scorer);

/// @notice Emitted when a two-step app admin transfer is initiated.
/// @param appId The app ID.
/// @param currentAdmin The current admin initiating the transfer.
/// @param newAdmin The proposed new admin address.
event AppAdminTransferInitiated(uint256 indexed appId, address indexed currentAdmin, address indexed newAdmin);

/// @notice Emitted when a two-step app admin transfer is completed.
/// @param appId The app ID.
/// @param oldAdmin The previous admin address.
/// @param newAdmin The new admin address.
event AppAdminTransferred(uint256 indexed appId, address indexed oldAdmin, address indexed newAdmin);

/// @notice Emitted when an app's recovery timelock is updated.
/// @param appId The app ID.
/// @param timelock The new recovery timelock duration in seconds.
event AppRecoveryTimelockSet(uint256 indexed appId, uint256 timelock);

/// @notice Emitted when key recovery is initiated for a credential.
/// @param registrationHash The registration hash of the credential being recovered.
/// @param credentialGroupId The target credential group (may differ for family group changes).
/// @param oldCommitment The old Semaphore identity commitment being replaced.
/// @param newCommitment The new Semaphore identity commitment queued for recovery.
/// @param executeAfter Timestamp after which the recovery can be finalized.
event RecoveryInitiated(
    bytes32 indexed registrationHash,
    uint256 indexed credentialGroupId,
    uint256 oldCommitment,
    uint256 newCommitment,
    uint256 executeAfter
);

/// @notice Emitted when a pending recovery is finalized.
/// @param registrationHash The registration hash of the recovered credential.
/// @param newCommitment The new Semaphore identity commitment now active.
event RecoveryExecuted(bytes32 indexed registrationHash, uint256 newCommitment);

/// @notice Emitted when a credential is renewed (re-activated or extended).
/// @param credentialGroupId The credential group.
/// @param appId The app.
/// @param commitment The Semaphore identity commitment (same as original registration).
/// @param credentialId The credential identity.
/// @param registrationHash The registration hash.
/// @param verifier The trusted verifier that signed the renewal attestation.
/// @param expiresAt The new expiry timestamp (0 if no expiry).
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
/// @param credentialGroupId The credential group.
/// @param appId The app.
/// @param credentialId The credential identity.
/// @param registrationHash The registration hash.
event CredentialExpired(
    uint256 indexed credentialGroupId, uint256 indexed appId, bytes32 credentialId, bytes32 registrationHash
);

/// @notice Emitted when a credential group's validity duration is updated.
/// @param credentialGroupId The credential group ID.
/// @param validityDuration The new validity duration in seconds.
event CredentialGroupValidityDurationSet(uint256 indexed credentialGroupId, uint256 validityDuration);

/// @notice Emitted when the global attestation validity duration is updated.
/// @param duration The new attestation validity duration in seconds.
event AttestationValidityDurationSet(uint256 duration);

/// @notice Emitted when a credential group's status changes (suspended or activated).
/// @param credentialGroupId The credential group ID.
/// @param status The new credential group status.
event CredentialGroupStatusChanged(uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroupStatus status);

/// @notice Emitted when the registry-level default Merkle tree duration is updated.
/// @param duration The new default duration in seconds.
event DefaultMerkleTreeDurationSet(uint256 indexed duration);

/// @notice Emitted when a per-app Merkle tree duration override is set.
/// @param appId The app ID.
/// @param merkleTreeDuration The new duration in seconds (0 = use registry default).
event AppMerkleTreeDurationSet(uint256 indexed appId, uint256 merkleTreeDuration);

/// @notice Emitted when the default scorer contract is updated by the owner.
/// @param oldScorer The previous default scorer address.
/// @param newScorer The new default scorer address.
event DefaultScorerUpdated(address indexed oldScorer, address indexed newScorer);
