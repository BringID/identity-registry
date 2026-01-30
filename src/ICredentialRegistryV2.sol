// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";

/// @title ICredentialRegistryV2
/// @notice Interface for the combined credential registry with apps and recovery
/// @dev Groups are score-oriented: score IS the groupId (0, 10, 20, 30, etc.)
interface ICredentialRegistryV2 {
    // ============ Enums ============

    enum ScoreGroupStatus {
        UNDEFINED,
        ACTIVE,
        SUSPENDED
    }

    enum AppStatus {
        UNDEFINED,
        ACTIVE
    }

    // ============ Structs ============

    struct ScoreGroup {
        uint256 semaphoreGroupId;
        ScoreGroupStatus status;
    }

    struct ScoreGroupProof {
        uint256 score;
        ISemaphore.SemaphoreProof semaphoreProof;
    }

    struct Attestation {
        address registry;
        uint256 score; // Score determines which group (score IS the groupId)
        bytes32 blindedId; // hash(idHash, domain, appId) - unique per identity, used as nullifier
        uint256 semaphoreIdentityCommitment;
    }

    struct App {
        address admin;
        uint256 recoveryDelay;
        AppStatus status;
    }

    struct PendingRecovery {
        uint256 newCommitment;
        uint256 unlockTime;
        uint256 score; // Score of the group to update
    }

    struct Identity {
        uint256 commitment;
        uint256 score; // Which score group the identity belongs to
    }

    // ============ Events ============

    // Score group events
    event ScoreGroupCreated(uint256 indexed score);
    event IdentityAdded(uint256 indexed score, uint256 indexed commitment);
    event ProofValidated(uint256 indexed score);

    // App events
    event AppRegistered(uint256 indexed appId, address indexed admin, uint256 recoveryDelay);
    event AppUpdated(uint256 indexed appId, uint256 recoveryDelay);

    // Identity/Recovery events
    event IdentityLinked(bytes32 indexed blindedId, uint256 indexed commitment, uint256 score);
    event RecoveryInitiated(bytes32 indexed blindedId, uint256 unlockTime);
    event RecoveryCancelled(bytes32 indexed blindedId);
    event RecoveryFinalized(bytes32 indexed blindedId, uint256 oldCommitment, uint256 newCommitment);

    // Admin events
    event VerifierSet(address indexed verifier);

    // ============ Score Group Functions ============

    function scoreGroupIsActive(uint256 score_) external view returns (bool);
    function scoreGroups(uint256 score_) external view returns (uint256 semaphoreGroupId, ScoreGroupStatus status);

    function joinGroup(Attestation memory attestation_, bytes memory signature_) external;
    function joinGroup(Attestation memory attestation_, uint8 v, bytes32 r, bytes32 s) external;

    function validateProof(uint256 context_, ScoreGroupProof memory proof_) external;
    function verifyProof(ScoreGroupProof calldata proof_) external view returns (bool);

    // ============ App Functions ============

    function registerApp(uint256 appId_, address admin_, uint256 recoveryDelay_) external;
    function updateAppRecoveryDelay(uint256 appId_, uint256 newRecoveryDelay_) external;
    function apps(uint256 appId_) external view returns (address admin, uint256 recoveryDelay, AppStatus status);
    function getApp(uint256 appId_) external view returns (App memory);

    // ============ Identity Recovery Functions ============

    function initiateRecovery(
        bytes32 blindedId_,
        uint256 appId_,
        uint256 newCommitment_,
        uint256 score_
    ) external;
    function cancelRecovery(bytes32 blindedId_) external;
    function finalizeRecovery(bytes32 blindedId_, uint256[] calldata merkleProofSiblings_) external;

    function identities(bytes32 blindedId_) external view returns (uint256 commitment, uint256 score);
    function getIdentity(bytes32 blindedId_) external view returns (Identity memory);
    function getPendingRecovery(bytes32 blindedId_) external view returns (PendingRecovery memory);
    function isRecoveryReady(bytes32 blindedId_) external view returns (bool);

    // ============ Admin Functions ============

    function createScoreGroup(uint256 score_) external;
    function suspendScoreGroup(uint256 score_) external;
    function setVerifier(address verifier_) external;
    function updateSemaphoreGroupAdmin(uint256 score_, address newAdmin_) external;
    function acceptSemaphoreGroupAdmin(uint256 semaphoreGroupId_) external;
}
