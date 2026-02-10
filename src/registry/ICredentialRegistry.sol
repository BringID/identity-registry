// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";

interface ICredentialRegistry {
    enum CredentialGroupStatus {
        UNDEFINED,
        ACTIVE,
        SUSPENDED
    }

    enum AppStatus {
        UNDEFINED,
        ACTIVE,
        SUSPENDED
    }

    struct CredentialGroup {
        CredentialGroupStatus status;
        uint256 validityDuration; // seconds, 0 = no expiry
    }

    struct App {
        AppStatus status;
        uint256 recoveryTimelock;
        address admin;
        address scorer;
    }

    struct RecoveryRequest {
        uint256 credentialGroupId;
        uint256 appId;
        uint256 newCommitment;
        uint256 executeAfter;
    }

    struct CredentialRecord {
        bool registered;
        uint256 commitment; // Semaphore identity commitment (persists across expiry for nullifier continuity)
        uint256 expiresAt; // 0 = no expiry
        RecoveryRequest pendingRecovery;
    }

    struct CredentialGroupProof {
        uint256 credentialGroupId;
        uint256 appId;
        ISemaphore.SemaphoreProof semaphoreProof;
    }

    struct Attestation {
        address registry;
        uint256 credentialGroupId;
        bytes32 credentialId;
        uint256 appId;
        uint256 semaphoreIdentityCommitment;
    }

    function submitProof(uint256 context_, CredentialGroupProof calldata proof) external;
    function submitProofs(uint256 context_, CredentialGroupProof[] calldata proofs) external returns (uint256);
    function verifyProof(uint256 context_, CredentialGroupProof calldata proof) external view returns (bool);
    function verifyProofs(uint256 context_, CredentialGroupProof[] calldata proofs) external view returns (bool);
    function getScore(uint256 context_, CredentialGroupProof[] calldata proofs) external view returns (uint256);
    function credentialGroupIsActive(uint256 credentialGroupId_) external view returns (bool);
    function appIsActive(uint256 appId_) external view returns (bool);
    function removeExpiredCredential(
        uint256 credentialGroupId_,
        bytes32 credentialId_,
        uint256 appId_,
        uint256[] calldata merkleProofSiblings_
    ) external;
}
