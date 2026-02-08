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
        uint256 score;
        uint256 semaphoreGroupId;
        CredentialGroupStatus status;
    }

    struct App {
        AppStatus status;
    }

    struct CredentialGroupProof {
        uint256 credentialGroupId;
        uint256 appId;
        bytes nullifierProof;
        ISemaphore.SemaphoreProof semaphoreProof;
    }

    struct Attestation {
        address registry;
        uint256 credentialGroupId;
        uint256 appId;
        bytes32 blindedId;
        uint256 semaphoreIdentityCommitment;
    }

    function score(uint256 context_, CredentialGroupProof[] calldata proofs) external returns (uint256);
    function validateProof(uint256 context, CredentialGroupProof calldata proof) external;
    function credentialGroupIsActive(uint256 credentialGroupId_) external view returns (bool);
    function credentialGroupScore(uint256 credentialGroupId_) external view returns (uint256);
    function appIsActive(uint256 appId_) external view returns (bool);
}
