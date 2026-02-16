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
        uint256 familyId; // 0 = standalone (no family constraint), >0 = family grouping
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
        bool expired; // true after removeExpiredCredential; cleared on renewal/recovery
        uint256 commitment; // Semaphore identity commitment (persists across expiry for nullifier continuity)
        uint256 expiresAt; // 0 = no expiry
        uint256 credentialGroupId; // which credential group within the family
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
        uint256 issuedAt;
    }

    // ── View helpers ──────────────────────────────
    function credentialGroupIsActive(uint256 credentialGroupId_) external view returns (bool);
    function appIsActive(uint256 appId_) external view returns (bool);
    function getCredentialGroupIds() external view returns (uint256[] memory);
    function verifyAttestation(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s)
        external
        view
        returns (address signer, bytes32 registrationHash);

    // ── Credential registration ─────────────────
    function registerCredential(Attestation calldata attestation_, bytes calldata signature_) external;
    function registerCredential(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s) external;

    // ── Credential renewal ──────────────────────
    function renewCredential(Attestation calldata attestation_, bytes calldata signature_) external;
    function renewCredential(Attestation calldata attestation_, uint8 v, bytes32 r, bytes32 s) external;

    // ── Proof validation ────────────────────────
    function submitProof(uint256 context_, CredentialGroupProof calldata proof) external returns (uint256);
    function submitProofs(uint256 context_, CredentialGroupProof[] calldata proofs) external returns (uint256);
    function verifyProof(uint256 context_, CredentialGroupProof calldata proof) external view returns (bool);
    function verifyProofs(uint256 context_, CredentialGroupProof[] calldata proofs) external view returns (bool);
    function getScore(uint256 context_, CredentialGroupProof[] calldata proofs) external view returns (uint256);

    // ── Credential expiry ───────────────────────
    function removeExpiredCredential(
        uint256 credentialGroupId_,
        bytes32 credentialId_,
        uint256 appId_,
        uint256[] calldata merkleProofSiblings_
    ) external;

    // ── Recovery ────────────────────────────────
    function initiateRecovery(
        Attestation calldata attestation_,
        bytes calldata signature_,
        uint256[] calldata merkleProofSiblings_
    ) external;
    function initiateRecovery(
        Attestation calldata attestation_,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256[] calldata merkleProofSiblings_
    ) external;
    function executeRecovery(bytes32 registrationHash_) external;

    // ── Owner administration ────────────────────
    function createCredentialGroup(uint256 credentialGroupId_, uint256 validityDuration_, uint256 familyId_) external;
    function setCredentialGroupValidityDuration(uint256 credentialGroupId_, uint256 validityDuration_) external;
    function setCredentialGroupFamily(uint256 credentialGroupId_, uint256 familyId_) external;
    function setAttestationValidityDuration(uint256 duration_) external;
    function suspendCredentialGroup(uint256 credentialGroupId_) external;
    function activateCredentialGroup(uint256 credentialGroupId_) external;
    function addTrustedVerifier(address verifier_) external;
    function removeTrustedVerifier(address verifier_) external;

    // ── App management ──────────────────────────
    function registerApp(uint256 recoveryTimelock_) external returns (uint256);
    function suspendApp(uint256 appId_) external;
    function activateApp(uint256 appId_) external;
    function setAppRecoveryTimelock(uint256 appId_, uint256 recoveryTimelock_) external;
    function setAppAdmin(uint256 appId_, address newAdmin_) external;
    function setAppScorer(uint256 appId_, address scorer_) external;
}
