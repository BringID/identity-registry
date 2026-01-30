// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICredentialRegistryV2} from "./ICredentialRegistryV2.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";

/// @title CredentialRegistryV2
/// @notice Combined credential registry with apps layer and identity recovery
/// @dev Groups are score-oriented: score IS the groupId (0, 10, 20, 30, etc.)
contract CredentialRegistryV2 is ICredentialRegistryV2, Ownable2Step {
    using ECDSA for bytes32;

    uint256 public constant MIN_RECOVERY_DELAY = 1 days;
    uint256 public constant MAX_RECOVERY_DELAY = 30 days;

    ISemaphore public immutable SEMAPHORE;
    address public verifier;

    // Score groups indexed by score (score IS the groupId)
    mapping(uint256 score => ScoreGroup) public scoreGroups;

    // Apps
    mapping(uint256 appId => App) public apps;

    // Identities: blindedId => Identity (commitment + score)
    // blindedId = hash(idHash, domain, appId) - computed off-chain
    mapping(bytes32 blindedId => Identity) public identities;
    mapping(bytes32 blindedId => PendingRecovery) public pendingRecoveries;

    modifier onlyVerifier() {
        require(msg.sender == verifier, "Only verifier");
        _;
    }

    modifier appExists(uint256 appId_) {
        require(apps[appId_].status != AppStatus.UNDEFINED, "App does not exist");
        _;
    }

    constructor(ISemaphore semaphore_, address verifier_) {
        require(address(semaphore_) != address(0), "Invalid Semaphore address");
        require(verifier_ != address(0), "Invalid verifier address");
        SEMAPHORE = semaphore_;
        verifier = verifier_;
    }

    // ============ Score Group Views ============

    function scoreGroupIsActive(uint256 score_) public view returns (bool) {
        return scoreGroups[score_].status == ScoreGroupStatus.ACTIVE;
    }

    // ============ Join Group ============

    /// @notice Join a score group with a signed attestation
    /// @dev Signature can be reused across all networks
    function joinGroup(
        Attestation memory attestation_,
        bytes memory signature_
    ) public {
        require(signature_.length == 65, "Bad signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(signature_, 0x20))
            s := mload(add(signature_, 0x40))
            v := byte(0, mload(add(signature_, 0x60)))
        }
        joinGroup(attestation_, v, r, s);
    }

    function joinGroup(
        Attestation memory attestation_,
        uint8 v, bytes32 r, bytes32 s
    ) public {
        ScoreGroup memory _scoreGroup = scoreGroups[attestation_.score];

        require(_scoreGroup.status == ScoreGroupStatus.ACTIVE, "Score group is inactive");
        require(attestation_.registry == address(this), "Wrong attestation message");
        require(attestation_.blindedId != bytes32(0), "Invalid blinded ID");
        require(identities[attestation_.blindedId].commitment == 0, "Identity already registered");

        (address signer,) = keccak256(
            abi.encode(attestation_)
        ).toEthSignedMessageHash().tryRecover(v, r, s);

        require(signer == verifier, "Invalid verifier signature");

        // Link identity with score (blindedId is the nullifier)
        identities[attestation_.blindedId] = Identity({
            commitment: attestation_.semaphoreIdentityCommitment,
            score: attestation_.score
        });

        SEMAPHORE.addMember(_scoreGroup.semaphoreGroupId, attestation_.semaphoreIdentityCommitment);

        emit IdentityLinked(attestation_.blindedId, attestation_.semaphoreIdentityCommitment, attestation_.score);
        emit IdentityAdded(attestation_.score, attestation_.semaphoreIdentityCommitment);
    }

    // ============ Proof Validation ============

    /// @notice Validates Semaphore proof
    /// @dev `context_` parameter is concatenated with sender address
    function validateProof(
        uint256 context_,
        ScoreGroupProof memory proof_
    ) public {
        ScoreGroup memory _scoreGroup = scoreGroups[proof_.score];
        require(_scoreGroup.status == ScoreGroupStatus.ACTIVE, "Score group is inactive");
        require(
            proof_.semaphoreProof.scope == uint256(keccak256(abi.encode(msg.sender, context_))),
            "Wrong scope"
        );

        SEMAPHORE.validateProof(_scoreGroup.semaphoreGroupId, proof_.semaphoreProof);
        emit ProofValidated(proof_.score);
    }

    function verifyProof(
        ScoreGroupProof calldata proof_
    ) public view returns (bool) {
        ScoreGroup memory _scoreGroup = scoreGroups[proof_.score];
        require(_scoreGroup.status == ScoreGroupStatus.ACTIVE, "Score group is inactive");
        return SEMAPHORE.verifyProof(_scoreGroup.semaphoreGroupId, proof_.semaphoreProof);
    }

    // ============ Apps Management ============

    function registerApp(
        uint256 appId_,
        address admin_,
        uint256 recoveryDelay_
    ) external onlyOwner {
        require(appId_ > 0, "App ID cannot be zero");
        require(admin_ != address(0), "Invalid admin address");
        require(apps[appId_].status == AppStatus.UNDEFINED, "App already exists");
        require(recoveryDelay_ >= MIN_RECOVERY_DELAY, "Recovery delay too short");
        require(recoveryDelay_ <= MAX_RECOVERY_DELAY, "Recovery delay too long");

        apps[appId_] = App({
            admin: admin_,
            recoveryDelay: recoveryDelay_,
            status: AppStatus.ACTIVE
        });

        emit AppRegistered(appId_, admin_, recoveryDelay_);
    }

    function updateAppRecoveryDelay(
        uint256 appId_,
        uint256 newRecoveryDelay_
    ) external appExists(appId_) {
        require(
            msg.sender == apps[appId_].admin || msg.sender == owner(),
            "Only app admin or owner"
        );
        require(newRecoveryDelay_ >= MIN_RECOVERY_DELAY, "Recovery delay too short");
        require(newRecoveryDelay_ <= MAX_RECOVERY_DELAY, "Recovery delay too long");

        apps[appId_].recoveryDelay = newRecoveryDelay_;

        emit AppUpdated(appId_, newRecoveryDelay_);
    }

    // ============ Identity Recovery ============

    function initiateRecovery(
        bytes32 blindedId_,
        uint256 appId_,
        uint256 newCommitment_,
        uint256 score_
    ) external onlyVerifier appExists(appId_) {
        require(blindedId_ != bytes32(0), "Invalid blinded ID");
        require(newCommitment_ != 0, "Invalid new commitment");

        Identity memory identity = identities[blindedId_];
        require(identity.commitment != 0, "Identity not registered");
        require(identity.commitment != newCommitment_, "New commitment same as old");
        require(identity.score == score_, "Score mismatch");
        require(pendingRecoveries[blindedId_].unlockTime == 0, "Recovery already pending");

        // Verify score group is active
        require(
            scoreGroups[score_].status == ScoreGroupStatus.ACTIVE,
            "Score group is not active"
        );

        uint256 unlockTime = block.timestamp + apps[appId_].recoveryDelay;

        pendingRecoveries[blindedId_] = PendingRecovery({
            newCommitment: newCommitment_,
            unlockTime: unlockTime,
            score: score_
        });

        emit RecoveryInitiated(blindedId_, unlockTime);
    }

    function cancelRecovery(bytes32 blindedId_) external onlyVerifier {
        require(pendingRecoveries[blindedId_].unlockTime != 0, "No pending recovery");

        delete pendingRecoveries[blindedId_];

        emit RecoveryCancelled(blindedId_);
    }

    function finalizeRecovery(
        bytes32 blindedId_,
        uint256[] calldata merkleProofSiblings_
    ) external {
        PendingRecovery memory pending = pendingRecoveries[blindedId_];

        require(pending.unlockTime != 0, "No pending recovery");
        require(block.timestamp >= pending.unlockTime, "Recovery timelock not expired");

        uint256 oldCommitment = identities[blindedId_].commitment;

        // Get semaphore group ID from score group using score
        uint256 semaphoreGroupId = scoreGroups[pending.score].semaphoreGroupId;

        // Update member in Semaphore (atomic swap)
        SEMAPHORE.updateMember(
            semaphoreGroupId,
            oldCommitment,
            pending.newCommitment,
            merkleProofSiblings_
        );

        // Update identity commitment (score stays the same)
        identities[blindedId_].commitment = pending.newCommitment;

        // Clear pending recovery
        delete pendingRecoveries[blindedId_];

        emit RecoveryFinalized(blindedId_, oldCommitment, pending.newCommitment);
    }

    // ============ View Functions ============

    function getIdentity(bytes32 blindedId_) external view returns (Identity memory) {
        return identities[blindedId_];
    }

    function getPendingRecovery(bytes32 blindedId_) external view returns (PendingRecovery memory) {
        return pendingRecoveries[blindedId_];
    }

    function getApp(uint256 appId_) external view returns (App memory) {
        return apps[appId_];
    }

    function isRecoveryReady(bytes32 blindedId_) external view returns (bool) {
        PendingRecovery memory pending = pendingRecoveries[blindedId_];
        return pending.unlockTime != 0 && block.timestamp >= pending.unlockTime;
    }

    // ============ Owner Functions ============

    /// @notice Create a score group for a specific score
    /// @param score_ The score value (e.g., 0, 10, 20, 30, etc.)
    function createScoreGroup(uint256 score_) public onlyOwner {
        require(scoreGroups[score_].status == ScoreGroupStatus.UNDEFINED, "Score group exists");

        scoreGroups[score_] = ScoreGroup({
            semaphoreGroupId: SEMAPHORE.createGroup(),
            status: ScoreGroupStatus.ACTIVE
        });

        emit ScoreGroupCreated(score_);
    }

    function suspendScoreGroup(uint256 score_) public onlyOwner {
        require(scoreGroups[score_].status == ScoreGroupStatus.ACTIVE, "Score group is not active");
        scoreGroups[score_].status = ScoreGroupStatus.SUSPENDED;
    }

    function setVerifier(address verifier_) public onlyOwner {
        require(verifier_ != address(0), "Invalid verifier address");
        verifier = verifier_;
        emit VerifierSet(verifier_);
    }

    function updateSemaphoreGroupAdmin(uint256 score_, address newAdmin_) public onlyOwner {
        require(newAdmin_ != address(0), "Invalid admin address");
        require(scoreGroups[score_].status != ScoreGroupStatus.UNDEFINED, "Score group does not exist");
        SEMAPHORE.updateGroupAdmin(scoreGroups[score_].semaphoreGroupId, newAdmin_);
    }

    /// @notice Accept admin role for a Semaphore group (two-step admin transfer)
    function acceptSemaphoreGroupAdmin(uint256 semaphoreGroupId_) external onlyOwner {
        SEMAPHORE.acceptGroupAdmin(semaphoreGroupId_);
    }
}
