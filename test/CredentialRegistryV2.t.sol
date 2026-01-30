// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {CredentialRegistryV2} from "../src/CredentialRegistryV2.sol";
import {ICredentialRegistryV2} from "../src/ICredentialRegistryV2.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";

contract CredentialRegistryV2Test is Test {
    using ECDSA for bytes32;

    CredentialRegistryV2 registry;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;

    address owner;
    address tlsnVerifier;
    uint256 tlsnVerifierPrivateKey;
    address appAdmin;

    uint256 constant APP_ID = 1;
    uint256 constant SCORE = 100; // Score IS the groupId
    uint256 constant RECOVERY_DELAY = 7 days;

    event ScoreGroupCreated(uint256 indexed score);
    event IdentityAdded(uint256 indexed score, uint256 indexed commitment);
    event ProofValidated(uint256 indexed score);
    event AppRegistered(uint256 indexed appId, address indexed admin, uint256 recoveryDelay);
    event AppUpdated(uint256 indexed appId, uint256 recoveryDelay);
    event IdentityLinked(bytes32 indexed blindedId, uint256 indexed commitment, uint256 score);
    event RecoveryInitiated(bytes32 indexed blindedId, uint256 unlockTime);
    event RecoveryCancelled(bytes32 indexed blindedId);
    event RecoveryFinalized(bytes32 indexed blindedId, uint256 oldCommitment, uint256 newCommitment);
    event VerifierSet(address indexed verifier);

    function setUp() public {
        owner = address(this);
        (tlsnVerifier, tlsnVerifierPrivateKey) = makeAddrAndKey("tlsn-verifier");
        appAdmin = makeAddr("app-admin");

        // Deploy Semaphore
        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));

        // Deploy CredentialRegistryV2
        registry = new CredentialRegistryV2(ISemaphore(address(semaphore)), tlsnVerifier);

        // Create a score group for SCORE
        registry.createScoreGroup(SCORE);
    }

    // ============ Constructor Tests ============

    function testConstructor() public view {
        assertEq(address(registry.SEMAPHORE()), address(semaphore));
        assertEq(registry.verifier(), tlsnVerifier);
        assertEq(registry.owner(), owner);
    }

    function testConstructorRejectsZeroSemaphore() public {
        vm.expectRevert("Invalid Semaphore address");
        new CredentialRegistryV2(ISemaphore(address(0)), tlsnVerifier);
    }

    function testConstructorRejectsZeroVerifier() public {
        vm.expectRevert("Invalid verifier address");
        new CredentialRegistryV2(ISemaphore(address(semaphore)), address(0));
    }

    // ============ Score Group Tests ============

    function testCreateScoreGroup() public {
        uint256 newScore = 200;

        vm.expectEmit(true, false, false, false);
        emit ScoreGroupCreated(newScore);

        registry.createScoreGroup(newScore);

        assertTrue(registry.scoreGroupIsActive(newScore));
    }

    function testCreateScoreGroupOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.createScoreGroup(200);
    }

    function testCreateScoreGroupRejectsDuplicate() public {
        vm.expectRevert("Score group exists");
        registry.createScoreGroup(SCORE);
    }

    function testSuspendScoreGroup() public {
        registry.suspendScoreGroup(SCORE);

        assertFalse(registry.scoreGroupIsActive(SCORE));
    }

    function testScoreGroupIsActive() public view {
        assertTrue(registry.scoreGroupIsActive(SCORE));
    }

    // ============ Join Group Tests ============

    function testJoinGroup() public {
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistryV2.Attestation memory message = ICredentialRegistryV2.Attestation({
            registry: address(registry),
            score: SCORE,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );

        // Check events
        vm.expectEmit(true, false, false, false);
        emit IdentityLinked(blindedId, 0, 0);

        vm.expectEmit(true, false, false, false);
        emit IdentityAdded(SCORE, 0);

        registry.joinGroup(message, v, r, s);

        // Verify identity was linked with score
        ICredentialRegistryV2.Identity memory identity = registry.getIdentity(blindedId);
        assertEq(identity.commitment, commitment);
        assertEq(identity.score, SCORE);
    }

    function testJoinGroupRejectsZeroBlindedId() public {
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistryV2.Attestation memory message = ICredentialRegistryV2.Attestation({
            registry: address(registry),
            score: SCORE,
            blindedId: bytes32(0),
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );

        vm.expectRevert("Invalid blinded ID");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupRejectsDuplicateIdentity() public {
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        // First join
        ICredentialRegistryV2.Attestation memory message1 = ICredentialRegistryV2.Attestation({
            registry: address(registry),
            score: SCORE,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment1
        });

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message1)).toEthSignedMessageHash()
        );

        registry.joinGroup(message1, v1, r1, s1);

        // Second join with same blindedId should fail
        ICredentialRegistryV2.Attestation memory message2 = ICredentialRegistryV2.Attestation({
            registry: address(registry),
            score: SCORE,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment2
        });

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message2)).toEthSignedMessageHash()
        );

        vm.expectRevert("Identity already registered");
        registry.joinGroup(message2, v2, r2, s2);
    }

    function testJoinGroupInactiveGroup() public {
        registry.suspendScoreGroup(SCORE);

        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistryV2.Attestation memory message = ICredentialRegistryV2.Attestation({
            registry: address(registry),
            score: SCORE,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );

        vm.expectRevert("Score group is inactive");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupWrongRegistry() public {
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistryV2.Attestation memory message = ICredentialRegistryV2.Attestation({
            registry: address(0x123),
            score: SCORE,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );

        vm.expectRevert("Wrong attestation message");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupInvalidSignature() public {
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistryV2.Attestation memory message = ICredentialRegistryV2.Attestation({
            registry: address(registry),
            score: SCORE,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            123456, // Wrong private key
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );

        vm.expectRevert("Invalid verifier signature");
        registry.joinGroup(message, v, r, s);
    }

    // ============ App Registration Tests ============

    function testRegisterApp() public {
        vm.expectEmit(true, true, false, true);
        emit AppRegistered(APP_ID, appAdmin, RECOVERY_DELAY);

        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        ICredentialRegistryV2.App memory app = registry.getApp(APP_ID);
        assertEq(app.admin, appAdmin);
        assertEq(app.recoveryDelay, RECOVERY_DELAY);
        assertEq(uint256(app.status), uint256(ICredentialRegistryV2.AppStatus.ACTIVE));
    }

    function testRegisterAppOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);
    }

    function testRegisterAppRejectsZeroId() public {
        vm.expectRevert("App ID cannot be zero");
        registry.registerApp(0, appAdmin, RECOVERY_DELAY);
    }

    function testRegisterAppRejectsZeroAdmin() public {
        vm.expectRevert("Invalid admin address");
        registry.registerApp(APP_ID, address(0), RECOVERY_DELAY);
    }

    function testRegisterAppRejectsDuplicate() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        vm.expectRevert("App already exists");
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);
    }

    function testRegisterAppRejectsDelayTooShort() public {
        vm.expectRevert("Recovery delay too short");
        registry.registerApp(APP_ID, appAdmin, 1 hours);
    }

    function testRegisterAppRejectsDelayTooLong() public {
        vm.expectRevert("Recovery delay too long");
        registry.registerApp(APP_ID, appAdmin, 60 days);
    }

    // ============ Update App Tests ============

    function testUpdateAppRecoveryDelay() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        uint256 newDelay = 14 days;

        vm.expectEmit(true, false, false, true);
        emit AppUpdated(APP_ID, newDelay);

        vm.prank(appAdmin);
        registry.updateAppRecoveryDelay(APP_ID, newDelay);

        ICredentialRegistryV2.App memory app = registry.getApp(APP_ID);
        assertEq(app.recoveryDelay, newDelay);
    }

    function testUpdateAppRecoveryDelayByOwner() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        uint256 newDelay = 14 days;
        registry.updateAppRecoveryDelay(APP_ID, newDelay);

        ICredentialRegistryV2.App memory app = registry.getApp(APP_ID);
        assertEq(app.recoveryDelay, newDelay);
    }

    function testUpdateAppRecoveryDelayUnauthorized() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        address unauthorized = makeAddr("unauthorized");
        vm.prank(unauthorized);
        vm.expectRevert("Only app admin or owner");
        registry.updateAppRecoveryDelay(APP_ID, 14 days);
    }

    function testUpdateAppRecoveryDelayNonExistent() public {
        vm.expectRevert("App does not exist");
        registry.updateAppRecoveryDelay(APP_ID, 14 days);
    }

    // ============ Recovery Flow Tests ============

    /// @dev Helper to join a group and link identity
    function _joinGroupWithIdentity(bytes32 blindedId, uint256 commitment) internal {
        ICredentialRegistryV2.Attestation memory message = ICredentialRegistryV2.Attestation({
            registry: address(registry),
            score: SCORE,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            tlsnVerifierPrivateKey,
            keccak256(abi.encode(message)).toEthSignedMessageHash()
        );

        registry.joinGroup(message, v, r, s);
    }

    function testInitiateRecovery() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _joinGroupWithIdentity(blindedId, oldCommitment);

        uint256 expectedUnlockTime = block.timestamp + RECOVERY_DELAY;

        vm.expectEmit(true, false, false, true);
        emit RecoveryInitiated(blindedId, expectedUnlockTime);

        vm.prank(tlsnVerifier);
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, SCORE);

        ICredentialRegistryV2.PendingRecovery memory pending = registry.getPendingRecovery(blindedId);
        assertEq(pending.newCommitment, newCommitment);
        assertEq(pending.unlockTime, expectedUnlockTime);
        assertEq(pending.score, SCORE);
    }

    function testInitiateRecoveryOnlyVerifier() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _joinGroupWithIdentity(blindedId, oldCommitment);

        address notVerifier = makeAddr("not-verifier");
        vm.prank(notVerifier);
        vm.expectRevert("Only verifier");
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, SCORE);
    }

    function testInitiateRecoveryRejectsUnregisteredIdentity() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        vm.prank(tlsnVerifier);
        vm.expectRevert("Identity not registered");
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, SCORE);
    }

    function testInitiateRecoveryRejectsSameCommitment() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        _joinGroupWithIdentity(blindedId, commitment);

        vm.prank(tlsnVerifier);
        vm.expectRevert("New commitment same as old");
        registry.initiateRecovery(blindedId, APP_ID, commitment, SCORE);
    }

    function testInitiateRecoveryRejectsScoreMismatch() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);
        registry.createScoreGroup(200); // Create another score group

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _joinGroupWithIdentity(blindedId, oldCommitment); // Joins SCORE=100

        vm.prank(tlsnVerifier);
        vm.expectRevert("Score mismatch");
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, 200); // Try wrong score
    }

    function testInitiateRecoveryRejectsPendingRecovery() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);
        uint256 anotherCommitment = TestUtils.semaphoreCommitment(11111);

        _joinGroupWithIdentity(blindedId, oldCommitment);

        vm.prank(tlsnVerifier);
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, SCORE);

        vm.prank(tlsnVerifier);
        vm.expectRevert("Recovery already pending");
        registry.initiateRecovery(blindedId, APP_ID, anotherCommitment, SCORE);
    }

    function testCancelRecovery() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _joinGroupWithIdentity(blindedId, oldCommitment);

        vm.prank(tlsnVerifier);
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, SCORE);

        vm.expectEmit(true, false, false, false);
        emit RecoveryCancelled(blindedId);

        vm.prank(tlsnVerifier);
        registry.cancelRecovery(blindedId);

        ICredentialRegistryV2.PendingRecovery memory pending = registry.getPendingRecovery(blindedId);
        assertEq(pending.unlockTime, 0);
    }

    function testCancelRecoveryRejectsNoPending() public {
        vm.prank(tlsnVerifier);
        vm.expectRevert("No pending recovery");
        registry.cancelRecovery(keccak256("blinded-id-1"));
    }

    function testFinalizeRecovery() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _joinGroupWithIdentity(blindedId, oldCommitment);

        vm.prank(tlsnVerifier);
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, SCORE);

        // Warp time past the timelock
        vm.warp(block.timestamp + RECOVERY_DELAY + 1);

        // Get merkle proof siblings (for a single-member tree, this is empty)
        uint256[] memory siblings = new uint256[](0);

        vm.expectEmit(true, false, false, true);
        emit RecoveryFinalized(blindedId, oldCommitment, newCommitment);

        registry.finalizeRecovery(blindedId, siblings);

        // Verify identity was updated (score stays the same)
        ICredentialRegistryV2.Identity memory identity = registry.getIdentity(blindedId);
        assertEq(identity.commitment, newCommitment);
        assertEq(identity.score, SCORE);

        // Verify pending recovery was cleared
        ICredentialRegistryV2.PendingRecovery memory pending = registry.getPendingRecovery(blindedId);
        assertEq(pending.unlockTime, 0);
    }

    function testFinalizeRecoveryRejectsNoPending() public {
        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert("No pending recovery");
        registry.finalizeRecovery(keccak256("blinded-id-1"), siblings);
    }

    function testFinalizeRecoveryRejectsBeforeTimelock() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _joinGroupWithIdentity(blindedId, oldCommitment);

        vm.prank(tlsnVerifier);
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, SCORE);

        // Don't warp time - still within timelock
        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert("Recovery timelock not expired");
        registry.finalizeRecovery(blindedId, siblings);
    }

    // ============ View Function Tests ============

    function testIsRecoveryReady() public {
        registry.registerApp(APP_ID, appAdmin, RECOVERY_DELAY);

        bytes32 blindedId = keccak256("blinded-id-1");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _joinGroupWithIdentity(blindedId, oldCommitment);

        // No pending recovery
        assertFalse(registry.isRecoveryReady(blindedId));

        vm.prank(tlsnVerifier);
        registry.initiateRecovery(blindedId, APP_ID, newCommitment, SCORE);

        // Pending but not ready
        assertFalse(registry.isRecoveryReady(blindedId));

        // Warp time
        vm.warp(block.timestamp + RECOVERY_DELAY + 1);

        // Now ready
        assertTrue(registry.isRecoveryReady(blindedId));
    }

    // ============ Admin Function Tests ============

    function testSetVerifier() public {
        address newVerifier = makeAddr("new-verifier");

        vm.expectEmit(true, false, false, false);
        emit VerifierSet(newVerifier);

        registry.setVerifier(newVerifier);
        assertEq(registry.verifier(), newVerifier);
    }

    function testSetVerifierOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setVerifier(makeAddr("new-verifier"));
    }

    function testSetVerifierRejectsZeroAddress() public {
        vm.expectRevert("Invalid verifier address");
        registry.setVerifier(address(0));
    }
}
