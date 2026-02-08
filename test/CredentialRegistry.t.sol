// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {INullifierVerifier} from "../src/registry/INullifierVerifier.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";

contract CredentialRegistryTest is Test {
    using ECDSA for bytes32;

    CredentialRegistry registry;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;

    address owner;
    address trustedVerifier;
    uint256 trustedVerifierPrivateKey;
    address mockNullifierVerifier;

    uint256 constant DEFAULT_APP_ID = 1;

    event CredentialGroupCreated(
        uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroup credentialGroup
    );
    event CredentialRegistered(
        uint256 indexed credentialGroupId,
        uint256 indexed commitment,
        bytes32 credentialId,
        bytes32 registrationHash,
        address verifier
    );
    event ProofValidated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 nullifier);
    event TrustedVerifierAdded(address indexed verifier);
    event TrustedVerifierRemoved(address indexed verifier);
    event NullifierVerifierSet(address indexed verifier);
    event AppRegistered(uint256 indexed appId);
    event AppSuspended(uint256 indexed appId);
    event AppRecoveryTimelockSet(uint256 indexed appId, uint256 timelock);
    event RecoveryInitiated(
        bytes32 indexed registrationHash,
        uint256 indexed credentialGroupId,
        uint256 oldCommitment,
        uint256 newCommitment,
        uint256 executeAfter
    );
    event RecoveryExecuted(bytes32 indexed registrationHash, uint256 newCommitment);

    function setUp() public {
        owner = address(this);
        (trustedVerifier, trustedVerifierPrivateKey) = makeAddrAndKey("trusted-verifier");
        mockNullifierVerifier = makeAddr("nullifier-verifier");

        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier, mockNullifierVerifier);

        // Register default app
        registry.registerApp(DEFAULT_APP_ID);

        // Mock INullifierVerifier.verifyProof to succeed (no revert) by default
        vm.mockCall(
            mockNullifierVerifier, abi.encodeWithSelector(INullifierVerifier.verifyProof.selector), abi.encode()
        );
    }

    // --- Helper functions ---

    function _createAttestation(uint256 credentialGroupId, bytes32 credentialId, uint256 commitment)
        internal
        view
        returns (ICredentialRegistry.Attestation memory)
    {
        return ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            semaphoreIdentityCommitment: commitment
        });
    }

    function _signAttestation(ICredentialRegistry.Attestation memory att)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(trustedVerifierPrivateKey, keccak256(abi.encode(att)).toEthSignedMessageHash());
    }

    function _registerCredential(uint256 credentialGroupId, bytes32 credentialId, uint256 commitment) internal {
        ICredentialRegistry.Attestation memory att = _createAttestation(credentialGroupId, credentialId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        registry.registerCredential(att, v, r, s);
    }

    function _makeProof(
        uint256 credentialGroupId,
        uint256 appId,
        uint256 commitmentKey,
        uint256 scope,
        uint256 commitment
    ) internal returns (ICredentialRegistry.CredentialGroupProof memory) {
        uint256[] memory comms = new uint256[](1);
        comms[0] = commitment;
        (uint256 depth, uint256 root, uint256 nullifier, uint256 msg_, uint256[8] memory pts) =
            TestUtils.semaphoreProof(commitmentKey, scope, comms);
        return ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            appId: appId,
            nullifierProof: hex"dead",
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: depth,
                merkleTreeRoot: root,
                nullifier: nullifier,
                message: msg_,
                scope: scope,
                points: pts
            })
        });
    }

    // --- Constructor tests ---

    function testConstructor() public {
        assertEq(address(registry.SEMAPHORE()), address(semaphore));
        assertTrue(registry.trustedVerifiers(trustedVerifier));
        assertEq(registry.nullifierVerifier(), mockNullifierVerifier);
        assertEq(registry.owner(), owner);
    }

    function testConstructorRejectsZeroTrustedVerifier() public {
        vm.expectRevert("Invalid trusted verifier address");
        new CredentialRegistry(ISemaphore(address(semaphore)), address(0), mockNullifierVerifier);
    }

    function testConstructorRejectsZeroNullifierVerifier() public {
        vm.expectRevert("Invalid nullifier verifier address");
        new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier, address(0));
    }

    // --- Credential group tests ---

    function testCreateCredentialGroup() public {
        uint256 credentialGroupId = 1;
        uint256 score = 100;

        vm.expectEmit(true, false, false, true);
        emit CredentialGroupCreated(
            credentialGroupId,
            ICredentialRegistry.CredentialGroup(score, 0, ICredentialRegistry.CredentialGroupStatus.ACTIVE)
        );

        registry.createCredentialGroup(credentialGroupId, score);

        (uint256 storedScore, uint256 groupId, ICredentialRegistry.CredentialGroupStatus status) =
            registry.credentialGroups(credentialGroupId);
        assertEq(storedScore, score);
        assertTrue(groupId >= 0);
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testCreateCredentialGroupOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.createCredentialGroup(1, 100);
    }

    function testCreateCredentialGroupDuplicate() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        vm.expectRevert("Credential group exists");
        registry.createCredentialGroup(credentialGroupId, 200);
    }

    function testCreateCredentialGroupWithZeroScore() public {
        uint256 credentialGroupId = 1;
        uint256 score = 0;

        vm.expectEmit(true, false, false, true);
        emit CredentialGroupCreated(
            credentialGroupId,
            ICredentialRegistry.CredentialGroup(score, 0, ICredentialRegistry.CredentialGroupStatus.ACTIVE)
        );

        registry.createCredentialGroup(credentialGroupId, score);

        (uint256 storedScore, uint256 groupId, ICredentialRegistry.CredentialGroupStatus status) =
            registry.credentialGroups(credentialGroupId);
        assertEq(storedScore, 0);
        assertTrue(groupId >= 0);
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testFuzzNewVerification(uint256 credentialGroupId, uint256 score) public {
        vm.assume(credentialGroupId != 0 && credentialGroupId < type(uint256).max);
        vm.assume(score < type(uint256).max);

        registry.createCredentialGroup(credentialGroupId, score);

        (uint256 storedScore, uint256 groupId, ICredentialRegistry.CredentialGroupStatus status) =
            registry.credentialGroups(credentialGroupId);
        assertEq(storedScore, score);
        assertTrue(groupId >= 0);
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testCreateCredentialGroupShouldRejectZeroId() public {
        vm.expectRevert();
        registry.createCredentialGroup(0, 100);
    }

    // --- Trusted verifier tests ---

    function testAddTrustedVerifier() public {
        address newVerifier = makeAddr("new-verifier");

        vm.expectEmit(true, false, false, false);
        emit TrustedVerifierAdded(newVerifier);

        registry.addTrustedVerifier(newVerifier);
        assertTrue(registry.trustedVerifiers(newVerifier));
    }

    function testAddTrustedVerifierRejectsZeroAddress() public {
        vm.expectRevert("Invalid verifier address");
        registry.addTrustedVerifier(address(0));
    }

    function testAddTrustedVerifierOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.addTrustedVerifier(makeAddr("new-verifier"));
    }

    function testRemoveTrustedVerifier() public {
        address newVerifier = makeAddr("new-verifier");
        registry.addTrustedVerifier(newVerifier);
        assertTrue(registry.trustedVerifiers(newVerifier));

        vm.expectEmit(true, false, false, false);
        emit TrustedVerifierRemoved(newVerifier);

        registry.removeTrustedVerifier(newVerifier);
        assertFalse(registry.trustedVerifiers(newVerifier));
    }

    function testRemoveTrustedVerifierOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.removeTrustedVerifier(trustedVerifier);
    }

    function testRemoveTrustedVerifierNotTrusted() public {
        address untrusted = makeAddr("untrusted");
        vm.expectRevert("Verifier is not trusted");
        registry.removeTrustedVerifier(untrusted);
    }

    function testSetNullifierVerifier() public {
        address newVerifier = makeAddr("new-nullifier-verifier");

        vm.expectEmit(true, false, false, false);
        emit NullifierVerifierSet(newVerifier);

        registry.setNullifierVerifier(newVerifier);
        assertEq(registry.nullifierVerifier(), newVerifier);
    }

    function testSetNullifierVerifierOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setNullifierVerifier(makeAddr("new-nullifier-verifier"));
    }

    function testSetNullifierVerifierRejectsZeroAddress() public {
        vm.expectRevert("Invalid nullifier verifier address");
        registry.setNullifierVerifier(address(0));
    }

    // --- App management tests ---

    function testRegisterApp() public {
        uint256 appId = 42;

        vm.expectEmit(true, false, false, false);
        emit AppRegistered(appId);

        registry.registerApp(appId);
        assertTrue(registry.appIsActive(appId));
    }

    function testRegisterAppOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.registerApp(42);
    }

    function testRegisterAppDuplicate() public {
        uint256 appId = 42;
        registry.registerApp(appId);

        vm.expectRevert("App already exists");
        registry.registerApp(appId);
    }

    function testRegisterAppZeroId() public {
        vm.expectRevert("App ID cannot equal zero");
        registry.registerApp(0);
    }

    function testSuspendApp() public {
        uint256 appId = 42;
        registry.registerApp(appId);
        assertTrue(registry.appIsActive(appId));

        vm.expectEmit(true, false, false, false);
        emit AppSuspended(appId);

        registry.suspendApp(appId);
        assertFalse(registry.appIsActive(appId));
    }

    function testSuspendAppOnlyOwner() public {
        uint256 appId = 42;
        registry.registerApp(appId);

        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.suspendApp(appId);
    }

    function testSuspendAppNotActive() public {
        vm.expectRevert("App is not active");
        registry.suspendApp(999);
    }

    // --- JoinGroup tests ---

    function testRegisterCredential() public {
        uint256 credentialGroupId = 1;
        uint256 score = 100;
        registry.createCredentialGroup(credentialGroupId, score);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message = _createAttestation(credentialGroupId, credentialId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectEmit(true, true, false, false);
        emit CredentialRegistered(credentialGroupId, commitment, bytes32(0), bytes32(0), address(0));

        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialWithBytes() public {
        uint256 credentialGroupId = 1;
        uint256 score = 100;
        registry.createCredentialGroup(credentialGroupId, score);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message = _createAttestation(credentialGroupId, credentialId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, false, false);
        emit CredentialRegistered(credentialGroupId, commitment, bytes32(0), bytes32(0), address(0));

        registry.registerCredential(message, signature);
    }

    function testRegisterCredentialInactiveVerification() public {
        uint256 credentialGroupId = 1;
        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message = _createAttestation(credentialGroupId, credentialId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert("Credential group is inactive");
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialWrongRegistry() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(0x123),
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert("Wrong attestation message");
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialUsedNonce() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message = _createAttestation(credentialGroupId, credentialId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        registry.registerCredential(message, v, r, s);

        vm.expectRevert("Credential already registered");
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialUsedNonceWithDifferentCommitment() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        // First join succeeds
        ICredentialRegistry.Attestation memory message1 =
            _createAttestation(credentialGroupId, credentialId, commitment1);
        (uint8 v1, bytes32 r1, bytes32 s1) = _signAttestation(message1);
        registry.registerCredential(message1, v1, r1, s1);

        // Second join with same credentialId but different commitment should fail
        ICredentialRegistry.Attestation memory message2 =
            _createAttestation(credentialGroupId, credentialId, commitment2);
        (uint8 v2, bytes32 r2, bytes32 s2) = _signAttestation(message2);

        vm.expectRevert("Credential already registered");
        registry.registerCredential(message2, v2, r2, s2);
    }

    function testRegisterCredentialSameUserDifferentApps() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 credentialId1 = keccak256("blinded-id-app1");
        bytes32 credentialId2 = keccak256("blinded-id-app2");
        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        // Join with app 1 credentialId
        _registerCredential(credentialGroupId, credentialId1, commitment1);

        // Join with app 2 — different credentialId so different nonce, should succeed
        _registerCredential(credentialGroupId, credentialId2, commitment2);
    }

    function testRegisterCredentialInvalidSignature() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message = _createAttestation(credentialGroupId, credentialId, commitment);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(123456, keccak256(abi.encode(message)).toEthSignedMessageHash());

        vm.expectRevert("Untrusted verifier");
        registry.registerCredential(message, v, r, s);
    }

    // --- ValidateProof tests ---

    function testValidateProof() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(credentialGroupId, keccak256("blinded-id"), commitment);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        ICredentialRegistry.CredentialGroupProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, scope, commitment);

        vm.expectEmit(true, true, false, true);
        emit ProofValidated(credentialGroupId, DEFAULT_APP_ID, proof.semaphoreProof.nullifier);

        vm.prank(prover);
        registry.validateProof(0, proof);
    }

    function testValidateProofInactiveVerification() public {
        uint256 credentialGroupId = 1;

        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            appId: DEFAULT_APP_ID,
            nullifierProof: hex"dead",
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: 0,
                scope: 0,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        vm.expectRevert("Credential group is inactive");
        registry.validateProof(0, proof);
    }

    function testValidateProofAppNotActive() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        uint256 inactiveAppId = 999;

        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            appId: inactiveAppId,
            nullifierProof: hex"dead",
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: 0,
                scope: 0,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        vm.expectRevert("App is not active");
        registry.validateProof(0, proof);
    }

    function testValidateProofWrongScope() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(credentialGroupId, keccak256("blinded-id"), commitment);

        address prover = makeAddr("prover");
        uint256 wrongScope = uint256(keccak256(abi.encode(makeAddr("wrong"), uint256(0))));

        ICredentialRegistry.CredentialGroupProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, wrongScope, commitment);

        vm.expectRevert("Wrong scope");
        vm.prank(prover);
        registry.validateProof(0, proof);
    }

    function testValidateProofNullifierProofFails() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(credentialGroupId, keccak256("blinded-id"), commitment);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        // Mock the nullifier verifier to revert
        vm.mockCallRevert(
            mockNullifierVerifier,
            abi.encodeWithSelector(INullifierVerifier.verifyProof.selector),
            abi.encodeWithSignature("ProofVerificationFailed()")
        );

        ICredentialRegistry.CredentialGroupProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, scope, commitment);

        vm.expectRevert();
        vm.prank(prover);
        registry.validateProof(0, proof);
    }

    // --- Score tests ---

    function testScore() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        uint256 score1 = 100;
        uint256 score2 = 200;

        registry.createCredentialGroup(credentialGroupId1, score1);
        registry.createCredentialGroup(credentialGroupId2, score2);

        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);

        _registerCredential(credentialGroupId1, keccak256("blinded-id-1"), commitment1);
        _registerCredential(credentialGroupId2, keccak256("blinded-id-2"), commitment2);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, DEFAULT_APP_ID, commitmentKey2, scope, commitment2);

        uint256 totalScore = registry.score(0, proofs);
        assertEq(totalScore, score1 + score2);
    }

    function testScoreFailOnInactive() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;

        registry.createCredentialGroup(credentialGroupId1, 100);
        // Don't create credentialGroupId2, it will be inactive

        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        _registerCredential(credentialGroupId1, keccak256("blinded-id-1"), commitment1);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId2,
            appId: DEFAULT_APP_ID,
            nullifierProof: hex"dead",
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: 0,
                scope: scope,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        vm.expectRevert("Credential group is inactive");
        registry.score(0, proofs);
    }

    // --- Recovery timelock tests ---

    function testSetAppRecoveryTimelock() public {
        uint256 appId = 42;
        registry.registerApp(appId);

        vm.expectEmit(true, false, false, true);
        emit AppRecoveryTimelockSet(appId, 1 days);

        registry.setAppRecoveryTimelock(appId, 1 days);

        (, uint256 timelock) = registry.apps(appId);
        assertEq(timelock, 1 days);
    }

    function testSetAppRecoveryTimelockOnlyOwner() public {
        uint256 appId = 42;
        registry.registerApp(appId);

        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setAppRecoveryTimelock(appId, 1 days);
    }

    function testSetAppRecoveryTimelockAppNotActive() public {
        vm.expectRevert("App is not active");
        registry.setAppRecoveryTimelock(999, 1 days);
    }

    function testSetAppRecoveryTimelockZero() public {
        uint256 appId = 42;
        registry.registerApp(appId);

        vm.expectRevert("Recovery timelock must be positive");
        registry.setAppRecoveryTimelock(appId, 0);
    }

    // --- Initiate recovery tests ---

    function _initiateRecovery(
        uint256 credentialGroupId,
        uint256 appId,
        bytes32 credentialId,
        uint256 newCommitment,
        uint256[] memory siblings
    ) internal {
        ICredentialRegistry.Attestation memory att = _createAttestation(credentialGroupId, credentialId, newCommitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        registry.initiateRecovery(att, v, r, s, appId, siblings);
    }

    function testInitiateRecovery() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, oldCommitment);

        bytes32 registrationHash = keccak256(abi.encode(address(registry), credentialGroupId, credentialId));

        uint256[] memory siblings = new uint256[](0);

        vm.expectEmit(true, true, false, true);
        emit RecoveryInitiated(
            registrationHash, credentialGroupId, oldCommitment, newCommitment, block.timestamp + 1 days
        );

        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        (uint256 reqGroupId, uint256 reqAppId, uint256 reqNewCommitment, uint256 reqExecuteAfter) =
            registry.pendingRecoveries(registrationHash);
        assertEq(reqGroupId, credentialGroupId);
        assertEq(reqAppId, DEFAULT_APP_ID);
        assertEq(reqNewCommitment, newCommitment);
        assertEq(reqExecuteAfter, block.timestamp + 1 days);
    }

    function testInitiateRecoveryWithBytes() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, oldCommitment);

        ICredentialRegistry.Attestation memory att = _createAttestation(credentialGroupId, credentialId, newCommitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256[] memory siblings = new uint256[](0);
        registry.initiateRecovery(att, signature, DEFAULT_APP_ID, siblings);

        bytes32 registrationHash = keccak256(abi.encode(address(registry), credentialGroupId, credentialId));
        (,, uint256 reqNewCommitment,) = registry.pendingRecoveries(registrationHash);
        assertEq(reqNewCommitment, newCommitment);
    }

    function testInitiateRecoveryNotRegistered() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert("Credential not registered");
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);
    }

    function testInitiateRecoveryAlreadyPending() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment1 = TestUtils.semaphoreCommitment(67890);
        uint256 newCommitment2 = TestUtils.semaphoreCommitment(11111);

        _registerCredential(credentialGroupId, credentialId, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment1, siblings);

        vm.expectRevert("Recovery already pending");
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment2, siblings);
    }

    function testInitiateRecoveryNotEnabled() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, oldCommitment);

        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert("Recovery not enabled for app");
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);
    }

    // --- Execute recovery tests ---

    function testExecuteRecovery() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        bytes32 registrationHash = keccak256(abi.encode(address(registry), credentialGroupId, credentialId));

        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(true, false, false, true);
        emit RecoveryExecuted(registrationHash, newCommitment);

        registry.executeRecovery(registrationHash);

        assertEq(registry.registeredCommitments(registrationHash), newCommitment);

        (,,, uint256 reqExecuteAfter) = registry.pendingRecoveries(registrationHash);
        assertEq(reqExecuteAfter, 0);
    }

    function testExecuteRecoveryTimelockNotExpired() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        bytes32 registrationHash = keccak256(abi.encode(address(registry), credentialGroupId, credentialId));

        vm.warp(block.timestamp + 1 days - 1);

        vm.expectRevert("Recovery timelock not expired");
        registry.executeRecovery(registrationHash);
    }

    function testExecuteRecoveryNoPending() public {
        bytes32 fakeHash = keccak256("no-such-recovery");

        vm.expectRevert("No pending recovery");
        registry.executeRecovery(fakeHash);
    }
}
