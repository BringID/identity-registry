// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {IVerifier} from "../src/registry/IVerifier.sol";
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
    address tlsnVerifier;
    uint256 tlsnVerifierPrivateKey;
    address mockNullifierVerifier;

    uint256 constant DEFAULT_APP_ID = 1;

    event CredentialGroupCreated(
        uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroup credentialGroup
    );
    event CredentialAdded(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 indexed commitment);
    event ProofValidated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 nullifier);
    event TLSNVerifierSet(address indexed verifier);
    event NullifierVerifierSet(address indexed verifier);
    event AppRegistered(uint256 indexed appId);
    event AppSuspended(uint256 indexed appId);

    function setUp() public {
        owner = address(this);
        (tlsnVerifier, tlsnVerifierPrivateKey) = makeAddrAndKey("tlsn-verifier");
        mockNullifierVerifier = makeAddr("nullifier-verifier");

        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), tlsnVerifier, mockNullifierVerifier);

        // Register default app
        registry.registerApp(DEFAULT_APP_ID);

        // Mock IVerifier.verify to return true by default
        vm.mockCall(mockNullifierVerifier, abi.encodeWithSelector(IVerifier.verify.selector), abi.encode(true));
    }

    // --- Helper functions ---

    function _createAttestation(
        uint256 credentialGroupId,
        uint256 appId,
        bytes32 idHash,
        bytes32 blindedId,
        uint256 commitment
    ) internal view returns (ICredentialRegistry.Attestation memory) {
        return ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            appId: appId,
            idHash: idHash,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment
        });
    }

    function _signAttestation(ICredentialRegistry.Attestation memory att)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(tlsnVerifierPrivateKey, keccak256(abi.encode(att)).toEthSignedMessageHash());
    }

    function _joinGroup(uint256 credentialGroupId, uint256 appId, bytes32 idHash, bytes32 blindedId, uint256 commitment)
        internal
    {
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, appId, idHash, blindedId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        registry.joinGroup(att, v, r, s);
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
            bringIdProof: hex"dead",
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
        assertEq(registry.TLSNVerifier(), tlsnVerifier);
        assertEq(registry.nullifierVerifier(), mockNullifierVerifier);
        assertEq(registry.owner(), owner);
    }

    function testConstructorRejectsZeroNullifierVerifier() public {
        vm.expectRevert("Invalid nullifier verifier address");
        new CredentialRegistry(ISemaphore(address(semaphore)), tlsnVerifier, address(0));
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

    // --- Verifier setter tests ---

    function testSetVerifierShouldRejectZeroAddress() public {
        vm.expectRevert();
        registry.setVerifier(address(0));
    }

    function testSetVerifier() public {
        address newVerifier = makeAddr("new-verifier");

        vm.expectEmit(true, false, false, false);
        emit TLSNVerifierSet(newVerifier);

        registry.setVerifier(newVerifier);
        assertEq(registry.TLSNVerifier(), newVerifier);
    }

    function testSetVerifierOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setVerifier(makeAddr("new-verifier"));
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

    function testJoinGroup() public {
        uint256 credentialGroupId = 1;
        uint256 score = 100;
        registry.createCredentialGroup(credentialGroupId, score);

        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, DEFAULT_APP_ID, idHash, blindedId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectEmit(true, true, true, false);
        emit CredentialAdded(credentialGroupId, DEFAULT_APP_ID, commitment);

        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupWithBytes() public {
        uint256 credentialGroupId = 1;
        uint256 score = 100;
        registry.createCredentialGroup(credentialGroupId, score);

        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, DEFAULT_APP_ID, idHash, blindedId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, false);
        emit CredentialAdded(credentialGroupId, DEFAULT_APP_ID, commitment);

        registry.joinGroup(message, signature);
    }

    function testJoinGroupInactiveVerification() public {
        uint256 credentialGroupId = 1;
        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, DEFAULT_APP_ID, idHash, blindedId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert("Credential group is inactive");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupAppNotActive() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        uint256 inactiveAppId = 999;
        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, inactiveAppId, idHash, blindedId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert("App is not active");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupWrongRegistry() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(0x123),
            credentialGroupId: credentialGroupId,
            appId: DEFAULT_APP_ID,
            idHash: idHash,
            blindedId: blindedId,
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert("Wrong attestation message");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupUsedNonce() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, DEFAULT_APP_ID, idHash, blindedId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        registry.joinGroup(message, v, r, s);

        vm.expectRevert("Nonce is used");
        registry.joinGroup(message, v, r, s);
    }

    function testJoinGroupUsedNonceWithDifferentCommitment() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        // First join succeeds
        ICredentialRegistry.Attestation memory message1 =
            _createAttestation(credentialGroupId, DEFAULT_APP_ID, idHash, blindedId, commitment1);
        (uint8 v1, bytes32 r1, bytes32 s1) = _signAttestation(message1);
        registry.joinGroup(message1, v1, r1, s1);

        // Second join with same blindedId but different commitment should fail
        ICredentialRegistry.Attestation memory message2 =
            _createAttestation(credentialGroupId, DEFAULT_APP_ID, idHash, blindedId, commitment2);
        (uint8 v2, bytes32 r2, bytes32 s2) = _signAttestation(message2);

        vm.expectRevert("Nonce is used");
        registry.joinGroup(message2, v2, r2, s2);
    }

    function testJoinGroupSameUserDifferentApps() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        uint256 appId2 = 2;
        registry.registerApp(appId2);

        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId1 = keccak256("blinded-id-app1");
        bytes32 blindedId2 = keccak256("blinded-id-app2");
        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        // Join with app 1
        _joinGroup(credentialGroupId, DEFAULT_APP_ID, idHash, blindedId1, commitment1);

        // Join with app 2 — different blindedId so different nonce, should succeed
        _joinGroup(credentialGroupId, appId2, idHash, blindedId2, commitment2);
    }

    function testJoinGroupInvalidSignature() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        bytes32 idHash = keccak256("test-id");
        bytes32 blindedId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, DEFAULT_APP_ID, idHash, blindedId, commitment);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(123456, keccak256(abi.encode(message)).toEthSignedMessageHash());

        vm.expectRevert("Invalid TLSN Verifier signature");
        registry.joinGroup(message, v, r, s);
    }

    // --- ValidateProof tests ---

    function testValidateProof() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _joinGroup(credentialGroupId, DEFAULT_APP_ID, keccak256("test-id"), keccak256("blinded-id"), commitment);

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
            bringIdProof: hex"dead",
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
            bringIdProof: hex"dead",
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
        _joinGroup(credentialGroupId, DEFAULT_APP_ID, keccak256("test-id"), keccak256("blinded-id"), commitment);

        address prover = makeAddr("prover");
        uint256 wrongScope = uint256(keccak256(abi.encode(makeAddr("wrong"), uint256(0))));

        ICredentialRegistry.CredentialGroupProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, wrongScope, commitment);

        vm.expectRevert("Wrong scope");
        vm.prank(prover);
        registry.validateProof(0, proof);
    }

    function testValidateProofBringIdFails() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 100);

        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _joinGroup(credentialGroupId, DEFAULT_APP_ID, keccak256("test-id"), keccak256("blinded-id"), commitment);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        // Mock the nullifier verifier to return false
        vm.mockCall(mockNullifierVerifier, abi.encodeWithSelector(IVerifier.verify.selector), abi.encode(false));

        ICredentialRegistry.CredentialGroupProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, scope, commitment);

        vm.expectRevert("BringID proof verification failed");
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

        _joinGroup(credentialGroupId1, DEFAULT_APP_ID, keccak256("test-id-1"), keccak256("blinded-id-1"), commitment1);
        _joinGroup(credentialGroupId2, DEFAULT_APP_ID, keccak256("test-id-2"), keccak256("blinded-id-2"), commitment2);

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
        _joinGroup(credentialGroupId1, DEFAULT_APP_ID, keccak256("test-id-1"), keccak256("blinded-id-1"), commitment1);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId2,
            appId: DEFAULT_APP_ID,
            bringIdProof: hex"dead",
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
}
