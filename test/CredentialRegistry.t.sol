// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {IScorer} from "../src/registry/IScorer.sol";
import {DefaultScorer} from "../src/registry/DefaultScorer.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";

contract MockScorer is IScorer {
    mapping(uint256 => uint256) public scores;

    function setScore(uint256 credentialGroupId_, uint256 score_) public {
        scores[credentialGroupId_] = score_;
    }

    function getScore(uint256 credentialGroupId_) external view returns (uint256) {
        return scores[credentialGroupId_];
    }
}

contract CredentialRegistryTest is Test {
    using ECDSA for bytes32;

    CredentialRegistry registry;
    DefaultScorer scorer;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;

    address owner;
    address trustedVerifier;
    uint256 trustedVerifierPrivateKey;

    uint256 DEFAULT_APP_ID;

    event CredentialGroupCreated(
        uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroup credentialGroup
    );
    event AppSemaphoreGroupCreated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 semaphoreGroupId);
    event CredentialRegistered(
        uint256 indexed credentialGroupId,
        uint256 indexed appId,
        uint256 indexed commitment,
        bytes32 credentialId,
        bytes32 registrationHash,
        address verifier
    );
    event ProofValidated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 nullifier);
    event TrustedVerifierAdded(address indexed verifier);
    event TrustedVerifierRemoved(address indexed verifier);
    event AppRegistered(uint256 indexed appId, address indexed admin, uint256 recoveryTimelock);
    event AppSuspended(uint256 indexed appId);
    event AppRecoveryTimelockSet(uint256 indexed appId, uint256 timelock);
    event AppScorerSet(uint256 indexed appId, address indexed scorer);
    event AppAdminTransferred(uint256 indexed appId, address indexed oldAdmin, address indexed newAdmin);
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

        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier);

        scorer = DefaultScorer(registry.defaultScorer());

        // Register default app (caller = owner = admin)
        DEFAULT_APP_ID = registry.registerApp(0);
    }

    // --- Helper functions ---

    function _createAttestation(uint256 credentialGroupId, bytes32 credentialId, uint256 appId, uint256 commitment)
        internal
        view
        returns (ICredentialRegistry.Attestation memory)
    {
        return ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: appId,
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

    function _registerCredential(uint256 credentialGroupId, bytes32 credentialId, uint256 appId, uint256 commitment)
        internal
    {
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, appId, commitment);
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
        assertEq(registry.owner(), owner);
    }

    function testConstructorRejectsZeroTrustedVerifier() public {
        vm.expectRevert("Invalid trusted verifier address");
        new CredentialRegistry(ISemaphore(address(semaphore)), address(0));
    }

    function testDefaultScorerDeployedInConstructor() public {
        address scorerAddr = registry.defaultScorer();
        assertTrue(scorerAddr != address(0));
        // DefaultScorer is owned by the deployer (this test contract)
        DefaultScorer ds = DefaultScorer(scorerAddr);
        assertEq(ds.owner(), owner);
    }

    function testDefaultScorerSetScore() public {
        scorer.setScore(1, 500);
        assertEq(scorer.getScore(1), 500);
    }

    // --- Credential group tests ---

    function testCreateCredentialGroup() public {
        uint256 credentialGroupId = 1;

        vm.expectEmit(true, false, false, true);
        emit CredentialGroupCreated(
            credentialGroupId, ICredentialRegistry.CredentialGroup(ICredentialRegistry.CredentialGroupStatus.ACTIVE)
        );

        registry.createCredentialGroup(credentialGroupId);

        (ICredentialRegistry.CredentialGroupStatus status) = registry.credentialGroups(credentialGroupId);
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testCreateCredentialGroupOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.createCredentialGroup(1);
    }

    function testCreateCredentialGroupDuplicate() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        vm.expectRevert("Credential group exists");
        registry.createCredentialGroup(credentialGroupId);
    }

    function testFuzzNewVerification(uint256 credentialGroupId) public {
        vm.assume(credentialGroupId != 0 && credentialGroupId < type(uint256).max);

        registry.createCredentialGroup(credentialGroupId);

        (ICredentialRegistry.CredentialGroupStatus status) = registry.credentialGroups(credentialGroupId);
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testCreateCredentialGroupShouldRejectZeroId() public {
        vm.expectRevert();
        registry.createCredentialGroup(0);
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

    // --- App management tests ---

    function testRegisterAppPublic() public {
        address appAdmin = makeAddr("app-admin");

        vm.prank(appAdmin);
        vm.expectEmit(true, true, false, true);
        emit AppRegistered(2, appAdmin, 0);

        uint256 appId = registry.registerApp(0);
        assertEq(appId, 2);
        assertTrue(registry.appIsActive(appId));

        (ICredentialRegistry.AppStatus status, uint256 timelock, address admin, address appScorer) =
            registry.apps(appId);
        assertEq(uint256(status), uint256(ICredentialRegistry.AppStatus.ACTIVE));
        assertEq(timelock, 0);
        assertEq(admin, appAdmin);
        assertEq(appScorer, registry.defaultScorer());
    }

    function testRegisterAppReturnsIncrementingIds() public {
        uint256 id1 = registry.registerApp(0);
        uint256 id2 = registry.registerApp(0);
        uint256 id3 = registry.registerApp(0);
        // DEFAULT_APP_ID = 1 from setUp
        assertEq(id1, 2);
        assertEq(id2, 3);
        assertEq(id3, 4);
    }

    function testSuspendApp() public {
        uint256 appId = registry.registerApp(0);
        assertTrue(registry.appIsActive(appId));

        vm.expectEmit(true, false, false, false);
        emit AppSuspended(appId);

        registry.suspendApp(appId);
        assertFalse(registry.appIsActive(appId));
    }

    function testSuspendAppOnlyOwner() public {
        uint256 appId = registry.registerApp(0);

        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.suspendApp(appId);
    }

    function testSuspendAppNotActive() public {
        vm.expectRevert("App is not active");
        registry.suspendApp(999);
    }

    function testSetAppAdmin() public {
        address newAdmin = makeAddr("new-admin");

        vm.expectEmit(true, true, true, false);
        emit AppAdminTransferred(DEFAULT_APP_ID, owner, newAdmin);

        registry.setAppAdmin(DEFAULT_APP_ID, newAdmin);

        (,, address admin,) = registry.apps(DEFAULT_APP_ID);
        assertEq(admin, newAdmin);
    }

    function testSetAppAdminNonAdmin() public {
        address notAdmin = makeAddr("not-admin");

        vm.prank(notAdmin);
        vm.expectRevert("Not app admin");
        registry.setAppAdmin(DEFAULT_APP_ID, notAdmin);
    }

    function testSetAppScorer() public {
        MockScorer customScorer = new MockScorer();

        vm.expectEmit(true, true, false, false);
        emit AppScorerSet(DEFAULT_APP_ID, address(customScorer));

        registry.setAppScorer(DEFAULT_APP_ID, address(customScorer));

        (,,, address appScorer) = registry.apps(DEFAULT_APP_ID);
        assertEq(appScorer, address(customScorer));
    }

    function testSetAppScorerNonAdmin() public {
        address notAdmin = makeAddr("not-admin");

        vm.prank(notAdmin);
        vm.expectRevert("Not app admin");
        registry.setAppScorer(DEFAULT_APP_ID, address(0x123));
    }

    // --- JoinGroup tests ---

    function testRegisterCredential() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectEmit(true, true, true, false);
        emit CredentialRegistered(credentialGroupId, DEFAULT_APP_ID, commitment, bytes32(0), bytes32(0), address(0));

        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialWithBytes() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, false);
        emit CredentialRegistered(credentialGroupId, DEFAULT_APP_ID, commitment, bytes32(0), bytes32(0), address(0));

        registry.registerCredential(message, signature);
    }

    function testRegisterCredentialInactiveVerification() public {
        uint256 credentialGroupId = 1;
        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert("Credential group is inactive");
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialAppNotActive() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);
        uint256 inactiveAppId = 999;

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, inactiveAppId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert("App is not active");
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialWrongRegistry() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(0x123),
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: DEFAULT_APP_ID,
            semaphoreIdentityCommitment: commitment
        });

        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert("Wrong attestation message");
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialUsedNonce() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        registry.registerCredential(message, v, r, s);

        vm.expectRevert("Credential already registered");
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialUsedNonceWithDifferentCommitment() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        // First join succeeds
        ICredentialRegistry.Attestation memory message1 =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment1);
        (uint8 v1, bytes32 r1, bytes32 s1) = _signAttestation(message1);
        registry.registerCredential(message1, v1, r1, s1);

        // Second join with same credentialId but different commitment should fail
        ICredentialRegistry.Attestation memory message2 =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment2);
        (uint8 v2, bytes32 r2, bytes32 s2) = _signAttestation(message2);

        vm.expectRevert("Credential already registered");
        registry.registerCredential(message2, v2, r2, s2);
    }

    function testRegisterCredentialSameUserDifferentApps() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        uint256 app2 = registry.registerApp(0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        // Register for app 1
        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment1);

        // Register for app 2 — same credentialId but different app, should succeed
        _registerCredential(credentialGroupId, credentialId, app2, commitment2);
    }

    function testRegisterCredentialInvalidSignature() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(123456, keccak256(abi.encode(message)).toEthSignedMessageHash());

        vm.expectRevert("Untrusted verifier");
        registry.registerCredential(message, v, r, s);
    }

    // --- Per-app Semaphore group tests ---

    function testLazySemaphoreGroupCreation() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        // No Semaphore group should exist yet
        assertFalse(registry.appSemaphoreGroupCreated(credentialGroupId, DEFAULT_APP_ID));

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = TestUtils.semaphoreCommitment(12345);

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        // Now the Semaphore group should exist
        assertTrue(registry.appSemaphoreGroupCreated(credentialGroupId, DEFAULT_APP_ID));
    }

    function testSecondRegistrationReusesSemaphoreGroup() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, keccak256("id-1"), DEFAULT_APP_ID, commitment1);
        uint256 groupIdAfterFirst = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);

        _registerCredential(credentialGroupId, keccak256("id-2"), DEFAULT_APP_ID, commitment2);
        uint256 groupIdAfterSecond = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);

        assertEq(groupIdAfterFirst, groupIdAfterSecond);
    }

    function testDifferentAppsDifferentSemaphoreGroups() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        uint256 app2 = registry.registerApp(0);

        uint256 commitment1 = TestUtils.semaphoreCommitment(12345);
        uint256 commitment2 = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, keccak256("id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId, keccak256("id-1"), app2, commitment2);

        uint256 group1 = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);
        uint256 group2 = registry.appSemaphoreGroups(credentialGroupId, app2);

        assertTrue(group1 != group2);
    }

    // --- ValidateProof tests ---

    function testValidateProof() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        ICredentialRegistry.CredentialGroupProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, scope, commitment);

        vm.expectEmit(true, true, false, true);
        emit ProofValidated(credentialGroupId, DEFAULT_APP_ID, proof.semaphoreProof.nullifier);

        vm.prank(prover);
        registry.submitProof(0, proof);
    }

    function testValidateProofInactiveVerification() public {
        uint256 credentialGroupId = 1;

        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            appId: DEFAULT_APP_ID,
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
        registry.submitProof(0, proof);
    }

    function testValidateProofAppNotActive() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        uint256 inactiveAppId = 999;

        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            appId: inactiveAppId,
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
        registry.submitProof(0, proof);
    }

    function testValidateProofWrongScope() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        address prover = makeAddr("prover");
        uint256 wrongScope = uint256(keccak256(abi.encode(makeAddr("wrong"), uint256(0))));

        ICredentialRegistry.CredentialGroupProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, wrongScope, commitment);

        vm.expectRevert("Wrong scope");
        vm.prank(prover);
        registry.submitProof(0, proof);
    }

    function testValidateProofNoSemaphoreGroup() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        // Don't register any credential — no Semaphore group exists

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        ICredentialRegistry.CredentialGroupProof memory proof = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            appId: DEFAULT_APP_ID,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: 0,
                scope: scope,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        vm.expectRevert("No Semaphore group for this credential group and app");
        vm.prank(prover);
        registry.submitProof(0, proof);
    }

    // --- Score tests ---

    function testScoreUsesDefaultScorer() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        uint256 score1 = 100;
        uint256 score2 = 200;

        registry.createCredentialGroup(credentialGroupId1);
        registry.createCredentialGroup(credentialGroupId2);
        scorer.setScore(credentialGroupId1, score1);
        scorer.setScore(credentialGroupId2, score2);

        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);

        _registerCredential(credentialGroupId1, keccak256("blinded-id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId2, keccak256("blinded-id-2"), DEFAULT_APP_ID, commitment2);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, DEFAULT_APP_ID, commitmentKey2, scope, commitment2);

        uint256 totalScore = registry.submitProofs(0, proofs);
        assertEq(totalScore, score1 + score2);
    }

    function testScoreUsesCustomScorer() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;

        registry.createCredentialGroup(credentialGroupId1);
        registry.createCredentialGroup(credentialGroupId2);

        // Set default scores
        scorer.setScore(credentialGroupId1, 100);
        scorer.setScore(credentialGroupId2, 200);

        // Create a custom scorer with different scores
        MockScorer customScorer = new MockScorer();
        customScorer.setScore(credentialGroupId1, 999);
        customScorer.setScore(credentialGroupId2, 1);

        // Set custom scorer on the default app
        registry.setAppScorer(DEFAULT_APP_ID, address(customScorer));

        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        uint256 commitment2 = TestUtils.semaphoreCommitment(commitmentKey2);

        _registerCredential(credentialGroupId1, keccak256("blinded-id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId2, keccak256("blinded-id-2"), DEFAULT_APP_ID, commitment2);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, DEFAULT_APP_ID, commitmentKey2, scope, commitment2);

        uint256 totalScore = registry.submitProofs(0, proofs);
        assertEq(totalScore, 999 + 1);
    }

    function testScoreFailOnInactive() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;

        registry.createCredentialGroup(credentialGroupId1);
        scorer.setScore(credentialGroupId1, 100);
        // Don't create credentialGroupId2, it will be inactive

        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = TestUtils.semaphoreCommitment(commitmentKey1);
        _registerCredential(credentialGroupId1, keccak256("blinded-id-1"), DEFAULT_APP_ID, commitment1);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = ICredentialRegistry.CredentialGroupProof({
            credentialGroupId: credentialGroupId2,
            appId: DEFAULT_APP_ID,
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
        registry.submitProofs(0, proofs);
    }

    // --- Recovery timelock tests ---

    function testSetAppRecoveryTimelock() public {
        vm.expectEmit(true, false, false, true);
        emit AppRecoveryTimelockSet(DEFAULT_APP_ID, 1 days);

        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        (, uint256 timelock,,) = registry.apps(DEFAULT_APP_ID);
        assertEq(timelock, 1 days);
    }

    function testSetAppRecoveryTimelockNotAdmin() public {
        address notAdmin = makeAddr("not-admin");
        vm.prank(notAdmin);
        vm.expectRevert("Not app admin");
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);
    }

    function testSetAppRecoveryTimelockAppNotActive() public {
        uint256 appId = registry.registerApp(0);
        registry.suspendApp(appId);

        vm.expectRevert("Not app admin");
        registry.setAppRecoveryTimelock(999, 1 days);
    }

    function testSetAppRecoveryTimelockZero() public {
        vm.expectRevert("Recovery timelock must be positive");
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 0);
    }

    // --- Initiate recovery tests ---

    function _initiateRecovery(
        uint256 credentialGroupId,
        uint256 appId,
        bytes32 credentialId,
        uint256 newCommitment,
        uint256[] memory siblings
    ) internal {
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, appId, newCommitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        registry.initiateRecovery(att, v, r, s, siblings);
    }

    function testInitiateRecovery() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), credentialGroupId, credentialId, DEFAULT_APP_ID));

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
        registry.createCredentialGroup(credentialGroupId);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, newCommitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256[] memory siblings = new uint256[](0);
        registry.initiateRecovery(att, signature, siblings);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), credentialGroupId, credentialId, DEFAULT_APP_ID));
        (,, uint256 reqNewCommitment,) = registry.pendingRecoveries(registrationHash);
        assertEq(reqNewCommitment, newCommitment);
    }

    function testInitiateRecoveryNotRegistered() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert("Credential not registered");
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);
    }

    function testInitiateRecoveryAlreadyPending() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment1 = TestUtils.semaphoreCommitment(67890);
        uint256 newCommitment2 = TestUtils.semaphoreCommitment(11111);

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment1, siblings);

        vm.expectRevert("Recovery already pending");
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment2, siblings);
    }

    function testInitiateRecoveryNotEnabled() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert("Recovery not enabled for app");
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);
    }

    // --- Execute recovery tests ---

    function testExecuteRecovery() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), credentialGroupId, credentialId, DEFAULT_APP_ID));

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
        registry.createCredentialGroup(credentialGroupId);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = TestUtils.semaphoreCommitment(12345);
        uint256 newCommitment = TestUtils.semaphoreCommitment(67890);

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), credentialGroupId, credentialId, DEFAULT_APP_ID));

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
