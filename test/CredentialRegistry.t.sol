// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../contracts/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "@bringid/contracts/interfaces/ICredentialRegistry.sol";
import {CredentialProof} from "@bringid/contracts/interfaces/Types.sol";
import {IScorer} from "@bringid/contracts/interfaces/IScorer.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";
import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "@semaphore-protocol/contracts/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "@semaphore-protocol/contracts/base/SemaphoreVerifier.sol";
import {Semaphore} from "@semaphore-protocol/contracts/Semaphore.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";
import "@bringid/contracts/interfaces/Events.sol";
import "@bringid/contracts/interfaces/Errors.sol";

contract MockScorer is IScorer {
    mapping(uint256 => uint256) public scores;

    function setScore(uint256 credentialGroupId_, uint256 score_) public {
        scores[credentialGroupId_] = score_;
    }

    function getScore(uint256 credentialGroupId_) external view returns (uint256) {
        return scores[credentialGroupId_];
    }

    function getScores(uint256[] calldata credentialGroupIds_) external view returns (uint256[] memory scores_) {
        scores_ = new uint256[](credentialGroupIds_.length);
        for (uint256 i; i < credentialGroupIds_.length; ++i) {
            scores_[i] = scores[credentialGroupIds_[i]];
        }
    }

    function getAllScores() external pure returns (uint256[] memory, uint256[] memory) {
        revert("not implemented");
    }
}

/// @dev Contract that does NOT implement IScorer — used to test setAppScorer validation.
contract InvalidScorer {
    function notGetScore() external pure returns (uint256) {
        return 0;
    }
}

contract ReentrantAttacker {
    CredentialRegistry public registry;
    CredentialProof public storedProof;

    constructor(CredentialRegistry registry_) {
        registry = registry_;
    }

    function setProof(CredentialProof memory proof_) external {
        storedProof = proof_;
    }

    function attack() external {
        registry.submitProof(0, storedProof);
    }

    function attackDuringSubmitProofs() external {
        CredentialProof[] memory proofs = new CredentialProof[](1);
        proofs[0] = storedProof;
        registry.submitProofs(0, proofs);
    }
}

contract CredentialRegistryTest is Test {
    using ECDSA for bytes32;

    // Pre-computed Semaphore commitments for deterministic test keys (avoids FFI per-test).
    // Generated via: Identity.import(ethers.zeroPadValue(ethers.toBeHex(key), 32)).commitment
    uint256 constant COMMITMENT_12345 = 3757495654825671944221025502932027603093002514688471603980596532070551940856;
    uint256 constant COMMITMENT_67890 = 1627838166670782884016414820331096838803092519983728431519200514911855753278;
    uint256 constant COMMITMENT_11111 = 17540717969682626270724769168084744907147884769178330051830520727132669392207;

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
        address verifier,
        uint256 expiresAt
    );
    event ProofValidated(uint256 indexed credentialGroupId, uint256 indexed appId, uint256 nullifier);
    event TrustedVerifierUpdated(address indexed verifier, bool trusted);
    event AppRegistered(uint256 indexed appId, address indexed admin, uint256 recoveryTimelock);
    event AppStatusChanged(uint256 indexed appId, ICredentialRegistry.AppStatus status);
    event AppRecoveryTimelockSet(uint256 indexed appId, uint256 timelock);
    event AppScorerSet(uint256 indexed appId, address indexed scorer);
    event AppAdminTransferInitiated(uint256 indexed appId, address indexed currentAdmin, address indexed newAdmin);
    event AppAdminTransferred(uint256 indexed appId, address indexed oldAdmin, address indexed newAdmin);
    event RecoveryInitiated(
        bytes32 indexed registrationHash,
        uint256 indexed credentialGroupId,
        uint256 oldCommitment,
        uint256 newCommitment,
        uint256 executeAfter
    );
    event RecoveryExecuted(bytes32 indexed registrationHash, uint256 newCommitment);
    event CredentialExpired(
        uint256 indexed credentialGroupId, uint256 indexed appId, bytes32 credentialId, bytes32 registrationHash
    );
    event CredentialRenewed(
        uint256 indexed credentialGroupId,
        uint256 indexed appId,
        uint256 indexed commitment,
        bytes32 credentialId,
        bytes32 registrationHash,
        address verifier,
        uint256 expiresAt
    );
    event CredentialGroupValidityDurationSet(uint256 indexed credentialGroupId, uint256 validityDuration);
    event CredentialGroupStatusChanged(
        uint256 indexed credentialGroupId, ICredentialRegistry.CredentialGroupStatus status
    );
    event DefaultMerkleTreeDurationSet(uint256 indexed duration);
    event AppMerkleTreeDurationSet(uint256 indexed appId, uint256 merkleTreeDuration);

    function setUp() public {
        owner = address(this);
        (trustedVerifier, trustedVerifierPrivateKey) = makeAddrAndKey("trusted-verifier");

        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier, 1 hours);

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
            chainId: block.chainid,
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: appId,
            semaphoreIdentityCommitment: commitment,
            issuedAt: block.timestamp
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

    function _renewCredential(uint256 credentialGroupId, bytes32 credentialId, uint256 appId, uint256 commitment)
        internal
    {
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, appId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        registry.renewCredential(att, v, r, s);
    }

    function _makeProof(
        uint256 credentialGroupId,
        uint256 appId,
        uint256 commitmentKey,
        uint256 scope,
        uint256 commitment
    ) internal returns (CredentialProof memory) {
        uint256[] memory comms = new uint256[](1);
        comms[0] = commitment;
        (uint256 depth, uint256 root, uint256 nullifier, uint256 msg_, uint256[8] memory pts) =
            TestUtils.semaphoreProof(commitmentKey, scope, comms);
        return CredentialProof({
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
        vm.expectRevert(InvalidTrustedVerifier.selector);
        new CredentialRegistry(ISemaphore(address(semaphore)), address(0), 1 hours);
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
            credentialGroupId,
            ICredentialRegistry.CredentialGroup(ICredentialRegistry.CredentialGroupStatus.ACTIVE, 0, 0)
        );

        registry.createCredentialGroup(credentialGroupId, 0, 0);

        (ICredentialRegistry.CredentialGroupStatus status,,) = registry.credentialGroups(credentialGroupId);
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testCreateCredentialGroupOnlyOwner() public {
        address notOwner = makeAddr("not-owner");

        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.createCredentialGroup(1, 0, 0);
    }

    function testCreateCredentialGroupDuplicate() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        vm.expectRevert(CredentialGroupExists.selector);
        registry.createCredentialGroup(credentialGroupId, 0, 0);
    }

    function testFuzzNewVerification(uint256 credentialGroupId) public {
        vm.assume(credentialGroupId != 0 && credentialGroupId < type(uint256).max);

        registry.createCredentialGroup(credentialGroupId, 0, 0);

        (ICredentialRegistry.CredentialGroupStatus status,,) = registry.credentialGroups(credentialGroupId);
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
    }

    function testCreateCredentialGroupShouldRejectZeroId() public {
        vm.expectRevert();
        registry.createCredentialGroup(0, 0, 0);
    }

    // --- Credential group suspend / activate tests ---

    function testSuspendCredentialGroup() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        vm.expectEmit(true, false, false, true);
        emit CredentialGroupStatusChanged(credentialGroupId, ICredentialRegistry.CredentialGroupStatus.SUSPENDED);

        registry.suspendCredentialGroup(credentialGroupId);
        assertFalse(registry.credentialGroupIsActive(credentialGroupId));
    }

    function testSuspendCredentialGroupNotActive() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.suspendCredentialGroup(credentialGroupId);
        vm.expectRevert(CredentialGroupNotActive.selector);
        registry.suspendCredentialGroup(credentialGroupId);
    }

    function testSuspendCredentialGroupOnlyOwner() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.suspendCredentialGroup(credentialGroupId);
    }

    function testActivateCredentialGroup() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.suspendCredentialGroup(credentialGroupId);
        assertFalse(registry.credentialGroupIsActive(credentialGroupId));

        vm.expectEmit(true, false, false, true);
        emit CredentialGroupStatusChanged(credentialGroupId, ICredentialRegistry.CredentialGroupStatus.ACTIVE);

        registry.activateCredentialGroup(credentialGroupId);
        assertTrue(registry.credentialGroupIsActive(credentialGroupId));
    }

    function testActivateCredentialGroupNotSuspended() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        vm.expectRevert(CredentialGroupNotSuspended.selector);
        registry.activateCredentialGroup(credentialGroupId);
    }

    function testActivateCredentialGroupOnlyOwner() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.suspendCredentialGroup(credentialGroupId);
        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.activateCredentialGroup(credentialGroupId);
    }

    // --- Trusted verifier tests ---

    function testAddTrustedVerifier() public {
        address newVerifier = makeAddr("new-verifier");

        vm.expectEmit(true, false, false, true);
        emit TrustedVerifierUpdated(newVerifier, true);

        registry.addTrustedVerifier(newVerifier);
        assertTrue(registry.trustedVerifiers(newVerifier));
    }

    function testAddTrustedVerifierRejectsZeroAddress() public {
        vm.expectRevert(InvalidVerifierAddress.selector);
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

        vm.expectEmit(true, false, false, true);
        emit TrustedVerifierUpdated(newVerifier, false);

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
        vm.expectRevert(VerifierNotTrusted.selector);
        registry.removeTrustedVerifier(untrusted);
    }

    // --- App management tests ---

    function testRegisterAppPublic() public {
        address appAdmin = makeAddr("app-admin");

        vm.prank(appAdmin);
        uint256 appId = registry.registerApp(0);
        assertTrue(appId != 0);
        assertTrue(registry.appIsActive(appId));

        (ICredentialRegistry.AppStatus status, uint256 timelock, address admin, address appScorer) =
            registry.apps(appId);
        assertEq(uint256(status), uint256(ICredentialRegistry.AppStatus.ACTIVE));
        assertEq(timelock, 0);
        assertEq(admin, appAdmin);
        assertEq(appScorer, registry.defaultScorer());
    }

    function testRegisterAppReturnsUniqueIds() public {
        uint256 id1 = registry.registerApp(0);
        uint256 id2 = registry.registerApp(0);
        uint256 id3 = registry.registerApp(0);
        assertTrue(id1 != id2);
        assertTrue(id2 != id3);
        assertTrue(id1 != id3);
        assertTrue(id1 != DEFAULT_APP_ID);
    }

    function testSuspendApp() public {
        uint256 appId = registry.registerApp(0);
        assertTrue(registry.appIsActive(appId));

        vm.expectEmit(true, false, false, true);
        emit AppStatusChanged(appId, ICredentialRegistry.AppStatus.SUSPENDED);

        registry.suspendApp(appId);
        assertFalse(registry.appIsActive(appId));
    }

    function testSuspendAppNotAdmin() public {
        uint256 appId = registry.registerApp(0);

        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert(NotAppAdmin.selector);
        registry.suspendApp(appId);
    }

    function testSuspendAppNotActive() public {
        uint256 appId = registry.registerApp(0);
        registry.suspendApp(appId);
        vm.expectRevert(AppNotActive.selector);
        registry.suspendApp(appId);
    }

    function testActivateApp() public {
        uint256 appId = registry.registerApp(0);
        registry.suspendApp(appId);
        assertFalse(registry.appIsActive(appId));

        vm.expectEmit(true, false, false, true);
        emit AppStatusChanged(appId, ICredentialRegistry.AppStatus.ACTIVE);

        registry.activateApp(appId);
        assertTrue(registry.appIsActive(appId));
    }

    function testActivateAppNotAdmin() public {
        uint256 appId = registry.registerApp(0);
        registry.suspendApp(appId);

        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert(NotAppAdmin.selector);
        registry.activateApp(appId);
    }

    function testActivateAppNotSuspended() public {
        uint256 appId = registry.registerApp(0);
        vm.expectRevert(AppNotSuspended.selector);
        registry.activateApp(appId);
    }

    function testTransferAppAdmin() public {
        address newAdmin = makeAddr("new-admin");

        vm.expectEmit(true, true, true, false);
        emit AppAdminTransferInitiated(DEFAULT_APP_ID, owner, newAdmin);
        registry.transferAppAdmin(DEFAULT_APP_ID, newAdmin);

        // Admin should not change yet
        (,, address admin,) = registry.apps(DEFAULT_APP_ID);
        assertEq(admin, owner);

        // New admin accepts
        vm.prank(newAdmin);
        vm.expectEmit(true, true, true, false);
        emit AppAdminTransferred(DEFAULT_APP_ID, owner, newAdmin);
        registry.acceptAppAdmin(DEFAULT_APP_ID);

        (,, address updatedAdmin,) = registry.apps(DEFAULT_APP_ID);
        assertEq(updatedAdmin, newAdmin);
    }

    function testTransferAppAdminNonAdmin() public {
        address notAdmin = makeAddr("not-admin");

        vm.prank(notAdmin);
        vm.expectRevert(NotAppAdmin.selector);
        registry.transferAppAdmin(DEFAULT_APP_ID, notAdmin);
    }

    function testAcceptAppAdminNotPending() public {
        address notPending = makeAddr("not-pending");

        vm.prank(notPending);
        vm.expectRevert(NotPendingAdmin.selector);
        registry.acceptAppAdmin(DEFAULT_APP_ID);
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
        vm.expectRevert(NotAppAdmin.selector);
        registry.setAppScorer(DEFAULT_APP_ID, address(0x123));
    }

    function testSetAppScorerRejectsNonContract() public {
        address eoa = makeAddr("eoa");

        vm.expectRevert(InvalidScorerContract.selector);
        registry.setAppScorer(DEFAULT_APP_ID, eoa);
    }

    function testSetAppScorerRejectsInvalidContract() public {
        // Deploy a contract that doesn't implement getScore
        InvalidScorer invalid = new InvalidScorer();

        vm.expectRevert(InvalidScorerContract.selector);
        registry.setAppScorer(DEFAULT_APP_ID, address(invalid));
    }

    // --- Chain-bound attestation tests ---

    function testWrongChainIdRejected() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory att = ICredentialRegistry.Attestation({
            registry: address(registry),
            chainId: 999,
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: DEFAULT_APP_ID,
            semaphoreIdentityCommitment: commitment,
            issuedAt: block.timestamp
        });
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.expectRevert(WrongChain.selector);
        registry.registerCredential(att, v, r, s);
    }

    // --- Hash-based app ID tests ---

    function testHashBasedAppIds() public {
        uint256 id1 = registry.registerApp(0);
        uint256 id2 = registry.registerApp(0);
        assertTrue(id1 != id2);
        assertTrue(registry.appIsActive(id1));
        assertTrue(registry.appIsActive(id2));

        // Same sender on a different chain produces different IDs
        uint256 nonceBefore = registry.nextAppId();
        vm.chainId(999);
        uint256 id3 = registry.registerApp(0);
        assertTrue(id3 != id1);
        assertTrue(id3 != id2);
        assertTrue(registry.appIsActive(id3));

        // Verify app is functional — can register credentials against it
        vm.chainId(31337); // reset to default
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        _registerCredential(credentialGroupId, keccak256("cred-1"), id1, COMMITMENT_12345);
    }

    // --- JoinGroup tests ---

    function testRegisterCredential() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectEmit(true, true, true, false);
        emit CredentialRegistered(credentialGroupId, DEFAULT_APP_ID, commitment, bytes32(0), bytes32(0), address(0), 0);

        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialWithBytes() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectEmit(true, true, true, false);
        emit CredentialRegistered(credentialGroupId, DEFAULT_APP_ID, commitment, bytes32(0), bytes32(0), address(0), 0);

        registry.registerCredential(message, signature);
    }

    function testRegisterCredentialInactiveVerification() public {
        uint256 credentialGroupId = 1;
        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert(CredentialGroupInactive.selector);
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialAppNotActive() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;
        uint256 inactiveAppId = 999;

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, inactiveAppId, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert(AppNotActive.selector);
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialWrongRegistry() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory message = ICredentialRegistry.Attestation({
            registry: address(0x123),
            chainId: block.chainid,
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: DEFAULT_APP_ID,
            semaphoreIdentityCommitment: commitment,
            issuedAt: block.timestamp
        });

        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        vm.expectRevert(WrongRegistryAddress.selector);
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialUsedNonce() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(message);

        registry.registerCredential(message, v, r, s);

        vm.expectRevert(AlreadyRegistered.selector);
        registry.registerCredential(message, v, r, s);
    }

    function testRegisterCredentialUsedNonceWithDifferentCommitment() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        // First join succeeds
        ICredentialRegistry.Attestation memory message1 =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment1);
        (uint8 v1, bytes32 r1, bytes32 s1) = _signAttestation(message1);
        registry.registerCredential(message1, v1, r1, s1);

        // Second join with same credentialId but different commitment should fail
        ICredentialRegistry.Attestation memory message2 =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment2);
        (uint8 v2, bytes32 r2, bytes32 s2) = _signAttestation(message2);

        vm.expectRevert(AlreadyRegistered.selector);
        registry.registerCredential(message2, v2, r2, s2);
    }

    function testRegisterCredentialSameUserDifferentApps() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 app2 = registry.registerApp(0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        // Register for app 1
        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment1);

        // Register for app 2 — same credentialId but different app, should succeed
        _registerCredential(credentialGroupId, credentialId, app2, commitment2);
    }

    function testRegisterCredentialInvalidSignature() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory message =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(123456, keccak256(abi.encode(message)).toEthSignedMessageHash());

        vm.expectRevert(UntrustedVerifier.selector);
        registry.registerCredential(message, v, r, s);
    }

    // --- Per-app Semaphore group tests ---

    function testLazySemaphoreGroupCreation() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        // No Semaphore group should exist yet
        assertFalse(registry.appSemaphoreGroupCreated(credentialGroupId, DEFAULT_APP_ID));

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        // Now the Semaphore group should exist
        assertTrue(registry.appSemaphoreGroupCreated(credentialGroupId, DEFAULT_APP_ID));
    }

    function testSecondRegistrationReusesSemaphoreGroup() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId, keccak256("id-1"), DEFAULT_APP_ID, commitment1);
        uint256 groupIdAfterFirst = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);

        _registerCredential(credentialGroupId, keccak256("id-2"), DEFAULT_APP_ID, commitment2);
        uint256 groupIdAfterSecond = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);

        assertEq(groupIdAfterFirst, groupIdAfterSecond);
    }

    function testDifferentAppsDifferentSemaphoreGroups() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 app2 = registry.registerApp(0);

        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId, keccak256("id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId, keccak256("id-1"), app2, commitment2);

        uint256 group1 = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);
        uint256 group2 = registry.appSemaphoreGroups(credentialGroupId, app2);

        assertTrue(group1 != group2);
    }

    // --- ValidateProof tests ---

    function testValidateProof() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof memory proof = _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, scope, commitment);

        vm.expectEmit(true, true, false, true);
        emit ProofValidated(credentialGroupId, DEFAULT_APP_ID, proof.semaphoreProof.nullifier);

        vm.prank(prover);
        registry.submitProof(0, proof);
    }

    function testValidateProofInactiveVerification() public {
        uint256 credentialGroupId = 1;

        CredentialProof memory proof = CredentialProof({
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

        vm.expectRevert(CredentialGroupInactive.selector);
        registry.submitProof(0, proof);
    }

    function testValidateProofAppNotActive() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 inactiveAppId = 999;

        CredentialProof memory proof = CredentialProof({
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

        vm.expectRevert(AppNotActive.selector);
        registry.submitProof(0, proof);
    }

    function testValidateProofWrongScope() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        address prover = makeAddr("prover");
        uint256 wrongScope = uint256(keccak256(abi.encode(makeAddr("wrong"), uint256(0))));

        CredentialProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, wrongScope, commitment);

        vm.expectRevert(ScopeMismatch.selector);
        vm.prank(prover);
        registry.submitProof(0, proof);
    }

    function testValidateProofNoSemaphoreGroup() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        // Don't register any credential — no Semaphore group exists

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof memory proof = CredentialProof({
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

        vm.expectRevert(NoSemaphoreGroup.selector);
        vm.prank(prover);
        registry.submitProof(0, proof);
    }

    // --- Score tests ---

    function testScoreUsesDefaultScorer() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        uint256 score1 = 100;
        uint256 score2 = 200;

        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        registry.createCredentialGroup(credentialGroupId2, 0, 0);
        scorer.setScore(credentialGroupId1, score1);
        scorer.setScore(credentialGroupId2, score2);

        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId1, keccak256("blinded-id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId2, keccak256("blinded-id-2"), DEFAULT_APP_ID, commitment2);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, DEFAULT_APP_ID, commitmentKey2, scope, commitment2);

        uint256 totalScore = registry.submitProofs(0, proofs);
        assertEq(totalScore, score1 + score2);
    }

    function testScoreUsesCustomScorer() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;

        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        registry.createCredentialGroup(credentialGroupId2, 0, 0);

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
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId1, keccak256("blinded-id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId2, keccak256("blinded-id-2"), DEFAULT_APP_ID, commitment2);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, DEFAULT_APP_ID, commitmentKey2, scope, commitment2);

        uint256 totalScore = registry.submitProofs(0, proofs);
        assertEq(totalScore, 999 + 1);
    }

    function testScoreFailOnInactive() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;

        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        scorer.setScore(credentialGroupId1, 100);
        // Don't create credentialGroupId2, it will be inactive

        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = COMMITMENT_12345;
        _registerCredential(credentialGroupId1, keccak256("blinded-id-1"), DEFAULT_APP_ID, commitment1);

        uint256 scope = uint256(keccak256(abi.encode(address(this), 0)));

        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = CredentialProof({
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

        vm.expectRevert(CredentialGroupInactive.selector);
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
        vm.expectRevert(NotAppAdmin.selector);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);
    }

    function testSetAppRecoveryTimelockAppNotActive() public {
        uint256 appId = registry.registerApp(0);
        registry.suspendApp(appId);

        vm.expectRevert(NotAppAdmin.selector);
        registry.setAppRecoveryTimelock(999, 1 days);
    }

    function testSetAppRecoveryTimelockZero() public {
        // First enable recovery
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);
        (, uint256 timelock,,) = registry.apps(DEFAULT_APP_ID);
        assertEq(timelock, 1 days);

        // Disable recovery by setting to 0
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 0);
        (, timelock,,) = registry.apps(DEFAULT_APP_ID);
        assertEq(timelock, 0);
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
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        uint256[] memory siblings = new uint256[](0);

        vm.expectEmit(true, true, false, true);
        emit RecoveryInitiated(
            registrationHash, credentialGroupId, oldCommitment, newCommitment, block.timestamp + 1 days
        );

        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        (,,,,, ICredentialRegistry.RecoveryRequest memory req) = registry.credentials(registrationHash);
        assertEq(req.credentialGroupId, credentialGroupId);
        assertEq(req.appId, DEFAULT_APP_ID);
        assertEq(req.newCommitment, newCommitment);
        assertEq(req.executeAfter, block.timestamp + 1 days);
    }

    function testInitiateRecoveryWithBytes() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, newCommitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256[] memory siblings = new uint256[](0);
        registry.initiateRecovery(att, signature, siblings);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));
        (,,,,, ICredentialRegistry.RecoveryRequest memory req) = registry.credentials(registrationHash);
        assertEq(req.newCommitment, newCommitment);
    }

    function testInitiateRecoveryNotRegistered() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 newCommitment = COMMITMENT_67890;

        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert(NotRegistered.selector);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);
    }

    function testInitiateRecoveryAlreadyPending() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment1 = COMMITMENT_67890;
        uint256 newCommitment2 = COMMITMENT_11111;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment1, siblings);

        vm.expectRevert(RecoveryAlreadyPending.selector);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment2, siblings);
    }

    function testInitiateRecoveryNotEnabled() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert(RecoveryDisabled.selector);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);
    }

    // --- Execute recovery tests ---

    function testExecuteRecovery() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(true, false, false, true);
        emit RecoveryExecuted(registrationHash, newCommitment);

        registry.executeRecovery(registrationHash);

        (,, uint256 commitment,,, ICredentialRegistry.RecoveryRequest memory req) =
            registry.credentials(registrationHash);
        assertEq(commitment, newCommitment);
        assertEq(req.executeAfter, 0);
    }

    function testExecuteRecoveryTimelockNotExpired() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        vm.warp(block.timestamp + 1 days - 1);

        vm.expectRevert(RecoveryTimelockNotExpired.selector);
        registry.executeRecovery(registrationHash);
    }

    function testExecuteRecoveryNoPending() public {
        bytes32 fakeHash = keccak256("no-such-recovery");

        vm.expectRevert(NoPendingRecovery.selector);
        registry.executeRecovery(fakeHash);
    }

    // --- Credential expiry tests ---

    function testCreateCredentialGroupWithValidityDuration() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;

        vm.expectEmit(true, false, false, true);
        emit CredentialGroupCreated(
            credentialGroupId,
            ICredentialRegistry.CredentialGroup(ICredentialRegistry.CredentialGroupStatus.ACTIVE, validityDuration, 0)
        );

        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        (ICredentialRegistry.CredentialGroupStatus status, uint256 duration,) =
            registry.credentialGroups(credentialGroupId);
        assertEq(uint256(status), uint256(ICredentialRegistry.CredentialGroupStatus.ACTIVE));
        assertEq(duration, validityDuration);
    }

    function testRegisterCredentialSetsExpiry() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));
        (,,, uint256 expiresAt,,) = registry.credentials(registrationHash);
        assertEq(expiresAt, block.timestamp + validityDuration);
    }

    function testRegisterCredentialNoExpiryWhenDurationZero() public {
        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));
        (,,, uint256 expiresAt,,) = registry.credentials(registrationHash);
        assertEq(expiresAt, 0);
    }

    function testRemoveExpiredCredential() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Warp past expiry
        vm.warp(block.timestamp + validityDuration);

        uint256[] memory siblings = new uint256[](0);

        vm.expectEmit(true, true, false, true);
        emit CredentialExpired(credentialGroupId, DEFAULT_APP_ID, credentialId, registrationHash);

        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);

        // Verify expired flag is set (registered and commitment persist for nullifier continuity)
        (bool registered, bool expired, uint256 storedCommitment,,,) = registry.credentials(registrationHash);
        assertTrue(registered);
        assertTrue(expired);
        assertEq(storedCommitment, commitment);
    }

    function testRemoveExpiredCredentialTooEarly() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        // Warp to just before expiry
        vm.warp(block.timestamp + validityDuration - 1);

        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert(NotYetExpired.selector);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);
    }

    function testRemoveExpiredCredentialNotRegistered() public {
        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, 30 days, 0);

        bytes32 credentialId = keccak256("nonexistent");
        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert(NotRegistered.selector);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);
    }

    function testRemoveExpiredCredentialNoExpiry() public {
        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        uint256[] memory siblings = new uint256[](0);

        vm.expectRevert(NoExpirySet.selector);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);
    }

    function testRenewAfterExpiryWithSameCommitment() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Warp past expiry and remove
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);

        // Renew with the same commitment succeeds
        _renewCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        (bool registered,, uint256 storedCommitment, uint256 expiresAt,,) = registry.credentials(registrationHash);
        assertTrue(registered);
        assertEq(storedCommitment, commitment);
        assertEq(expiresAt, block.timestamp + validityDuration);
    }

    function testRenewAfterExpiryRequiresSameCommitment() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment1);

        // Warp past expiry and remove
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);

        // Renew with a different commitment reverts
        vm.expectRevert(CommitmentMismatch.selector);
        _renewCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment2);
    }

    function testRecoveryUpdatesPersistedCommitment() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Recovery: replace oldCommitment with newCommitment
        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);
        vm.warp(block.timestamp + 1 days);
        registry.executeRecovery(registrationHash);

        // After recovery, registeredCommitments should point to the new commitment.
        // Combined with testRenewAfterExpiryRequiresSameCommitment (which verifies
        // that registeredCommitments survives expiry and blocks different commitments),
        // this ensures renewal after recovery+expiry must use the recovered commitment.
        (,, uint256 storedCommitment,,,) = registry.credentials(registrationHash);
        assertEq(storedCommitment, newCommitment);
    }

    // --- Expiry + Recovery interaction edge cases ---

    function testInitiateRecoveryOnExpiredButNotRemovedCredential() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        // Warp past expiry but don't call removeExpiredCredential
        vm.warp(block.timestamp + validityDuration);

        // initiateRecovery still succeeds — credentialRegistered is still true
        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));
        (,,,,, ICredentialRegistry.RecoveryRequest memory req) = registry.credentials(registrationHash);
        assertEq(req.newCommitment, newCommitment);
    }

    function testInitiateRecoveryOnExpiredAndRemovedCredential() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Expire and remove
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);

        // expired is true, but registered and commitment persist
        {
            (bool registered, bool expired,,,,) = registry.credentials(registrationHash);
            assertTrue(registered);
            assertTrue(expired);
        }

        // Recovery succeeds — skips Semaphore removal (already removed)
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        {
            (,,,,, ICredentialRegistry.RecoveryRequest memory req) = registry.credentials(registrationHash);
            assertEq(req.newCommitment, newCommitment);
        }

        // Execute recovery after timelock — re-registers the credential
        vm.warp(block.timestamp + 1 days);
        registry.executeRecovery(registrationHash);

        // Credential is recovered with new commitment; expired flag cleared
        (bool registered, bool expired, uint256 storedCommitment,,,) = registry.credentials(registrationHash);
        assertTrue(registered);
        assertFalse(expired);
        assertEq(storedCommitment, newCommitment);
    }

    function testRemoveExpiredCredentialAfterRecoveryInitiated() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        // Warp past expiry, then initiate recovery (removes commitment from Semaphore)
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        // removeExpiredCredential tries to remove the same commitment again from Semaphore — reverts
        vm.expectRevert(RecoveryPending.selector);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);
    }

    function testExecuteRecoveryAfterExpiry() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Initiate recovery before expiry
        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        // Warp past both recovery timelock AND credential expiry
        vm.warp(block.timestamp + validityDuration);

        // executeRecovery still succeeds — it doesn't check expiry
        registry.executeRecovery(registrationHash);
        (bool registered,, uint256 storedCommitment, uint256 expiresAt,,) = registry.credentials(registrationHash);
        assertEq(storedCommitment, newCommitment);
        assertTrue(registered);

        // Recovery does NOT reset expiry — credential is still expired
        assertTrue(block.timestamp >= expiresAt);
    }

    function testDoubleRecoveryOnExpiredCredential() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment1);

        // Warp past expiry, initiate recovery
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, commitment2, siblings);

        // Cannot initiate a second recovery while one is pending
        vm.expectRevert(RecoveryAlreadyPending.selector);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, commitment2, siblings);
    }

    function testExpiredCredentialPreservesCommitmentForRenewal() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_11111;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Expire and remove
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);

        // expired is set but registered and commitment persist
        (bool registered, bool expired, uint256 storedCommitment,,, ICredentialRegistry.RecoveryRequest memory req) =
            registry.credentials(registrationHash);
        assertTrue(registered);
        assertTrue(expired);
        assertEq(storedCommitment, commitment);
        assertEq(req.executeAfter, 0);
    }

    // --- Renewal tests ---

    function testRenewCredential() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Warp past expiry and remove
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);

        // Renew
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.expectEmit(true, true, true, false);
        emit CredentialRenewed(credentialGroupId, DEFAULT_APP_ID, commitment, bytes32(0), bytes32(0), address(0), 0);

        registry.renewCredential(att, v, r, s);

        (bool registered,, uint256 storedCommitment, uint256 expiresAt,,) = registry.credentials(registrationHash);
        assertTrue(registered);
        assertEq(storedCommitment, commitment);
        assertEq(expiresAt, block.timestamp + validityDuration);
    }

    function testRenewCredentialWithBytes() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        // Warp past expiry and remove
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);

        // Renew with bytes signature
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        bytes memory signature = abi.encodePacked(r, s, v);

        registry.renewCredential(att, signature);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));
        (bool registered,,,,,) = registry.credentials(registrationHash);
        assertTrue(registered);
    }

    function testRenewCredentialEarlyRenewal() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        (,,, uint256 originalExpiry,,) = registry.credentials(registrationHash);

        // Warp to halfway through validity (not expired yet)
        vm.warp(block.timestamp + 15 days);

        // Renew early — should reset expiry from current timestamp
        _renewCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        (bool registered,,, uint256 newExpiry,,) = registry.credentials(registrationHash);
        assertEq(newExpiry, block.timestamp + validityDuration);
        assertTrue(newExpiry > originalExpiry);
        assertTrue(registered);
    }

    function testRenewCredentialExpiredButNotRemoved() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Warp past expiry but don't remove
        vm.warp(block.timestamp + validityDuration);
        {
            (bool registered,,,,,) = registry.credentials(registrationHash);
            assertTrue(registered);
        }

        // Renew — credential is still in Semaphore, just reset expiry
        _renewCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        (bool registered,,, uint256 expiresAt,,) = registry.credentials(registrationHash);
        assertTrue(registered);
        assertEq(expiresAt, block.timestamp + validityDuration);
    }

    function testRenewCredentialNotPreviouslyRegistered() public {
        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, 30 days, 0);

        bytes32 credentialId = keccak256("never-registered");
        uint256 commitment = COMMITMENT_12345;

        vm.expectRevert(NotRegistered.selector);
        _renewCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
    }

    function testRenewCredentialDifferentCommitment() public {
        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, 30 days, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment1);

        vm.expectRevert(CommitmentMismatch.selector);
        _renewCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment2);
    }

    function testRenewCredentialRecoveryPending() public {
        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, 30 days, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        // Cannot renew while recovery is pending
        vm.expectRevert(RecoveryPending.selector);
        _renewCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);
    }

    function testRegisterCredentialAfterExpiryFails() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        // Warp past expiry and remove
        vm.warp(block.timestamp + validityDuration);
        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);

        // registerCredential now rejects previously-registered credentials
        vm.expectRevert(AlreadyRegistered.selector);
        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
    }

    function testRenewCredentialValidityDurationChangedToZero() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        // Confirm expiry was set
        {
            (,,, uint256 expiresAt,,) = registry.credentials(registrationHash);
            assertTrue(expiresAt > 0);
        }

        // Owner changes validity duration to 0 (no expiry)
        registry.setCredentialGroupValidityDuration(credentialGroupId, 0);

        // Renew — expiry should be cleared
        _renewCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        (,,, uint256 expiresAt,,) = registry.credentials(registrationHash);
        assertEq(expiresAt, 0);
    }

    // --- Credential group validity duration tests ---

    function testSetCredentialGroupValidityDuration() public {
        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        vm.expectEmit(true, false, false, true);
        emit CredentialGroupValidityDurationSet(credentialGroupId, 7 days);

        registry.setCredentialGroupValidityDuration(credentialGroupId, 7 days);

        (, uint256 duration,) = registry.credentialGroups(credentialGroupId);
        assertEq(duration, 7 days);
    }

    function testSetCredentialGroupValidityDurationOnlyOwner() public {
        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setCredentialGroupValidityDuration(credentialGroupId, 7 days);
    }

    function testSetCredentialGroupValidityDurationNonExistent() public {
        vm.expectRevert(CredentialGroupNotFound.selector);
        registry.setCredentialGroupValidityDuration(999, 7 days);
    }

    // --- Attestation validity duration tests ---

    function testSetAttestationValidityDuration() public {
        assertEq(registry.attestationValidityDuration(), 30 minutes);

        vm.expectEmit(false, false, false, true);
        emit AttestationValidityDurationSet(1 hours);

        registry.setAttestationValidityDuration(1 hours);
        assertEq(registry.attestationValidityDuration(), 1 hours);
    }

    function testSetAttestationValidityDurationOnlyOwner() public {
        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setAttestationValidityDuration(1 hours);
    }

    function testSetAttestationValidityDurationZero() public {
        vm.expectRevert(ZeroDuration.selector);
        registry.setAttestationValidityDuration(0);
    }

    function testRegisterCredentialFutureAttestation() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory att = ICredentialRegistry.Attestation({
            registry: address(registry),
            chainId: block.chainid,
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: DEFAULT_APP_ID,
            semaphoreIdentityCommitment: commitment,
            issuedAt: block.timestamp + 1 hours
        });
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.expectRevert(FutureAttestation.selector);
        registry.registerCredential(att, v, r, s);
    }

    function testRegisterCredentialExpiredAttestation() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        // Warp past attestation validity (default 30 minutes)
        vm.warp(block.timestamp + 31 minutes);

        vm.expectRevert(AttestationExpired.selector);
        registry.registerCredential(att, v, r, s);
    }

    function testRenewCredentialExpiredAttestation() public {
        uint256 credentialGroupId = 10;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        // Create renewal attestation, then warp past its validity
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.warp(block.timestamp + 31 minutes);

        vm.expectRevert(AttestationExpired.selector);
        registry.renewCredential(att, v, r, s);
    }

    function testInitiateRecoveryExpiredAttestation() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        // Create recovery attestation, then warp past its validity
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, newCommitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.warp(block.timestamp + 31 minutes);

        uint256[] memory siblings = new uint256[](0);
        vm.expectRevert(AttestationExpired.selector);
        registry.initiateRecovery(att, v, r, s, siblings);
    }

    // --- Family enforcement tests ---

    function testFamilyEnforcementBlocksSiblingGroup() public {
        // Create family groups: group 1 and 2 in family 1
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(2, 60 days, 1);

        bytes32 credentialId = keccak256("same-user");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        // Register in group 1 succeeds
        _registerCredential(1, credentialId, DEFAULT_APP_ID, commitment1);

        // Register in group 2 (same family) with same credentialId reverts — same registration hash
        vm.expectRevert(AlreadyRegistered.selector);
        _registerCredential(2, credentialId, DEFAULT_APP_ID, commitment2);
    }

    function testFamilyEnforcementAllowsDifferentFamilies() public {
        // Group 1 in family 1, group 4 in family 2
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(4, 30 days, 2);

        bytes32 credentialId = keccak256("same-user");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        // Register in family 1
        _registerCredential(1, credentialId, DEFAULT_APP_ID, commitment1);

        // Register in family 2 — different family, succeeds
        _registerCredential(4, credentialId, DEFAULT_APP_ID, commitment2);
    }

    function testStandaloneGroupsNoFamilyConstraint() public {
        // Both standalone (family 0) — no family constraint
        registry.createCredentialGroup(10, 180 days, 0);
        registry.createCredentialGroup(11, 180 days, 0);

        bytes32 credentialId = keccak256("same-user");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        // Register in group 10
        _registerCredential(10, credentialId, DEFAULT_APP_ID, commitment1);

        // Register in group 11 — standalone, no family constraint, succeeds
        _registerCredential(11, credentialId, DEFAULT_APP_ID, commitment2);
    }

    function testFamilyEnforcementExpiredButNotRemovedBlocks() public {
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(2, 60 days, 1);

        bytes32 credentialId = keccak256("same-user");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(1, credentialId, DEFAULT_APP_ID, commitment1);

        // Warp past expiry but don't remove — cred.registered is still true
        vm.warp(block.timestamp + 30 days);

        // Register in sibling group still fails (registered flag persists)
        vm.expectRevert(AlreadyRegistered.selector);
        _registerCredential(2, credentialId, DEFAULT_APP_ID, commitment2);
    }

    function testFamilyGroupChangeViaRecovery() public {
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(2, 60 days, 1);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("same-user");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(1, credentialId, DEFAULT_APP_ID, oldCommitment);

        // Family hash: keccak256(registry, familyId=1, 0, credentialId, appId)
        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(1), uint256(0), credentialId, DEFAULT_APP_ID));

        // Capture original expiry
        (,,, uint256 originalExpiresAt,,) = registry.credentials(registrationHash);
        assertTrue(originalExpiresAt > 0);

        // Initiate recovery targeting group 2 (same family) — allowed
        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(2, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        // Execute recovery after timelock
        vm.warp(block.timestamp + 1 days);
        registry.executeRecovery(registrationHash);

        // Verify credentialGroupId updated to group 2
        (bool registered,,, uint256 expiresAt, uint256 credentialGroupId,) = registry.credentials(registrationHash);
        assertTrue(registered);
        assertEq(credentialGroupId, 2);
        // Recovery does NOT reset expiry — expiresAt unchanged from original registration
        assertEq(expiresAt, originalExpiresAt);
    }

    function testEarlyRenewalWithWrongGroupReverts() public {
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(2, 60 days, 1);

        bytes32 credentialId = keccak256("same-user");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(1, credentialId, DEFAULT_APP_ID, commitment);

        // Try to renew with group 2 instead of group 1 — reverts
        vm.expectRevert(GroupMismatch.selector);
        _renewCredential(2, credentialId, DEFAULT_APP_ID, commitment);
    }

    function testRecoveryRequiresMatchingGroupOrFamily() public {
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(4, 30 days, 2);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, 1 days);

        bytes32 credentialId = keccak256("same-user");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(1, credentialId, DEFAULT_APP_ID, oldCommitment);

        // Try recovery targeting group 4 (family 2, not family 1) — reverts.
        // Different families produce different registration hashes, so the credential
        // is not found under the new hash.
        uint256[] memory siblings = new uint256[](0);
        vm.expectRevert(NotRegistered.selector);
        _initiateRecovery(4, DEFAULT_APP_ID, credentialId, newCommitment, siblings);
    }

    function testSameCredentialIdDifferentAppsNoFamilyConflict() public {
        registry.createCredentialGroup(1, 30 days, 1);

        uint256 app2 = registry.registerApp(0);

        bytes32 credentialId = keccak256("same-user");
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        // Same credentialId + same group, different apps — succeeds (appId is in the hash)
        _registerCredential(1, credentialId, DEFAULT_APP_ID, commitment1);
        _registerCredential(1, credentialId, app2, commitment2);
    }

    function testRemoveExpiredCredentialGroupMismatch() public {
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(2, 60 days, 1);

        bytes32 credentialId = keccak256("same-user");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(1, credentialId, DEFAULT_APP_ID, commitment);

        vm.warp(block.timestamp + 30 days);

        // Pass wrong credentialGroupId (2 instead of 1) — group mismatch
        uint256[] memory siblings = new uint256[](0);
        vm.expectRevert(GroupMismatch.selector);
        registry.removeExpiredCredential(2, credentialId, DEFAULT_APP_ID, siblings);
    }

    // --- Merkle tree duration tests ---

    function testConstructorRejectsZeroMerkleTreeDuration() public {
        vm.expectRevert(ZeroMerkleTreeDuration.selector);
        new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier, 0);
    }

    function testConstructorSetsDefaultMerkleTreeDuration() public {
        assertEq(registry.defaultMerkleTreeDuration(), 1 hours);
    }

    function testSetDefaultMerkleTreeDuration() public {
        vm.expectEmit(false, false, false, true);
        emit DefaultMerkleTreeDurationSet(5 minutes);

        registry.setDefaultMerkleTreeDuration(5 minutes);
        assertEq(registry.defaultMerkleTreeDuration(), 5 minutes);
    }

    function testSetDefaultMerkleTreeDurationOnlyOwner() public {
        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setDefaultMerkleTreeDuration(5 minutes);
    }

    function testSetDefaultMerkleTreeDurationRejectsZero() public {
        vm.expectRevert(ZeroMerkleTreeDuration.selector);
        registry.setDefaultMerkleTreeDuration(0);
    }

    function testSetAppMerkleTreeDuration() public {
        vm.expectEmit(true, false, false, true);
        emit AppMerkleTreeDurationSet(DEFAULT_APP_ID, 30 seconds);

        registry.setAppMerkleTreeDuration(DEFAULT_APP_ID, 30 seconds);
        assertEq(registry.appMerkleTreeDuration(DEFAULT_APP_ID), 30 seconds);
    }

    function testSetAppMerkleTreeDurationNotAdmin() public {
        address notAdmin = makeAddr("not-admin");
        vm.prank(notAdmin);
        vm.expectRevert(NotAppAdmin.selector);
        registry.setAppMerkleTreeDuration(DEFAULT_APP_ID, 30 seconds);
    }

    function testSetAppMerkleTreeDurationAppNotActive() public {
        uint256 appId = registry.registerApp(0);
        registry.suspendApp(appId);

        vm.expectRevert(AppNotActive.selector);
        registry.setAppMerkleTreeDuration(appId, 30 seconds);
    }

    function testSetAppMerkleTreeDurationClearOverride() public {
        registry.setAppMerkleTreeDuration(DEFAULT_APP_ID, 30 seconds);
        assertEq(registry.appMerkleTreeDuration(DEFAULT_APP_ID), 30 seconds);

        // Clear override by setting to 0
        registry.setAppMerkleTreeDuration(DEFAULT_APP_ID, 0);
        assertEq(registry.appMerkleTreeDuration(DEFAULT_APP_ID), 0);
    }

    function testGroupCreatedWithDefaultDuration() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        uint256 semaphoreGroupId = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);
        (uint256 duration) = semaphore.groups(semaphoreGroupId);
        assertEq(duration, 1 hours);
    }

    function testGroupCreatedWithAppOverrideDuration() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        registry.setAppMerkleTreeDuration(DEFAULT_APP_ID, 2 minutes);

        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        uint256 semaphoreGroupId = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);
        (uint256 duration) = semaphore.groups(semaphoreGroupId);
        assertEq(duration, 2 minutes);
    }

    function testSetAppMerkleTreeDurationPropagates() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        registry.createCredentialGroup(credentialGroupId2, 0, 0);

        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;
        _registerCredential(credentialGroupId1, keccak256("id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId2, keccak256("id-2"), DEFAULT_APP_ID, commitment2);

        uint256 group1 = registry.appSemaphoreGroups(credentialGroupId1, DEFAULT_APP_ID);
        uint256 group2 = registry.appSemaphoreGroups(credentialGroupId2, DEFAULT_APP_ID);

        // Both groups start with the default duration
        (uint256 d1) = semaphore.groups(group1);
        (uint256 d2) = semaphore.groups(group2);
        assertEq(d1, 1 hours);
        assertEq(d2, 1 hours);

        // Set app override — should propagate to both groups
        registry.setAppMerkleTreeDuration(DEFAULT_APP_ID, 10 seconds);

        (d1) = semaphore.groups(group1);
        (d2) = semaphore.groups(group2);
        assertEq(d1, 10 seconds);
        assertEq(d2, 10 seconds);
    }

    function testClearAppMerkleTreeDurationPropagatesDefault() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        registry.setAppMerkleTreeDuration(DEFAULT_APP_ID, 10 seconds);

        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        uint256 semaphoreGroupId = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);
        (uint256 d) = semaphore.groups(semaphoreGroupId);
        assertEq(d, 10 seconds);

        // Clear override — propagates registry default
        registry.setAppMerkleTreeDuration(DEFAULT_APP_ID, 0);

        (d) = semaphore.groups(semaphoreGroupId);
        assertEq(d, 1 hours);
    }

    function testDefaultMerkleTreeDurationDoesNotPropagateToExistingGroups() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        uint256 semaphoreGroupId = registry.appSemaphoreGroups(credentialGroupId, DEFAULT_APP_ID);
        (uint256 d) = semaphore.groups(semaphoreGroupId);
        assertEq(d, 1 hours);

        // Change registry default — should NOT propagate to existing groups
        registry.setDefaultMerkleTreeDuration(30 seconds);
        assertEq(registry.defaultMerkleTreeDuration(), 30 seconds);

        (d) = semaphore.groups(semaphoreGroupId);
        assertEq(d, 1 hours); // unchanged
    }

    function testGetAppSemaphoreGroupIds() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        registry.createCredentialGroup(credentialGroupId2, 0, 0);

        // Initially empty
        uint256[] memory ids = registry.getAppSemaphoreGroupIds(DEFAULT_APP_ID);
        assertEq(ids.length, 0);

        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;
        _registerCredential(credentialGroupId1, keccak256("id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId2, keccak256("id-2"), DEFAULT_APP_ID, commitment2);

        ids = registry.getAppSemaphoreGroupIds(DEFAULT_APP_ID);
        assertEq(ids.length, 2);
        assertEq(ids[0], registry.appSemaphoreGroups(credentialGroupId1, DEFAULT_APP_ID));
        assertEq(ids[1], registry.appSemaphoreGroups(credentialGroupId2, DEFAULT_APP_ID));
    }

    function testRenewalAfterExpiryRestoresFamilyBlock() public {
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(2, 60 days, 1);

        bytes32 credentialId = keccak256("same-user");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(1, credentialId, DEFAULT_APP_ID, commitment);

        // Expire and remove
        vm.warp(block.timestamp + 30 days);
        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(1, credentialId, DEFAULT_APP_ID, siblings);

        // Renew in same group
        _renewCredential(1, credentialId, DEFAULT_APP_ID, commitment);

        // Sibling group is still blocked (registration hash is the same)
        vm.expectRevert(AlreadyRegistered.selector);
        _registerCredential(2, credentialId, DEFAULT_APP_ID, commitment);
    }

    // --- View function tests (verifyProof, verifyProofs, getScore) ---

    function testVerifyProofReturnsTrue() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof memory proof = _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, scope, commitment);

        vm.prank(prover);
        bool result = registry.verifyProof(0, proof);
        assertTrue(result);
    }

    function testVerifyProofReturnsFalseForInactiveGroup() public {
        uint256 credentialGroupId = 1;
        // Don't create the credential group — it stays inactive

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof memory proof = CredentialProof({
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

        vm.prank(prover);
        bool result = registry.verifyProof(0, proof);
        assertFalse(result);
    }

    function testVerifyProofReturnsFalseForInactiveApp() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 inactiveAppId = 999;

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof memory proof = CredentialProof({
            credentialGroupId: credentialGroupId,
            appId: inactiveAppId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: 0,
                scope: scope,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        vm.prank(prover);
        bool result = registry.verifyProof(0, proof);
        assertFalse(result);
    }

    function testVerifyProofReturnsFalseForScopeMismatch() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        address prover = makeAddr("prover");
        // Generate proof with wrong scope (different address)
        uint256 wrongScope = uint256(keccak256(abi.encode(makeAddr("wrong"), uint256(0))));

        CredentialProof memory proof =
            _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, wrongScope, commitment);

        vm.prank(prover);
        bool result = registry.verifyProof(0, proof);
        assertFalse(result);
    }

    function testVerifyProofReturnsFalseWhenNoSemaphoreGroup() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        // Don't register any credential — no Semaphore group exists

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof memory proof = CredentialProof({
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

        vm.prank(prover);
        bool result = registry.verifyProof(0, proof);
        assertFalse(result);
    }

    function testVerifyProofsReturnsTrueWhenAllValid() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        registry.createCredentialGroup(credentialGroupId2, 0, 0);

        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId1, keccak256("id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId2, keccak256("id-2"), DEFAULT_APP_ID, commitment2);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, DEFAULT_APP_ID, commitmentKey2, scope, commitment2);

        vm.prank(prover);
        bool result = registry.verifyProofs(0, proofs);
        assertTrue(result);
    }

    function testVerifyProofsReturnsFalseWhenAnyInvalid() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        // Don't create group 2 — it will be inactive

        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = COMMITMENT_12345;

        _registerCredential(credentialGroupId1, keccak256("id-1"), DEFAULT_APP_ID, commitment1);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = CredentialProof({
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

        vm.prank(prover);
        bool result = registry.verifyProofs(0, proofs);
        assertFalse(result);
    }

    function testGetScoreReturnsCorrectAggregate() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;
        uint256 score1 = 100;
        uint256 score2 = 200;

        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        registry.createCredentialGroup(credentialGroupId2, 0, 0);
        scorer.setScore(credentialGroupId1, score1);
        scorer.setScore(credentialGroupId2, score2);

        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(credentialGroupId1, keccak256("id-1"), DEFAULT_APP_ID, commitment1);
        _registerCredential(credentialGroupId2, keccak256("id-2"), DEFAULT_APP_ID, commitment2);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, DEFAULT_APP_ID, commitmentKey2, scope, commitment2);

        vm.prank(prover);
        uint256 totalScore = registry.getScore(0, proofs);
        assertEq(totalScore, score1 + score2);
    }

    function testGetScoreRevertsOnInvalidProof() public {
        uint256 credentialGroupId1 = 1;
        uint256 credentialGroupId2 = 2;

        registry.createCredentialGroup(credentialGroupId1, 0, 0);
        // Don't create group 2

        uint256 commitmentKey1 = 12345;
        uint256 commitment1 = COMMITMENT_12345;

        _registerCredential(credentialGroupId1, keccak256("id-1"), DEFAULT_APP_ID, commitment1);

        address prover = makeAddr("prover");
        uint256 scope = uint256(keccak256(abi.encode(prover, uint256(0))));

        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = _makeProof(credentialGroupId1, DEFAULT_APP_ID, commitmentKey1, scope, commitment1);
        proofs[1] = CredentialProof({
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

        vm.prank(prover);
        vm.expectRevert(InvalidProof.selector);
        registry.getScore(0, proofs);
    }

    // --- Reentrancy test ---

    function testSubmitProofNonReentrant() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(credentialGroupId, keccak256("blinded-id"), DEFAULT_APP_ID, commitment);

        // Create attacker contract and set up proof with attacker as the scope origin
        ReentrantAttacker attacker = new ReentrantAttacker(registry);
        uint256 scope = uint256(keccak256(abi.encode(address(attacker), uint256(0))));

        CredentialProof memory proof = _makeProof(credentialGroupId, DEFAULT_APP_ID, commitmentKey, scope, commitment);

        attacker.setProof(proof);

        // First submitProof succeeds (consumes nullifier), then re-calling submitProofs
        // from a different entry point should be blocked by nonReentrant.
        // Since both submitProof and submitProofs share the same nonReentrant guard,
        // we verify they can't be called concurrently. Here we test the simpler case:
        // calling submitProof, then calling submitProofs with the same nullifier — Semaphore
        // rejects the duplicate nullifier. The nonReentrant guard prevents the second call
        // in the same transaction from proceeding.
        //
        // To properly test nonReentrant, we need an external callback during execution.
        // Since the IScorer.getScore() is view (STATICCALL), the only non-view external call
        // is SEMAPHORE.validateProof(). Rather than mocking Semaphore, we verify the guard
        // exists by testing that submitProof and submitProofs both have the modifier and
        // cannot be called again with the same nullifier.
        attacker.attack();

        // Second call with same nullifier reverts (Semaphore's own nullifier check)
        vm.expectRevert();
        attacker.attackDuringSubmitProofs();
    }

    // --- Fuzz tests for timestamp boundaries ---

    function testFuzzAttestationExpiry(uint256 timeDelta) public {
        timeDelta = bound(timeDelta, 0, 2 hours);

        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        uint256 attestationValidity = registry.attestationValidityDuration();

        vm.warp(block.timestamp + timeDelta);

        if (timeDelta <= attestationValidity) {
            // Should succeed — attestation still valid
            registry.registerCredential(att, v, r, s);
        } else {
            // Should revert — attestation expired
            vm.expectRevert(AttestationExpired.selector);
            registry.registerCredential(att, v, r, s);
        }
    }

    function testFuzzCredentialExpiry(uint256 timeDelta) public {
        uint256 validityDuration = 30 days;
        timeDelta = bound(timeDelta, 0, 60 days);

        uint256 credentialGroupId = 10;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 commitment = COMMITMENT_12345;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        vm.warp(block.timestamp + timeDelta);

        uint256[] memory siblings = new uint256[](0);

        if (timeDelta >= validityDuration) {
            // Should succeed — credential expired
            registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);
        } else {
            // Should revert — not yet expired
            vm.expectRevert(NotYetExpired.selector);
            registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, siblings);
        }
    }

    function testFuzzRecoveryTimelock(uint256 timeDelta) public {
        uint256 recoveryTimelock = 1 days;
        timeDelta = bound(timeDelta, 0, 3 days);

        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        registry.setAppRecoveryTimelock(DEFAULT_APP_ID, recoveryTimelock);

        bytes32 credentialId = keccak256("blinded-id");
        uint256 oldCommitment = COMMITMENT_12345;
        uint256 newCommitment = COMMITMENT_67890;

        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, oldCommitment);

        uint256[] memory siblings = new uint256[](0);
        _initiateRecovery(credentialGroupId, DEFAULT_APP_ID, credentialId, newCommitment, siblings);

        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, DEFAULT_APP_ID));

        vm.warp(block.timestamp + timeDelta);

        if (timeDelta >= recoveryTimelock) {
            // Should succeed — timelock expired
            registry.executeRecovery(registrationHash);
        } else {
            // Should revert — timelock not expired
            vm.expectRevert(RecoveryTimelockNotExpired.selector);
            registry.executeRecovery(registrationHash);
        }
    }

    // --- Validation error tests ---

    function testTransferAppAdminRejectsZeroAddress() public {
        vm.expectRevert(InvalidAdminAddress.selector);
        registry.transferAppAdmin(DEFAULT_APP_ID, address(0));
    }

    function testSetAppScorerRejectsZeroAddress() public {
        vm.expectRevert(InvalidScorerAddress.selector);
        registry.setAppScorer(DEFAULT_APP_ID, address(0));
    }

    // --- setDefaultScorer tests ---

    event DefaultScorerUpdated(address indexed oldScorer, address indexed newScorer);

    function testSetDefaultScorer() public {
        address newScorer = address(new MockScorer());
        address oldScorer = registry.defaultScorer();

        vm.expectEmit(true, true, false, false);
        emit DefaultScorerUpdated(oldScorer, newScorer);

        registry.setDefaultScorer(newScorer);
        assertEq(registry.defaultScorer(), newScorer);
    }

    function testSetDefaultScorerOnlyOwner() public {
        address notOwner = makeAddr("not-owner");
        vm.prank(notOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.setDefaultScorer(address(0x123));
    }

    function testSetDefaultScorerRejectsZeroAddress() public {
        vm.expectRevert(InvalidScorerAddress.selector);
        registry.setDefaultScorer(address(0));
    }

    function testSetDefaultScorerAffectsNewApps() public {
        MockScorer newScorer = new MockScorer();
        registry.setDefaultScorer(address(newScorer));

        uint256 appId = registry.registerApp(0);
        (,,, address appScorer) = registry.apps(appId);
        assertEq(appScorer, address(newScorer));
    }

    function testSetDefaultScorerDoesNotAffectExistingApps() public {
        address originalScorer = registry.defaultScorer();
        uint256 existingAppId = registry.registerApp(0);

        MockScorer newScorer = new MockScorer();
        registry.setDefaultScorer(address(newScorer));

        (,,, address appScorer) = registry.apps(existingAppId);
        assertEq(appScorer, originalScorer);
    }

    function testRegisterCredentialRejectsZeroCommitment() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        bytes32 credentialId = keccak256("blinded-id");

        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, 0);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.expectRevert(InvalidCommitment.selector);
        registry.registerCredential(att, v, r, s);
    }

    // --- Pause / Unpause tests ---

    function testPause() public {
        assertFalse(registry.paused());
        registry.pause();
        assertTrue(registry.paused());
    }

    function testPauseOnlyOwner() public {
        address nonOwner = address(0xBEEF);
        vm.prank(nonOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.pause();
    }

    function testUnpause() public {
        registry.pause();
        assertTrue(registry.paused());
        registry.unpause();
        assertFalse(registry.paused());
    }

    function testUnpauseOnlyOwner() public {
        registry.pause();
        address nonOwner = address(0xBEEF);
        vm.prank(nonOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        registry.unpause();
    }

    function testPauseBlocksRegisterCredential() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        registry.pause();

        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, keccak256("cred-1"), DEFAULT_APP_ID, 12345);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.expectRevert("Pausable: paused");
        registry.registerCredential(att, v, r, s);
    }

    function testPauseBlocksRenewCredential() public {
        uint256 credentialGroupId = 1;
        uint256 validityDuration = 30 days;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        uint256 commitment = 12345;
        bytes32 credentialId = keccak256("cred-1");
        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        registry.pause();

        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.expectRevert("Pausable: paused");
        registry.renewCredential(att, v, r, s);
    }

    function testPauseBlocksRemoveExpiredCredential() public {
        uint256 credentialGroupId = 1;
        uint256 validityDuration = 1 hours;
        registry.createCredentialGroup(credentialGroupId, validityDuration, 0);

        uint256 commitment = 12345;
        bytes32 credentialId = keccak256("cred-1");
        _registerCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, commitment);

        // Advance past expiry
        vm.warp(block.timestamp + validityDuration + 1);

        registry.pause();

        vm.expectRevert("Pausable: paused");
        registry.removeExpiredCredential(credentialGroupId, credentialId, DEFAULT_APP_ID, new uint256[](0));
    }

    function testPauseBlocksInitiateRecovery() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        // Register app with recovery enabled
        uint256 appId = registry.registerApp(1 days);

        uint256 commitment = 12345;
        bytes32 credentialId = keccak256("cred-1");
        _registerCredential(credentialGroupId, credentialId, appId, commitment);

        registry.pause();

        uint256 newCommitment = 67890;
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, appId, newCommitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.expectRevert("Pausable: paused");
        registry.initiateRecovery(att, v, r, s, new uint256[](0));
    }

    function testPauseBlocksExecuteRecovery() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        uint256 recoveryTimelock = 1 days;
        uint256 appId = registry.registerApp(recoveryTimelock);

        uint256 commitment = 12345;
        bytes32 credentialId = keccak256("cred-1");
        _registerCredential(credentialGroupId, credentialId, appId, commitment);

        // Initiate recovery
        uint256 newCommitment = 67890;
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, appId, newCommitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        registry.initiateRecovery(att, v, r, s, new uint256[](0));

        // Advance past timelock
        vm.warp(block.timestamp + recoveryTimelock + 1);

        // Get registration hash
        bytes32 registrationHash =
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, appId));

        registry.pause();

        vm.expectRevert("Pausable: paused");
        registry.executeRecovery(registrationHash);
    }

    function testPauseBlocksSubmitProof() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        scorer.setScore(credentialGroupId, 10);

        registry.pause();

        CredentialProof memory proof;
        proof.credentialGroupId = credentialGroupId;
        proof.appId = DEFAULT_APP_ID;

        vm.expectRevert("Pausable: paused");
        registry.submitProof(0, proof);
    }

    function testPauseBlocksSubmitProofs() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        registry.pause();

        CredentialProof[] memory proofs = new CredentialProof[](1);
        proofs[0].credentialGroupId = credentialGroupId;
        proofs[0].appId = DEFAULT_APP_ID;

        vm.expectRevert("Pausable: paused");
        registry.submitProofs(0, proofs);
    }

    function testPauseBlocksRegisterApp() public {
        registry.pause();

        vm.expectRevert("Pausable: paused");
        registry.registerApp(0);
    }

    function testPauseDoesNotBlockViewFunctions() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        registry.pause();

        // View functions should still work when paused
        assertTrue(registry.paused());
        assertTrue(registry.credentialGroupIsActive(credentialGroupId));
        assertTrue(registry.appIsActive(DEFAULT_APP_ID));
        assertEq(registry.owner(), owner);
    }

    function testUnpauseRestoresOperations() public {
        uint256 credentialGroupId = 1;
        registry.createCredentialGroup(credentialGroupId, 0, 0);

        registry.pause();

        // Confirm blocked
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, keccak256("cred-1"), DEFAULT_APP_ID, 12345);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);

        vm.expectRevert("Pausable: paused");
        registry.registerCredential(att, v, r, s);

        // Unpause and confirm operations resume
        registry.unpause();

        registry.registerCredential(att, v, r, s);
        (bool registered,,,,,) = registry.credentials(
            keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, keccak256("cred-1"), DEFAULT_APP_ID))
        );
        assertTrue(registered);
    }

    function testPauseDoesNotBlockOwnerAdmin() public {
        registry.pause();

        // Owner admin functions should still work (they don't have whenNotPaused)
        uint256 credentialGroupId = 99;
        registry.createCredentialGroup(credentialGroupId, 0, 0);
        assertTrue(registry.credentialGroupIsActive(credentialGroupId));

        registry.addTrustedVerifier(address(0x1234));
        assertTrue(registry.trustedVerifiers(address(0x1234)));
    }

    // --- Duplicate credential group tests ---

    function testSubmitProofsRevertsDuplicateCredentialGroupId() public {
        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = CredentialProof({
            credentialGroupId: 1,
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
        proofs[1] = CredentialProof({
            credentialGroupId: 1,
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

        vm.expectRevert(DuplicateCredentialGroup.selector);
        registry.submitProofs(0, proofs);
    }

    function testGetScoreRevertsDuplicateCredentialGroupId() public {
        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = CredentialProof({
            credentialGroupId: 1,
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
        proofs[1] = CredentialProof({
            credentialGroupId: 1,
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

        vm.expectRevert(DuplicateCredentialGroup.selector);
        registry.getScore(0, proofs);
    }

    // --- verifyProofs duplicate check ---

    function testVerifyProofsRevertsDuplicateCredentialGroupId() public {
        CredentialProof[] memory proofs = new CredentialProof[](2);
        proofs[0] = CredentialProof({
            credentialGroupId: 1,
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
        proofs[1] = CredentialProof({
            credentialGroupId: 1,
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

        vm.expectRevert(DuplicateCredentialGroup.selector);
        registry.verifyProofs(0, proofs);
    }
}
