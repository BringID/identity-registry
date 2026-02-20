// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../contracts/registry/CredentialRegistry.sol";
import {ICredentialRegistry, CredentialGroupProof} from "@bringid/contracts/interfaces/ICredentialRegistry.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";
import {SimpleAirdrop} from "@bringid/contracts/examples/SimpleAirdrop.sol";
import {BringIDGated} from "@bringid/contracts/BringIDGated.sol";
import {IBringIDGated} from "@bringid/contracts/interfaces/IBringIDGated.sol";
import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "@semaphore-protocol/contracts/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "@semaphore-protocol/contracts/base/SemaphoreVerifier.sol";
import {Semaphore} from "@semaphore-protocol/contracts/Semaphore.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";

contract BringIDGatedTest is Test {
    using ECDSA for bytes32;

    // Pre-computed Semaphore commitment for deterministic test key (avoids FFI per-test).
    // Generated via: Identity.import(ethers.zeroPadValue(ethers.toBeHex(12345), 32)).commitment
    uint256 constant COMMITMENT_12345 = 3757495654825671944221025502932027603093002514688471603980596532070551940856;
    // Generated via: Identity.import(ethers.zeroPadValue(ethers.toBeHex(67890), 32)).commitment
    uint256 constant COMMITMENT_67890 = 1627838166670782884016414820331096838803092519983728431519200514911855753278;

    CredentialRegistry registry;
    DefaultScorer scorer;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;
    SimpleAirdrop airdrop;

    address owner;
    address trustedVerifier;
    uint256 trustedVerifierPrivateKey;

    uint256 appId;
    uint256 constant CREDENTIAL_GROUP_ID = 1;
    uint256 constant SCORE = 100;
    uint256 constant MIN_SCORE = 50;

    function setUp() public {
        owner = address(this);
        (trustedVerifier, trustedVerifierPrivateKey) = makeAddrAndKey("trusted-verifier");

        // Deploy Semaphore infrastructure
        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier, 1 hours);

        scorer = DefaultScorer(registry.defaultScorer());

        // Create credential group and set score
        registry.createCredentialGroup(CREDENTIAL_GROUP_ID, 0, 0);
        scorer.setScore(CREDENTIAL_GROUP_ID, SCORE);

        // Register app (caller = owner = admin)
        appId = registry.registerApp(0);

        // Deploy SimpleAirdrop pinned to appId
        airdrop = new SimpleAirdrop(ICredentialRegistry(address(registry)), MIN_SCORE, appId);
    }

    // --- Helper functions ---

    function _createAttestation(uint256 credentialGroupId, bytes32 credentialId, uint256 appId_, uint256 commitment)
        internal
        view
        returns (ICredentialRegistry.Attestation memory)
    {
        return ICredentialRegistry.Attestation({
            registry: address(registry),
            chainId: block.chainid,
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: appId_,
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

    function _registerCredential(uint256 credentialGroupId, bytes32 credentialId, uint256 appId_, uint256 commitment)
        internal
    {
        ICredentialRegistry.Attestation memory att =
            _createAttestation(credentialGroupId, credentialId, appId_, commitment);
        (uint8 v, bytes32 r, bytes32 s) = _signAttestation(att);
        registry.registerCredential(att, v, r, s);
    }

    function _makeProofWithMessage(
        uint256 credentialGroupId,
        uint256 appId_,
        uint256 commitmentKey,
        uint256 scope,
        uint256 message,
        uint256 commitment
    ) internal returns (CredentialGroupProof memory) {
        uint256[] memory comms = new uint256[](1);
        comms[0] = commitment;
        (uint256 depth, uint256 root, uint256 nullifier, uint256 msg_, uint256[8] memory pts) =
            TestUtils.semaphoreProofWithMessage(commitmentKey, scope, message, comms);
        return CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            appId: appId_,
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

    function _makeProof(
        uint256 credentialGroupId,
        uint256 appId_,
        uint256 commitmentKey,
        uint256 scope,
        uint256 commitment
    ) internal returns (CredentialGroupProof memory) {
        uint256[] memory comms = new uint256[](1);
        comms[0] = commitment;
        (uint256 depth, uint256 root, uint256 nullifier, uint256 msg_, uint256[8] memory pts) =
            TestUtils.semaphoreProof(commitmentKey, scope, comms);
        return CredentialGroupProof({
            credentialGroupId: credentialGroupId,
            appId: appId_,
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

    // --- Tests ---

    function testClaimWithCorrectMessageBinding() public {
        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        address alice = makeAddr("alice");
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), 0)));
        uint256 message = uint256(keccak256(abi.encodePacked(alice)));

        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](1);
        proofs[0] = _makeProofWithMessage(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, message, commitment);

        airdrop.claim(alice, proofs);

        assertTrue(airdrop.claimed(alice));
    }

    function testClaimRevertsOnMessageMismatch() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        // Build a dummy proof with message bound to bob (wrong recipient for alice claim)
        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](1);
        proofs[0] = CredentialGroupProof({
            credentialGroupId: CREDENTIAL_GROUP_ID,
            appId: appId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: uint256(keccak256(abi.encodePacked(bob))),
                scope: 0,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        uint256 expectedMsg = uint256(keccak256(abi.encodePacked(alice)));
        uint256 actualMsg = uint256(keccak256(abi.encodePacked(bob)));

        vm.expectRevert(abi.encodeWithSelector(IBringIDGated.WrongProofRecipient.selector, expectedMsg, actualMsg));
        airdrop.claim(alice, proofs);
    }

    function testClaimRevertsOnZeroRecipient() public {
        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](1);
        proofs[0] = CredentialGroupProof({
            credentialGroupId: CREDENTIAL_GROUP_ID,
            appId: appId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: 0,
                scope: 0,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        vm.expectRevert(IBringIDGated.ZeroRecipient.selector);
        airdrop.claim(address(0), proofs);
    }

    function testFrontRunningPrevented() public {
        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), 0)));
        uint256 aliceMessage = uint256(keccak256(abi.encodePacked(alice)));

        // Alice generates a proof bound to herself
        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](1);
        proofs[0] = _makeProofWithMessage(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, aliceMessage, commitment);

        // Bob copies the proof and tries to claim for himself — reverts because message is bound to alice
        uint256 expectedMsg = uint256(keccak256(abi.encodePacked(bob)));
        uint256 actualMsg = proofs[0].semaphoreProof.message;

        vm.expectRevert(abi.encodeWithSelector(IBringIDGated.WrongProofRecipient.selector, expectedMsg, actualMsg));
        airdrop.claim(bob, proofs);

        // Alice's claim succeeds
        airdrop.claim(alice, proofs);
        assertTrue(airdrop.claimed(alice));
        assertFalse(airdrop.claimed(bob));
    }

    function testMultipleProofsOneMismatchReverts() public {
        uint256 credentialGroupId2 = 2;
        registry.createCredentialGroup(credentialGroupId2, 0, 0);

        address alice = makeAddr("alice");
        uint256 correctMessage = uint256(keccak256(abi.encodePacked(alice)));
        uint256 wrongMessage = uint256(keccak256(abi.encodePacked(makeAddr("wrong"))));

        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](2);
        // First proof has correct message
        proofs[0] = CredentialGroupProof({
            credentialGroupId: CREDENTIAL_GROUP_ID,
            appId: appId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: correctMessage,
                scope: 0,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });
        // Second proof has wrong message and different credential group
        proofs[1] = CredentialGroupProof({
            credentialGroupId: credentialGroupId2,
            appId: appId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: wrongMessage,
                scope: 0,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        vm.expectRevert(
            abi.encodeWithSelector(IBringIDGated.WrongProofRecipient.selector, correctMessage, wrongMessage)
        );
        airdrop.claim(alice, proofs);
    }

    function testAlreadyClaimedReverts() public {
        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        address alice = makeAddr("alice");
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), 0)));
        uint256 message = uint256(keccak256(abi.encodePacked(alice)));

        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](1);
        proofs[0] = _makeProofWithMessage(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, message, commitment);

        // First claim succeeds
        airdrop.claim(alice, proofs);
        assertTrue(airdrop.claimed(alice));

        // Second claim reverts
        vm.expectRevert(SimpleAirdrop.AlreadyClaimed.selector);
        airdrop.claim(alice, proofs);
    }

    function testClaimRevertsOnWrongAppId() public {
        // Register a second app
        uint256 attackerAppId = registry.registerApp(0);

        address alice = makeAddr("alice");
        uint256 correctMessage = uint256(keccak256(abi.encodePacked(alice)));

        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](1);
        proofs[0] = CredentialGroupProof({
            credentialGroupId: CREDENTIAL_GROUP_ID,
            appId: attackerAppId,
            semaphoreProof: ISemaphore.SemaphoreProof({
                merkleTreeDepth: 0,
                merkleTreeRoot: 0,
                nullifier: 0,
                message: correctMessage,
                scope: 0,
                points: [uint256(0), 0, 0, 0, 0, 0, 0, 0]
            })
        });

        vm.expectRevert(abi.encodeWithSelector(IBringIDGated.AppIdMismatch.selector, appId, attackerAppId));
        airdrop.claim(alice, proofs);
    }

    function testInsufficientScoreReverts() public {
        // Set score below minimum
        scorer.setScore(CREDENTIAL_GROUP_ID, MIN_SCORE - 1);

        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        address alice = makeAddr("alice");
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), 0)));
        uint256 message = uint256(keccak256(abi.encodePacked(alice)));

        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](1);
        proofs[0] = _makeProofWithMessage(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, message, commitment);

        vm.expectRevert(abi.encodeWithSelector(SimpleAirdrop.InsufficientScore.selector, MIN_SCORE - 1, MIN_SCORE));
        airdrop.claim(alice, proofs);
    }

    // --- View function tests (verifyProof / verifyProofs / getScore via BringIDGated) ---

    function testVerifyProofViaBringIDGated() public {
        uint256 commitmentKey = 12345;
        uint256 commitment = COMMITMENT_12345;
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        // Scope is bound to airdrop contract address (msg.sender inside registry call)
        uint256 context = 42;
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), context)));

        CredentialGroupProof memory proof = _makeProof(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, commitment);

        // Off-chain caller can verify through the BringIDGated consumer
        address offChainCaller = makeAddr("off-chain-caller");
        vm.prank(offChainCaller);
        bool result = airdrop.verifyProof(context, proof);
        assertTrue(result);
    }

    function testVerifyProofsViaBringIDGated() public {
        uint256 credentialGroupId2 = 2;
        registry.createCredentialGroup(credentialGroupId2, 0, 0);

        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("id-1"), appId, commitment1);
        _registerCredential(credentialGroupId2, keccak256("id-2"), appId, commitment2);

        uint256 context = 42;
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), context)));

        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](2);
        proofs[0] = _makeProof(CREDENTIAL_GROUP_ID, appId, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, appId, commitmentKey2, scope, commitment2);

        address offChainCaller = makeAddr("off-chain-caller");
        vm.prank(offChainCaller);
        bool result = airdrop.verifyProofs(context, proofs);
        assertTrue(result);
    }

    function testGetScoreViaBringIDGated() public {
        uint256 credentialGroupId2 = 2;
        uint256 score1 = 100;
        uint256 score2 = 200;

        registry.createCredentialGroup(credentialGroupId2, 0, 0);
        scorer.setScore(CREDENTIAL_GROUP_ID, score1);
        scorer.setScore(credentialGroupId2, score2);

        uint256 commitmentKey1 = 12345;
        uint256 commitmentKey2 = 67890;
        uint256 commitment1 = COMMITMENT_12345;
        uint256 commitment2 = COMMITMENT_67890;

        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("id-1"), appId, commitment1);
        _registerCredential(credentialGroupId2, keccak256("id-2"), appId, commitment2);

        uint256 context = 42;
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), context)));

        CredentialGroupProof[] memory proofs = new CredentialGroupProof[](2);
        proofs[0] = _makeProof(CREDENTIAL_GROUP_ID, appId, commitmentKey1, scope, commitment1);
        proofs[1] = _makeProof(credentialGroupId2, appId, commitmentKey2, scope, commitment2);

        address offChainCaller = makeAddr("off-chain-caller");
        vm.prank(offChainCaller);
        uint256 totalScore = airdrop.getScore(context, proofs);
        assertEq(totalScore, score1 + score2);
    }
}
