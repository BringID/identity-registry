// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "@bringid/contracts/ICredentialRegistry.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";
import {SafeAirdrop} from "@bringid/contracts/examples/SafeAirdrop.sol";
import {SafeProofConsumer} from "@bringid/contracts/SafeProofConsumer.sol";
import {ScoreGated} from "@bringid/contracts/ScoreGated.sol";
import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "@semaphore-protocol/contracts/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "@semaphore-protocol/contracts/base/SemaphoreVerifier.sol";
import {Semaphore} from "@semaphore-protocol/contracts/Semaphore.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TestUtils} from "./TestUtils.sol";

contract SafeProofConsumerTest is Test {
    using ECDSA for bytes32;

    CredentialRegistry registry;
    DefaultScorer scorer;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;
    SafeAirdrop airdrop;

    address owner;
    address trustedVerifier;
    uint256 trustedVerifierPrivateKey;

    uint256 appId;
    uint256 constant CREDENTIAL_GROUP_ID = 1;
    uint256 constant SCORE = 100;
    uint256 constant MIN_SCORE = 50;
    uint256 constant CONTEXT = 42;

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

        // Deploy SafeAirdrop pinned to appId
        airdrop = new SafeAirdrop(ICredentialRegistry(address(registry)), MIN_SCORE, CONTEXT, appId, 15);
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
    ) internal returns (ICredentialRegistry.CredentialGroupProof memory) {
        uint256[] memory comms = new uint256[](1);
        comms[0] = commitment;
        (uint256 depth, uint256 root, uint256 nullifier, uint256 msg_, uint256[8] memory pts) =
            TestUtils.semaphoreProofWithMessage(commitmentKey, scope, message, comms);
        return ICredentialRegistry.CredentialGroupProof({
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
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        address alice = makeAddr("alice");
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), CONTEXT)));
        uint256 message = airdrop.expectedMessage(alice);

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = _makeProofWithMessage(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, message, commitment);

        airdrop.claim(alice, proofs);

        assertTrue(airdrop.claimed(alice));
    }

    function testClaimRevertsOnMessageMismatch() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        // Build a dummy proof with message bound to bob (wrong recipient for alice claim)
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = ICredentialRegistry.CredentialGroupProof({
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

        vm.expectRevert(
            abi.encodeWithSelector(SafeProofConsumer.MessageBindingMismatch.selector, expectedMsg, actualMsg)
        );
        airdrop.claim(alice, proofs);
    }

    function testClaimRevertsOnZeroRecipient() public {
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = ICredentialRegistry.CredentialGroupProof({
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

        vm.expectRevert(SafeProofConsumer.ZeroRecipient.selector);
        airdrop.claim(address(0), proofs);
    }

    function testFrontRunningPrevented() public {
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), CONTEXT)));
        uint256 aliceMessage = airdrop.expectedMessage(alice);

        // Alice generates a proof bound to herself
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = _makeProofWithMessage(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, aliceMessage, commitment);

        // Bob copies the proof and tries to claim for himself — reverts because message is bound to alice
        uint256 expectedMsg = uint256(keccak256(abi.encodePacked(bob)));
        uint256 actualMsg = proofs[0].semaphoreProof.message;

        vm.expectRevert(
            abi.encodeWithSelector(SafeProofConsumer.MessageBindingMismatch.selector, expectedMsg, actualMsg)
        );
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

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](2);
        // First proof has correct message
        proofs[0] = ICredentialRegistry.CredentialGroupProof({
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
        proofs[1] = ICredentialRegistry.CredentialGroupProof({
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
            abi.encodeWithSelector(SafeProofConsumer.MessageBindingMismatch.selector, correctMessage, wrongMessage)
        );
        airdrop.claim(alice, proofs);
    }

    function testExpectedMessageComputation() public {
        address addr = makeAddr("test-addr");
        uint256 expected = uint256(keccak256(abi.encodePacked(addr)));
        assertEq(airdrop.expectedMessage(addr), expected);
    }

    function testAlreadyClaimedReverts() public {
        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        address alice = makeAddr("alice");
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), CONTEXT)));
        uint256 message = airdrop.expectedMessage(alice);

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = _makeProofWithMessage(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, message, commitment);

        // First claim succeeds
        airdrop.claim(alice, proofs);
        assertTrue(airdrop.claimed(alice));

        // Second claim reverts
        vm.expectRevert(SafeAirdrop.AlreadyClaimed.selector);
        airdrop.claim(alice, proofs);
    }

    function testClaimRevertsOnWrongAppId() public {
        // Register a second app
        uint256 attackerAppId = registry.registerApp(0);

        address alice = makeAddr("alice");
        uint256 correctMessage = uint256(keccak256(abi.encodePacked(alice)));

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = ICredentialRegistry.CredentialGroupProof({
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

        vm.expectRevert(abi.encodeWithSelector(ScoreGated.AppIdMismatch.selector, appId, attackerAppId));
        airdrop.claim(alice, proofs);
    }

    function testClaimRevertsTooManyProofs() public {
        address alice = makeAddr("alice");
        uint256 correctMessage = uint256(keccak256(abi.encodePacked(alice)));

        // Create 16 proofs (exceeds MAX_PROOFS = 15)
        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](16);
        for (uint256 i = 0; i < 16; i++) {
            proofs[i] = ICredentialRegistry.CredentialGroupProof({
                credentialGroupId: i + 1,
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
        }

        vm.expectRevert(ScoreGated.TooManyProofs.selector);
        airdrop.claim(alice, proofs);
    }

    function testInsufficientScoreReverts() public {
        // Set score below minimum
        scorer.setScore(CREDENTIAL_GROUP_ID, MIN_SCORE - 1);

        uint256 commitmentKey = 12345;
        uint256 commitment = TestUtils.semaphoreCommitment(commitmentKey);
        _registerCredential(CREDENTIAL_GROUP_ID, keccak256("cred-1"), appId, commitment);

        address alice = makeAddr("alice");
        uint256 scope = uint256(keccak256(abi.encode(address(airdrop), CONTEXT)));
        uint256 message = airdrop.expectedMessage(alice);

        ICredentialRegistry.CredentialGroupProof[] memory proofs = new ICredentialRegistry.CredentialGroupProof[](1);
        proofs[0] = _makeProofWithMessage(CREDENTIAL_GROUP_ID, appId, commitmentKey, scope, message, commitment);

        vm.expectRevert(abi.encodeWithSelector(ScoreGated.InsufficientScore.selector, MIN_SCORE - 1, MIN_SCORE));
        airdrop.claim(alice, proofs);
    }
}
