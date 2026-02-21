// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {CredentialRegistry} from "../../contracts/registry/CredentialRegistry.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";
import {ICredentialRegistry} from "@bringid/contracts/interfaces/ICredentialRegistry.sol";
import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "@semaphore-protocol/contracts/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "@semaphore-protocol/contracts/base/SemaphoreVerifier.sol";
import {Semaphore} from "@semaphore-protocol/contracts/Semaphore.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {RegistryHandler} from "./RegistryHandler.sol";

/// @notice Invariant tests for CredentialRegistry critical properties.
contract InvariantRegistryTest is Test {
    using ECDSA for bytes32;

    CredentialRegistry registry;
    DefaultScorer scorer;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;
    RegistryHandler handler;

    address owner;
    address trustedVerifier;
    uint256 trustedVerifierPrivateKey;

    function setUp() public {
        owner = address(this);
        (trustedVerifier, trustedVerifierPrivateKey) = makeAddrAndKey("trusted-verifier");

        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier, 1 hours);
        scorer = DefaultScorer(registry.defaultScorer());

        // Create credential groups (owner = this contract)
        registry.createCredentialGroup(1, 30 days, 1); // family 1
        registry.createCredentialGroup(2, 30 days, 1); // family 1
        registry.createCredentialGroup(3, 60 days, 0); // standalone
        registry.createCredentialGroup(4, 0, 0); // standalone, no expiry
        registry.createCredentialGroup(5, 90 days, 2); // family 2

        // Register apps with recovery timelock enabled
        uint256[] memory appIdsArr = new uint256[](3);
        for (uint256 i; i < 3; i++) {
            appIdsArr[i] = registry.registerApp(1 hours);
        }

        uint256[] memory groupIds = new uint256[](5);
        groupIds[0] = 1;
        groupIds[1] = 2;
        groupIds[2] = 3;
        groupIds[3] = 4;
        groupIds[4] = 5;

        handler = new RegistryHandler(registry, trustedVerifierPrivateKey);
        handler.initialize(groupIds, appIdsArr);

        // Focus fuzzing on specific handler selectors
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = handler.registerCredential.selector;
        selectors[1] = handler.renewCredential.selector;
        selectors[2] = handler.removeExpiredCredential.selector;
        selectors[3] = handler.initiateRecovery.selector;
        selectors[4] = handler.executeRecovery.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    // ──────────────────────────────────────────────
    //  Existing invariants (1–4)
    // ──────────────────────────────────────────────

    /// @notice Registration uniqueness: a registration hash can only have registered=true once
    ///         without going through the full unregister flow. Double-registering the same hash must fail.
    function invariant_registrationUniqueness() public view {
        bytes32[] memory hashes = handler.getRegistrationHashes();
        for (uint256 i; i < hashes.length; i++) {
            (bool registered,,,,,) = registry.credentials(hashes[i]);
            assertTrue(registered, "tracked hash must be registered");
        }
        // The count of unique registered hashes must match the handler's tracking
        assertEq(handler.registrationCount(), hashes.length);
    }

    /// @notice Commitment continuity: the stored commitment for a registration hash
    ///         never becomes zero once registered (it persists through expiry and renewal).
    function invariant_commitmentNonZero() public view {
        bytes32[] memory hashes = handler.getRegistrationHashes();
        for (uint256 i; i < hashes.length; i++) {
            (,, uint256 commitment,,,) = registry.credentials(hashes[i]);
            assertGt(commitment, 0, "commitment must never be zero after registration");
        }
    }

    /// @notice Family constraint: within a single family and app, only one credential
    ///         can be registered per credentialId. Since family groups share a registration hash,
    ///         the handler tracks (familyId, credentialId, appId) tuples and ensures no duplicates.
    function invariant_familyConstraint() public view {
        // The handler enforces this by tracking family slots. If we get here without reverts,
        // it means no double-registration within a family was possible.
        // Verify all family registrations are unique by checking the handler's family slot count.
        assertEq(handler.familySlotCount(), handler.uniqueFamilySlots());
    }

    /// @notice Credential group ID stored in the record must match what was registered.
    function invariant_credentialGroupIdConsistency() public view {
        bytes32[] memory hashes = handler.getRegistrationHashes();
        uint256[] memory expectedGroups = handler.getExpectedCredentialGroupIds();
        for (uint256 i; i < hashes.length; i++) {
            (,,,, uint256 credentialGroupId,) = registry.credentials(hashes[i]);
            assertEq(credentialGroupId, expectedGroups[i], "credential group ID mismatch");
        }
    }

    // ──────────────────────────────────────────────
    //  New invariants (5–8)
    // ──────────────────────────────────────────────

    /// @notice Commitment continuity: for every ghost credential, the on-chain commitment
    ///         must always match the handler's tracked commitment. After registration the
    ///         commitment is the original value; after recovery execution it is the new value;
    ///         renewal and expiry never change the commitment.
    function invariant_commitmentContinuity() public view {
        uint256 count = handler.ghostCredentialCount();
        for (uint256 i; i < count; i++) {
            (bytes32 regHash,, uint256 ghostCommitment,,,) = handler.getGhostCredential(i);
            (,, uint256 onChainCommitment,,,) = registry.credentials(regHash);
            assertEq(onChainCommitment, ghostCommitment, "commitment must match ghost state");
        }
    }

    /// @notice Pending recovery clears after execution: when the handler marks a recovery as
    ///         complete, the on-chain pendingRecovery.executeAfter must be 0. When pending,
    ///         the on-chain executeAfter must match the ghost state.
    function invariant_pendingRecoveryClearsAfterExecution() public view {
        uint256 count = handler.ghostCredentialCount();
        for (uint256 i; i < count; i++) {
            (bytes32 regHash,,,, bool hasPending, uint256 ghostExecuteAfter) = handler.getGhostCredential(i);
            (,,,,, ICredentialRegistry.RecoveryRequest memory req) = registry.credentials(regHash);
            if (!hasPending) {
                assertEq(req.executeAfter, 0, "pendingRecovery must be cleared after execution");
            } else {
                assertEq(req.executeAfter, ghostExecuteAfter, "pending recovery executeAfter mismatch");
            }
        }
    }

    /// @notice Expired flag consistency: if a credential is expired on-chain, it must still
    ///         be registered (expired implies was-registered). Additionally, the on-chain
    ///         expired flag must match the handler's ghost state at all times.
    function invariant_expiredFlagConsistency() public view {
        uint256 count = handler.ghostCredentialCount();
        for (uint256 i; i < count; i++) {
            (bytes32 regHash,,, bool ghostExpired,,) = handler.getGhostCredential(i);
            (bool registered, bool onChainExpired,,,,) = registry.credentials(regHash);
            // Expired implies registered
            if (onChainExpired) {
                assertTrue(registered, "expired credential must be registered");
            }
            // Ghost and on-chain expired flags must agree
            assertEq(onChainExpired, ghostExpired, "expired flag must match ghost state");
        }
    }

    /// @notice No double registration: all tracked registration hashes are registered
    ///         exactly once. The handler skips already-registered hashes, so the count of
    ///         tracked hashes must equal the ghost credential count, and each must be
    ///         registered on-chain.
    function invariant_noDoubleRegistration() public view {
        bytes32[] memory hashes = handler.getRegistrationHashes();
        uint256 ghostCount = handler.ghostCredentialCount();
        // Ghost credentials and registration hashes grow together (only during registerCredential)
        assertEq(hashes.length, ghostCount, "ghost count must match registration hash count");
        for (uint256 i; i < ghostCount; i++) {
            (bool registered,,,,,) = registry.credentials(hashes[i]);
            assertTrue(registered, "each tracked hash must be registered on-chain");
        }
    }
}
