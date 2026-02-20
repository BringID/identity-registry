// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {CredentialRegistry} from "../../contracts/registry/CredentialRegistry.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";
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

        // Register apps
        uint256[] memory appIds = new uint256[](3);
        for (uint256 i; i < 3; i++) {
            appIds[i] = registry.registerApp(1 hours);
        }

        uint256[] memory groupIds = new uint256[](5);
        groupIds[0] = 1;
        groupIds[1] = 2;
        groupIds[2] = 3;
        groupIds[3] = 4;
        groupIds[4] = 5;

        handler = new RegistryHandler(registry, trustedVerifierPrivateKey);
        handler.initialize(groupIds, appIds);

        // Focus fuzzing on the handler
        targetContract(address(handler));
    }

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
}
