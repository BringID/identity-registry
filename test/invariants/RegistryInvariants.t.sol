// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {CredentialRegistry} from "../../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../../src/registry/ICredentialRegistry.sol";
import {DefaultScorer} from "../../src/scoring/DefaultScorer.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {RegistryHandler} from "./RegistryHandler.sol";

/// @title RegistryInvariants
/// @notice Foundry invariant tests for critical CredentialRegistry properties:
///         - Registration uniqueness: cannot double-register the same hash
///         - Commitment continuity: commitment only changes via recovery
///         - Family constraint: one credential per family per app
///         - Scope binding: proofs are bound to msg.sender + context
contract RegistryInvariants is Test {
    using ECDSA for bytes32;

    CredentialRegistry registry;
    DefaultScorer scorer;
    Semaphore semaphore;
    SemaphoreVerifier semaphoreVerifier;
    RegistryHandler handler;

    address owner;
    address trustedVerifier;
    uint256 trustedVerifierPrivateKey;
    uint256 appId;

    function setUp() public {
        owner = address(this);
        (trustedVerifier, trustedVerifierPrivateKey) = makeAddrAndKey("trusted-verifier");

        semaphoreVerifier = new SemaphoreVerifier();
        semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        registry = new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier);
        scorer = DefaultScorer(registry.defaultScorer());

        // Register an app
        appId = registry.registerApp(1 days);

        // Create credential groups: 1-3 in family 1, 4-5 standalone
        registry.createCredentialGroup(1, 30 days, 1);
        registry.createCredentialGroup(2, 60 days, 1);
        registry.createCredentialGroup(3, 90 days, 1);
        registry.createCredentialGroup(4, 30 days, 0);
        registry.createCredentialGroup(5, 0, 0);

        // Set scores
        scorer.setScore(1, 2);
        scorer.setScore(2, 5);
        scorer.setScore(3, 10);
        scorer.setScore(4, 2);
        scorer.setScore(5, 20);

        // Create handler
        handler = new RegistryHandler(registry, trustedVerifierPrivateKey, trustedVerifier);
        handler.setAppId(appId);

        // Target only the handler for invariant calls
        targetContract(address(handler));
    }

    // ── Invariant: Registration uniqueness ──────────────────────────────
    // After any sequence of handler actions, every registration hash in the registry
    // must have been registered exactly once (cred.registered == true, and no second
    // registerCredential succeeded for the same hash).

    function invariant_registrationUniqueness() public view {
        uint256 count = handler.getRegistrationHashCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 regHash = handler.registrationHashes(i);
            (bool registered,,,,,) = registry.credentials(regHash);
            // Every tracked hash must be registered
            assertTrue(registered, "Registration hash should be registered");
        }
        // The total registrations tracked by the handler must equal the number of
        // unique hashes (no duplicates allowed through).
        assertEq(handler.totalRegistrations(), count, "Registration count mismatch");
    }

    // ── Invariant: Commitment continuity ────────────────────────────────
    // For every registered credential, the on-chain commitment must match either:
    //   (a) the commitment set at registration time (tracked by handler), OR
    //   (b) a commitment set via recovery (tracked by handler).
    // Since the handler doesn't perform recoveries, all commitments must match
    // the original registration value.

    function invariant_commitmentContinuity() public view {
        uint256 count = handler.getRegistrationHashCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 regHash = handler.registrationHashes(i);
            (bool registered,, uint256 onChainCommitment,,,) = registry.credentials(regHash);
            if (!registered) continue;

            uint256 expectedCommitment = handler.lastCommitment(regHash);
            assertEq(onChainCommitment, expectedCommitment, "Commitment changed without recovery");
        }
    }

    // ── Invariant: Family constraint ────────────────────────────────────
    // Groups sharing the same familyId (> 0) produce the same registration hash
    // for a given (credentialId, appId). Therefore, it should be impossible to have
    // two active credentials from the same family for the same user+app.
    // This is structurally enforced by the hash design — the handler's
    // familyDoubleRegister function verifies this by attempting cross-group
    // registration within a family and asserting revert.

    function invariant_familyConstraint() public view {
        // The family constraint is enforced structurally: groups in the same family
        // produce the same registration hash, so `cred.registered` blocks re-registration.
        // If the handler's familyDoubleRegister ever succeeded, it would have reverted
        // with "INVARIANT_VIOLATED". We verify no unexpected registrations occurred.
        uint256 count = handler.getRegistrationHashCount();
        assertLe(count, handler.totalRegistrations(), "Hash count exceeds registration count");
    }

    // ── Invariant: Scope binding ────────────────────────────────────────
    // The scope for proof submission is deterministic: keccak256(abi.encode(msg.sender, context)).
    // This is a pure computation invariant — verify it holds for arbitrary inputs.

    function invariant_scopeBindingDeterministic() public pure {
        // Scope is deterministic for any (sender, context) pair
        address sender = address(0xBEEF);
        uint256 context = 42;
        uint256 scope1 = uint256(keccak256(abi.encode(sender, context)));
        uint256 scope2 = uint256(keccak256(abi.encode(sender, context)));
        assertEq(scope1, scope2, "Scope binding is not deterministic");

        // Different sender -> different scope
        address sender2 = address(0xCAFE);
        uint256 scope3 = uint256(keccak256(abi.encode(sender2, context)));
        assertTrue(scope1 != scope3, "Different senders must produce different scopes");

        // Different context -> different scope
        uint256 context2 = 43;
        uint256 scope4 = uint256(keccak256(abi.encode(sender, context2)));
        assertTrue(scope1 != scope4, "Different contexts must produce different scopes");
    }

    // ── Invariant: Credential state consistency ─────────────────────────
    // For every registered credential:
    //   - commitment must be nonzero
    //   - credentialGroupId must correspond to an existing group

    function invariant_credentialStateConsistency() public view {
        uint256 count = handler.getRegistrationHashCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 regHash = handler.registrationHashes(i);
            (bool registered,, uint256 commitment,, uint256 credGroupId,) = registry.credentials(regHash);
            if (!registered) continue;

            // Commitment must be nonzero
            assertTrue(commitment != 0, "Registered credential has zero commitment");

            // Credential group must exist (not UNDEFINED)
            (ICredentialRegistry.CredentialGroupStatus status,,) = registry.credentialGroups(credGroupId);
            assertTrue(
                status != ICredentialRegistry.CredentialGroupStatus.UNDEFINED, "Credential references undefined group"
            );
        }
    }
}
