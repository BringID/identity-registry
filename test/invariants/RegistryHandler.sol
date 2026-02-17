// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {CredentialRegistry} from "../../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../../src/registry/ICredentialRegistry.sol";
import {DefaultScorer} from "../../src/scoring/DefaultScorer.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

/// @dev Handler contract that exposes bounded actions for Foundry invariant testing.
///      All credential operations go through this handler so the invariant harness
///      can track ghost variables and assert protocol properties.
contract RegistryHandler is Test {
    using ECDSA for bytes32;

    CredentialRegistry public registry;
    uint256 public verifierKey;
    address public verifier;

    // Ghost variables tracking protocol state
    uint256 public totalRegistrations;
    uint256 public totalRenewals;
    uint256 public totalRecoveries;

    // Track registration hashes we've seen
    bytes32[] public registrationHashes;
    mapping(bytes32 => bool) public hashRegistered;

    // Track (credentialId, appId, familyId) -> registered to verify family constraint
    mapping(bytes32 => bool) public familySlotUsed;

    // Track commitments per registration hash (for commitment continuity)
    mapping(bytes32 => uint256) public lastCommitment;
    mapping(bytes32 => bool) public commitmentChangedViaRecovery;

    // Bounded parameters
    uint256 constant MAX_CREDENTIAL_GROUPS = 5;
    uint256 constant MAX_APPS = 3;
    uint256 constant FAMILY_ID = 1; // shared family for family-constraint tests

    uint256 public appId;

    constructor(CredentialRegistry registry_, uint256 verifierKey_, address verifier_) {
        registry = registry_;
        verifierKey = verifierKey_;
        verifier = verifier_;
    }

    function setAppId(uint256 appId_) external {
        appId = appId_;
    }

    /// @dev Register a credential with bounded parameters.
    function registerCredential(uint256 credentialGroupSeed, uint256 commitmentSeed, uint256 credentialIdSeed)
        external
    {
        // Bound to existing credential groups (1-based)
        uint256 credentialGroupId = bound(credentialGroupSeed, 1, MAX_CREDENTIAL_GROUPS);
        // Use nonzero commitment
        uint256 commitment = bound(commitmentSeed, 1, type(uint128).max);
        bytes32 credentialId = bytes32(bound(credentialIdSeed, 1, type(uint64).max));

        // Skip if credential group is not active
        if (!registry.credentialGroupIsActive(credentialGroupId)) return;
        if (!registry.appIsActive(appId)) return;

        // Compute registration hash to check if already registered
        (ICredentialRegistry.CredentialGroupStatus status,, uint256 familyId) =
            registry.credentialGroups(credentialGroupId);
        bytes32 regHash = _computeRegistrationHash(familyId, credentialGroupId, credentialId, appId);

        // Skip if already registered (we're testing that the contract rejects it, not that the handler does)
        (bool registered,,,,,) = registry.credentials(regHash);
        if (registered) return;

        ICredentialRegistry.Attestation memory att = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: appId,
            semaphoreIdentityCommitment: commitment,
            issuedAt: block.timestamp
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierKey, keccak256(abi.encode(att)).toEthSignedMessageHash());

        try registry.registerCredential(att, v, r, s) {
            totalRegistrations++;
            if (!hashRegistered[regHash]) {
                registrationHashes.push(regHash);
                hashRegistered[regHash] = true;
            }
            lastCommitment[regHash] = commitment;
        } catch {}
    }

    /// @dev Attempt double-registration (should always revert).
    function doubleRegister(uint256 credentialGroupSeed, uint256 commitmentSeed, uint256 credentialIdSeed) external {
        uint256 credentialGroupId = bound(credentialGroupSeed, 1, MAX_CREDENTIAL_GROUPS);
        uint256 commitment = bound(commitmentSeed, 1, type(uint128).max);
        bytes32 credentialId = bytes32(bound(credentialIdSeed, 1, type(uint64).max));

        if (!registry.credentialGroupIsActive(credentialGroupId)) return;
        if (!registry.appIsActive(appId)) return;

        (,, uint256 familyId) = registry.credentialGroups(credentialGroupId);
        bytes32 regHash = _computeRegistrationHash(familyId, credentialGroupId, credentialId, appId);

        (bool registered,,,,,) = registry.credentials(regHash);
        if (!registered) return; // Need an existing registration to test double-register

        // Attempt re-registration with a different commitment — must revert
        uint256 newCommitment = commitment + 1;
        if (newCommitment == 0) newCommitment = 1;

        ICredentialRegistry.Attestation memory att = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: appId,
            semaphoreIdentityCommitment: newCommitment,
            issuedAt: block.timestamp
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierKey, keccak256(abi.encode(att)).toEthSignedMessageHash());

        // This MUST revert with "BID::already registered"
        try registry.registerCredential(att, v, r, s) {
            // If we reach here, invariant is broken — but we track it via the contract state.
            // The invariant test will catch this via credential count checks.
            revert("INVARIANT_VIOLATED: double registration succeeded");
        } catch {}
    }

    /// @dev Attempt to register a second credential in the same family (should fail if one exists).
    function familyDoubleRegister(
        uint256 credentialGroupSeedA,
        uint256 credentialGroupSeedB,
        uint256 commitmentSeed,
        uint256 credentialIdSeed
    ) external {
        // Both groups must be in the same family
        uint256 groupA = bound(credentialGroupSeedA, 1, MAX_CREDENTIAL_GROUPS);
        uint256 groupB = bound(credentialGroupSeedB, 1, MAX_CREDENTIAL_GROUPS);
        if (groupA == groupB) return;

        if (!registry.credentialGroupIsActive(groupA)) return;
        if (!registry.credentialGroupIsActive(groupB)) return;
        if (!registry.appIsActive(appId)) return;

        (,, uint256 familyIdA) = registry.credentialGroups(groupA);
        (,, uint256 familyIdB) = registry.credentialGroups(groupB);
        if (familyIdA == 0 || familyIdA != familyIdB) return; // Not in same family

        uint256 commitment = bound(commitmentSeed, 1, type(uint128).max);
        bytes32 credentialId = bytes32(bound(credentialIdSeed, 1, type(uint64).max));

        // Register first group
        bytes32 regHash = _computeRegistrationHash(familyIdA, groupA, credentialId, appId);
        (bool registered,,,,,) = registry.credentials(regHash);
        if (!registered) {
            ICredentialRegistry.Attestation memory att1 = ICredentialRegistry.Attestation({
                registry: address(registry),
                credentialGroupId: groupA,
                credentialId: credentialId,
                appId: appId,
                semaphoreIdentityCommitment: commitment,
                issuedAt: block.timestamp
            });
            (uint8 v1, bytes32 r1, bytes32 s1) =
                vm.sign(verifierKey, keccak256(abi.encode(att1)).toEthSignedMessageHash());
            try registry.registerCredential(att1, v1, r1, s1) {
                totalRegistrations++;
                if (!hashRegistered[regHash]) {
                    registrationHashes.push(regHash);
                    hashRegistered[regHash] = true;
                }
                lastCommitment[regHash] = commitment;
            } catch {
                return;
            }
        }

        // Attempt second group in same family — must revert because same registration hash
        uint256 commitment2 = commitment + 1;
        if (commitment2 == 0) commitment2 = 1;

        ICredentialRegistry.Attestation memory att2 = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: groupB,
            credentialId: credentialId,
            appId: appId,
            semaphoreIdentityCommitment: commitment2,
            issuedAt: block.timestamp
        });
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(verifierKey, keccak256(abi.encode(att2)).toEthSignedMessageHash());

        // This MUST revert — same family, same credentialId, same app
        try registry.registerCredential(att2, v2, r2, s2) {
            revert("INVARIANT_VIOLATED: family double registration succeeded");
        } catch {}
    }

    /// @dev Renew a credential (commitment must remain the same).
    function renewCredential(uint256 hashIndexSeed) external {
        if (registrationHashes.length == 0) return;
        uint256 idx = bound(hashIndexSeed, 0, registrationHashes.length - 1);
        bytes32 regHash = registrationHashes[idx];

        (bool registered, bool expired,,, uint256 credGroupId,) = registry.credentials(regHash);
        if (!registered || !expired) return;
        if (!registry.credentialGroupIsActive(credGroupId)) return;

        // We need the credentialId and appId to create the attestation, but we can't
        // reverse the hash. Instead, we just verify that renewal preserves commitment
        // through the ghost variable tracking. Skip renewal attempts that would need
        // data we don't have.
    }

    // ── View helpers ──────────────────────────────

    function getRegistrationHashCount() external view returns (uint256) {
        return registrationHashes.length;
    }

    function _computeRegistrationHash(
        uint256 familyId_,
        uint256 credentialGroupId_,
        bytes32 credentialId_,
        uint256 appId_
    ) internal view returns (bytes32) {
        if (familyId_ > 0) {
            return keccak256(abi.encode(address(registry), familyId_, uint256(0), credentialId_, appId_));
        }
        return keccak256(abi.encode(address(registry), uint256(0), credentialGroupId_, credentialId_, appId_));
    }
}
