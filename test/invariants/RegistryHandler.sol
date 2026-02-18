// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {CredentialRegistry} from "../../src/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "../../src/registry/ICredentialRegistry.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

/// @notice Handler contract that the fuzzer calls to exercise CredentialRegistry
///         registration paths while tracking ghost state for invariant checks.
contract RegistryHandler is Test {
    using ECDSA for bytes32;

    CredentialRegistry public registry;
    uint256 public trustedVerifierPrivateKey;

    // Ghost state for invariant tracking
    bytes32[] internal _registrationHashes;
    mapping(bytes32 => bool) internal _hashTracked;
    uint256[] internal _expectedCredentialGroupIds;

    // Family slot tracking: keccak256(familyId, credentialId, appId) => registered
    mapping(bytes32 => bool) internal _familySlots;
    uint256 public familySlotCount;
    uint256 public uniqueFamilySlots;

    // Track registration count
    uint256 public registrationCount;

    // Bounded constants to keep fuzzing focused
    uint256 constant NUM_COMMITMENTS = 10;

    // Pre-created state (set by the test setUp via initialize)
    uint256[] public appIds;
    uint256[] public credentialGroupIdList;

    constructor(CredentialRegistry registry_, uint256 trustedVerifierPrivateKey_) {
        registry = registry_;
        trustedVerifierPrivateKey = trustedVerifierPrivateKey_;
    }

    /// @notice Called by the test setUp after creating credential groups and apps.
    function initialize(uint256[] memory credentialGroupIds_, uint256[] memory appIds_) external {
        for (uint256 i; i < credentialGroupIds_.length; i++) {
            credentialGroupIdList.push(credentialGroupIds_[i]);
        }
        for (uint256 i; i < appIds_.length; i++) {
            appIds.push(appIds_[i]);
        }
    }

    /// @notice Fuzzed registration: attempts to register a credential with bounded inputs.
    function registerCredential(uint256 groupSeed, uint256 credIdSeed, uint256 appSeed, uint256 commitmentSeed)
        external
    {
        if (credentialGroupIdList.length == 0 || appIds.length == 0) return;

        // Bound inputs
        uint256 groupIdx = bound(groupSeed, 0, credentialGroupIdList.length - 1);
        uint256 credentialGroupId = credentialGroupIdList[groupIdx];
        uint256 appIdx = bound(appSeed, 0, appIds.length - 1);
        uint256 appId = appIds[appIdx];
        bytes32 credentialId = bytes32(bound(credIdSeed, 1, NUM_COMMITMENTS));
        uint256 commitment = bound(commitmentSeed, 1, type(uint128).max);

        // Compute the registration hash the same way the contract does
        uint256 familyId = _getFamilyId(credentialGroupId);
        bytes32 registrationHash = _computeRegistrationHash(familyId, credentialGroupId, credentialId, appId);

        // Skip if already registered (we're testing uniqueness, not double-registration reverts)
        if (_hashTracked[registrationHash]) return;

        // Track family constraint
        if (familyId > 0) {
            bytes32 familySlot = keccak256(abi.encode(familyId, credentialId, appId));
            if (_familySlots[familySlot]) return; // Would revert — same family slot
            _familySlots[familySlot] = true;
            familySlotCount++;
            uniqueFamilySlots++;
        }

        ICredentialRegistry.Attestation memory att = ICredentialRegistry.Attestation({
            registry: address(registry),
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: appId,
            semaphoreIdentityCommitment: commitment,
            issuedAt: block.timestamp
        });

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(trustedVerifierPrivateKey, keccak256(abi.encode(att)).toEthSignedMessageHash());

        registry.registerCredential(att, v, r, s);

        // Track state
        _registrationHashes.push(registrationHash);
        _expectedCredentialGroupIds.push(credentialGroupId);
        _hashTracked[registrationHash] = true;
        registrationCount++;
    }

    // --- View helpers for invariant checks ---

    function getRegistrationHashes() external view returns (bytes32[] memory) {
        return _registrationHashes;
    }

    function getExpectedCredentialGroupIds() external view returns (uint256[] memory) {
        return _expectedCredentialGroupIds;
    }

    // --- Internal helpers ---

    function _getFamilyId(uint256 credentialGroupId) internal view returns (uint256) {
        (,, uint256 familyId) = registry.credentialGroups(credentialGroupId);
        return familyId;
    }

    function _computeRegistrationHash(uint256 familyId, uint256 credentialGroupId, bytes32 credentialId, uint256 appId)
        internal
        view
        returns (bytes32)
    {
        if (familyId > 0) {
            return keccak256(abi.encode(address(registry), familyId, uint256(0), credentialId, appId));
        }
        return keccak256(abi.encode(address(registry), uint256(0), credentialGroupId, credentialId, appId));
    }
}
