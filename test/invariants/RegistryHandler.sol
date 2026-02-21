// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {CredentialRegistry} from "../../contracts/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "@bringid/contracts/interfaces/ICredentialRegistry.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Handler contract that the fuzzer calls to exercise CredentialRegistry
///         registration, renewal, expiry removal, and recovery paths while tracking
///         ghost state for invariant checks.
contract RegistryHandler is Test {
    using ECDSA for bytes32;

    CredentialRegistry public registry;
    uint256 public trustedVerifierPrivateKey;

    // --- Ghost state ---

    struct GhostCredential {
        bytes32 registrationHash;
        uint256 credentialGroupId;
        bytes32 credentialId;
        uint256 appId;
        uint256 commitment;
        uint256 expiresAt;
        bool expired;
        bool hasPendingRecovery;
        uint256 pendingNewCommitment;
        uint256 pendingExecuteAfter;
        uint256 pendingCredentialGroupId;
    }

    GhostCredential[] internal _ghostCredentials;

    // Legacy ghost state (for existing invariants)
    bytes32[] internal _registrationHashes;
    mapping(bytes32 => bool) internal _hashTracked;
    uint256[] internal _expectedCredentialGroupIds;

    // Family slot tracking: keccak256(familyId, credentialId, appId) => registered
    mapping(bytes32 => bool) internal _familySlots;
    uint256 public familySlotCount;
    uint256 public uniqueFamilySlots;

    // Counters
    uint256 public registrationCount;
    uint256 public renewalCount;
    uint256 public expiryRemovalCount;
    uint256 public recoveryInitiationCount;
    uint256 public recoveryExecutionCount;

    // Ghost index: registrationHash => index+1 in _ghostCredentials (0 = not tracked)
    mapping(bytes32 => uint256) internal _ghostIndexPlusOne;

    // Active member count per Semaphore group (for Merkle proof feasibility).
    // Only attempt removal/recovery with empty siblings when count == 1.
    mapping(uint256 => uint256) internal _semaphoreGroupActiveMemberCount;

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

    // ──────────────────────────────────────────────
    //  Fuzzed handlers
    // ──────────────────────────────────────────────

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
            chainId: block.chainid,
            credentialGroupId: credentialGroupId,
            credentialId: credentialId,
            appId: appId,
            semaphoreIdentityCommitment: commitment,
            issuedAt: block.timestamp
        });

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(trustedVerifierPrivateKey, keccak256(abi.encode(att)).toEthSignedMessageHash());

        registry.registerCredential(att, v, r, s);

        // Track legacy state
        _registrationHashes.push(registrationHash);
        _expectedCredentialGroupIds.push(credentialGroupId);
        _hashTracked[registrationHash] = true;
        registrationCount++;

        // Compute expiry from on-chain validity duration
        (, uint256 validityDuration,) = registry.credentialGroups(credentialGroupId);
        uint256 expiresAt = validityDuration > 0 ? block.timestamp + validityDuration : 0;

        // Track ghost state
        _ghostIndexPlusOne[registrationHash] = _ghostCredentials.length + 1;
        _ghostCredentials.push(
            GhostCredential({
                registrationHash: registrationHash,
                credentialGroupId: credentialGroupId,
                credentialId: credentialId,
                appId: appId,
                commitment: commitment,
                expiresAt: expiresAt,
                expired: false,
                hasPendingRecovery: false,
                pendingNewCommitment: 0,
                pendingExecuteAfter: 0,
                pendingCredentialGroupId: 0
            })
        );

        // Track Semaphore group member count
        uint256 semGroupId = registry.appSemaphoreGroups(credentialGroupId, appId);
        _semaphoreGroupActiveMemberCount[semGroupId]++;
    }

    /// @notice Fuzzed renewal: picks an already-registered credential and renews it.
    ///         Renewal preserves the same commitment and resets the validity duration.
    ///         Works on both active and expired (but removed) credentials.
    function renewCredential(uint256 seed) external {
        uint256 idx = _findRenewable(seed);
        if (idx == type(uint256).max) return;

        GhostCredential storage ghost = _ghostCredentials[idx];

        ICredentialRegistry.Attestation memory att = ICredentialRegistry.Attestation({
            registry: address(registry),
            chainId: block.chainid,
            credentialGroupId: ghost.credentialGroupId,
            credentialId: ghost.credentialId,
            appId: ghost.appId,
            semaphoreIdentityCommitment: ghost.commitment,
            issuedAt: block.timestamp
        });

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(trustedVerifierPrivateKey, keccak256(abi.encode(att)).toEthSignedMessageHash());

        registry.renewCredential(att, v, r, s);

        // If was expired, the contract re-adds the commitment to the Semaphore group
        if (ghost.expired) {
            uint256 semGroupId = registry.appSemaphoreGroups(ghost.credentialGroupId, ghost.appId);
            _semaphoreGroupActiveMemberCount[semGroupId]++;
            ghost.expired = false;
        }

        // Reset expiry in ghost state
        (, uint256 validityDuration,) = registry.credentialGroups(ghost.credentialGroupId);
        ghost.expiresAt = validityDuration > 0 ? block.timestamp + validityDuration : 0;
        renewalCount++;
    }

    /// @notice Fuzzed expiry removal: picks an expired credential and removes it.
    ///         Warps time forward if needed. Only targets single-member Semaphore groups
    ///         so that empty Merkle proof siblings are valid.
    function removeExpiredCredential(uint256 seed) external {
        uint256 idx = _findExpirable(seed);
        if (idx == type(uint256).max) return;

        GhostCredential storage ghost = _ghostCredentials[idx];

        // Warp past expiry if needed
        if (block.timestamp < ghost.expiresAt) {
            vm.warp(ghost.expiresAt);
        }

        uint256[] memory siblings = new uint256[](0);
        registry.removeExpiredCredential(ghost.credentialGroupId, ghost.credentialId, ghost.appId, siblings);

        ghost.expired = true;

        // Decrement Semaphore group member count
        uint256 semGroupId = registry.appSemaphoreGroups(ghost.credentialGroupId, ghost.appId);
        _semaphoreGroupActiveMemberCount[semGroupId]--;

        expiryRemovalCount++;
    }

    /// @notice Fuzzed recovery initiation: picks an already-registered credential and
    ///         initiates key recovery with a new commitment. Same group (key replacement).
    ///         Only targets single-member groups (or expired credentials) for empty siblings.
    function initiateRecovery(uint256 seed, uint256 newCommitmentSeed) external {
        uint256 idx = _findRecoverable(seed);
        if (idx == type(uint256).max) return;

        GhostCredential storage ghost = _ghostCredentials[idx];
        uint256 newCommitment = bound(newCommitmentSeed, 1, type(uint128).max);
        // Ensure new commitment differs from old
        if (newCommitment == ghost.commitment) {
            newCommitment = (ghost.commitment % type(uint128).max) + 1;
        }

        ICredentialRegistry.Attestation memory att = ICredentialRegistry.Attestation({
            registry: address(registry),
            chainId: block.chainid,
            credentialGroupId: ghost.credentialGroupId, // same group (key recovery)
            credentialId: ghost.credentialId,
            appId: ghost.appId,
            semaphoreIdentityCommitment: newCommitment,
            issuedAt: block.timestamp
        });

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(trustedVerifierPrivateKey, keccak256(abi.encode(att)).toEthSignedMessageHash());

        uint256[] memory siblings = new uint256[](0);
        registry.initiateRecovery(att, v, r, s, siblings);

        // Update ghost state
        (, uint256 recoveryTimelock,,) = registry.apps(ghost.appId);
        ghost.hasPendingRecovery = true;
        ghost.pendingNewCommitment = newCommitment;
        ghost.pendingExecuteAfter = block.timestamp + recoveryTimelock;
        ghost.pendingCredentialGroupId = ghost.credentialGroupId;

        // If not already expired, the old commitment was removed from Semaphore
        if (!ghost.expired) {
            uint256 semGroupId = registry.appSemaphoreGroups(ghost.credentialGroupId, ghost.appId);
            _semaphoreGroupActiveMemberCount[semGroupId]--;
        }

        recoveryInitiationCount++;
    }

    /// @notice Fuzzed recovery execution: picks a credential with pending recovery
    ///         whose timelock has passed and finalizes the recovery.
    function executeRecovery(uint256 seed) external {
        uint256 idx = _findExecutableRecovery(seed);
        if (idx == type(uint256).max) return;

        GhostCredential storage ghost = _ghostCredentials[idx];

        // Warp past timelock if needed
        if (block.timestamp < ghost.pendingExecuteAfter) {
            vm.warp(ghost.pendingExecuteAfter);
        }

        registry.executeRecovery(ghost.registrationHash);

        // Update ghost state: new commitment replaces old
        ghost.commitment = ghost.pendingNewCommitment;
        ghost.credentialGroupId = ghost.pendingCredentialGroupId;
        ghost.expired = false;
        ghost.hasPendingRecovery = false;
        ghost.pendingNewCommitment = 0;
        ghost.pendingExecuteAfter = 0;
        ghost.pendingCredentialGroupId = 0;

        // New commitment added to Semaphore group
        uint256 semGroupId = registry.appSemaphoreGroups(ghost.credentialGroupId, ghost.appId);
        _semaphoreGroupActiveMemberCount[semGroupId]++;

        // Note: _expectedCredentialGroupIds is not updated because this handler
        // always recovers within the same group. If cross-family group changes
        // were added, _expectedCredentialGroupIds[legacyIdx] would need updating.

        recoveryExecutionCount++;
    }

    // ──────────────────────────────────────────────
    //  View helpers for invariant checks
    // ──────────────────────────────────────────────

    function getRegistrationHashes() external view returns (bytes32[] memory) {
        return _registrationHashes;
    }

    function getExpectedCredentialGroupIds() external view returns (uint256[] memory) {
        return _expectedCredentialGroupIds;
    }

    function ghostCredentialCount() external view returns (uint256) {
        return _ghostCredentials.length;
    }

    function getGhostCredential(uint256 index)
        external
        view
        returns (
            bytes32 registrationHash,
            uint256 credentialGroupId,
            uint256 commitment,
            bool expired,
            bool hasPendingRecovery,
            uint256 pendingExecuteAfter
        )
    {
        GhostCredential storage g = _ghostCredentials[index];
        return
            (
                g.registrationHash,
                g.credentialGroupId,
                g.commitment,
                g.expired,
                g.hasPendingRecovery,
                g.pendingExecuteAfter
            );
    }

    // ──────────────────────────────────────────────
    //  Internal: candidate finders
    // ──────────────────────────────────────────────

    /// @dev Find a credential that can be renewed (registered, no pending recovery).
    ///      Renewal works on both active and expired credentials — no Merkle proof needed.
    function _findRenewable(uint256 seed) internal view returns (uint256) {
        uint256 len = _ghostCredentials.length;
        if (len == 0) return type(uint256).max;
        uint256 start = seed % len;
        for (uint256 i; i < len; i++) {
            uint256 idx = (start + i) % len;
            if (!_ghostCredentials[idx].hasPendingRecovery) return idx;
        }
        return type(uint256).max;
    }

    /// @dev Find a credential that can be expired: not already expired, has expiry set,
    ///      no pending recovery, and the Semaphore group has exactly 1 active member
    ///      (so empty Merkle proof siblings are valid for removal).
    function _findExpirable(uint256 seed) internal view returns (uint256) {
        uint256 len = _ghostCredentials.length;
        if (len == 0) return type(uint256).max;
        uint256 start = seed % len;
        for (uint256 i; i < len; i++) {
            uint256 idx = (start + i) % len;
            GhostCredential storage g = _ghostCredentials[idx];
            if (!g.expired && g.expiresAt > 0 && !g.hasPendingRecovery) {
                uint256 semGroupId = registry.appSemaphoreGroups(g.credentialGroupId, g.appId);
                if (_semaphoreGroupActiveMemberCount[semGroupId] == 1) return idx;
            }
        }
        return type(uint256).max;
    }

    /// @dev Find a credential that can initiate recovery: no pending recovery already,
    ///      and either expired (no Semaphore removal needed) or single active member
    ///      in the Semaphore group (empty siblings valid).
    function _findRecoverable(uint256 seed) internal view returns (uint256) {
        uint256 len = _ghostCredentials.length;
        if (len == 0) return type(uint256).max;
        uint256 start = seed % len;
        for (uint256 i; i < len; i++) {
            uint256 idx = (start + i) % len;
            GhostCredential storage g = _ghostCredentials[idx];
            if (!g.hasPendingRecovery) {
                // Expired credentials don't need Merkle proof (removal is skipped)
                if (g.expired) return idx;
                // Non-expired: need single-member group for empty siblings
                uint256 semGroupId = registry.appSemaphoreGroups(g.credentialGroupId, g.appId);
                if (_semaphoreGroupActiveMemberCount[semGroupId] == 1) return idx;
            }
        }
        return type(uint256).max;
    }

    /// @dev Find a credential with pending recovery that can be executed.
    function _findExecutableRecovery(uint256 seed) internal view returns (uint256) {
        uint256 len = _ghostCredentials.length;
        if (len == 0) return type(uint256).max;
        uint256 start = seed % len;
        for (uint256 i; i < len; i++) {
            uint256 idx = (start + i) % len;
            if (_ghostCredentials[idx].hasPendingRecovery) return idx;
        }
        return type(uint256).max;
    }

    // ──────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────

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
