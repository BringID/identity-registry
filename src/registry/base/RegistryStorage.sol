// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "../Errors.sol";
import "../Events.sol";
import {ICredentialRegistry} from "../ICredentialRegistry.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Ownable2Step} from "openzeppelin/access/Ownable2Step.sol";
import {Pausable} from "openzeppelin/security/Pausable.sol";
import {ReentrancyGuard} from "openzeppelin/security/ReentrancyGuard.sol";

/// @title RegistryStorage
/// @notice Base contract holding all state variables, internal helpers, and view helpers
///         for the CredentialRegistry. Inherits OpenZeppelin access control and security primitives.
abstract contract RegistryStorage is ICredentialRegistry, Ownable2Step, Pausable, ReentrancyGuard {
    /// @notice The Semaphore contract used for group management and ZK proof verification.
    ISemaphore public immutable SEMAPHORE;

    /// @notice Registry of trusted verifiers that can sign attestations.
    /// Each verifier is an ECDSA signer whose signatures are accepted for
    /// credential attestations. Supports multiple verification methods
    /// (TLSN, OAuth, zkPassport, etc.).
    mapping(address => bool) public trustedVerifiers;

    /// @notice Registry of credential groups. Each group has a status (UNDEFINED / ACTIVE / SUSPENDED).
    mapping(uint256 credentialGroupId => CredentialGroup) public credentialGroups;

    /// @notice Registry of apps. Each app has a status (UNDEFINED / ACTIVE / SUSPENDED).
    /// Apps must be registered before users can register credentials or submit proofs for them.
    mapping(uint256 appId => App) public apps;

    /// @notice Maps (credentialGroupId, appId) to the Semaphore group ID for that pair.
    /// Created lazily on first credential registration for the pair.
    mapping(uint256 credentialGroupId => mapping(uint256 appId => uint256 semaphoreGroupId)) public appSemaphoreGroups;

    /// @notice Tracks whether a Semaphore group has been created for a (credentialGroup, app) pair.
    mapping(uint256 credentialGroupId => mapping(uint256 appId => bool)) public appSemaphoreGroupCreated;

    /// @notice Per-credential state keyed by registration hash.
    /// For family groups (familyId > 0): key = keccak256(registry, familyId, 0, credentialId, appId)
    /// — all groups in the same family share one slot, preventing double registration.
    /// For standalone groups (familyId == 0): key = keccak256(registry, 0, credentialGroupId, credentialId, appId).
    /// The `commitment` field persists across expiry/removal for nullifier continuity.
    mapping(bytes32 registrationHash => CredentialRecord) public credentials;

    /// @notice Maximum age (in seconds) an attestation is accepted. Default 30 minutes.
    uint256 public attestationValidityDuration = 30 minutes;

    /// @notice Array of all registered credential group IDs (for enumeration).
    uint256[] public credentialGroupIds;

    /// @notice Nonce used in hash-based app ID generation. Incremented on each registerApp() call.
    uint256 public nextAppId = 1;

    /// @notice Address of the DefaultScorer contract deployed by the constructor.
    address public defaultScorer;

    /// @notice Registry-level default Merkle tree duration (seconds) for new Semaphore groups.
    uint256 public defaultMerkleTreeDuration;

    /// @notice Per-app override for Merkle tree duration. 0 = use registry default.
    mapping(uint256 appId => uint256) public appMerkleTreeDuration;

    /// @notice Tracks all Semaphore group IDs created for an app (for duration propagation).
    mapping(uint256 appId => uint256[]) internal _appSemaphoreGroupIds;

    /// @notice Pending admin for two-step app admin transfer.
    mapping(uint256 appId => address) public pendingAppAdmin;

    constructor(ISemaphore semaphore_) {
        SEMAPHORE = semaphore_;
    }

    // ──────────────────────────────────────────────
    //  View helpers
    // ──────────────────────────────────────────────

    /// @notice Returns true if the credential group is currently active.
    /// @param credentialGroupId_ The credential group ID to check.
    function credentialGroupIsActive(uint256 credentialGroupId_) public view returns (bool) {
        return credentialGroups[credentialGroupId_].status == CredentialGroupStatus.ACTIVE;
    }

    /// @notice Returns true if the app is currently active.
    /// @param appId_ The app ID to check.
    function appIsActive(uint256 appId_) public view returns (bool) {
        return apps[appId_].status == AppStatus.ACTIVE;
    }

    /// @notice Returns all registered credential group IDs.
    function getCredentialGroupIds() external view returns (uint256[] memory) {
        return credentialGroupIds;
    }

    /// @notice Returns all Semaphore group IDs created for an app.
    /// @param appId_ The app ID to query.
    function getAppSemaphoreGroupIds(uint256 appId_) external view returns (uint256[] memory) {
        return _appSemaphoreGroupIds[appId_];
    }

    // ──────────────────────────────────────────────
    //  Internal helpers
    // ──────────────────────────────────────────────

    /// @dev Unpacks a 65-byte ECDSA signature into its (v, r, s) components.
    function _unpackSignature(bytes memory signature_) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        if (signature_.length != 65) revert InvalidAttestationSigLength();
        assembly {
            r := mload(add(signature_, 0x20))
            s := mload(add(signature_, 0x40))
            v := byte(0, mload(add(signature_, 0x60)))
        }
    }

    /// @dev Computes the registration hash. For family groups, uses familyId (shared across the
    ///      family) to naturally prevent double registration. For standalone groups, uses credentialGroupId.
    ///      The two-slot encoding (familyId, credentialGroupId) prevents collisions:
    ///      family hashes always have slot2=0, standalone hashes always have slot1=0.
    function _registrationHash(uint256 familyId_, uint256 credentialGroupId_, bytes32 credentialId_, uint256 appId_)
        internal
        view
        returns (bytes32)
    {
        if (familyId_ > 0) {
            return keccak256(abi.encode(address(this), familyId_, uint256(0), credentialId_, appId_));
        }
        return keccak256(abi.encode(address(this), uint256(0), credentialGroupId_, credentialId_, appId_));
    }

    /// @dev Ensures a Semaphore group exists for the (credentialGroupId, appId) pair.
    ///      Creates one lazily if it doesn't exist yet, using the resolved Merkle tree duration
    ///      (per-app override if set, otherwise registry default).
    /// @return semaphoreGroupId The Semaphore group ID for the pair.
    function _ensureAppSemaphoreGroup(uint256 credentialGroupId_, uint256 appId_)
        internal
        returns (uint256 semaphoreGroupId)
    {
        if (!appSemaphoreGroupCreated[credentialGroupId_][appId_]) {
            uint256 appDuration = appMerkleTreeDuration[appId_];
            uint256 duration = appDuration > 0 ? appDuration : defaultMerkleTreeDuration;
            semaphoreGroupId = SEMAPHORE.createGroup(address(this), duration);
            appSemaphoreGroups[credentialGroupId_][appId_] = semaphoreGroupId;
            appSemaphoreGroupCreated[credentialGroupId_][appId_] = true;
            _appSemaphoreGroupIds[appId_].push(semaphoreGroupId);
            emit AppSemaphoreGroupCreated(credentialGroupId_, appId_, semaphoreGroupId);
        } else {
            semaphoreGroupId = appSemaphoreGroups[credentialGroupId_][appId_];
        }
    }
}
