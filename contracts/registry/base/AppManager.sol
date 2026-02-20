// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "@bringid/contracts/Errors.sol";
import "@bringid/contracts/Events.sol";
import {RegistryStorage} from "./RegistryStorage.sol";

/// @title AppManager
/// @notice App registration, admin management, scorer configuration, and Merkle tree duration.
abstract contract AppManager is RegistryStorage {
    // ──────────────────────────────────────────────
    //  App management
    // ──────────────────────────────────────────────

    /// @notice Registers a new app. Caller becomes the app admin.
    /// @dev App IDs are derived from keccak256(chainId, sender, nonce) for unpredictability
    ///      and natural chain-uniqueness. The app uses the defaultScorer by default.
    /// @param recoveryTimelock_ The recovery timelock duration in seconds (0 to disable).
    /// @return appId_ The newly assigned app ID.
    function registerApp(uint256 recoveryTimelock_) public returns (uint256 appId_) {
        appId_ = uint256(keccak256(abi.encodePacked(block.chainid, msg.sender, nextAppId++)));
        apps[appId_] = App(AppStatus.ACTIVE, recoveryTimelock_, msg.sender, defaultScorer);
        emit AppRegistered(appId_, msg.sender, recoveryTimelock_);
    }

    /// @notice Suspends an active app, preventing new registrations and proof validations for it.
    /// @dev Only callable by the app admin.
    /// @param appId_ The app ID to suspend.
    function suspendApp(uint256 appId_) public {
        if (apps[appId_].admin != msg.sender) revert NotAppAdmin();
        if (apps[appId_].status != AppStatus.ACTIVE) revert AppNotActive();
        apps[appId_].status = AppStatus.SUSPENDED;
        emit AppStatusChanged(appId_, AppStatus.SUSPENDED);
    }

    /// @notice Reactivates a suspended app.
    /// @dev Only callable by the app admin.
    /// @param appId_ The app ID to activate.
    function activateApp(uint256 appId_) public {
        if (apps[appId_].admin != msg.sender) revert NotAppAdmin();
        if (apps[appId_].status != AppStatus.SUSPENDED) revert AppNotSuspended();
        apps[appId_].status = AppStatus.ACTIVE;
        emit AppStatusChanged(appId_, AppStatus.ACTIVE);
    }

    /// @notice Sets the recovery timelock duration for an app.
    /// @dev Only callable by the app admin. Set to 0 to disable recovery.
    /// @param appId_ The app ID to configure.
    /// @param recoveryTimelock_ The timelock duration in seconds (0 to disable recovery).
    function setAppRecoveryTimelock(uint256 appId_, uint256 recoveryTimelock_) public {
        if (apps[appId_].admin != msg.sender) revert NotAppAdmin();
        if (apps[appId_].status != AppStatus.ACTIVE) revert AppNotActive();
        apps[appId_].recoveryTimelock = recoveryTimelock_;
        emit AppRecoveryTimelockSet(appId_, recoveryTimelock_);
    }

    /// @notice Initiates a two-step app admin transfer. The new admin must call acceptAppAdmin() to complete.
    /// @param appId_ The app ID.
    /// @param newAdmin_ The new admin address.
    function transferAppAdmin(uint256 appId_, address newAdmin_) public {
        if (apps[appId_].admin != msg.sender) revert NotAppAdmin();
        if (newAdmin_ == address(0)) revert InvalidAdminAddress();
        pendingAppAdmin[appId_] = newAdmin_;
        emit AppAdminTransferInitiated(appId_, apps[appId_].admin, newAdmin_);
    }

    /// @notice Completes a two-step app admin transfer. Must be called by the pending admin.
    /// @param appId_ The app ID.
    function acceptAppAdmin(uint256 appId_) public {
        if (pendingAppAdmin[appId_] != msg.sender) revert NotPendingAdmin();
        address oldAdmin = apps[appId_].admin;
        apps[appId_].admin = msg.sender;
        delete pendingAppAdmin[appId_];
        emit AppAdminTransferred(appId_, oldAdmin, msg.sender);
    }

    /// @notice Sets a custom scorer contract for an app.
    /// @param appId_ The app ID.
    /// @param scorer_ The scorer contract address.
    function setAppScorer(uint256 appId_, address scorer_) public {
        if (apps[appId_].admin != msg.sender) revert NotAppAdmin();
        if (scorer_ == address(0)) revert InvalidScorerAddress();
        apps[appId_].scorer = scorer_;
        emit AppScorerSet(appId_, scorer_);
    }

    /// @notice Sets a per-app Merkle tree duration override and propagates to all existing groups.
    /// @dev Only callable by the app admin. Setting to 0 clears the override and propagates
    ///      the registry default to all existing groups for this app.
    /// @param appId_ The app ID to configure.
    /// @param merkleTreeDuration_ The Merkle tree duration in seconds (0 = use registry default).
    function setAppMerkleTreeDuration(uint256 appId_, uint256 merkleTreeDuration_) public {
        if (apps[appId_].admin != msg.sender) revert NotAppAdmin();
        if (apps[appId_].status != AppStatus.ACTIVE) revert AppNotActive();
        appMerkleTreeDuration[appId_] = merkleTreeDuration_;

        uint256 effectiveDuration = merkleTreeDuration_ > 0 ? merkleTreeDuration_ : defaultMerkleTreeDuration;
        uint256[] storage groupIds = _appSemaphoreGroupIds[appId_];
        for (uint256 i = 0; i < groupIds.length; i++) {
            SEMAPHORE.updateGroupMerkleTreeDuration(groupIds[i], effectiveDuration);
        }

        emit AppMerkleTreeDurationSet(appId_, merkleTreeDuration_);
    }
}
