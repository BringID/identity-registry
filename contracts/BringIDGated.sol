// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {SafeProofConsumer} from "./SafeProofConsumer.sol";

/// @title BringIDGated
/// @notice Abstract base for contracts that validate and submit BringID credential proofs.
///         Enforces app ID matching, then submits proofs to the registry.
/// @dev Inherit this contract and call `_submitAndValidate()` to perform the validation flow:
///      1. Validate each proof targets APP_ID
///      2. Validate message binding to recipient
///      3. Submit proofs to the registry (consuming nullifiers)
///      Score threshold checking is the consumer's responsibility.
abstract contract BringIDGated is SafeProofConsumer {
    /// @notice The app ID that all proofs must target.
    uint256 public immutable APP_ID;

    /// @notice Thrown when a proof targets an unexpected app ID.
    /// @param expected The expected app ID.
    /// @param actual The actual app ID found in the proof.
    error AppIdMismatch(uint256 expected, uint256 actual);

    /// @param registry_ The BringID CredentialRegistry address.
    /// @param appId_ The app ID that all proofs must target.
    constructor(ICredentialRegistry registry_, uint256 appId_) SafeProofConsumer(registry_) {
        APP_ID = appId_;
    }

    /// @notice Validates proofs and submits them to the registry.
    /// @dev Performs the validation flow: app ID, message binding, and submission.
    ///      Reverts if any check fails. Does NOT enforce a score threshold — callers handle that.
    /// @param recipient_ The intended recipient (used for message binding validation).
    /// @param context_ Application-defined context value for scope computation.
    /// @param proofs_ Array of credential group proofs to validate and submit.
    /// @return score The aggregate score returned by the registry.
    function _submitAndValidate(
        address recipient_,
        uint256 context_,
        ICredentialRegistry.CredentialGroupProof[] calldata proofs_
    ) internal returns (uint256 score) {
        for (uint256 i = 0; i < proofs_.length; i++) {
            if (proofs_[i].appId != APP_ID) revert AppIdMismatch(APP_ID, proofs_[i].appId);
        }

        _validateMessageBindings(proofs_, recipient_);

        score = REGISTRY.submitProofs(context_, proofs_);
    }
}
