// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {SafeProofConsumer} from "./SafeProofConsumer.sol";

/// @title BringIDGated
/// @notice Abstract base for contracts that validate and submit BringID credential proofs.
///         Enforces app ID matching, then submits proofs to the registry.
/// @dev Inherit this contract and call `_submitProofsForRecipient()` to perform the validation flow:
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

    /// @notice Validates proofs and submits them to the registry using context = 0.
    /// @dev Calls the 3-parameter version with context_ = 0. Override this in subcontracts
    ///      that need a different default context (e.g. BringIDGatedWithContext).
    /// @param recipient_ The intended recipient (used for message binding validation).
    /// @param proofs_ Array of credential group proofs to validate and submit.
    /// @return bringIDScore The aggregate score returned by the registry.
    function _submitProofsForRecipient(address recipient_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_)
        internal
        virtual
        returns (uint256 bringIDScore)
    {
        bringIDScore = _submitProofsForRecipient(recipient_, 0, proofs_);
    }

    /// @notice Validates proofs and submits them to the registry.
    /// @dev Performs the validation flow: app ID, message binding, and submission.
    ///      Reverts if any check fails. Does NOT enforce a score threshold — callers handle that.
    /// @param recipient_ The intended recipient (used for message binding validation).
    /// @param context_ Application-defined context value for scope computation.
    /// @param proofs_ Array of credential group proofs to validate and submit.
    /// @return bringIDScore The aggregate score returned by the registry.
    function _submitProofsForRecipient(
        address recipient_,
        uint256 context_,
        ICredentialRegistry.CredentialGroupProof[] calldata proofs_
    ) internal returns (uint256 bringIDScore) {
        for (uint256 i = 0; i < proofs_.length; i++) {
            if (proofs_[i].appId != APP_ID) {
                revert AppIdMismatch(APP_ID, proofs_[i].appId);
            }
        }

        _validateMessageBindings(proofs_, recipient_);

        bringIDScore = REGISTRY.submitProofs(context_, proofs_);
    }
}
