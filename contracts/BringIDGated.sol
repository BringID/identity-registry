// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {SafeProofConsumer} from "./SafeProofConsumer.sol";

/// @title BringIDGated
/// @notice Abstract base for contracts that validate and submit BringID credential proofs.
///         Enforces app ID matching and proof count limits, then submits proofs to the registry.
/// @dev Inherit this contract and call `_submitAndValidate()` to perform the validation flow:
///      1. Check proof count <= MAX_PROOFS
///      2. Validate each proof targets APP_ID
///      3. Validate message binding to recipient
///      4. Submit proofs to the registry (consuming nullifiers)
///      Score threshold checking is the consumer's responsibility.
abstract contract BringIDGated is SafeProofConsumer {
    /// @notice The app ID that all proofs must target.
    uint256 public immutable APP_ID;

    /// @notice Maximum number of proofs accepted per call.
    uint256 public immutable MAX_PROOFS;

    /// @notice Thrown when the number of proofs exceeds `MAX_PROOFS`.
    error TooManyProofs();

    /// @notice Thrown when a proof targets an unexpected app ID.
    /// @param expected The expected app ID.
    /// @param actual The actual app ID found in the proof.
    error AppIdMismatch(uint256 expected, uint256 actual);

    /// @param registry_ The BringID CredentialRegistry address.
    /// @param appId_ The app ID that all proofs must target.
    /// @param maxProofs_ Maximum number of proofs accepted per call.
    constructor(ICredentialRegistry registry_, uint256 appId_, uint256 maxProofs_) SafeProofConsumer(registry_) {
        APP_ID = appId_;
        MAX_PROOFS = maxProofs_;
    }

    /// @notice Validates proofs and submits them to the registry.
    /// @dev Performs the validation flow: proof count, app ID, message binding, and submission.
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
        if (proofs_.length > MAX_PROOFS) {
            revert TooManyProofs();
        }

        for (uint256 i = 0; i < proofs_.length; i++) {
            if (proofs_[i].appId != APP_ID) revert AppIdMismatch(APP_ID, proofs_[i].appId);
        }

        _validateMessageBindings(proofs_, recipient_);

        score = REGISTRY.submitProofs(context_, proofs_);
    }
}
