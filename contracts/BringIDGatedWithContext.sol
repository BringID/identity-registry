// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {BringIDGated} from "./BringIDGated.sol";

/// @title BringIDGatedWithContext
/// @notice Convenience layer over `BringIDGated` that stores a fixed context value.
///         Provides a 2-parameter `_submitAndValidate` overload that passes the stored CONTEXT.
/// @dev Inherit this contract when your consuming contract uses a single, fixed context value.
///      For dynamic context values, inherit `BringIDGated` directly.
abstract contract BringIDGatedWithContext is BringIDGated {
    /// @notice Application-defined context value passed to the registry.
    uint256 public immutable CONTEXT;

    /// @param registry_ The BringID CredentialRegistry address.
    /// @param context_ Application-defined context value for scope computation.
    /// @param appId_ The app ID that all proofs must target.
    /// @param maxProofs_ Maximum number of proofs accepted per call.
    constructor(ICredentialRegistry registry_, uint256 context_, uint256 appId_, uint256 maxProofs_)
        BringIDGated(registry_, appId_, maxProofs_)
    {
        CONTEXT = context_;
    }

    /// @notice Validates proofs and submits them using the stored CONTEXT.
    /// @param recipient_ The intended recipient (used for message binding validation).
    /// @param proofs_ Array of credential group proofs to validate and submit.
    /// @return score The aggregate score returned by the registry.
    function _submitAndValidate(address recipient_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_)
        internal
        returns (uint256 score)
    {
        score = _submitAndValidate(recipient_, CONTEXT, proofs_);
    }
}
