// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";
import {SafeProofConsumer} from "./SafeProofConsumer.sol";

/// @title ScoreGated
/// @notice Abstract base for contracts that gate access behind a minimum BringID credential score.
///         Validates proofs, checks score thresholds, and enforces app ID and proof count limits.
/// @dev Inherit this contract and call `_submitAndValidate()` to perform the full validation flow:
///      1. Check proof count <= MAX_PROOFS
///      2. Validate each proof targets APP_ID
///      3. Validate message binding to recipient
///      4. Submit proofs to the registry (consuming nullifiers)
///      5. Check aggregate score >= MIN_SCORE
abstract contract ScoreGated is SafeProofConsumer {
    /// @notice Minimum aggregate score required.
    uint256 public immutable MIN_SCORE;

    /// @notice Application-defined context value passed to the registry.
    uint256 public immutable CONTEXT;

    /// @notice The app ID that all proofs must target.
    uint256 public immutable APP_ID;

    /// @notice Maximum number of proofs accepted per call.
    uint256 public immutable MAX_PROOFS;

    /// @notice Thrown when the aggregate proof score is below `MIN_SCORE`.
    /// @param score The actual score returned by the registry.
    /// @param minScore The required minimum score.
    error InsufficientScore(uint256 score, uint256 minScore);

    /// @notice Thrown when the number of proofs exceeds `MAX_PROOFS`.
    error TooManyProofs();

    /// @notice Thrown when a proof targets an unexpected app ID.
    /// @param expected The expected app ID.
    /// @param actual The actual app ID found in the proof.
    error AppIdMismatch(uint256 expected, uint256 actual);

    /// @param registry_ The BringID CredentialRegistry address.
    /// @param minScore_ Minimum aggregate score required.
    /// @param context_ Application-defined context value for scope computation.
    /// @param appId_ The app ID that all proofs must target.
    /// @param maxProofs_ Maximum number of proofs accepted per call.
    constructor(ICredentialRegistry registry_, uint256 minScore_, uint256 context_, uint256 appId_, uint256 maxProofs_)
        SafeProofConsumer(registry_)
    {
        MIN_SCORE = minScore_;
        CONTEXT = context_;
        APP_ID = appId_;
        MAX_PROOFS = maxProofs_;
    }

    /// @notice Validates proofs, submits them to the registry, and checks the score threshold.
    /// @dev Performs the full validation flow: proof count, app ID, message binding, submission,
    ///      and score check. Reverts if any check fails.
    /// @param recipient_ The intended recipient (used for message binding validation).
    /// @param proofs_ Array of credential group proofs to validate and submit.
    /// @return score The aggregate score returned by the registry.
    function _submitAndValidate(address recipient_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_)
        internal
        returns (uint256 score)
    {
        if (proofs_.length > MAX_PROOFS) revert TooManyProofs();

        for (uint256 i = 0; i < proofs_.length; i++) {
            if (proofs_[i].appId != APP_ID) revert AppIdMismatch(APP_ID, proofs_[i].appId);
        }

        _validateMessageBindings(proofs_, recipient_);

        score = REGISTRY.submitProofs(CONTEXT, proofs_);

        if (score < MIN_SCORE) revert InsufficientScore(score, MIN_SCORE);
    }
}
