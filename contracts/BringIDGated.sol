// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "./interfaces/ICredentialRegistry.sol";
import {IBringIDGated} from "./interfaces/IBringIDGated.sol";

/// @title BringIDGated
/// @notice Abstract base for contracts that validate and submit BringID credential proofs.
///         Validates that the Semaphore proof `message` field is bound to an intended
///         recipient address (preventing mempool front-running), enforces app ID matching,
///         then submits proofs to the registry.
/// @dev When a smart contract calls `registry.submitProofs()`, the `scope` is bound to
///      `msg.sender` (the contract) + `context`. Any user can copy the proof from the
///      mempool and submit it first through the same contract, because `msg.sender` is
///      identical. Binding the `message` field to the intended recipient makes copied
///      proofs useless to the attacker.
///
///      Inherit this contract and call `_submitProofsForRecipient()` to perform the validation flow:
///      1. Validate each proof targets APP_ID
///      2. Validate message binding to recipient
///      3. Submit proofs to the registry (consuming nullifiers)
///      Score threshold checking is the consumer's responsibility.
abstract contract BringIDGated is IBringIDGated {
    ICredentialRegistry public immutable REGISTRY;

    /// @notice The app ID that all proofs must target.
    uint256 public immutable APP_ID;

    /// @param registry_ The BringID CredentialRegistry address.
    /// @param appId_ The app ID that all proofs must target.
    constructor(ICredentialRegistry registry_, uint256 appId_) {
        REGISTRY = registry_;
        APP_ID = appId_;
    }

    /// @notice Computes the expected Semaphore `message` value for a given recipient.
    /// @param recipient_ The intended recipient address.
    /// @return The expected message: `uint256(keccak256(abi.encodePacked(recipient_)))`.
    function expectedMessage(address recipient_) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(recipient_)));
    }

    /// @notice View-only: verifies a single proof using this contract's address for scope.
    /// @dev Delegates to `REGISTRY.verifyProof()` where `msg.sender` is `address(this)`.
    /// @param context_ Application-defined context value for scope computation.
    /// @param proof_ The credential group proof to verify.
    /// @return True if the proof is valid.
    function verifyProof(uint256 context_, ICredentialRegistry.CredentialGroupProof calldata proof_)
        public
        view
        returns (bool)
    {
        return REGISTRY.verifyProof(context_, proof_);
    }

    /// @notice View-only: verifies multiple proofs using this contract's address for scope.
    /// @dev Delegates to `REGISTRY.verifyProofs()` where `msg.sender` is `address(this)`.
    /// @param context_ Application-defined context value for scope computation.
    /// @param proofs_ Array of credential group proofs to verify.
    /// @return True if all proofs are valid.
    function verifyProofs(uint256 context_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_)
        public
        view
        returns (bool)
    {
        return REGISTRY.verifyProofs(context_, proofs_);
    }

    /// @notice View-only: verifies proofs and returns aggregate score using this contract's address.
    /// @dev Delegates to `REGISTRY.getScore()` where `msg.sender` is `address(this)`.
    /// @param context_ Application-defined context value for scope computation.
    /// @param proofs_ Array of credential group proofs to verify and score.
    /// @return The total score across all verified credential groups.
    function getScore(uint256 context_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_)
        public
        view
        returns (uint256)
    {
        return REGISTRY.getScore(context_, proofs_);
    }

    /// @notice Validates proofs and submits them to the registry using context = 0.
    /// @dev Calls the 3-parameter version with context_ = 0. For a non-zero fixed context,
    ///      store your own immutable and call the 3-param overload directly.
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

    /// @notice Validates that a single proof's message is bound to the intended recipient.
    /// @param proof_ The credential group proof to validate.
    /// @param recipient_ The intended recipient address (must not be zero).
    function _validateMessageBinding(ICredentialRegistry.CredentialGroupProof calldata proof_, address recipient_)
        internal
        pure
    {
        if (recipient_ == address(0)) revert ZeroRecipient();
        uint256 expected = expectedMessage(recipient_);
        if (proof_.semaphoreProof.message != expected) {
            revert MessageBindingMismatch(expected, proof_.semaphoreProof.message);
        }
    }

    /// @notice Validates that all proofs' messages are bound to the intended recipient.
    /// @param proofs_ Array of credential group proofs to validate.
    /// @param recipient_ The intended recipient address (must not be zero).
    function _validateMessageBindings(ICredentialRegistry.CredentialGroupProof[] calldata proofs_, address recipient_)
        internal
        pure
    {
        if (recipient_ == address(0)) revert ZeroRecipient();
        uint256 expected = expectedMessage(recipient_);
        for (uint256 i = 0; i < proofs_.length; i++) {
            if (proofs_[i].semaphoreProof.message != expected) {
                revert MessageBindingMismatch(expected, proofs_[i].semaphoreProof.message);
            }
        }
    }
}
