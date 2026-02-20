// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "../registry/ICredentialRegistry.sol";

/// @title SafeProofConsumer
/// @notice Abstract helper for smart contracts that consume BringID credential proofs.
///         Validates that the Semaphore proof `message` field is bound to an intended
///         recipient address, preventing mempool front-running attacks.
/// @dev When a smart contract calls `registry.submitProofs()`, the `scope` is bound to
///      `msg.sender` (the contract) + `context`. Any user can copy the proof from the
///      mempool and submit it first through the same contract, because `msg.sender` is
///      identical. Binding the `message` field to the intended recipient makes copied
///      proofs useless to the attacker.
///
///      Usage: inherit this contract, call `_validateMessageBinding()` or
///      `_validateMessageBindings()` before forwarding proofs to the registry.
abstract contract SafeProofConsumer {
    ICredentialRegistry public immutable REGISTRY;

    /// @notice Thrown when a proof's message does not match the expected recipient binding.
    /// @param expected The expected message value (hash of the recipient address).
    /// @param actual The actual message value found in the proof.
    error MessageBindingMismatch(uint256 expected, uint256 actual);

    /// @notice Thrown when the recipient address is the zero address.
    error ZeroRecipient();

    constructor(ICredentialRegistry registry_) {
        REGISTRY = registry_;
    }

    /// @notice Computes the expected Semaphore `message` value for a given recipient.
    /// @param recipient_ The intended recipient address.
    /// @return The expected message: `uint256(keccak256(abi.encodePacked(recipient_)))`.
    function expectedMessage(address recipient_) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(recipient_)));
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
