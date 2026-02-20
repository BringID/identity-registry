// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "./ICredentialRegistry.sol";

/// @title IBringIDGated
/// @notice Interface for contracts that validate and submit BringID credential proofs.
///         Exposes view functions for off-chain callers to pre-check proofs scoped to
///         the consumer contract, plus configuration getters.
interface IBringIDGated {
    /// @notice Thrown when a proof's message does not match the expected recipient binding.
    /// @param expected The expected message value (hash of the recipient address).
    /// @param actual The actual message value found in the proof.
    error WrongProofRecipient(uint256 expected, uint256 actual);

    /// @notice Thrown when the recipient address is the zero address.
    error ZeroRecipient();

    /// @notice Thrown when a proof targets an unexpected app ID.
    /// @param expected The expected app ID.
    /// @param actual The actual app ID found in the proof.
    error AppIdMismatch(uint256 expected, uint256 actual);

    /// @notice The BringID CredentialRegistry this contract submits proofs to.
    function REGISTRY() external view returns (ICredentialRegistry);

    /// @notice Validates that a single proof's message is bound to the intended recipient.
    /// @param proof_ The credential group proof to validate.
    /// @param recipient_ The intended recipient address (must not be zero).
    function validateProofRecipient(ICredentialRegistry.CredentialGroupProof calldata proof_, address recipient_)
        external
        pure;

    /// @notice Validates that all proofs' messages are bound to the intended recipient.
    /// @param proofs_ Array of credential group proofs to validate.
    /// @param recipient_ The intended recipient address (must not be zero).
    function validateProofRecipients(ICredentialRegistry.CredentialGroupProof[] calldata proofs_, address recipient_)
        external
        pure;

    /// @notice The app ID that all proofs must target.
    function APP_ID() external view returns (uint256);

    /// @notice View-only: verifies a single proof using this contract's address for scope.
    /// @param context_ Application-defined context value for scope computation.
    /// @param proof_ The credential group proof to verify.
    /// @return True if the proof is valid.
    function verifyProof(uint256 context_, ICredentialRegistry.CredentialGroupProof calldata proof_)
        external
        view
        returns (bool);

    /// @notice View-only: verifies multiple proofs using this contract's address for scope.
    /// @param context_ Application-defined context value for scope computation.
    /// @param proofs_ Array of credential group proofs to verify.
    /// @return True if all proofs are valid.
    function verifyProofs(uint256 context_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_)
        external
        view
        returns (bool);

    /// @notice View-only: verifies proofs and returns aggregate score using this contract's address.
    /// @param context_ Application-defined context value for scope computation.
    /// @param proofs_ Array of credential group proofs to verify and score.
    /// @return The total score across all verified credential groups.
    function getScore(uint256 context_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_)
        external
        view
        returns (uint256);
}
