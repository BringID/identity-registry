// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "../ICredentialRegistry.sol";
import {ScoreGated} from "../ScoreGated.sol";

/// @title SafeAirdrop
/// @notice Example airdrop contract demonstrating front-running-resistant proof consumption.
///         Users submit credential proofs bound to their address via the Semaphore `message`
///         field. The contract validates the binding before forwarding proofs to the registry,
///         ensuring that an attacker who copies a proof from the mempool cannot steal the claim.
/// @dev This is a minimal example — production contracts should add token distribution logic.
contract SafeAirdrop is ScoreGated {
    /// @notice Tracks which addresses have already claimed.
    mapping(address => bool) public claimed;

    /// @notice Thrown when an address has already claimed.
    error AlreadyClaimed();

    /// @notice Emitted when an airdrop claim succeeds.
    /// @param recipient The address that received the claim.
    /// @param score The aggregate credential score.
    event AirdropClaimed(address indexed recipient, uint256 score);

    /// @param registry_ The BringID CredentialRegistry address.
    /// @param minScore_ Minimum aggregate score to claim.
    /// @param context_ Application-defined context value for scope computation.
    /// @param appId_ The app ID that all proofs must target.
    /// @param maxProofs_ Maximum number of proofs accepted per claim.
    constructor(ICredentialRegistry registry_, uint256 minScore_, uint256 context_, uint256 appId_, uint256 maxProofs_)
        ScoreGated(registry_, minScore_, context_, appId_, maxProofs_)
    {}

    /// @notice Claims an airdrop by submitting message-bound credential proofs.
    /// @dev Flow:
    ///      1. Check recipient hasn't already claimed.
    ///      2. Validate proofs (count, app ID, message binding) and submit to registry.
    ///      3. Mark recipient as claimed.
    /// @param recipient_ The intended recipient of the airdrop (must match proof message binding).
    /// @param proofs_ Array of credential group proofs with `message = hash(recipient_)`.
    function claim(address recipient_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_) external {
        if (claimed[recipient_]) revert AlreadyClaimed();

        uint256 score = _submitAndValidate(recipient_, proofs_);

        claimed[recipient_] = true;

        emit AirdropClaimed(recipient_, score);
    }
}
