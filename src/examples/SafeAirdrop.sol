// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ICredentialRegistry} from "../registry/ICredentialRegistry.sol";
import {SafeProofConsumer} from "../registry/SafeProofConsumer.sol";

/// @title SafeAirdrop
/// @notice Example airdrop contract demonstrating front-running-resistant proof consumption.
///         Users submit credential proofs bound to their address via the Semaphore `message`
///         field. The contract validates the binding before forwarding proofs to the registry,
///         ensuring that an attacker who copies a proof from the mempool cannot steal the claim.
/// @dev This is a minimal example — production contracts should add token distribution logic.
contract SafeAirdrop is SafeProofConsumer {
    /// @notice Minimum aggregate score required to claim.
    uint256 public immutable MIN_SCORE;

    /// @notice Application-defined context value passed to the registry.
    uint256 public immutable CONTEXT;

    /// @notice The app ID that all proofs must target.
    uint256 public immutable APP_ID;

    /// @notice Tracks which addresses have already claimed.
    mapping(address => bool) public claimed;

    /// @notice Thrown when an address has already claimed.
    error AlreadyClaimed();

    /// @notice Thrown when the aggregate proof score is below `MIN_SCORE`.
    /// @param score The actual score returned by the registry.
    /// @param minScore The required minimum score.
    error InsufficientScore(uint256 score, uint256 minScore);

    /// @notice Thrown when a proof targets an unexpected app ID.
    /// @param expected The expected app ID.
    /// @param actual The actual app ID found in the proof.
    error AppIdMismatch(uint256 expected, uint256 actual);

    /// @notice Emitted when an airdrop claim succeeds.
    /// @param recipient The address that received the claim.
    /// @param score The aggregate credential score.
    event AirdropClaimed(address indexed recipient, uint256 score);

    /// @param registry_ The BringID CredentialRegistry address.
    /// @param minScore_ Minimum aggregate score to claim.
    /// @param context_ Application-defined context value for scope computation.
    /// @param appId_ The app ID that all proofs must target.
    constructor(ICredentialRegistry registry_, uint256 minScore_, uint256 context_, uint256 appId_)
        SafeProofConsumer(registry_)
    {
        MIN_SCORE = minScore_;
        CONTEXT = context_;
        APP_ID = appId_;
    }

    /// @notice Claims an airdrop by submitting message-bound credential proofs.
    /// @dev Flow:
    ///      1. Validate that each proof's `message` equals `hash(recipient_)`.
    ///      2. Forward proofs to the registry (consumes nullifiers, returns score).
    ///      3. Check score meets `MIN_SCORE`.
    ///      4. Mark recipient as claimed.
    /// @param recipient_ The intended recipient of the airdrop (must match proof message binding).
    /// @param proofs_ Array of credential group proofs with `message = hash(recipient_)`.
    function claim(address recipient_, ICredentialRegistry.CredentialGroupProof[] calldata proofs_) external {
        if (claimed[recipient_]) revert AlreadyClaimed();

        for (uint256 i = 0; i < proofs_.length; i++) {
            if (proofs_[i].appId != APP_ID) revert AppIdMismatch(APP_ID, proofs_[i].appId);
        }

        _validateMessageBindings(proofs_, recipient_);

        uint256 score = REGISTRY.submitProofs(CONTEXT, proofs_);

        if (score < MIN_SCORE) revert InsufficientScore(score, MIN_SCORE);

        claimed[recipient_] = true;

        emit AirdropClaimed(recipient_, score);
    }
}
