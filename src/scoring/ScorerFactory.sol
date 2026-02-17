// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {DefaultScorer} from "./DefaultScorer.sol";

/// @title ScorerFactory
/// @notice Deploys DefaultScorer instances owned by the caller.
///         Used by the App Manager dashboard so app admins can create
///         custom scorers in a single transaction.
contract ScorerFactory {
    event ScorerCreated(address indexed scorer, address indexed owner);

    /// @notice Deploy a new DefaultScorer owned by msg.sender.
    /// @return scorer The address of the newly deployed scorer.
    function create() external returns (address scorer) {
        DefaultScorer s = new DefaultScorer(msg.sender);
        scorer = address(s);
        emit ScorerCreated(scorer, msg.sender);
    }
}
