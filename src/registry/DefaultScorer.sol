// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IScorer} from "./IScorer.sol";
import {Ownable} from "openzeppelin/access/Ownable.sol";

/// @title DefaultScorer
/// @notice Default scoring contract owned by BringID. Stores global scores per credential group.
///         Apps that don't set a custom scorer use this by default.
contract DefaultScorer is IScorer, Ownable {
    mapping(uint256 credentialGroupId => uint256) public scores;

    /// @notice Sets the score for a credential group.
    /// @param credentialGroupId_ The credential group ID.
    /// @param score_ The score value.
    function setScore(uint256 credentialGroupId_, uint256 score_) public onlyOwner {
        scores[credentialGroupId_] = score_;
    }

    /// @notice Returns the score for a credential group.
    /// @param credentialGroupId_ The credential group ID.
    function getScore(uint256 credentialGroupId_) external view returns (uint256) {
        return scores[credentialGroupId_];
    }
}
