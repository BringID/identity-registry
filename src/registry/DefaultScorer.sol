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

    /// @notice Sets scores for multiple credential groups in one call.
    /// @param credentialGroupIds_ The credential group IDs.
    /// @param scores_ The score values (must match length of credentialGroupIds_).
    function setScores(uint256[] calldata credentialGroupIds_, uint256[] calldata scores_) external onlyOwner {
        require(credentialGroupIds_.length == scores_.length, "length mismatch");
        for (uint256 i; i < credentialGroupIds_.length; ++i) {
            scores[credentialGroupIds_[i]] = scores_[i];
        }
    }

    /// @notice Returns the score for a credential group.
    /// @param credentialGroupId_ The credential group ID.
    function getScore(uint256 credentialGroupId_) external view returns (uint256) {
        return scores[credentialGroupId_];
    }

    /// @notice Returns scores for multiple credential groups in one call.
    /// @param credentialGroupIds_ The credential group IDs.
    /// @return scores_ The score values.
    function getScores(uint256[] calldata credentialGroupIds_) external view returns (uint256[] memory scores_) {
        scores_ = new uint256[](credentialGroupIds_.length);
        for (uint256 i; i < credentialGroupIds_.length; ++i) {
            scores_[i] = scores[credentialGroupIds_[i]];
        }
    }
}
