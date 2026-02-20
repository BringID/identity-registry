// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @title IScorer
/// @notice Interface for scorer contracts that assign scores to credential groups.
///         Each app can use a custom scorer or the global DefaultScorer.
interface IScorer {
    /// @notice Returns the score for a single credential group.
    /// @param credentialGroupId The credential group ID to look up.
    /// @return The score value for the given credential group.
    function getScore(uint256 credentialGroupId) external view returns (uint256);

    /// @notice Returns scores for multiple credential groups in a single call.
    /// @param credentialGroupIds Array of credential group IDs to look up.
    /// @return Array of score values corresponding to the input IDs.
    function getScores(uint256[] calldata credentialGroupIds) external view returns (uint256[] memory);

    /// @notice Returns all credential group IDs that have scores set, along with their values.
    /// @return credentialGroupIds Array of credential group IDs with scores.
    /// @return scores Array of corresponding score values.
    function getAllScores() external view returns (uint256[] memory credentialGroupIds, uint256[] memory scores);
}
