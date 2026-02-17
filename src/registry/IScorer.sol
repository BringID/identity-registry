// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title IScorer
/// @notice Interface for scorer contracts that assign scores to credential groups.
///         Each app in the BringID registry points to a scorer (the DefaultScorer by default,
///         or a custom implementation). Scores are aggregated by submitProofs() and getScore()
///         to produce a total identity score.
interface IScorer {
    /// @notice Returns the score for a single credential group.
    /// @param credentialGroupId The credential group ID to look up.
    /// @return The score assigned to the credential group (0 if not set).
    function getScore(uint256 credentialGroupId) external view returns (uint256);

    /// @notice Returns scores for multiple credential groups in a single call.
    /// @param credentialGroupIds Array of credential group IDs to look up.
    /// @return Array of scores corresponding to each credential group ID.
    function getScores(uint256[] calldata credentialGroupIds) external view returns (uint256[] memory);

    /// @notice Returns all credential group IDs that have scores set, along with their values.
    /// @return credentialGroupIds Array of credential group IDs with assigned scores.
    /// @return scores Array of scores corresponding to each credential group ID.
    function getAllScores() external view returns (uint256[] memory credentialGroupIds, uint256[] memory scores);
}
