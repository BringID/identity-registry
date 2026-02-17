// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

interface IScorer {
    function getScore(uint256 credentialGroupId) external view returns (uint256);
    function getScores(uint256[] calldata credentialGroupIds) external view returns (uint256[] memory);
    function getAllScores() external view returns (uint256[] memory credentialGroupIds, uint256[] memory scores);
}
