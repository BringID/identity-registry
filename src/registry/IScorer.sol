// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

interface IScorer {
    function getScore(uint256 credentialGroupId) external view returns (uint256);
}
