// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

interface INullifierVerifier {
    function verifyProof(bytes32 nullifier, uint256 appId, uint256 scope, bytes calldata proof) external;
}
