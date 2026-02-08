// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Vm} from "forge-std/Vm.sol";
import {Test, console} from "forge-std/Test.sol";

library TestUtils {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function semaphoreCommitment(uint256 commitmentKey) public returns (uint256) {
        string[] memory inputs = new string[](3);
        inputs[0] = "node";
        inputs[1] = "test/semaphore-js/commitment.mjs";
        inputs[2] = vm.toString(bytes32(commitmentKey));
        return abi.decode(FFI(inputs), (uint256));
    }

    function semaphoreProof(uint256 commitmentKey, uint256 scope, uint256[] memory commitments)
        public
        returns (uint256, uint256, uint256, uint256, uint256[8] memory)
    {
        string[] memory inputs = new string[](4 + commitments.length);
        inputs[0] = "node";
        inputs[1] = "test/semaphore-js/proof.mjs";
        inputs[2] = vm.toString(bytes32(commitmentKey));
        inputs[3] = vm.toString(bytes32(scope));
        for (uint256 i; i < commitments.length; i++) {
            inputs[i + 4] = vm.toString(bytes32(commitments[i]));
        }
        return abi.decode(FFI(inputs), (uint256, uint256, uint256, uint256, uint256[8]));
    }

    function FFI(string[] memory inputs) public returns (bytes memory res) {
        res = vm.ffi(inputs);
    }
}
