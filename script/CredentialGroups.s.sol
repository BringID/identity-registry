// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CredentialRegistry, ICredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {DefaultScorer} from "../src/registry/DefaultScorer.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";
import {Script, console} from "forge-std/Script.sol";

contract Register is Script {
    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        CredentialRegistry registry;
        if (vm.envAddress("CREDENTIAL_REGISTRY_ADDRESS") != address(0)) {
            registry = CredentialRegistry(vm.envAddress("CREDENTIAL_REGISTRY_ADDRESS"));
        } else {
            revert("CREDENTIAL_REGISTRY_ADDRESS should be provided");
        }

        DefaultScorer scorer = DefaultScorer(registry.defaultScorer());

        registry.createCredentialGroup(99);
        scorer.setScore(99, 10);
        registry.createCredentialGroup(1);
        scorer.setScore(1, 10);
        registry.createCredentialGroup(2);
        scorer.setScore(2, 20);
        registry.createCredentialGroup(3);
        scorer.setScore(3, 10);
        registry.createCredentialGroup(4);
        scorer.setScore(4, 5);
        registry.createCredentialGroup(5);
        scorer.setScore(5, 10);
        vm.stopBroadcast();

        (uint256 semaphoreGroupId,) = registry.credentialGroups(99);
        console.log("99:", semaphoreGroupId);
        (semaphoreGroupId,) = registry.credentialGroups(1);
        console.log("1:", semaphoreGroupId);
        (semaphoreGroupId,) = registry.credentialGroups(2);
        console.log("2:", semaphoreGroupId);
        (semaphoreGroupId,) = registry.credentialGroups(3);
        console.log("3:", semaphoreGroupId);
        (semaphoreGroupId,) = registry.credentialGroups(4);
        console.log("4:", semaphoreGroupId);
        (semaphoreGroupId,) = registry.credentialGroups(5);
        console.log("5:", semaphoreGroupId);
    }
}
