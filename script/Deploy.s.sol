// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CredentialRegistryV2} from "../src/CredentialRegistryV2.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Script, console} from "forge-std/Script.sol";

contract Deploy is Script {
    function run() public {
        address verifierAddress = vm.envAddress("VERIFIER_ADDRESS");
        address semaphoreAddress = vm.envAddress("SEMAPHORE_ADDRESS");

        require(verifierAddress != address(0), "VERIFIER_ADDRESS required");
        require(semaphoreAddress != address(0), "SEMAPHORE_ADDRESS required");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            CredentialRegistryV2 registry = new CredentialRegistryV2(
                ISemaphore(semaphoreAddress),
                verifierAddress
            );
        vm.stopBroadcast();

        console.log("CredentialRegistryV2:", address(registry));
        console.log("Semaphore:", semaphoreAddress);
        console.log("Verifier:", verifierAddress);
    }
}

contract CreateScoreGroup is Script {
    function run() public {
        address registryAddress = vm.envAddress("REGISTRY_ADDRESS");
        uint256 score = vm.envUint("SCORE");

        require(registryAddress != address(0), "REGISTRY_ADDRESS required");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            CredentialRegistryV2 registry = CredentialRegistryV2(registryAddress);
            registry.createScoreGroup(score);
        vm.stopBroadcast();

        console.log("Score group created for score:", score);
    }
}

contract RegisterApp is Script {
    function run() public {
        address registryAddress = vm.envAddress("REGISTRY_ADDRESS");
        uint256 appId = vm.envUint("APP_ID");
        address appAdmin = vm.envAddress("APP_ADMIN_ADDRESS");
        uint256 recoveryDelay = vm.envUint("RECOVERY_DELAY");

        require(registryAddress != address(0), "REGISTRY_ADDRESS required");
        require(appId > 0, "APP_ID required");
        require(appAdmin != address(0), "APP_ADMIN_ADDRESS required");
        require(recoveryDelay >= 1 days, "RECOVERY_DELAY must be at least 1 day");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            CredentialRegistryV2 registry = CredentialRegistryV2(registryAddress);
            registry.registerApp(appId, appAdmin, recoveryDelay);
        vm.stopBroadcast();

        console.log("App registered:");
        console.log("  App ID:", appId);
        console.log("  Admin:", appAdmin);
        console.log("  Recovery Delay:", recoveryDelay, "seconds");
    }
}

/// @notice Setup standard score groups (0, 10, 20, 30, 40, 50, etc.)
contract SetupScoreGroups is Script {
    function run() public {
        address registryAddress = vm.envAddress("REGISTRY_ADDRESS");

        require(registryAddress != address(0), "REGISTRY_ADDRESS required");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
            CredentialRegistryV2 registry = CredentialRegistryV2(registryAddress);

            // Create score groups: 0, 10, 20, 30, 40, 50
            registry.createScoreGroup(0);
            registry.createScoreGroup(10);
            registry.createScoreGroup(20);
            registry.createScoreGroup(30);
            registry.createScoreGroup(40);
            registry.createScoreGroup(50);
        vm.stopBroadcast();

        console.log("Score groups created for scores: 0, 10, 20, 30, 40, 50");
    }
}
