// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {ISemaphoreVerifier} from "semaphore-protocol/interfaces/ISemaphoreVerifier.sol";
import {SemaphoreVerifier} from "semaphore-protocol/base/SemaphoreVerifier.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {Script, console} from "forge-std/Script.sol";

/// @notice Deploys everything needed for local e2e testing:
///         SemaphoreVerifier -> Semaphore -> CredentialRegistry
///         The deployer is set as the trusted verifier so they can sign attestations.
contract DeployLocal is Script {
    function run() public {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);

        vm.startBroadcast(pk);

        SemaphoreVerifier semaphoreVerifier = new SemaphoreVerifier();
        Semaphore semaphore = new Semaphore(ISemaphoreVerifier(address(semaphoreVerifier)));
        CredentialRegistry registry = new CredentialRegistry(ISemaphore(address(semaphore)), deployer);

        // Register a default app (appId = 1), caller = deployer = admin
        uint256 appId = registry.registerApp(0);

        vm.stopBroadcast();

        console.log("Deployer:            ", deployer);
        console.log("SemaphoreVerifier:   ", address(semaphoreVerifier));
        console.log("Semaphore:           ", address(semaphore));
        console.log("CredentialRegistry:  ", address(registry));
        console.log("DefaultScorer:       ", registry.defaultScorer());
        console.log("App ID:              ", appId);
    }
}
