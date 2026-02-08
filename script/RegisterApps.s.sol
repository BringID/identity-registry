// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CredentialRegistry, ICredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {Script, console} from "forge-std/Script.sol";

contract RegisterApps is Script {
    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        CredentialRegistry registry;
        if (vm.envAddress("CREDENTIAL_REGISTRY_ADDRESS") != address(0)) {
            registry = CredentialRegistry(vm.envAddress("CREDENTIAL_REGISTRY_ADDRESS"));
        } else {
            revert("CREDENTIAL_REGISTRY_ADDRESS should be provided");
        }

        registry.registerApp(1);
        registry.registerApp(2);
        registry.registerApp(3);
        vm.stopBroadcast();

        console.log("Registered apps 1, 2, 3 on registry:", address(registry));
    }
}
