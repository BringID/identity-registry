// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CredentialRegistry} from "../contracts/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "@bringid/contracts/ICredentialRegistry.sol";
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

        uint256 appId1 = registry.registerApp(0);
        uint256 appId2 = registry.registerApp(0);
        uint256 appId3 = registry.registerApp(0);
        vm.stopBroadcast();

        console.log("Registered app IDs:", appId1, appId2, appId3);
        console.log("On registry:", address(registry));
    }
}
