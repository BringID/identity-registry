// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICredentialRegistry} from "@bringid/contracts/ICredentialRegistry.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import {Semaphore} from "@semaphore-protocol/contracts/Semaphore.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Script, console} from "forge-std/Script.sol";

contract Token is ERC20 {
    constructor(string memory name_, string memory symbol_, address mintTo, uint256 mintAmount) ERC20(name_, symbol_) {
        _mint(mintTo, mintAmount);
    }
}

contract DeployDev is Script {
    function run() public {
        address trustedVerifierAddress = 0x3c50f7055D804b51e506Bc1EA7D082cB1548376C;
        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        Semaphore semaphore;
        if (vm.envAddress("SEMAPHORE_ADDRESS") != address(0)) {
            semaphore = Semaphore(vm.envAddress("SEMAPHORE_ADDRESS"));
        } else {
            revert("Semaphore address is not provided");
        }
        CredentialRegistry registry =
            new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifierAddress, 5 minutes);
        Token bringToken = new Token("Bring", "BRING", deployer, 10 ** 32);
        vm.stopBroadcast();

        console.log("Registry:", address(registry));
        console.log("Bring Token:", address(bringToken));
    }
}

contract DeployToken is Script {
    function run() public {
        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        Token bringToken = new Token("Bring", "BRING", deployer, 10 ** 32);
        vm.stopBroadcast();
        console.log("Bring Token:", address(bringToken));
    }
}

contract Deploy is Script {
    function run() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);
        address trustedVerifier = vm.envOr("TRUSTED_VERIFIER", deployer);

        vm.startBroadcast(deployerKey);
        Semaphore semaphore;
        if (vm.envAddress("SEMAPHORE_ADDRESS") != address(0)) {
            semaphore = Semaphore(vm.envAddress("SEMAPHORE_ADDRESS"));
        } else {
            revert("SEMAPHORE_ADDRESS should be provided");
        }
        CredentialRegistry registry = new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifier, 5 minutes);
        vm.stopBroadcast();

        console.log("Deployer:", deployer);
        console.log("Trusted verifier:", trustedVerifier);
        console.log("Semaphore:", address(semaphore));
        console.log("Registry:", address(registry));
        console.log("DefaultScorer:", registry.defaultScorer());
    }
}
