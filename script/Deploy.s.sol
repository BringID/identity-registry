// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICredentialRegistry} from "../src/registry/ICredentialRegistry.sol";
import {CredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {ISemaphore} from "semaphore-protocol/interfaces/ISemaphore.sol";
import {Semaphore} from "semaphore-protocol/Semaphore.sol";
import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";
import {Script, console} from "forge-std/Script.sol";

contract Token is ERC20 {
    constructor(string memory name_, string memory symbol_, address mintTo, uint256 mintAmount) ERC20(name_, symbol_) {
        _mint(mintTo, mintAmount);
    }
}

contract DeployDev is Script {
    function run() public {
        address trustedVerifierAddress = 0x3c50f7055D804b51e506Bc1EA7D082cB1548376C;
        address nullifierVerifierAddress = vm.envAddress("NULLIFIER_VERIFIER_ADDRESS");
        address deployer = vm.addr(vm.envUint("PRIVATE_KEY"));

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        Semaphore semaphore;
        if (vm.envAddress("SEMAPHORE_ADDRESS") != address(0)) {
            semaphore = Semaphore(vm.envAddress("SEMAPHORE_ADDRESS"));
        } else {
            revert("Semaphore address is not provided");
        }
        CredentialRegistry registry =
            new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifierAddress, nullifierVerifierAddress);
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
        address trustedVerifierAddress = 0x7043BE13423Ae8Fc371B8B18AEB2A40582f9CD69;
        address nullifierVerifierAddress = vm.envAddress("NULLIFIER_VERIFIER_ADDRESS");

        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        Semaphore semaphore;
        if (vm.envAddress("SEMAPHORE_ADDRESS") != address(0)) {
            semaphore = Semaphore(vm.envAddress("SEMAPHORE_ADDRESS"));
        } else {
            revert("SEMAPHORE_ADDRESS should be provided");
        }
        CredentialRegistry registry =
            new CredentialRegistry(ISemaphore(address(semaphore)), trustedVerifierAddress, nullifierVerifierAddress);
        vm.stopBroadcast();

        console.log("Semaphore:", address(semaphore));
        console.log("Registry:", address(registry));
    }
}
