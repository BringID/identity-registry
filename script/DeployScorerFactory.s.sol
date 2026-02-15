// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ScorerFactory} from "../src/scoring/ScorerFactory.sol";
import {Script, console} from "forge-std/Script.sol";

contract DeployScorerFactory is Script {
    function run() public {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);
        ScorerFactory factory = new ScorerFactory();
        vm.stopBroadcast();

        console.log("Deployer:", deployer);
        console.log("ScorerFactory:", address(factory));
    }
}
