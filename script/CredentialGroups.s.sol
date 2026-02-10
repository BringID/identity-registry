// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CredentialRegistry, ICredentialRegistry} from "../src/registry/CredentialRegistry.sol";
import {DefaultScorer} from "../src/registry/DefaultScorer.sol";
import {Script, console} from "forge-std/Script.sol";

/// @notice Deploys credential groups and sets default scores per
///         docs/credential_groups_and_default_scores.md
///
///  ID | Credential        | Group  | Score
///  ---|-------------------|--------|------
///   1 | Farcaster         | Low    |   2
///   2 | Farcaster         | Medium |   5
///   3 | Farcaster         | High   |  10
///   4 | GitHub            | Low    |   2
///   5 | GitHub            | Medium |   5
///   6 | GitHub            | High   |  10
///   7 | X (Twitter)       | Low    |   2
///   8 | X (Twitter)       | Medium |   5
///   9 | X (Twitter)       | High   |  10
///  10 | zkPassport        | —      |  20
///  11 | Self              | —      |  20
///  12 | Uber Rides        | —      |  10
///  13 | Apple Subs        | —      |  10
///  14 | Binance KYC       | —      |  20
///  15 | OKX KYC           | —      |  20
///
/// Usage:
///   PRIVATE_KEY=<key> CREDENTIAL_REGISTRY_ADDRESS=<addr> \
///     forge script script/CredentialGroups.s.sol:DeployCredentialGroups \
///     --rpc-url <rpc> --broadcast
contract DeployCredentialGroups is Script {
    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));

        CredentialRegistry registry = CredentialRegistry(vm.envAddress("CREDENTIAL_REGISTRY_ADDRESS"));
        DefaultScorer scorer = DefaultScorer(registry.defaultScorer());

        // --- credential group IDs, validity durations, and scores ---
        uint256[] memory ids = new uint256[](15);
        uint256[] memory scores = new uint256[](15);

        // Farcaster Low / Medium / High
        ids[0] = 1;
        scores[0] = 2;
        ids[1] = 2;
        scores[1] = 5;
        ids[2] = 3;
        scores[2] = 10;

        // GitHub Low / Medium / High
        ids[3] = 4;
        scores[3] = 2;
        ids[4] = 5;
        scores[4] = 5;
        ids[5] = 6;
        scores[5] = 10;

        // X (Twitter) Low / Medium / High
        ids[6] = 7;
        scores[6] = 2;
        ids[7] = 8;
        scores[7] = 5;
        ids[8] = 9;
        scores[8] = 10;

        // Binary credentials
        ids[9] = 10; // zkPassport
        scores[9] = 20;
        ids[10] = 11; // Self
        scores[10] = 20;
        ids[11] = 12; // Uber Rides
        scores[11] = 10;
        ids[12] = 13; // Apple Subs
        scores[12] = 10;
        ids[13] = 14; // Binance KYC
        scores[13] = 20;
        ids[14] = 15; // OKX KYC
        scores[14] = 20;

        // Create credential groups that don't already exist (validityDuration = 0 → no expiry)
        for (uint256 i = 0; i < ids.length; i++) {
            (ICredentialRegistry.CredentialGroupStatus status,) = registry.credentialGroups(ids[i]);
            if (status == ICredentialRegistry.CredentialGroupStatus.UNDEFINED) {
                registry.createCredentialGroup(ids[i], 0);
            }
        }

        // Batch-set scores on the DefaultScorer
        scorer.setScores(ids, scores);

        vm.stopBroadcast();

        // --- verification logging ---
        for (uint256 i = 0; i < ids.length; i++) {
            (ICredentialRegistry.CredentialGroupStatus status,) = registry.credentialGroups(ids[i]);
            uint256 score = scorer.getScore(ids[i]);
            console.log("Group %d: status=%d, score=%d", ids[i], uint256(status), score);
        }
    }
}
