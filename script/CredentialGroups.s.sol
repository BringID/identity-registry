// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CredentialRegistry} from "../contracts/registry/CredentialRegistry.sol";
import {ICredentialRegistry} from "@bringid/contracts/ICredentialRegistry.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";
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

        // --- credential group IDs, validity durations, families, and scores ---
        uint256[] memory ids = new uint256[](15);
        uint256[] memory durations = new uint256[](15);
        uint256[] memory families = new uint256[](15);
        uint256[] memory scores = new uint256[](15);

        // Farcaster Low / Medium / High — 30 / 60 / 90 days, family 1
        ids[0] = 1;
        durations[0] = 30 days;
        families[0] = 1;
        scores[0] = 2;
        ids[1] = 2;
        durations[1] = 60 days;
        families[1] = 1;
        scores[1] = 5;
        ids[2] = 3;
        durations[2] = 90 days;
        families[2] = 1;
        scores[2] = 10;

        // GitHub Low / Medium / High — 30 / 60 / 90 days, family 2
        ids[3] = 4;
        durations[3] = 30 days;
        families[3] = 2;
        scores[3] = 2;
        ids[4] = 5;
        durations[4] = 60 days;
        families[4] = 2;
        scores[4] = 5;
        ids[5] = 6;
        durations[5] = 90 days;
        families[5] = 2;
        scores[5] = 10;

        // X (Twitter) Low / Medium / High — 30 / 60 / 90 days, family 3
        ids[6] = 7;
        durations[6] = 30 days;
        families[6] = 3;
        scores[6] = 2;
        ids[7] = 8;
        durations[7] = 60 days;
        families[7] = 3;
        scores[7] = 5;
        ids[8] = 9;
        durations[8] = 90 days;
        families[8] = 3;
        scores[8] = 10;

        // zkPassport / Self — 180 days, standalone
        ids[9] = 10;
        durations[9] = 180 days;
        scores[9] = 20;
        ids[10] = 11;
        durations[10] = 180 days;
        scores[10] = 20;

        // zkTLS binary credentials — 180 days, standalone
        ids[11] = 12; // Uber Rides
        durations[11] = 180 days;
        scores[11] = 10;
        ids[12] = 13; // Apple Subs
        durations[12] = 180 days;
        scores[12] = 10;

        // zkKYC credentials — 180 days, standalone
        ids[13] = 14; // Binance KYC
        durations[13] = 180 days;
        scores[13] = 20;
        ids[14] = 15; // OKX KYC
        durations[14] = 180 days;
        scores[14] = 20;

        // Create credential groups that don't already exist
        for (uint256 i = 0; i < ids.length; i++) {
            (ICredentialRegistry.CredentialGroupStatus status,,) = registry.credentialGroups(ids[i]);
            if (status == ICredentialRegistry.CredentialGroupStatus.UNDEFINED) {
                registry.createCredentialGroup(ids[i], durations[i], families[i]);
            }
        }

        // Batch-set scores on the DefaultScorer
        scorer.setScores(ids, scores);

        vm.stopBroadcast();

        // --- verification logging ---
        for (uint256 i = 0; i < ids.length; i++) {
            (ICredentialRegistry.CredentialGroupStatus status,, uint256 familyId) = registry.credentialGroups(ids[i]);
            uint256 score = scorer.getScore(ids[i]);
            console.log("Group %d: status=%d, score=%d", ids[i], uint256(status), score);
        }
    }
}
