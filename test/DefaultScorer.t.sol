// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";

contract DefaultScorerTest is Test {
    DefaultScorer scorer;

    address owner;
    address nonOwner;

    event ScoreSet(uint256 indexed credentialGroupId, uint256 score);

    function setUp() public {
        owner = address(this);
        nonOwner = makeAddr("non-owner");
        scorer = new DefaultScorer(owner);
    }

    // --- setScores batch tests ---

    function testDefaultScorerSetScores() public {
        uint256[] memory ids = new uint256[](3);
        ids[0] = 1;
        ids[1] = 2;
        ids[2] = 3;

        uint256[] memory vals = new uint256[](3);
        vals[0] = 10;
        vals[1] = 20;
        vals[2] = 30;

        vm.expectEmit(true, false, false, true);
        emit ScoreSet(1, 10);
        vm.expectEmit(true, false, false, true);
        emit ScoreSet(2, 20);
        vm.expectEmit(true, false, false, true);
        emit ScoreSet(3, 30);

        scorer.setScores(ids, vals);

        assertEq(scorer.getScore(1), 10);
        assertEq(scorer.getScore(2), 20);
        assertEq(scorer.getScore(3), 30);
    }

    function testDefaultScorerSetScoresLengthMismatch() public {
        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;

        uint256[] memory vals = new uint256[](1);
        vals[0] = 10;

        vm.expectRevert(DefaultScorer.LengthMismatch.selector);
        scorer.setScores(ids, vals);
    }

    function testDefaultScorerSetScoresOnlyOwner() public {
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;

        uint256[] memory vals = new uint256[](1);
        vals[0] = 10;

        vm.prank(nonOwner);
        vm.expectRevert("Ownable: caller is not the owner");
        scorer.setScores(ids, vals);
    }

    // --- getScores batch tests ---

    function testDefaultScorerGetScores() public {
        scorer.setScore(1, 10);
        scorer.setScore(2, 20);
        scorer.setScore(3, 30);

        // Query a subset
        uint256[] memory queryIds = new uint256[](2);
        queryIds[0] = 1;
        queryIds[1] = 3;

        uint256[] memory result = scorer.getScores(queryIds);
        assertEq(result.length, 2);
        assertEq(result[0], 10);
        assertEq(result[1], 30);

        // Query unset group returns 0
        uint256[] memory unsetIds = new uint256[](1);
        unsetIds[0] = 99;

        uint256[] memory unsetResult = scorer.getScores(unsetIds);
        assertEq(unsetResult.length, 1);
        assertEq(unsetResult[0], 0);
    }

    // --- getAllScores tests ---

    function testDefaultScorerGetAllScores() public {
        scorer.setScore(5, 50);
        scorer.setScore(10, 100);
        scorer.setScore(15, 150);

        (uint256[] memory groupIds, uint256[] memory groupScores) = scorer.getAllScores();

        assertEq(groupIds.length, 3);
        assertEq(groupScores.length, 3);

        assertEq(groupIds[0], 5);
        assertEq(groupIds[1], 10);
        assertEq(groupIds[2], 15);

        assertEq(groupScores[0], 50);
        assertEq(groupScores[1], 100);
        assertEq(groupScores[2], 150);
    }

    // --- overwrite tests ---

    function testDefaultScorerSetScoresOverwrite() public {
        // Set initial score
        scorer.setScore(1, 10);
        assertEq(scorer.getScore(1), 10);

        // Overwrite via batch
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;

        uint256[] memory vals = new uint256[](1);
        vals[0] = 20;

        scorer.setScores(ids, vals);
        assertEq(scorer.getScore(1), 20);

        // Verify getAllScores does not contain duplicate group 1
        (uint256[] memory groupIds, uint256[] memory groupScores) = scorer.getAllScores();
        assertEq(groupIds.length, 1);
        assertEq(groupIds[0], 1);
        assertEq(groupScores[0], 20);
    }
}
