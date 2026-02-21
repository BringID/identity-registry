// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {ScorerFactory} from "@bringid/contracts/scoring/ScorerFactory.sol";
import {DefaultScorer} from "@bringid/contracts/scoring/DefaultScorer.sol";
import {IScorer} from "@bringid/contracts/interfaces/IScorer.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

contract ScorerFactoryTest is Test {
    ScorerFactory factory;

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    function setUp() public {
        factory = new ScorerFactory();
    }

    /// @notice Verify create() returns a non-zero address and the scorer implements IScorer.
    function testScorerFactoryCreate() public {
        address scorer = factory.create();
        assertTrue(scorer != address(0), "scorer address should be non-zero");
        // Verify the scorer is a valid IScorer — getScore for an unset group should return 0
        assertEq(IScorer(scorer).getScore(1), 0);
    }

    /// @notice Verify the created scorer is owned by msg.sender and access control works.
    function testScorerFactoryCreateOwnership() public {
        vm.prank(alice);
        address scorer = factory.create();

        // Owner should be alice
        assertEq(DefaultScorer(scorer).owner(), alice);

        // Alice can set a score
        vm.prank(alice);
        DefaultScorer(scorer).setScore(1, 42);
        assertEq(IScorer(scorer).getScore(1), 42);

        // Bob cannot set a score
        vm.prank(bob);
        vm.expectRevert("Ownable: caller is not the owner");
        DefaultScorer(scorer).setScore(1, 99);
    }

    event ScorerCreated(address indexed scorer, address indexed owner);

    /// @notice Verify the ScorerCreated event is emitted with correct parameters.
    function testScorerFactoryCreateEvent() public {
        // Predict the address the scorer will be deployed to
        address predicted = vm.computeCreateAddress(address(factory), vm.getNonce(address(factory)));
        vm.expectEmit(true, true, true, true, address(factory));
        emit ScorerCreated(predicted, address(this));
        address scorer = factory.create();
        assertEq(scorer, predicted);
    }

    /// @notice Verify multiple create() calls return different, independently owned scorers.
    function testScorerFactoryCreateMultiple() public {
        vm.startPrank(alice);
        address scorer1 = factory.create();
        address scorer2 = factory.create();
        vm.stopPrank();

        // Different addresses
        assertTrue(scorer1 != scorer2, "scorers should have different addresses");

        // Both owned by alice
        assertEq(DefaultScorer(scorer1).owner(), alice);
        assertEq(DefaultScorer(scorer2).owner(), alice);

        // Independent state: set score on scorer1, verify scorer2 is unaffected
        vm.prank(alice);
        DefaultScorer(scorer1).setScore(1, 10);
        assertEq(IScorer(scorer1).getScore(1), 10);
        assertEq(IScorer(scorer2).getScore(1), 0);
    }

    /// @notice Verify factory-deployed scorers support IScorer via ERC165.
    function testScorerFactoryCreateSupportsInterface() public {
        address scorer = factory.create();
        assertTrue(IERC165(scorer).supportsInterface(type(IScorer).interfaceId));
        assertTrue(IERC165(scorer).supportsInterface(type(IERC165).interfaceId));
        assertFalse(IERC165(scorer).supportsInterface(0xdeadbeef));
    }
}
