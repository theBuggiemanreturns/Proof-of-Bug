// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/real/R01_PerennialInflation.sol";
interface Vm { function prank(address) external; }

contract R01_PerennialInflationTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant A = address(0x11); // attacker
    address constant V = address(0x12); // victim

    function _attack(PerennialInflationVault v) internal returns (uint256 victimShares) {
        vm.prank(A); v.deposit(1);
        vm.prank(A); v.donate(100);
        vm.prank(V); victimShares = v.deposit(100);
    }

    function test_buggy_victimMintsZero() public {
        PerennialInflationVault v = new PerennialInflationVault(false, A);
        require(_attack(v) == 0, "buggy: expected 0 shares for 100 assets");
    }

    function test_fixed_victimMintsFair() public {
        PerennialInflationVault v = new PerennialInflationVault(true, A);
        require(_attack(v) == 100, "fixed: expected 100 shares");
    }
}
