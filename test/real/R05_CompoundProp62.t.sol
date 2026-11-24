// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/real/R05_CompoundProp62.sol";
interface Vm { function prank(address) external; }

contract R05_CompoundProp62Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant LEGACY = address(0x11);
    address constant ANY = address(0x12);

    function test_buggy_unearnedAccrual() public {
        CompoundProp62Distributor d = new CompoundProp62Distributor(false, LEGACY);
        vm.prank(ANY); d.distribute(LEGACY);
        require(d.compAccrued(LEGACY) == 100 && d.compIssued() == 0, "buggy: expected 100 unearned");
    }

    function test_fixed_noUnearnedAccrual() public {
        CompoundProp62Distributor d = new CompoundProp62Distributor(true, LEGACY);
        vm.prank(ANY); d.distribute(LEGACY);
        require(d.compAccrued(LEGACY) == 0, "fixed: should accrue 0");
        vm.prank(ANY); d.accrue(5);
        vm.prank(ANY); d.distribute(LEGACY);
        require(d.compAccrued(LEGACY) == 50 && d.compIssued() == 50, "fixed: honest accrual broken");
    }
}
