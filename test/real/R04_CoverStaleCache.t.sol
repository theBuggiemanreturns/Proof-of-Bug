// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/real/R04_CoverStaleCache.sol";
interface Vm { function prank(address) external; }

contract R04_CoverStaleCacheTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant HOLDER = address(0x11);
    address constant ATK = address(0x12);

    function _attack(CoverStaleCacheFarm f) internal {
        vm.prank(HOLDER); f.tick(10);
        vm.prank(ATK); f.deposit(10);
        vm.prank(ATK); f.claim();
    }

    function test_buggy_paysUnfundedRewards() public {
        CoverStaleCacheFarm f = new CoverStaleCacheFarm(false, HOLDER);
        _attack(f);
        require(f.rewardsPaid() == 100 && f.rewardsFunded() == 10, "buggy: expected 100 paid vs 10 funded");
    }

    function test_fixed_paysNothingExtra() public {
        CoverStaleCacheFarm f = new CoverStaleCacheFarm(true, HOLDER);
        _attack(f);
        require(f.rewardsPaid() == 0, "fixed: attacker should earn 0");
        vm.prank(HOLDER); f.claim();
        require(f.rewardsPaid() == 10 && f.rewardsPaid() <= f.rewardsFunded(), "fixed: holder share wrong");
    }
}
