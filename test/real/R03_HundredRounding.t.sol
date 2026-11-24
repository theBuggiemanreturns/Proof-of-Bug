// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/real/R03_HundredRounding.sol";
interface Vm { function prank(address) external; }

contract R03_HundredRoundingTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant VICTIM = address(0x11);
    address constant ATK = address(0x12);

    function test_buggy_overRedeem() public {
        HundredRoundingMarket m = new HundredRoundingMarket(false, VICTIM);
        vm.prank(ATK); m.deposit(50);          // 1 share for 50 assets
        uint256 preA = m.totalAssets(); uint256 preS = m.totalShares();
        vm.prank(ATK); m.withdraw(99);         // burns 1 share, takes 99
        require(m.paidOut(ATK) == 99, "buggy: expected 99 out for 50 in");
        // per-share backing dropped for the remaining holder
        require(m.totalAssets() * preS < preA * m.totalShares(), "buggy: price did not drop");
    }

    function test_fixed_overRedeemReverts() public {
        HundredRoundingMarket m = new HundredRoundingMarket(true, VICTIM);
        vm.prank(ATK); m.deposit(50);
        vm.prank(ATK);
        (bool ok, ) = address(m).call(abi.encodeWithSelector(m.withdraw.selector, 99));
        require(!ok, "fixed: over-redeem should revert");
        vm.prank(ATK); m.withdraw(50);         // fair exit still works
        require(m.totalAssets() == 50 && m.totalShares() == 1, "fixed: fair exit broken");
    }
}
