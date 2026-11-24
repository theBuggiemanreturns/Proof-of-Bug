// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/hidden/H01_ThreeMakers.sol";
interface Vm { function prank(address) external; }
contract H01Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function _run(bool f) internal returns (XrpLikeH01 c, bool ok) {
        c = new XrpLikeH01(f, address(0x11));
        vm.prank(address(0x11)); c.place(63);
        vm.prank(address(0x12)); c.place(63);
        vm.prank(address(0x13)); c.place(63); // third user: outside GateGuard's 2-user model
        (ok, ) = address(c).call(abi.encodeWithSelector(c.fill.selector, address(0x11), address(0x12), address(0x13)));
    }
    function test_buggy_mints() public {
        (XrpLikeH01 c, bool ok) = _run(false);
        require(ok && c.totalPaid() == 61, "buggy: expected 189 credited, 61 paid");
    }
    function test_fixed_reverts() public {
        (, bool ok) = _run(true);
        require(!ok, "fixed");
    }
    function test_twoMakersCannotWrap() public {
        XrpLikeH01 c = new XrpLikeH01(false, address(0x11));
        vm.prank(address(0x11)); c.place(63);
        vm.prank(address(0x12)); c.place(63);
        c.fill(address(0x11), address(0x12), address(0x11));
        require(c.totalPaid() == 126, "2 makers should be honest");
    }
}
