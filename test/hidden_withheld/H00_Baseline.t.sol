// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/hidden/H00_Baseline.sol";
interface Vm { function prank(address) external; }
contract H00Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function _run(bool f) internal returns (XrpLikeH00 c, bool ok) {
        c = new XrpLikeH00(f, address(0x11));
        vm.prank(address(0x11)); c.place(100);
        vm.prank(address(0x12)); c.place(100);
        (ok, ) = address(c).call(abi.encodeWithSelector(c.fill.selector, address(0x11), address(0x12)));
    }
    function test_buggy_mints() public {
        (XrpLikeH00 c, bool ok) = _run(false);
        require(ok && c.totalPaid() == 72 && c.credit(address(0x11)) + c.credit(address(0x12)) == 200, "buggy");
    }
    function test_fixed_reverts() public {
        (XrpLikeH00 c, bool ok) = _run(true);
        require(!ok && c.totalPaid() == 0, "fixed");
    }
}
