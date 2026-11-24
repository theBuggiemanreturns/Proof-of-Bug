// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/hidden/H02_DeepSequence.sol";
interface Vm { function prank(address) external; }
contract H02Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function _run(bool f) internal returns (XrpLikeH02 c, bool ok) {
        c = new XrpLikeH02(f, address(0x11));
        for (uint256 i = 0; i < 6; i++) { vm.prank(address(0x11)); c.place(20); }
        vm.prank(address(0x12)); c.place(8);
        (ok, ) = address(c).call(abi.encodeWithSelector(c.fill.selector, address(0x11), address(0x12)));
    }
    function test_buggy_mints_after8tx() public {
        (XrpLikeH02 c, bool ok) = _run(false);
        require(ok && c.totalPaid() == 0 && c.credit(address(0x11)) == 120 && c.credit(address(0x12)) == 8, "buggy");
    }
    function test_fixed_reverts() public {
        (, bool ok) = _run(true);
        require(!ok, "fixed");
    }
}
