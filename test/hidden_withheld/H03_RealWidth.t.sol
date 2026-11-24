// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/hidden/H03_RealWidth.sol";
interface Vm { function prank(address) external; }
contract H03Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function _run(bool f) internal returns (XrpLikeH03 c, bool ok) {
        c = new XrpLikeH03(f, address(0x11));
        vm.prank(address(0x11)); c.place(2 ** 63);
        vm.prank(address(0x12)); c.place(2 ** 63);
        (ok, ) = address(c).call(abi.encodeWithSelector(c.fill.selector, address(0x11), address(0x12)));
    }
    function test_buggy_mints_2pow64() public {
        (XrpLikeH03 c, bool ok) = _run(false);
        require(ok && c.totalPaid() == 0 && c.credit(address(0x11)) + c.credit(address(0x12)) == 2 ** 64, "buggy");
    }
    function test_fixed_reverts() public {
        (, bool ok) = _run(true);
        require(!ok, "fixed");
    }
    function test_smallLotsRejected() public {
        XrpLikeH03 c = new XrpLikeH03(false, address(0x11));
        (bool ok, ) = address(c).call(abi.encodeWithSelector(c.place.selector, uint256(255)));
        require(!ok, "small lot should be rejected");
    }
}
