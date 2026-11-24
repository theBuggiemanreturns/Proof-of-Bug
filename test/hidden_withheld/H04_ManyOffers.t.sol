// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/hidden/H04_ManyOffers.sol";
interface Vm { function prank(address) external; }
contract H04Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function _run(bool f) internal returns (XrpLikeH04 c, bool ok) {
        c = new XrpLikeH04(f, address(0x11));
        vm.prank(address(0x11)); c.placeLots(10);
        (ok, ) = address(c).call(abi.encodeWithSelector(c.fill.selector, address(0x11)));
    }
    function test_buggy_mints_16lots() public {
        (XrpLikeH04 c, bool ok) = _run(false);
        require(ok && c.totalPaid() == 32 && c.credit(address(0x11)) == 160, "buggy");
    }
    function test_fixed_reverts() public {
        (, bool ok) = _run(true);
        require(!ok, "fixed");
    }
}
