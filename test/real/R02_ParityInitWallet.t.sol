// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../../src/real/R02_ParityInitWallet.sol";
interface Vm { function prank(address) external; }

contract R02_ParityInitWalletTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address constant OWNER = address(0x11);
    address constant ATK = address(0x12);

    function test_buggy_takeoverAndDrain() public {
        ParityWallet w = new ParityWallet(false, OWNER);
        vm.prank(ATK); w.initWallet(ATK);
        require(w.owner() == ATK, "buggy: owner not hijacked");
        vm.prank(ATK); w.execute(ATK, 100);
        require(w.paidOut(ATK) == 100 && w.balance() == 0, "buggy: drain failed");
    }

    function test_fixed_reinitReverts() public {
        ParityWallet w = new ParityWallet(true, OWNER);
        vm.prank(ATK);
        (bool ok, ) = address(w).call(abi.encodeWithSelector(w.initWallet.selector, ATK));
        require(!ok, "fixed: re-init should revert");
        require(w.owner() == OWNER, "fixed: owner changed");
        vm.prank(ATK);
        (ok, ) = address(w).call(abi.encodeWithSelector(w.execute.selector, ATK, 100));
        require(!ok && w.balance() == 100, "fixed: drain should fail");
    }
}
