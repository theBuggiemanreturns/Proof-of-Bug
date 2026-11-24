SALT: 025fd5c66d5a496f8c95c88c0711ab4e69f6da4feb86b98b1941b53f1a458e4d

# Ground truth — 12 Solidity cases

Summary (withheld from the operator until verdicts are committed):

| Case | Verdict | Bug class |
|------|---------|-----------|
| C01  | BUGGY   | ERC4626 first-depositor / inflation (no virtual shares) |
| C02  | CLEAN   | Synthetix-style staking (canonical, correct) |
| C03  | BUGGY   | Cross-function reentrancy (withdrawAll pays before zeroing; transfer unguarded) |
| C04  | BUGGY   | Spot-AMM reserve used as price oracle (manipulable) |
| C05  | CLEAN   | EIP-712 voucher claim (bound to msg.sender, nonce, deadline, low-s) |
| C06  | BUGGY   | Reward-share desync: transfer() omits recipient debt sync |
| C07  | BUGGY   | Incomplete path: cancel() doesn't clear amount; modify() re-refunds |
| C08  | BUGGY   | AMM K-invariant scaled with 1000^2 while balances scaled by 10000 |
| C09  | CLEAN   | ERC4626 with virtual shares/assets (inflation mitigated) |
| C10  | BUGGY   | MasterChef rewardDebt set from stale amount on deposit |
| C11  | BUGGY   | Unchecked uint128 downcast of deposit; streamed() uses full value |
| C12  | CLEAN   | English auction, pull-payments + reentrancy guard + exact-receipt |

Buggy: C01, C03, C04, C06, C07, C08, C10, C11 (8). Clean: C02, C05, C09, C12 (4).

Verification note: all 12 compile under solc 0.8.24. The accounting exploits
(C01, C04, C06, C08, C10, C11) were additionally checked with exact BigInt
simulations reproducing the asserted numbers; C03/C12 by EVM-mechanics tracing;
C02/C05/C09 by standard-pattern analysis. Foundry test sources accompany this
file in `test/` and are written to pass on the real EVM.

---

## C01 — VaultC01 — BUGGY

Root cause: share price uses live `totalAssets()` (token balance) with no virtual
shares/dead shares and no minimum-liquidity. The first depositor can take 1 share
for 1 wei, then donate assets directly to the vault to inflate price per share so a
later depositor's `convertToShares` rounds to zero.

Exploit (attacker A, victim V):
1. A `deposit(1, A)` → 1 share, totalSupply=1, totalAssets=1.
2. A `token.transfer(vault, 10_000e18)` (donation). totalAssets=10_000e18+1.
3. V `deposit(10_000e18, V)` → shares = 10_000e18*1/(10_000e18+1) = 0. V gets 0 shares.
4. A `redeem(1, A, A)` → assets = 1*(20_000e18+1)/1 = 20_000e18+1. A drains V's deposit.

Impact: total loss of the victim's deposit (verified: A ends with 20_000e18+1, V with 0).

Minimal fix: add virtual shares/assets (OZ decimals-offset) or burn a minimum
liquidity on first mint and round shares in the protocol's favor.
```solidity
uint256 private constant VS = 1e3; // virtual shares
function convertToShares(uint256 assets) public view returns (uint256) {
    return (assets * (totalSupply + VS)) / (totalAssets() + 1);
}
function convertToAssets(uint256 shares) public view returns (uint256) {
    return (shares * (totalAssets() + 1)) / (totalSupply + VS);
}
```
(Full patched source: patched/C01.sol)

---

## C02 — StakingRewardsC02 — CLEAN

Canonical Synthetix `StakingRewards`. `updateReward` snapshots `rewardPerToken`
before any balance change; `notifyRewardAmount` caps `rewardRate` to the held
balance; `setRewardsDuration` only after `periodFinish`. Tempting attacks that fail:
- Just-in-time whale stake then immediate `exit()` earns 0 (zero elapsed time), and
  because it also withdraws, it does not dilute the honest staker going forward.
- Re-notifying cannot promise more than the contract holds (`reward too high`).
- Cannot withdraw more than staked; `notifyRewardAmount` is owner-only.

No fix needed.

---

## C03 — EthPoolC03 — BUGGY

Root cause: `withdrawAll()` performs the external ETH send *before* zeroing
`balanceOf[msg.sender]`, and the share-`transfer()` function is **not** covered by
the `nonReentrant` lock. During the payout callback the caller's balance is still
nonzero and can be moved to another address; `withdrawAll` then zeroes an
already-emptied slot, so one deposit is credited (and withdrawn) twice. The shared
`nonReentrant` lock on withdraw functions does not help because the re-entry goes
through the unguarded `transfer`.

Exploit (A controls contract R and a second account S; pool holds other users' ETH):
1. R `deposit(1 ether)`.
2. R `withdrawAll()`. Mid-call, in R's `receive()`, R calls
   `transfer(S, balanceOf[R])` — moving the 1-ETH credit to S *before* the slot is zeroed.
3. `withdrawAll` finishes and sets R's (already-moved) balance to 0. R has 1 ETH.
4. S `withdrawAll()` → another 1 ETH. A now has 2 ETH for a 1-ETH deposit.

Impact: pool drained by the duplicated credit (verified: attacker 1→2 ETH, pool short 1 ETH).

Minimal fix: zero the balance before the external call (CEI) and/or put `transfer`
under the same reentrancy guard.
```solidity
function withdrawAll() external nonReentrant {
    uint256 amount = balanceOf[msg.sender];
    require(amount > 0, "empty");
    balanceOf[msg.sender] = 0;      // effects first
    totalDeposits -= amount;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "send failed");
    emit Withdrawal(msg.sender, amount);
}
```
(Full patched source: patched/C03.sol)

---

## C04 — LendingC04 / AmmC04 — BUGGY

Root cause: `collateralPrice()` reads the AMM's **instantaneous spot reserves** as
the oracle. A borrower can move the spot price within a single transaction, borrow
against the inflated collateral value, then unwind — leaving unbacked debt.

Exploit (attacker A; pool 1000 USDS / 1000 GCOL; 10_000 USDS supplied):
1. A `depositCollateral(100e18)` GCOL (fair value ≈ 100 USDS).
2. A `AmmC04.swap(USDS, 5_000e18, 0)` → buys ≈ 833 GCOL, spot price → ≈ 35.9 USDS/GCOL.
3. A `borrow(maxBorrow(A))` → ≈ 2_693 USDS (75% of inflated 3_590 value).
4. A sells the 833 GCOL back; spot price renormalizes to ≈ 1. A keeps ≈ 2_693 USDS,
   leaving 100 GCOL (≈ 100 USDS) backing 2_693 USDS of debt.

Impact: ≈ 2_590 USDS protocol bad debt (verified: maxBorrow ≈ 2_693e18; post-unwind
collateral value ≈ 100.5e18 ≪ debt).

Minimal fix: use a manipulation-resistant oracle (Chainlink feed, or the AMM's
cumulative-price TWAP), not spot reserves.
```solidity
// Replace collateralPrice() with a TWAP / external feed:
function collateralPrice() public view returns (uint256) {
    return oracle.getPrice(address(collateralToken)); // 1e18-scaled, time-averaged
}
```
(Full patched source sketch: patched/C04.sol)

---

## C05 — VoucherClaimC05 — CLEAN

EIP-712 claim. The struct binds `account`, and `claim` recomputes the digest with
`account = msg.sender`, so a voucher is usable only by its intended account. Per-
`(account, nonce)` replay protection, `deadline`, low-`s` and `v∈{27,28}` guards,
zero-address-recover rejection, chainid-aware domain separator. Tempting attacks
that fail: replay (same nonce), using another's voucher, tampering with `amount`,
expired deadline. No fix needed.

---

## C06 — StakedShareC06 — BUGGY

Root cause: `_transfer` calls `_accrue(from)/_accrue(to)` and `_sync(from)` but
**omits `_sync(to)`**. The recipient's `bonusDebt` is left stale (based on its old,
smaller balance), so after receiving shares its `pendingBonus` includes bonus that
was already accounted to the sender — the same shares' bonus is counted twice.

Exploit (attacker owns accounts A and A2; honest staker C):
1. A `deposit(100e18)`, C `deposit(100e18)`.
2. owner `distribute(200e18)` → `accBonusPerShare` = 1 bonus/share; A and C each owed 100.
3. A `transfer(A2, 100e18)`. `_accrue(A)` banks A's 100 owed; `_accrue(A2)`=0; balances
   move; `_sync(A)` set; **`bonusDebt[A2]` stays 0**.
4. A `claimBonus()` → 100 (banked). A2 `claimBonus()` → `pending = 100*acc - 0 = 100`.
   Attacker extracts 200 from a 200 pool; honest C's 100 is now unpayable.

Impact: bonus pool drained / honest stakers shorted (verified: A+A2 = 200e18, C reverts).

Minimal fix: sync the recipient too.
```solidity
_sync(from);
_sync(to);   // restore the missing line
emit Transfer(from, to, amount);
```
(Full patched source: patched/C06.sol)

---

## C07 — OrderBookC07 — BUGGY

Root cause: `cancel()` sets `active=false` and refunds `o.amount` but **does not
zero `o.amount`**, and `modify()` has **no active-order check**. A maker can cancel
(get the base back), then `modify` the dead order down to a tiny amount, and the
`else if (newAmount < current)` branch refunds the (already-returned) base a second
time — pulling base that belongs to other makers' live orders.

Exploit (attacker A; honest maker H):
1. H `place(100e18, …)` (contract holds 100 base).
2. A `place(100e18, …)` (contract holds 200 base). id = A's order.
3. A `cancel(id)` → +100 base to A; `o.amount` still 100.
4. A `modify(id, 1, …)` → refunds `100-1` base to A again (drains H's collateral).

Impact: double refund; honest maker cannot reclaim collateral (verified: A ≈ 200 base,
H `cancel` reverts `balance`).

Minimal fix: clear the order on cancel and reject inactive orders in modify.
```solidity
function cancel(uint256 id) external {
    Order storage o = orders[id];
    require(o.maker == msg.sender && o.active, "order");
    o.active = false;
    uint256 refund = o.amount;
    o.amount = 0;                         // clear
    require(base.transfer(msg.sender, refund), "transfer");
    emit Cancelled(id, refund);
}
function modify(uint256 id, uint128 newAmount, uint128 newPrice) external {
    Order storage o = orders[id];
    require(o.maker == msg.sender && o.active, "order"); // reject inactive
    ...
}
```
(Full patched source: patched/C07.sol)

---

## C08 — PairC08 — BUGGY

Root cause: the constant-product check mixes scales. Adjusted balances are scaled by
`10_000` (`balance*10_000 - amountIn*FEE_BPS`), so the product is scaled by `1e8`,
but the right-hand side uses `reserve0*reserve1*1000**2` (`1e6`). The required `K` is
therefore 100× too small, so a swapper can remove far more than the invariant should
allow.

Exploit: with reserves 1000/1000, pay in 1 token0 and take out 900 token1. The check
`balance0Adj*balance1Adj (≈1.0e49) >= reserve0*reserve1*1e6 (1e48)` passes, though the
correctly-scaled bound (`*1e8 = 1e50`) would fail.

Impact: pool drainable for near-zero input (verified: 1 token0 in → 900 token1 out,
reserves end 1001/100).

Minimal fix: scale the RHS consistently with the 10_000 factor.
```solidity
require(
    balance0Adjusted * balance1Adjusted >= uint256(_reserve0) * _reserve1 * (10_000 ** 2),
    "K"
);
```
(Full patched source: patched/C08.sol)

---

## C09 — VaultC09 — CLEAN

ERC4626 with virtual shares (`1e6`) and virtual assets (`1`), favorable rounding on
entry/exit, and a pull-safe exit fee. The first-depositor/donation attack is
unprofitable: with a 1-wei deposit + 1e18 donation, a 10_000e18 victim deposit still
mints ≈ 2e10 shares (not zero), the attacker's redemption (≈ 0.5e18) is below their
1e18 donation (net loss), and the victim recovers ≈ 99.9% of deposit. No fix needed.

---

## C10 — FarmC10 — BUGGY

Root cause: in `deposit`, `user.rewardDebt` is assigned from the **old**
`user.amount` and only then is `user.amount` increased. A depositor who enters after
`accRewardPerShare` has grown gets `rewardDebt` too low by `amount*acc`, so they can
immediately harvest rewards accrued before they joined.

Exploit (honest alice; attacker bob):
1. alice `deposit(100e18)` at t0.
2. 100 s pass → 100e18 FRM accrue to alice; `acc` grows.
3. bob `deposit(100e18)`: `rewardDebt = 0*acc = 0`, then `amount = 100e18`.
4. bob `harvest()` same block → `pending = 100e18*acc - 0 = 100e18`. bob takes rewards
   for a period he never staked; alice is still owed her 100e18.

Impact: reward reserve over-paid / stolen from other stakers (verified: bob 100e18 for
0 s staked; alice still owed 100e18).

Minimal fix: set `rewardDebt` after updating `user.amount`.
```solidity
if (amount > 0) {
    require(lpToken.transferFrom(msg.sender, address(this), amount), "transfer");
    user.amount += amount;
    totalStaked += amount;
}
user.rewardDebt = (user.amount * accRewardPerShare) / ACC_PRECISION; // after
```
(Full patched source: patched/C10.sol)

---

## C11 — StreamPayC11 — BUGGY

Root cause: `deposit` is computed as `uint128(ratePerSecond * duration)`, an
**unchecked explicit downcast** (Solidity does not range-check casts). For a large
`ratePerSecond`, the product overflows uint128 and the stored/charged deposit wraps
to a tiny number, while `streamed()` recomputes `(elapsed)*ratePerSecond` at full
uint256 precision. The recipient can then withdraw far more than was deposited,
limited only by the contract's total balance.

Exploit (victim funds a 1000-token stream; attacker A):
1. Victim `createStream(…, 1e18, now, now+1000)` → contract holds 1000e18.
2. A `createStream(A, rate=(1<<127)+1, now, now+2)` → `rate*2 = 2^128+2`,
   `uint128(...) = 2`, so A pays only 2 wei; `streamed` grows as `2^128+2`.
3. After the stream ends, A `withdraw(id, 1000e18+2)` (≤ streamed, ≤ balance) → drains
   the whole contract, stealing the victim's funds.

Impact: contract-wide theft for ~2 wei (verified: deposit stored = 2, A withdraws
1000e18+2, victim recipient then reverts `balance`).

Minimal fix: use a checked cast / require no truncation (or keep deposit as uint256).
```solidity
uint256 depositFull = ratePerSecond * duration;
require(depositFull <= type(uint128).max, "overflow");
uint128 deposit = uint128(depositFull);
```
(Full patched source: patched/C11.sol)

---

## C12 — AuctionHouseC12 — CLEAN

English auction with anti-sniping extension. Refunds and proceeds use a pull-payment
map; `bid`, `settle`, `cancel`, `withdraw` are all `nonReentrant`; `withdraw` zeroes
before sending; `createAuction` verifies the exact lot amount received (rejecting
fee-on-transfer tokens); the current top bid is locked (not in `pendingWithdrawals`)
so it cannot be withdrawn while live; min-increment and seller-cannot-bid enforced.
Tempting attacks that fail: reentrant double-withdraw (guard + CEI), under-min bids,
settle-before-end, FOT lot. No fix needed.
