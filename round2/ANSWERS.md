bffcb407d3c50cd6acc70099fe9923fc03fc47dc833ba2fb0b2fe3cc7fad3ab6

# Answer key (12 cases: 9 buggy, 3 clean)

## R01.sol: BUGGY (VestingPool; source B03, stale share counter after release then cancel)
Root cause: release() adds to sharesWithdrawn and decrements totalShares but never decrements the lock's `shares` counter. cancel() then computes unvested = l.shares - vestedUnclaimed from the stale counter, so already-released shares are paid out a second time, and totalShares -= l.shares removes them twice. Remaining locks become undercollateralised.
Attack: (1) 0x2222 createLock(0x2222, 100e18, 100) (lock 1; pool 200e18, totalShares 200e18). (2) wait 50 s. (3) 0x2222 release(1): 50e18 shares, gets 50e18 tokens (totalShares 150e18). (4) 0x2222 cancel(1): unvested = 100e18 - 0 = 100e18 shares, gets 100e18 tokens; totalShares 50e18. 0x2222 got 150e18 for 100e18. Lock 0 (0x1111, 100e18 shares) is backed by only 50e18 tokens, and its later release over-claims or reverts.

## R02.sol: CLEAN (TimeLockedSavings, ETH time lock)
Owner-only actions, unlock time enforced, checks-effects-interactions in withdraw, unlock time can only be extended. No exploit intended.

## R03.sol: BUGGY (LiquidityVault; source B07, zero-liquidity withdrawal pays the whole balance)
Root cause: _withdraw pays `amount = bal` when totalLiquidity == 0, and withdraw(0) passes the liquidityOf >= 0 check. Seeded incentives (or leftovers after all LPs leave) can be taken by anyone.
Attack: 0x2222 calls withdraw(0) while totalLiquidity == 0 and receives all 500e18 incentives. (1 tx)

## R04.sol: BUGGY (StakeLedger; source B01, chained underflow then overflow)
Root cause: delegate() checks against balance + locked, but subtracts the full amount from the spendable balance in an unchecked block, so a vesting account with 0 spendable wraps to about 2^256. transfer() adds to the receiver unchecked, so sending the wrapped balance overflows the receiver.
Attack: (1) 0x2222 delegate(20e18): balanceOf[0x2222] = 2^256 - 20e18. (2) 0x2222 transfer(0x1111, 2^256 - 100e18): 0x1111's balance wraps to 0, 0x2222 keeps 80e18 spendable. totalSupply looks unchanged. (2 tx)

## R05.sol: BUGGY (BridgeGateway; source B08, negative fee offsets the debit)
Root cause: the signed `fee` is never checked against minFee (or >= 0). debit = quantity + fee, so fee = -quantity makes the debit 0 while the full quantity is still paid out.
Attack: 0x2222 (balance 0 in the gateway) withdraw(1_000e8, -1_000e8, dest): debit 0, receives 1_000e8 WA (0x1111's locked funds). (1 tx)

## R06.sol: BUGGY (ManagedTreasury; source B09, replaced rebalancer keeps its role)
Root cause: setRebalancer grants hasRebalanceRole to the new address and updates `rebalancer`, but never revokes the role from the previous one. rebalance() checks the role mapping, not the current rebalancer.
Attack: former operator 0x3333 calls rebalance(0x3333, 10e8) and drains 0x1111's deposit. (1 tx)

## R07.sol: BUGGY (DualAssetVault; source B04, depositMulti missing array-length check)
Root cause: depositMulti accepts amounts.length == 1 and values the vault using only the assets covered by the array, so token B's holdings are left out of `holdings` and shares are overpriced in the depositor's favour.
Attack: (1) 0x2222 depositMulti([100e18]): holdings = 100e18 (A only), shares = 100e18 * 200e18 / 100e18 = 200e18. (2) 0x2222 withdraw(200e18): gets 100e18 A + 50e18 B = 150e18 for 100e18 deposited. 0x1111 loses 50e18.

## R08.sol: BUGGY (RewardPool + LegacyPool; source B11, imported balance earns past rewards)
Root cause: importLegacy() adds the migrated amount to u.amount without harvesting first and without setting rewardDebt = amount * accRewardPerShare, so the imported stake is credited all past accRewardPerShare.
Attack: (1) 0x2222 OLD.deposit(100e18). (2) 0x2222 POOL.importLegacy(). (3) 0x2222 POOL.claim(): pending = 100e18 * acc(10e12) / 1e12 = 1_000e18, all of the rewards owed to 0x1111. (3 tx)

## R09.sol: BUGGY (DeflationaryToken + SimplePair; source B05, sell hook burns from the pair before the sale lands)
Root cause: on a transfer to the pair, _transfer first burns 50% of the sell amount from the PAIR's balance and calls pair.sync(), then credits the seller's tokens. Reserve0 collapses before the swap is priced, so the seller gets nearly all of reserve1 and k drops (LP loss).
Attack: 0x2222 (holds 2_000e18 TKN): (1) TKN.transfer(PAIR, 1_998e18): burns 999e18 from the pair, sync makes reserves 1e18 TKN / 1_000e18 USD, then 1_998e18 arrives. (2) PAIR.swap(0, 999e18, 0x2222): passes the K check against the reduced reserves; 0x2222 gets 999e18 USD. Fair output at the pre-trade price is about 666e18. (2 tx)

## R10.sol: CLEAN (DualAssetVault, fixed version of R07)
depositMulti requires amounts.length == 2, so holdings always cover both assets. Pro-rata minting and withdrawal round down in the vault's favour. No exploit intended.

## R11.sol: BUGGY (StablePool; source B10, tiny deposits round to zero but still mint LP)
Root cause: LP is minted from amount18 (18-decimal units), but the tokens pulled are amount18 / 1e12, which rounds down to 0 for amount18 < 1e12. Each such deposit mints LP for free.
Attack: 0x2222 deposit(1e12 - 1), repeated: each call mints about 1e12 - 1 LP and pulls 0 tokens, then withdraw redeems against 0x1111's assets. Per-call loss is under 1 base unit (dust, like the original), but the invariant "LP minted is backed by assets received" breaks in 1 tx.

## R12.sol: CLEAN (RewardPool + LegacyPool, fixed version of R08)
importLegacy harvests first and then sets rewardDebt = amount * accRewardPerShare. stake, withdraw and claim keep the debt in sync. No exploit intended.
