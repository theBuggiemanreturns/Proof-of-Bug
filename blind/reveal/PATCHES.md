REVEAL 2 of 3 — patched contracts (as exact diffs against the originals you already have; full files on request). solc 0.8.24, all compile.

C01 (VaultC01) — add virtual shares; replace both convert functions:
  convertToShares/convertToAssets =>
    uint256 private constant VS = 1e3;
    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (totalSupply + VS)) / (totalAssets() + 1);
    }
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return (shares * (totalAssets() + 1)) / (totalSupply + VS);
    }

C03 (EthPoolC03) — CEI in withdrawAll: move `balanceOf[msg.sender] = 0;` to BEFORE the external call (right after the require), remove it from after. (transfer can also be put under nonReentrant; the CEI reorder alone closes it.)

C04 (LendingC04) — replace the spot-reserve oracle with an external/TWAP feed:
    interface IPriceOracleC04 { function price1e18() external view returns (uint256); }
    // constructor takes IPriceOracleC04 oracle;
    function collateralPrice() public view returns (uint256) { return oracle.price1e18(); }
  (i.e. stop deriving price from priceSource.getReserves(); read a manipulation-resistant feed.)

C06 (StakedShareC06) — IMPORTANT, TWO fixes. My first patch only did fix (1) and left YOUR self-transfer bug live. The complete `_transfer`:
    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "zero address");
        _accrue(from);
        _accrue(to);
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;      // (2) drop the fromBalance/toBalance cache -> self-transfer nets to zero
        balanceOf[to] += amount;
        _sync(from);
        _sync(to);                       // (1) my intended fix: sync recipient debt
        emit Transfer(from, to, amount);
    }
  Verified on EVM: original self-transfer 3 -> 6 shares; fixed stays 3; bonus double-claim also closed, honest staker still paid.

C07 (OrderBookC07) — cancel() must zero the order, modify() must reject inactive:
    cancel: after `o.active = false;` and `uint256 refund = o.amount;` add `o.amount = 0;` before the transfer.
    modify: add `require(o.active, "inactive");` after the maker check.

C08 (PairC08) — fix the K-invariant scale (RHS must use 10_000, not 1000):
    require(balance0Adjusted * balance1Adjusted >= uint256(_reserve0) * _reserve1 * (10_000 ** 2), "K");

C10 (FarmC10) — in deposit(), set rewardDebt AFTER updating user.amount:
    move `user.rewardDebt = (user.amount * accRewardPerShare) / ACC_PRECISION;` to AFTER the `if (amount > 0) { ... user.amount += amount; ... }` block (remove the earlier assignment).

C11 (StreamPayC11) — checked downcast in createStream():
    uint256 depositFull = ratePerSecond * duration;
    require(depositFull <= type(uint128).max, "overflow");
    uint128 deposit = uint128(depositFull);

C02, C05, C09, C12: no changes (clean).

Reveal 3 (the 12 Foundry test files, which pass on real EVM) follows next.
