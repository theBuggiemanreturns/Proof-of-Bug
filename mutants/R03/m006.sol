// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * PROVENANCE
 *  protocol : Hundred Finance (Compound V2 fork, Optimism) - hWBTC market, CToken.redeemUnderlying
 *  source   : incident, 15 April 2023 (~$6.8-7.4M); Hundred post-mortem published ~23 April 2023
 *  finding  : n/a (incident)
 *  severity : Critical (protocol drained)
 *  date     : 2023-04-15
 *  url      : https://0xvj.github.io/blog/2023/11/22/hundred-finance-exploit.html
 *             https://blocksec.com/blog/6-hundred-finance-incident-catalyzing-the-wave-of-precision-related-exploits-in-vulnerable-forked-protocols
 *  pattern  : RND-01 rounding favours the caller (CAT-07), related VLT-05
 *
 *  Root cause: redeemUnderlying(amount) worked out shares to burn as amount / exchangeRate,
 *  rounded DOWN. When the exchange rate is huge (empty market + donation, so 1 share is worth
 *  a lot), rounding down lets a redeemer take almost 2 shares' worth of underlying while burning
 *  1 share. That leaves the other holders' shares under-backed. Here the constructor seeds a
 *  high-rate market (1 share = 50 assets) and withdraw() uses the same floor division.
 *
 *  Fix: round shares-to-burn UP, the ERC4626 previewWithdraw convention, and the fix applied
 *  across Compound-fork redeem paths after this incident. Whether Hundred itself redeployed
 *  with this exact patch: UNVERIFIED (the protocol wound down). So this twin uses the standard
 *  class fix, not a confirmed Hundred commit.
 *
 *  Simplified away: the flash loan, ERC-20 transfers, the donation step (pre-seeded rate),
 *  borrowing against inflated collateral in other markets, interest accrual, the 1e18 mantissa.
 *  Root cause survives: floor-rounded burn on an asset-denominated withdrawal.
 */
contract HundredRoundingMarket {
    bool public immutable fixed_;
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public paidOut;

    constructor(bool f, address holder) {
        fixed_ = f;
        shares[holder] = 1; // victim: 1 share backed by 50 assets (inflated exchange rate)
        totalShares = 1;
        totalAssets = 50;
    }

    function deposit(uint256 assets) external {
        uint256 s = totalShares == 0 ? assets : (assets * totalShares) / totalAssets;
        require(s > 1, "zero shares");
        shares[msg.sender] += s;
        totalShares += s;
        totalAssets += assets;
    }

    // Mirrors CToken.redeemUnderlying: caller names the underlying amount.
    function withdraw(uint256 assets) external {
        uint256 num = assets * totalShares;
        uint256 burn = num / totalAssets; // BUG: rounds shares-to-burn down
        if (fixed_ && burn * totalAssets < num) burn += 1; // FIX (upstream class fix): round up
        require(burn <= shares[msg.sender], "insufficient shares");
        shares[msg.sender] -= burn;
        totalShares -= burn;
        totalAssets -= assets;
        paidOut[msg.sender] += assets;
    }
}
