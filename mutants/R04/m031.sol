// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * PROVENANCE
 *  protocol : Cover Protocol - Blacksmith.sol (shield-mining / farming contract)
 *  source   : incident, 28 December 2020 (infinite COVER mint, >$4M impact); official Cover
 *             post-mortem (as cited by rekt.news); Secureum write-up of the incident
 *  finding  : n/a (incident). Vulnerable line, per the post-mortem as quoted by ImmuneBytes:
 *             `Pool memory pool = pools[_lpToken];` (Blacksmith.sol L118 in
 *             github.com/CoverProtocol/cover-token-mining)
 *  severity : Critical (unbounded mint)
 *  date     : 2020-12-28
 *  url      : https://rekt.news/cover-rekt ; https://mudit.blog/cover-protocol-hack-analysis-tokens-minted-exploit/
 *  pattern  : ACD-03 dependent value computed from state not yet updated (CAT-15 accounting desync)
 *
 *  Root cause: deposit() copied the pool into memory, then updatePool() wrote a new
 *  accRewardsPerToken to storage, but the reward write-off for the new stake was computed from
 *  the STALE memory copy. So the depositor's write-off was too low, and a later claim paid them
 *  rewards that accrued before they staked. This contract keeps the cached-copy -> update ->
 *  use-cached order exactly.
 *
 *  Fix: compute the write-off from the post-update accumulator. Cover's immediate response
 *  was to revoke Blacksmith's mint rights and relaunch. The exact upstream code patch:
 *  UNVERIFIED. The twin applies the fix every analysis describes (use the updated value).
 *
 *  Simplified away: block-time-based emission (tick() stands in for time passing), the
 *  CAL_MULTIPLIER fixed-point scale, bonus tokens, the LP-token balanceOf used as lpTotal
 *  (which amplified the real exploit), and the mint call (rewardsPaid counts the mint).
 */
contract CoverStaleCacheFarm {
    bool public immutable fixed_;
    uint256 public accPerToken;
    uint256 public pendingRewards;
    uint256 public totalStaked;
    uint256 public rewardsFunded;
    uint256 public rewardsPaid;
    mapping(address => uint256) public staked;
    mapping(address => uint256) public writeoff;

    constructor(bool f, address holder) {
        fixed_ = f;
        staked[holder] = 1;
        totalStaked = 1;
    }

    // Stand-in for emission over elapsed time.
    function tick(uint256 r) external {
        pendingRewards += r;
        rewardsFunded += r;
    }

    function _updatePool() internal {
        if (totalStaked > 0) {
            accPerToken += pendingRewards / totalStaked;
            pendingRewards = pendingRewards % totalStaked;
        }
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        uint256 cachedAcc = accPerToken; // mirrors `Pool memory pool = pools[_lpToken];`
        _updatePool();
        uint256 acc = fixed_ ? accPerToken : cachedAcc; // BUG: stale cached accumulator | FIX (upstream): post-update value
        uint256 owed = staked[msg.sender] * acc - writeoff[msg.sender];
        rewardsPaid += owed;
        staked[msg.sender] += amount;
        writeoff[msg.sender] = staked[msg.sender] * acc;
        totalStaked += amount;
    }

    function claim() external {
        _updatePool();
        uint256 owed = staked[msg.sender] * accPerToken - writeoff[msg.sender];
        writeoff[msg.sender] = staked[msg.sender] * accPerToken;
        rewardsPaid += owed;
    }
}
