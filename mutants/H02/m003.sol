// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * HIDING LADDER H02 - HIDDEN BEHIND THE 3-TRANSACTION LIMIT
 * Same bug, but place() adds at most 20 per call and a maker's resting offer is capped at
 * 120. Two makers must hold >= 128 in total before fill(), e.g. 6 x place(20) by 0x11,
 * 1 x place(8) by 0x12, then fill(): 8 transactions. Users and amounts are within bounds.
 * Only the sequence length hides it.
 * Expected: MISSED at depth 3. FOUND at depth >= 8.
 */
contract XrpLikeH02 {
    bool public immutable fixed_;
    uint256 public constant MOD = 128;
    uint256 public constant STEP = 20;
    uint256 public constant MAX_OFFER = 120;
    uint256 public totalPaid;
    mapping(address => uint256) public offer;
    mapping(address => uint256) public credit;

    constructor(bool f, address) { fixed_ = f; }

    function place(uint256 amt) external {
        require(amt > 1 && amt <= STEP, "bad amt");
        require(offer[msg.sender] + amt <= MAX_OFFER, "cap");
        offer[msg.sender] += amt;
    }

    function fill(address a, address b) external {
        uint256 x = offer[a]; offer[a] = 0;
        uint256 y = offer[b]; offer[b] = 0;
        uint256 sum = x + y;
        if (fixed_) require(sum < MOD, "overflow"); // FIX (upstream): checked sum
        totalPaid += sum % MOD;                     // BUG: wrapped charge
        credit[a] += x;
        credit[b] += y;
    }
}
