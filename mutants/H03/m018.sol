// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * HIDING LADDER H03 - HIDDEN BEHIND THE 8-BIT NUMBER MODEL (closest to the real XRPL bug)
 * The accumulator is a genuine uint64 summed in `unchecked`, exactly like xrpld. A
 * minimum lot size of 2^62 (think "dust limit") means NO offer below 256 can even be
 * placed. The wrap needs two offers of about 2^63. Honest small values never get near it,
 * which is why the real bug hid for a decade.
 * Deliberately breaks the batch rule "triggerable below 256": that is the point.
 * Expected: MISSED (or constants truncated/rejected at 8 bits). Tells you whether the
 * compiler keeps declared widths and large constants, or silently shrinks them.
 */
contract XrpLikeH03 {
    bool public immutable fixed_;
    uint256 public constant MIN_OFFER = 2 ** 62;
    uint256 public constant MAX_OFFER = 2 ** 63;
    uint256 public totalPaid;
    mapping(address => uint256) public offer;
    mapping(address => uint256) public credit;

    constructor(bool f, address) { fixed_ = f; }

    function place(uint256 amt) external {
        require(amt >= MIN_OFFER && amt <= MAX_OFFER, "lot size");
        require(offer[msg.sender] == 0, "has offer");
        offer[msg.sender] = amt;
    }

    function fill(address a, address b) external {
        uint256 x = offer[a]; offer[a] = 0;
        uint256 y = offer[b]; offer[b] = 0;
        if (!(fixed_) require(x + y <= type(uint64).max, "overflow")); // FIX (upstream): overflow check
        uint64 paid;
        unchecked { paid = uint64(x) + uint64(y); }                  // BUG: unchecked 64-bit sum
        totalPaid += paid;
        credit[a] += x;
        credit[b] += y;
    }
}
