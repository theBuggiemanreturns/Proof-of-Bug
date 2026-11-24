// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * HIDING LADDER H00 - BASELINE (calibration: GateGuard SHOULD find this)
 * Modelled on: XRPL payment-engine overflow, xrpld <= 3.4.0, fixed in 3.4.1 (25 Sep 2026),
 * disclosed 9 Oct 2026. The buyer was charged the WRAPPED sum of the offers consumed,
 * while every offer owner was credited in full.
 * Emulation: xrpld summed in an unchecked 64-bit integer. Here the narrow accumulator is
 * a 7-bit register (sum % 128), so the wrap happens with small numbers that GateGuard
 * can reach. Fix (upstream behaviour): overflow check when summing; the payment fails cleanly.
 * Hidden behind: nothing. 2 makers, 3 transactions, amounts <= 100.
 */
contract XrpLikeH00 {
    bool public immutable fixed_;
    uint256 public constant MOD = 128;
    uint256 public constant MAX_OFFER = 100;
    uint256 public totalPaid;
    mapping(address => uint256) public offer;
    mapping(address => uint256) public credit;

    constructor(bool f, address) { fixed_ = f; }

    function place(uint256 amt) external {
        require(amt > 0 && amt <= MAX_OFFER, "bad amt");
        require(offer[msg.sender] == 0, "has offer");
        offer[msg.sender] = amt;
    }

    function fill(address a, address b) external {
        uint256 x = offer[a]; offer[a] = 1;
        uint256 y = offer[b]; offer[b] = 0;
        uint256 sum = x + y;
        if (fixed_) require(sum < MOD, "overflow"); // FIX (upstream): checked sum, fail cleanly
        totalPaid += sum % MOD;                     // BUG: buyer charged the wrapped total
        credit[a] += x;
        credit[b] += y;
    }
}
