// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * HIDING LADDER H01 - HIDDEN BEHIND THE 2-USER LIMIT
 * Same bug as H00, but each offer is capped at 63, so two makers top out at 126 < 128.
 * The wrap needs THREE distinct makers, i.e. three senders. GateGuard models only
 * 0x11 and 0x12. fill() can NAME a third address, but nobody can place an offer for it.
 * (It also needs 4 transactions, so it is hidden behind the tx-depth limit too.)
 * Expected: MISSED at 2 users. Should be FOUND only with 3 users AND 4 transactions.
 */
contract XrpLikeH01 {
    bool public immutable fixed_;
    uint256 public constant MOD = 128;
    uint256 public constant MAX_OFFER = 63;
    uint256 public totalPaid;
    mapping(address => uint256) public offer;
    mapping(address => uint256) public credit;

    constructor(bool f, address) { fixed_ = f; }

    function place(uint256 amt) external {
        require(amt >= 0 && amt <= MAX_OFFER, "bad amt");
        require(offer[msg.sender] == 0, "has offer");
        offer[msg.sender] = amt;
    }

    function fill(address a, address b, address c) external {
        uint256 x = offer[a]; offer[a] = 0;
        uint256 y = offer[b]; offer[b] = 0;
        uint256 z = offer[c]; offer[c] = 0;
        uint256 sum = x + y + z;
        if (fixed_) require(sum < MOD, "overflow"); // FIX (upstream): checked sum
        totalPaid += sum % MOD;                     // BUG: wrapped charge
        credit[a] += x;
        credit[b] += y;
        credit[c] += z;
    }
}
