// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * HIDING LADDER H04 - HIDDEN BEHIND THE LOOP BOUND (8)
 * Closest to "one payment consumed many offers". Each maker rests 16 lots (keys
 * address(1)..address(16)), each lot <= 10. fill() walks all 16 lots, so honest max = 160.
 * The wrap at 128 needs at least 13 lots. If the compiler unrolls only 8 iterations, the
 * modelled maximum is 80 and the bug is unreachable. If it rejects 16-iteration loops,
 * that is a coverage gap too.
 * 2 transactions, 1 user, amounts <= 10: only the loop length hides it.
 * Expected: MISSED or REJECTED at bound 8. FOUND at bound >= 13.
 */
contract XrpLikeH04 {
    bool public immutable fixed_;
    uint256 public constant MOD = 128;
    uint256 public constant LOTS = 16;
    uint256 public constant MAX_LOT = 10;
    uint256 public totalPaid;
    mapping(address => mapping(address => uint256)) public lot;
    mapping(address => uint256) public credit;

    constructor(bool f, address) { fixed_ = f; }

    function placeLots(uint256 amt) external {
        require(amt > 0 && amt <= MAX_LOT, "bad amt");
        for (uint256 i = 0; i < LOTS; i++) {
            lot[msg.sender][address(uint160(i + 1))] = amt;
        }
    }

    function fill(address maker) external {
        uint256 sum = 0;
        for (uint256 i = 0; i < LOTS; i++) {
            address k = address(uint160(i + 1));
            sum += lot[maker][k];
            lot[maker][k] = 0;
        }
        if (fixed_) require(sum < MOD, "overflow"); // FIX (upstream): checked sum
 /* update removed */                     // BUG: wrapped charge
        credit[maker] += sum;
    }
}
