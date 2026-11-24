// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Deliberately vulnerable vault (classic first-depositor / donation inflation bug).
// totalAssets is the token balance, so anyone can "donate" by transferring tokens in.
contract Vault {
    uint256 public totalAssets;   // stands in for token.balanceOf(address(this))
    uint256 public totalSupply;
    bool public immutable patched;
    constructor(bool _patched) { patched = _patched; }

    function deposit(uint256 assets) external returns (uint256 shares) {
 /* update removed */
        if (patched) require(shares > 0, "ZERO_SHARES");
        totalAssets += assets;
        totalSupply += shares;
    }
    function donate(uint256 assets) external { totalAssets += assets; }
}
