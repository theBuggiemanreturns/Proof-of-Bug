// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * PROVENANCE
 *  protocol : Perennial (Vault.sol)
 *  source   : Zellic audit of Perennial - Critical finding "ERC-4626 inflation attack on Vault"
 *  finding  : UNVERIFIED - the Zellic page gives no numeric finding ID
 *  severity : Critical (Critical impact, High likelihood) - per Zellic
 *  date     : UNVERIFIED - page only shows "Zellic (c) 2023"; exact report date not confirmed
 *  url      : https://reports.zellic.io/publications/perennial/findings/critical-vaultsol-erc-4626-inflation-attack-on-vault
 *  pattern  : VLT-01 first-depositor / inflation attack (CAT-03 ERC4626 vaults)
 *
 *  Root cause: the vault priced shares off a balance that anyone could raise with a direct
 *  token transfer ("donation") without minting shares. An attacker who holds the only share
 *  donates, so a victim's later deposit rounds down to zero shares. Here, donate() raising
 *  totalAssets stands in for the direct transfer; deposit() keeps the same
 *  assets*supply/totalAssets floor division.
 *
 *  Fix: Zellic recommended (a) a large trusted seed deposit, or (b) tracking assets
 *  internally so donations do not move the share price. This twin applies (b).
 *  WHICH mitigation Perennial actually shipped: UNVERIFIED (Zellic's page references a fix
 *  commit, but the hash did not render).
 *
 *  Simplified away: ERC-20 token, Perennial market positions/oracle-based NAV, redeem path,
 *  fees. Root cause (donation-inflatable price + floor rounding) is preserved.
 */
contract PerennialInflationVault {
    bool public immutable fixed_;
    uint256 public totalAssets;
    uint256 public totalSupply;
    uint256 public untracked; // donations the fixed version refuses to count
    mapping(address => uint256) public balanceOf;

    constructor(bool f, address) {
        fixed_ = f;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero");
        shares = totalSupply == 0 ? assets : (assets * totalSupply) / totalAssets;
        balanceOf[msg.sender] += shares;
 /* update removed */
        totalAssets += assets;
    }

    // Stand-in for an ERC-20 transfer straight to the vault address.
    function donate(uint256 assets) external {
        if (fixed_) {
            untracked += assets; // FIX (upstream recommendation): internal accounting ignores donations
        } else {
            totalAssets += assets; // BUG: donation inflates the price of existing shares
        }
    }
}
