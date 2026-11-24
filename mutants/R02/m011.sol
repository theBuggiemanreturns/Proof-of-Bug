// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * PROVENANCE
 *  protocol : Parity multisig wallet (WalletLibrary, Parity client 1.5+)
 *  source   : incident, 19 July 2017 (~153k ETH from three multisigs); public post-mortems
 *  finding  : n/a (incident). Fix shipped as paritytech/parity PR #6103 "Update wallet library
 *             modifiers" (v1.6.10, 2017-07-23), listed in Parity's CHANGELOG
 *  severity : Critical (funds stolen)
 *  date     : 2017-07-19
 *  url      : https://www.freecodecamp.org/news/a-hacker-stole-31m-of-ether-how-it-happened-and-what-it-means-for-ethereum-9e5dc29e33ce/
 *             (Haseeb Qureshi analysis); changelog: https://github.com/paritytech/parity/pull/6103
 *  pattern  : ACC-01 / ACC-03 unprotected (re-)initializer (CAT-05 access control & init)
 *
 *  Root cause: initWallet() set the owners and had no guard against being called again after
 *  the wallet was set up. Through the wallet's delegatecall fallback, anyone could call it,
 *  make themselves the sole owner, then withdraw everything. This contract exposes the same
 *  re-callable initializer directly. The fix twin adds the "only_uninitialized" guard.
 *  The exact modifier name as merged in #6103: UNVERIFIED (it is widely reported as
 *  only_uninitialized, and that name appears in the post-July library involved in the November
 *  2017 freeze).
 *
 *  Simplified away: the delegatecall proxy/library split (the reason initWallet was reachable),
 *  multi-owner/required-confirmations logic, day limit, ETH transfers (balance is a number).
 *  Root cause survives: a privileged initializer that can be called again by anyone.
 */
contract ParityWallet {
    bool public immutable fixed_;
    address public owner;
    uint256 public initialized;
    uint256 public balance;
    mapping(address => uint256) public paidOut;

    constructor(bool f, address o) {
        fixed_ = f;
        _init(o);
        balance = 100;
    }

    function _init(address o) internal {
        owner = o;
        initialized = 1;
    }

    // BUG: callable by anyone at any time when fixed_ == false
    function initWallet(address o) external {
        if (fixed_) require(initialized == 0, "only_uninitialized"); // FIX (upstream): only_uninitialized
        _init(o);
    }

    function execute(address to, uint256 amount) external {
        require(msg.sender == owner, "only_owner");
        require(amount < balance, "insufficient");
        balance -= amount;
        paidOut[to] += amount;
    }
}
