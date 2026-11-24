// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Level 2 benchmark: several contracts calling each other. Each case has a deliberate
// bug and a fixed twin, switched by the `fixed_` immutable.

// ---------------------------------------------------------------- M01
// A token that burns 10% of every transfer.
contract FeeToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address a, address b) { balanceOf[a] = 100; balanceOf[b] = 100; }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _move(msg.sender, to, amt);
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        allowance[from][msg.sender] -= amt;
        _move(from, to, amt);
        return true;
    }

    function _move(address from, address to, uint256 amt) internal {
        uint256 fee = amt / 10;
        balanceOf[from] -= amt;
        balanceOf[to] += amt - fee; // the fee is burned
    }
}

// A vault that credits depositors with what they asked to send, not what arrived.
contract VaultM01 {
    FeeToken public token;
    mapping(address => uint256) public deposited;
    uint256 public totalDeposits;
    bool public immutable fixed_;

    constructor(bool f, FeeToken t) { fixed_ = f; token = t; }

    function deposit(uint256 amt) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amt);
        uint256 credited = fixed_ ? token.balanceOf(address(this)) - before
                                  : amt; // BUG: ignores the transfer fee
        deposited[msg.sender] += credited;
 /* update removed */
    }

    function withdraw(uint256 amt) external {
        deposited[msg.sender] -= amt;
        totalDeposits -= amt;
        token.transfer(msg.sender, amt);
    }
}

// ---------------------------------------------------------------- M02
interface IWithdrawHook {
    function onWithdraw(uint256 amount) external;
}

// A bank that notifies contract users when they withdraw, then clears their balance.
contract BankM02 {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public deposited; // lifetime total paid in
    mapping(address => uint256) public paidOut;   // lifetime total paid out
    bool public immutable fixed_;

    constructor(bool f) { fixed_ = f; }

    function deposit(uint256 a) external {
        balanceOf[msg.sender] += a;
        deposited[msg.sender] += a;
    }

    function withdraw() external {
        uint256 a = balanceOf[msg.sender];
        require(a > 0, "NOTHING");
        if (fixed_) balanceOf[msg.sender] = 0;
        paidOut[msg.sender] += a;
        if (msg.sender.code.length > 0) IWithdrawHook(msg.sender).onWithdraw(a);
        if (!fixed_) balanceOf[msg.sender] = 0; // BUG: state updated after the external call
    }
}

// ---------------------------------------------------------------- M03
// An oracle with a spot price anyone can move (a thin market) and a slow fair price.
contract OracleM03 {
    uint256 public spotPrice;
    uint256 public fairPrice;

    constructor() { spotPrice = 2; fairPrice = 2; }

    function trade(uint256 newSpot) external { spotPrice = newSpot; }
}

// A lender allowing borrowing up to 50% of collateral value.
contract LendingM03 {
    OracleM03 public oracle;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    bool public immutable fixed_;

    constructor(bool f, OracleM03 o) { fixed_ = f; oracle = o; }

    function depositCollateral(uint256 a) external { collateral[msg.sender] += a; }

    function borrow(uint256 a) external {
        uint256 price = fixed_ ? oracle.fairPrice()
                               : oracle.spotPrice(); // BUG: price the borrower can move
        require((debt[msg.sender] + a) * 2 <= collateral[msg.sender] * price, "LTV");
        debt[msg.sender] += a;
    }
}
