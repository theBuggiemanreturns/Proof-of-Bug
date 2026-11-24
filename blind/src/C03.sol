// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: EthPoolC03
//
// DEPLOY:
// 1. EthPoolC03() with no constructor arguments.
// 2. Users call deposit() with ETH (or send ETH directly). Balances are internal and transferable.

contract EthPoolC03 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalDeposits;

    uint256 private status = 1;

    event Deposit(address indexed account, uint256 amount);
    event Withdrawal(address indexed account, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    modifier nonReentrant() {
        require(status == 1, "locked");
        status = 2;
        _;
        status = 1;
    }

    receive() external payable {
        _deposit(msg.sender, msg.value);
    }

    function deposit() external payable {
        _deposit(msg.sender, msg.value);
    }

    function depositFor(address account) external payable {
        _deposit(account, msg.value);
    }

    function _deposit(address account, uint256 amount) internal {
        require(amount > 0, "zero");
        balanceOf[account] += amount;
        totalDeposits += amount;
        emit Deposit(account, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        emit Withdrawal(msg.sender, amount);
    }

    function withdrawAll() external nonReentrant {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "empty");
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balanceOf[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            require(allowed >= amount, "allowance");
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
