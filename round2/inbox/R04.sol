// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: StakeLedger
  Constructor: none (deployer becomes admin)
  Setup (admin calls, in order):
    1. credit(0x1111111111111111111111111111111111111111, 100e18)       // ordinary holder, 100e18 spendable
    2. grantVesting(0x2222222222222222222222222222222222222222, 20e18)  // vesting account: 20e18 locked, 0 spendable
  Users: 0x1111... and 0x2222... (any other address may also call)
*/
contract StakeLedger {
    address public admin;
    uint256 public totalSupply;
    uint256 public totalDelegated;

    mapping(address => uint256) public balanceOf;   // spendable
    mapping(address => uint256) public locked;      // vesting, not spendable
    mapping(address => uint256) public delegated;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Delegated(address indexed account, uint256 amount);
    event Undelegated(address indexed account, uint256 amount);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "admin");
        _;
    }

    function credit(address to, uint256 amount) external onlyAdmin {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function grantVesting(address to, uint256 amount) external onlyAdmin {
        locked[to] += amount;
        totalSupply += amount;
    }

    function delegate(uint256 amount) external {
        require(amount > 0, "zero");
        require(amount <= balanceOf[msg.sender] + locked[msg.sender] - delegated[msg.sender], "insufficient");
        delegated[msg.sender] += amount;
        totalDelegated += amount;
        unchecked {
            balanceOf[msg.sender] -= amount;
        }
        emit Delegated(msg.sender, amount);
    }

    function undelegate(uint256 amount) external {
        require(amount > 0 && amount <= delegated[msg.sender], "amount");
        delegated[msg.sender] -= amount;
        totalDelegated -= amount;
        unchecked {
            balanceOf[msg.sender] += amount;
        }
        emit Undelegated(msg.sender, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "to");
        require(balanceOf[msg.sender] >= amount, "balance");
        unchecked {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
