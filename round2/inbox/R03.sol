// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: LiquidityVault (MockToken is a helper)
  Deploy order:
    1. MockToken("USD Stable", 18)        -> USD
    2. LiquidityVault(address(USD))       // deployer is owner
  Setup:
    - USD.mint(deployer, 500e18); deployer approves the vault; deployer calls addIncentives(500e18)
    - USD.mint(0x1111111111111111111111111111111111111111, 1_000e18); 0x1111 approves the vault
    - USD.mint(0x2222222222222222222222222222222222222222, 1_000e18); 0x2222 approves the vault
  Users: 0x1111..., 0x2222... (no liquidity has been provided yet)
*/

contract MockToken {
    string public name;
    uint8 public immutable decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public immutable minter;

    constructor(string memory n, uint8 d) {
        minter = msg.sender;
        name = n;
        decimals = d;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "minter");
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address s, uint256 amount) external returns (bool) {
        allowance[msg.sender][s] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract LiquidityVault {
    MockToken public immutable asset;
    address public owner;
    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidityOf;

    event Deposited(address indexed user, uint256 amount, uint256 liquidity);
    event Withdrawn(address indexed user, uint256 liquidity, uint256 amount);
    event IncentivesAdded(uint256 amount);

    constructor(MockToken _asset) {
        asset = _asset;
        owner = msg.sender;
    }

    function addIncentives(uint256 amount) external {
        require(msg.sender == owner, "owner");
        asset.transferFrom(msg.sender, address(this), amount);
        emit IncentivesAdded(amount);
    }

    function deposit(uint256 amount) external returns (uint256 liquidity) {
        require(amount > 0, "zero");
        uint256 bal = asset.balanceOf(address(this));
        liquidity = (totalLiquidity == 0 || bal == 0) ? amount : amount * totalLiquidity / bal;
        require(liquidity > 0, "liquidity");
        asset.transferFrom(msg.sender, address(this), amount);
        totalLiquidity += liquidity;
        liquidityOf[msg.sender] += liquidity;
        emit Deposited(msg.sender, amount, liquidity);
    }

    function withdraw(uint256 liquidity) external returns (uint256 amount) {
        amount = _withdraw(msg.sender, liquidity);
    }

    function _withdraw(address user, uint256 liquidity) internal returns (uint256 amount) {
        require(liquidityOf[user] >= liquidity, "balance");
        uint256 bal = asset.balanceOf(address(this));
        if (totalLiquidity == 0) {
            amount = bal;
        } else {
            amount = liquidity * bal / totalLiquidity;
        }
        liquidityOf[user] -= liquidity;
        totalLiquidity -= liquidity;
        if (amount > 0) asset.transfer(user, amount);
        emit Withdrawn(user, liquidity, amount);
    }
}
