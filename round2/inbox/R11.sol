// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: StablePool (MockToken is a helper)
  Deploy order:
    1. MockToken("USD Coin", 6)       -> USD6 (6 decimals)
    2. StablePool(address(USD6))      // pool accounts in 18-decimal units; LP token has 18 decimals
  Setup:
    - USD6.mint(0x1111111111111111111111111111111111111111, 1_000e6); 0x1111 approves the pool; 0x1111 calls deposit(1_000e18)
    - USD6.mint(0x2222222222222222222222222222222222222222, 10e6); 0x2222 approves the pool
  Users: 0x1111..., 0x2222...
  deposit/withdraw amounts are in 18-decimal units (1e18 = 1 USD).
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

contract StablePool {
    MockToken public immutable asset;
    uint256 public constant SCALE = 1e12;

    string public constant name = "Stable Pool LP";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Deposit(address indexed user, uint256 amount18, uint256 pulled, uint256 lp);
    event Withdraw(address indexed user, uint256 lp, uint256 paid);

    constructor(MockToken _asset) {
        asset = _asset;
    }

    function totalAssets18() public view returns (uint256) {
        return asset.balanceOf(address(this)) * SCALE;
    }

    function deposit(uint256 amount18) external returns (uint256 lp) {
        require(amount18 > 0, "zero");
        uint256 assets18 = totalAssets18();
        lp = (totalSupply == 0 || assets18 == 0) ? amount18 : amount18 * totalSupply / assets18;
        require(lp > 0, "lp");
        uint256 pulled = amount18 / SCALE;
        if (pulled > 0) asset.transferFrom(msg.sender, address(this), pulled);
        totalSupply += lp;
        balanceOf[msg.sender] += lp;
        emit Deposit(msg.sender, amount18, pulled, lp);
    }

    function withdraw(uint256 lp) external returns (uint256 paid) {
        require(lp > 0 && balanceOf[msg.sender] >= lp, "lp");
        paid = lp * asset.balanceOf(address(this)) / totalSupply;
        balanceOf[msg.sender] -= lp;
        totalSupply -= lp;
        if (paid > 0) asset.transfer(msg.sender, paid);
        emit Withdraw(msg.sender, lp, paid);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
