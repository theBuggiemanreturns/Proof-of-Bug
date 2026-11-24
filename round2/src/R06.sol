// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: ManagedTreasury (MockToken is a helper)
  Deploy order:
    1. MockToken("Wrapped BTC", 8)              -> WB
    2. ManagedTreasury(address(WB))             // deployer is owner
  Setup (owner calls, in order):
    1. setRebalancer(0x3333333333333333333333333333333333333333)   // first operator
    2. setRebalancer(0x2222222222222222222222222222222222222222)   // operator replaced; 0x2222 is now the trusted operator
  Then:
    - WB.mint(0x1111111111111111111111111111111111111111, 10e8); 0x1111 approves the treasury; 0x1111 calls deposit(10e8)
  Users: 0x1111..., 0x2222..., 0x3333...
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

contract ManagedTreasury {
    MockToken public immutable asset;
    address public owner;
    address public rebalancer;
    mapping(address => bool) public hasRebalanceRole;
    mapping(address => uint256) public deployedTo;

    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    event RebalancerSet(address indexed rebalancer);
    event Rebalanced(address indexed by, address indexed to, uint256 amount);

    constructor(MockToken _asset) {
        asset = _asset;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function setRebalancer(address r) external onlyOwner {
        require(r != address(0), "zero");
        hasRebalanceRole[r] = true;
        rebalancer = r;
        emit RebalancerSet(r);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        uint256 ta = totalAssets();
        uint256 shares = (totalShares == 0 || ta == 0) ? amount : amount * totalShares / ta;
        asset.transferFrom(msg.sender, address(this), amount);
        totalShares += shares;
        sharesOf[msg.sender] += shares;
    }

    function withdraw(uint256 shares) external {
        require(shares > 0 && sharesOf[msg.sender] >= shares, "shares");
        uint256 amount = shares * totalAssets() / totalShares;
        sharesOf[msg.sender] -= shares;
        totalShares -= shares;
        asset.transfer(msg.sender, amount);
    }

    function rebalance(address to, uint256 amount) external {
        require(hasRebalanceRole[msg.sender], "role");
        deployedTo[to] += amount;
        asset.transfer(to, amount);
        emit Rebalanced(msg.sender, to, amount);
    }
}
