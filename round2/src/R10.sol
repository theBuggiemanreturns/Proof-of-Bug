// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: DualAssetVault (MockToken is a helper)
  Deploy order:
    1. MockToken("Stable A", 18) -> A
    2. MockToken("Stable B", 18) -> B
    3. DualAssetVault(address(A), address(B))     // both assets valued 1:1
  Setup:
    - A.mint and B.mint 100e18 each to 0x1111111111111111111111111111111111111111; 0x1111 approves the vault for both
    - 0x1111 calls depositMulti([100e18, 100e18])  // vault: 100e18 A + 100e18 B, 200e18 shares
    - A.mint and B.mint 100e18 each to 0x2222222222222222222222222222222222222222; 0x2222 approves the vault for both
  Users: 0x1111..., 0x2222...
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

contract DualAssetVault {
    MockToken[2] public assets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Deposit(address indexed user, uint256 value, uint256 shares);
    event Withdraw(address indexed user, uint256 shares, uint256 out0, uint256 out1);

    constructor(MockToken a0, MockToken a1) {
        assets[0] = a0;
        assets[1] = a1;
    }

    function totalHoldings() public view returns (uint256) {
        return assets[0].balanceOf(address(this)) + assets[1].balanceOf(address(this));
    }

    function depositMulti(uint256[] calldata amounts) external returns (uint256 shares) {
        require(amounts.length == 2, "length");
        uint256 holdings;
        uint256 value;
        for (uint256 i = 0; i < amounts.length; i++) {
            holdings += assets[i].balanceOf(address(this));
            value += amounts[i];
        }
        require(value > 0, "zero");
        shares = (totalSupply == 0 || holdings == 0) ? value : value * totalSupply / holdings;
        require(shares > 0, "shares");

        for (uint256 i = 0; i < amounts.length; i++) {
            if (amounts[i] > 0) assets[i].transferFrom(msg.sender, address(this), amounts[i]);
        }
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
        emit Deposit(msg.sender, value, shares);
    }

    function withdraw(uint256 shares) external {
        require(shares > 0 && balanceOf[msg.sender] >= shares, "shares");
        uint256 out0 = shares * assets[0].balanceOf(address(this)) / totalSupply;
        uint256 out1 = shares * assets[1].balanceOf(address(this)) / totalSupply;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        if (out0 > 0) assets[0].transfer(msg.sender, out0);
        if (out1 > 0) assets[1].transfer(msg.sender, out1);
        emit Withdraw(msg.sender, shares, out0, out1);
    }
}
