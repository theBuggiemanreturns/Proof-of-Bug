// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: BridgeGateway (MockToken is a helper)
  Deploy order:
    1. MockToken("Wrapped Asset", 8)                       -> WA
    2. BridgeGateway(address(WA), 1e6)                      // minFee = 1e6 (0.01 WA); deployer is owner
  Setup:
    - WA.mint(0x1111111111111111111111111111111111111111, 1_000e8); 0x1111 approves the gateway; 0x1111 calls lockIn(1_000e8)
    - WA.mint(0x2222222222222222222222222222222222222222, 10e8); 0x2222 approves the gateway
  Users: 0x1111..., 0x2222...
  withdraw(quantity, fee, destination): fee is a signed relayer fee (same unit as quantity).
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

contract BridgeGateway {
    MockToken public immutable token;
    address public owner;
    int256 public minFee;
    uint256 public feesAccrued;
    uint256 public nonce;
    mapping(address => uint256) public balanceOf;

    event LockedIn(address indexed user, uint256 amount);
    event WithdrawRequested(uint256 indexed nonce, address indexed user, bytes32 destination, uint256 quantity, int256 fee);

    constructor(MockToken _token, int256 _minFee) {
        token = _token;
        owner = msg.sender;
        minFee = _minFee;
    }

    function setMinFee(int256 f) external {
        require(msg.sender == owner, "owner");
        minFee = f;
    }

    function lockIn(uint256 amount) external {
        require(amount > 0, "zero");
        token.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
        emit LockedIn(msg.sender, amount);
    }

    function withdraw(uint256 quantity, int256 fee, bytes32 destination) external {
        require(quantity > 0 && quantity <= uint256(type(int256).max), "quantity");
        int256 total = int256(quantity) + fee;
        require(total >= 0, "total");
        uint256 debit = uint256(total);
        require(balanceOf[msg.sender] >= debit, "balance");
        balanceOf[msg.sender] -= debit;
        if (fee > 0) feesAccrued += uint256(fee);

        token.transfer(msg.sender, quantity);
        emit WithdrawRequested(nonce++, msg.sender, destination, quantity, fee);
    }

    function collectFees(address to) external {
        require(msg.sender == owner, "owner");
        uint256 f = feesAccrued;
        feesAccrued = 0;
        token.transfer(to, f);
    }
}
