// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: VestingPool (MockToken is a helper)
  Deploy order:
    1. MockToken("Project Token", 18)                 -> TKN (deployer is the only minter)
    2. VestingPool(address(TKN))
  Setup:
    - TKN.mint(0x1111111111111111111111111111111111111111, 100e18); 0x1111 approves VestingPool for 100e18
    - TKN.mint(0x2222222222222222222222222222222222222222, 100e18); 0x2222 approves VestingPool for 100e18
    - 0x1111 calls createLock(0x1111, 100e18, 100)   // lock id 0: beneficiary 0x1111, 100 second linear vesting
  Users: 0x1111..., 0x2222... (0x2222 starts with no lock; it may create its own)
  Time: block.timestamp advances between transactions.
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

contract VestingPool {
    struct Lock {
        address creator;
        address beneficiary;
        uint256 sharesDeposited;
        uint256 sharesWithdrawn;
        uint256 shares;
        uint64 start;
        uint64 end;
    }

    MockToken public immutable token;
    uint256 public totalShares;
    uint256 public nextLockId;
    mapping(uint256 => Lock) public locks;

    event LockCreated(uint256 indexed id, address indexed creator, address indexed beneficiary, uint256 amount, uint256 shares);
    event Released(uint256 indexed id, uint256 shares, uint256 amount);
    event Cancelled(uint256 indexed id, uint256 toCreator, uint256 toBeneficiary);

    constructor(MockToken _token) {
        token = _token;
    }

    function createLock(address beneficiary, uint256 amount, uint64 duration) external returns (uint256 id) {
        require(amount > 0 && duration > 0, "params");
        require(beneficiary != address(0), "beneficiary");
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 shares = (totalShares == 0 || balanceBefore == 0) ? amount : amount * totalShares / balanceBefore;
        require(shares > 0, "shares");

        id = nextLockId++;
        locks[id] = Lock({
            creator: msg.sender,
            beneficiary: beneficiary,
            sharesDeposited: shares,
            sharesWithdrawn: 0,
            shares: shares,
            start: uint64(block.timestamp),
            end: uint64(block.timestamp) + duration
        });
        totalShares += shares;
        emit LockCreated(id, msg.sender, beneficiary, amount, shares);
    }

    function vestedShares(uint256 id) public view returns (uint256) {
        Lock storage l = locks[id];
        if (block.timestamp >= l.end) return l.sharesDeposited;
        if (block.timestamp <= l.start) return 0;
        return l.sharesDeposited * (block.timestamp - l.start) / (l.end - l.start);
    }

    function sharesToTokens(uint256 shares) public view returns (uint256) {
        if (totalShares == 0) return 0;
        return shares * token.balanceOf(address(this)) / totalShares;
    }

    function release(uint256 id) external {
        Lock storage l = locks[id];
        require(msg.sender == l.beneficiary, "not beneficiary");
        uint256 available = vestedShares(id) - l.sharesWithdrawn;
        require(available > 0, "nothing vested");
        uint256 amount = sharesToTokens(available);
        l.sharesWithdrawn += available;
        totalShares -= available;
        token.transfer(l.beneficiary, amount);
        emit Released(id, available, amount);
    }

    function cancel(uint256 id) external {
        Lock storage l = locks[id];
        require(msg.sender == l.creator, "not creator");
        require(l.shares > 0, "closed");
        uint256 vestedUnclaimed = vestedShares(id) - l.sharesWithdrawn;
        uint256 unvested = l.shares - vestedUnclaimed;

        uint256 toCreator = sharesToTokens(unvested);
        uint256 toBeneficiary = sharesToTokens(vestedUnclaimed);
        totalShares -= l.shares;
        l.sharesWithdrawn = l.sharesDeposited;
        l.shares = 0;

        if (toCreator > 0) token.transfer(l.creator, toCreator);
        if (toBeneficiary > 0) token.transfer(l.beneficiary, toBeneficiary);
        emit Cancelled(id, toCreator, toBeneficiary);
    }
}
