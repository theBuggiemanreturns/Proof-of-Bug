// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: RewardPool together with LegacyPool (MockToken is a helper)
  Deploy order:
    1. MockToken("Stake Token", 18)                         -> STK
    2. MockToken("Reward Token", 18)                        -> RWD
    3. LegacyPool(address(STK))                             -> OLD (deployer is owner)
    4. RewardPool(address(STK), address(RWD), address(OLD)) -> POOL (deployer is owner)
    5. OLD.setMigrator(address(POOL))
  Setup:
    - STK.mint(0x1111111111111111111111111111111111111111, 100e18); 0x1111 approves POOL; 0x1111 calls POOL.stake(100e18)
    - RWD.mint(deployer, 1_000e18); deployer approves POOL; deployer calls POOL.notifyReward(1_000e18)
    - STK.mint(0x2222222222222222222222222222222222222222, 100e18); 0x2222 approves OLD and POOL
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

contract LegacyPool {
    MockToken public immutable stakeToken;
    address public owner;
    address public migrator;
    mapping(address => uint256) public balanceOf;

    constructor(MockToken _stake) {
        stakeToken = _stake;
        owner = msg.sender;
    }

    function setMigrator(address m) external {
        require(msg.sender == owner, "owner");
        migrator = m;
    }

    function deposit(uint256 amount) external {
        stakeToken.transferFrom(msg.sender, address(this), amount);
        balanceOf[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        stakeToken.transfer(msg.sender, amount);
    }

    function migrate(address user) external returns (uint256 amount) {
        require(msg.sender == migrator, "migrator");
        amount = balanceOf[user];
        balanceOf[user] = 0;
        if (amount > 0) stakeToken.transfer(migrator, amount);
    }
}

contract RewardPool {
    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
    }

    uint256 private constant ACC = 1e12;

    MockToken public immutable stakeToken;
    MockToken public immutable rewardToken;
    LegacyPool public immutable legacy;
    address public owner;
    uint256 public accRewardPerShare;
    uint256 public totalStaked;
    mapping(address => UserInfo) public userInfo;

    event Staked(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event Imported(address indexed user, uint256 amount);
    event Claimed(address indexed user, uint256 amount);

    constructor(MockToken _stake, MockToken _reward, LegacyPool _legacy) {
        stakeToken = _stake;
        rewardToken = _reward;
        legacy = _legacy;
        owner = msg.sender;
    }

    function notifyReward(uint256 amount) external {
        require(msg.sender == owner, "owner");
        require(totalStaked > 0, "no stake");
        rewardToken.transferFrom(msg.sender, address(this), amount);
        accRewardPerShare += amount * ACC / totalStaked;
    }

    function pending(address user) public view returns (uint256) {
        UserInfo storage u = userInfo[user];
        return u.amount * accRewardPerShare / ACC - u.rewardDebt;
    }

    function _harvest(address user) internal {
        uint256 p = pending(user);
        if (p > 0) {
            rewardToken.transfer(user, p);
            emit Claimed(user, p);
        }
    }

    function stake(uint256 amount) external {
        require(amount > 0, "zero");
        UserInfo storage u = userInfo[msg.sender];
        _harvest(msg.sender);
        stakeToken.transferFrom(msg.sender, address(this), amount);
        u.amount += amount;
        totalStaked += amount;
        u.rewardDebt = u.amount * accRewardPerShare / ACC;
        emit Staked(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        UserInfo storage u = userInfo[msg.sender];
        require(amount > 0 && u.amount >= amount, "amount");
        _harvest(msg.sender);
        u.amount -= amount;
        totalStaked -= amount;
        u.rewardDebt = u.amount * accRewardPerShare / ACC;
        stakeToken.transfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    function importLegacy() external {
        uint256 amount = legacy.migrate(msg.sender);
        require(amount > 0, "nothing");
        UserInfo storage u = userInfo[msg.sender];
        _harvest(msg.sender);
        u.amount += amount;
        totalStaked += amount;
        u.rewardDebt = u.amount * accRewardPerShare / ACC;
        emit Imported(msg.sender, amount);
    }

    function claim() external {
        UserInfo storage u = userInfo[msg.sender];
        _harvest(msg.sender);
        u.rewardDebt = u.amount * accRewardPerShare / ACC;
    }
}
