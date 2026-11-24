// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: FarmC10
//
// DEPLOY:
// 1. TokenC10("LP Token", "LP") and TokenC10("Farm Reward", "FRM") from the deployer.
// 2. FarmC10(LP, FRM, 1e18) from the deployer (rewardPerSecond = 1e18, deployer becomes owner).
// 3. Deployer mints 1,000,000e18 FRM to FarmC10 as the emission reserve.
// 4. Deployer mints LP to users; users approve and deposit.

contract FarmC10 {
    struct UserInfo {
        uint256 amount;
        uint256 rewardDebt;
    }

    uint256 private constant ACC_PRECISION = 1e12;

    TokenC10 public immutable lpToken;
    TokenC10 public immutable rewardToken;
    address public owner;

    uint256 public rewardPerSecond;
    uint256 public lastRewardTime;
    uint256 public accRewardPerShare;
    uint256 public totalStaked;

    mapping(address => UserInfo) public userInfo;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event Harvest(address indexed user, uint256 amount);
    event EmergencyWithdraw(address indexed user, uint256 amount);
    event RewardRateUpdated(uint256 rewardPerSecond);

    constructor(TokenC10 _lpToken, TokenC10 _rewardToken, uint256 _rewardPerSecond) {
        lpToken = _lpToken;
        rewardToken = _rewardToken;
        rewardPerSecond = _rewardPerSecond;
        lastRewardTime = block.timestamp;
        owner = msg.sender;
    }

    function pendingReward(address account) external view returns (uint256) {
        UserInfo storage user = userInfo[account];
        uint256 acc = accRewardPerShare;
        if (block.timestamp > lastRewardTime && totalStaked != 0) {
            acc += ((block.timestamp - lastRewardTime) * rewardPerSecond * ACC_PRECISION) / totalStaked;
        }
        return (user.amount * acc) / ACC_PRECISION - user.rewardDebt;
    }

    function updatePool() public {
        if (block.timestamp <= lastRewardTime) return;
        if (totalStaked == 0) {
            lastRewardTime = block.timestamp;
            return;
        }
        uint256 reward = (block.timestamp - lastRewardTime) * rewardPerSecond;
        accRewardPerShare += (reward * ACC_PRECISION) / totalStaked;
        lastRewardTime = block.timestamp;
    }

    function deposit(uint256 amount) external {
        updatePool();
        UserInfo storage user = userInfo[msg.sender];
        if (user.amount > 0) {
            uint256 pending = (user.amount * accRewardPerShare) / ACC_PRECISION - user.rewardDebt;
            if (pending > 0) {
                _safeRewardTransfer(msg.sender, pending);
                emit Harvest(msg.sender, pending);
            }
        }
        user.rewardDebt = (user.amount * accRewardPerShare) / ACC_PRECISION;
        if (amount > 0) {
            require(lpToken.transferFrom(msg.sender, address(this), amount), "transfer");
            user.amount += amount;
            totalStaked += amount;
        }
        emit Deposit(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        UserInfo storage user = userInfo[msg.sender];
        require(user.amount >= amount, "amount");
        updatePool();
        uint256 pending = (user.amount * accRewardPerShare) / ACC_PRECISION - user.rewardDebt;
        if (pending > 0) {
            _safeRewardTransfer(msg.sender, pending);
            emit Harvest(msg.sender, pending);
        }
        if (amount > 0) {
            user.amount -= amount;
            totalStaked -= amount;
            require(lpToken.transfer(msg.sender, amount), "transfer");
        }
        user.rewardDebt = (user.amount * accRewardPerShare) / ACC_PRECISION;
        emit Withdraw(msg.sender, amount);
    }

    function harvest() external {
        updatePool();
        UserInfo storage user = userInfo[msg.sender];
        uint256 accumulated = (user.amount * accRewardPerShare) / ACC_PRECISION;
        uint256 pending = accumulated - user.rewardDebt;
        user.rewardDebt = accumulated;
        if (pending > 0) {
            _safeRewardTransfer(msg.sender, pending);
            emit Harvest(msg.sender, pending);
        }
    }

    function emergencyWithdraw() external {
        UserInfo storage user = userInfo[msg.sender];
        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        totalStaked -= amount;
        require(lpToken.transfer(msg.sender, amount), "transfer");
        emit EmergencyWithdraw(msg.sender, amount);
    }

    function setRewardPerSecond(uint256 _rewardPerSecond) external {
        require(msg.sender == owner, "owner");
        updatePool();
        rewardPerSecond = _rewardPerSecond;
        emit RewardRateUpdated(_rewardPerSecond);
    }

    function _safeRewardTransfer(address to, uint256 amount) internal {
        uint256 balance = rewardToken.balanceOf(address(this));
        if (amount > balance) amount = balance;
        require(rewardToken.transfer(to, amount), "transfer");
    }
}

contract TokenC10 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    address public immutable minter;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
        minter = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "minter");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
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
