// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: StakedShareC06
//
// DEPLOY:
// 1. TokenC06("Base Asset", "BASE") and TokenC06("Bonus", "BNS") from the deployer.
// 2. StakedShareC06(BASE, BNS) from the deployer (deployer becomes owner).
// 3. Deployer mints BASE to users; users approve and deposit.
// 4. Owner periodically mints BNS to itself, approves StakedShareC06 and calls distribute(amount).

contract StakedShareC06 {
    string public constant name = "Staked BASE";
    string public constant symbol = "sBASE";
    uint8 public constant decimals = 18;
    uint256 private constant ACC = 1e18;

    TokenC06 public immutable asset;
    TokenC06 public immutable bonus;
    address public owner;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public accBonusPerShare;
    mapping(address => uint256) public bonusDebt;
    mapping(address => uint256) public bonusOwed;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(address indexed account, uint256 assets, uint256 shares);
    event Redeem(address indexed account, uint256 shares, uint256 assets);
    event Distribute(uint256 amount);
    event BonusClaimed(address indexed account, uint256 amount);

    constructor(TokenC06 _asset, TokenC06 _bonus) {
        asset = _asset;
        bonus = _bonus;
        owner = msg.sender;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function pendingBonus(address account) public view returns (uint256) {
        return bonusOwed[account] + (balanceOf[account] * accBonusPerShare) / ACC - bonusDebt[account];
    }

    function _accrue(address account) internal {
        if (account == address(0)) return;
        bonusOwed[account] = pendingBonus(account);
    }

    function _sync(address account) internal {
        if (account == address(0)) return;
        bonusDebt[account] = (balanceOf[account] * accBonusPerShare) / ACC;
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero");
        uint256 supply = totalSupply;
        uint256 managed = totalAssets();
        shares = supply == 0 ? assets : (assets * supply) / managed;
        require(shares > 0, "zero shares");
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer");
        _accrue(msg.sender);
        totalSupply = supply + shares;
        balanceOf[msg.sender] += shares;
        _sync(msg.sender);
        emit Transfer(address(0), msg.sender, shares);
        emit Deposit(msg.sender, assets, shares);
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        require(shares > 0, "zero");
        require(balanceOf[msg.sender] >= shares, "balance");
        assets = (shares * totalAssets()) / totalSupply;
        _accrue(msg.sender);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        _sync(msg.sender);
        emit Transfer(msg.sender, address(0), shares);
        emit Redeem(msg.sender, shares, assets);
        require(asset.transfer(msg.sender, assets), "transfer");
    }

    function distribute(uint256 amount) external {
        require(msg.sender == owner, "owner");
        require(totalSupply > 0, "no stakers");
        require(bonus.transferFrom(msg.sender, address(this), amount), "transfer");
        accBonusPerShare += (amount * ACC) / totalSupply;
        emit Distribute(amount);
    }

    function claimBonus() external returns (uint256 amount) {
        _accrue(msg.sender);
        amount = bonusOwed[msg.sender];
        bonusOwed[msg.sender] = 0;
        _sync(msg.sender);
        if (amount > 0) {
            require(bonus.transfer(msg.sender, amount), "transfer");
            emit BonusClaimed(msg.sender, amount);
        }
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
        require(to != address(0), "zero address");
        _accrue(from);
        _accrue(to);
        uint256 fromBalance = balanceOf[from];
        uint256 toBalance = balanceOf[to];
        require(fromBalance >= amount, "balance");
        balanceOf[from] = fromBalance - amount;
        balanceOf[to] = toBalance + amount;
        _sync(from);
        emit Transfer(from, to, amount);
    }
}

contract TokenC06 {
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
