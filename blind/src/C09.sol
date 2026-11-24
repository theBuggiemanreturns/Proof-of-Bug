// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: VaultC09
//
// DEPLOY:
// 1. TokenC09("Wrapped Dollar", "WD") from the deployer.
// 2. VaultC09(WD, feeRecipient) from the deployer.
// 3. Deployer mints WD to users; users approve the vault and call deposit / mint.
// 4. Yield is added by transferring WD directly to the vault.

contract VaultC09 {
    uint256 public constant VIRTUAL_SHARES = 1e6;
    uint256 public constant VIRTUAL_ASSETS = 1;
    uint256 public constant EXIT_FEE_BPS = 10;
    uint256 public constant BPS = 10_000;

    TokenC09 public immutable asset;
    address public immutable feeRecipient;

    string public constant name = "WD Yield Share";
    string public constant symbol = "yWD";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);

    constructor(TokenC09 _asset, address _feeRecipient) {
        require(_feeRecipient != address(0), "fee recipient");
        asset = _asset;
        feeRecipient = _feeRecipient;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function _mulDiv(uint256 x, uint256 y, uint256 d, bool roundUp) internal pure returns (uint256 z) {
        z = (x * y) / d;
        if (roundUp && mulmod(x, y, d) != 0) z += 1;
    }

    function _toShares(uint256 assets, bool roundUp) internal view returns (uint256) {
        return _mulDiv(assets, totalSupply + VIRTUAL_SHARES, totalAssets() + VIRTUAL_ASSETS, roundUp);
    }

    function _toAssets(uint256 shares, bool roundUp) internal view returns (uint256) {
        return _mulDiv(shares, totalAssets() + VIRTUAL_ASSETS, totalSupply + VIRTUAL_SHARES, roundUp);
    }

    function convertToShares(uint256 assets) external view returns (uint256) {
        return _toShares(assets, false);
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        return _toAssets(shares, false);
    }

    function previewDeposit(uint256 assets) public view returns (uint256) {
        return _toShares(assets, false);
    }

    function previewMint(uint256 shares) public view returns (uint256) {
        return _toAssets(shares, true);
    }

    function previewRedeem(uint256 shares) public view returns (uint256) {
        uint256 gross = _toAssets(shares, false);
        return gross - _mulDiv(gross, EXIT_FEE_BPS, BPS, true);
    }

    function previewWithdraw(uint256 assets) public view returns (uint256) {
        uint256 gross = _mulDiv(assets, BPS, BPS - EXIT_FEE_BPS, true);
        return _toShares(gross, true);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        require(shares > 0, "zero shares");
        _enter(receiver, assets, shares);
    }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        require(shares > 0, "zero shares");
        assets = previewMint(shares);
        _enter(receiver, assets, shares);
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = previewRedeem(shares);
        require(assets > 0, "zero assets");
        _exit(owner, receiver, assets, shares);
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        require(assets > 0, "zero assets");
        shares = previewWithdraw(assets);
        _exit(owner, receiver, assets, shares);
    }

    function _enter(address receiver, uint256 assets, uint256 shares) internal {
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer");
        totalSupply += shares;
        balanceOf[receiver] += shares;
        emit Transfer(address(0), receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function _exit(address owner, address receiver, uint256 assets, uint256 shares) internal {
        if (msg.sender != owner) {
            uint256 allowed = allowance[owner][msg.sender];
            if (allowed != type(uint256).max) {
                require(allowed >= shares, "allowance");
                allowance[owner][msg.sender] = allowed - shares;
            }
        }
        uint256 gross = _toAssets(shares, false);
        uint256 fee = gross > assets ? gross - assets : 0;
        require(balanceOf[owner] >= shares, "balance");
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        emit Transfer(owner, address(0), shares);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
        require(asset.transfer(receiver, assets), "transfer");
        if (fee > 0) {
            require(asset.transfer(feeRecipient, fee), "fee");
        }
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}

contract TokenC09 {
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
