// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: LendingC04
//
// DEPLOY:
// 1. TokenC04("USD Stable", "USDS") and TokenC04("Gov Collateral", "GCOL") from the deployer.
// 2. AmmC04(USDS, GCOL) from the deployer.
// 3. Deployer mints 1,000e18 USDS and 1,000e18 GCOL, approves the AMM and calls addLiquidity(1_000e18, 1_000e18).
// 4. LendingC04(USDS, GCOL, AmmC04) from the deployer.
// 5. A lender is minted 10,000e18 USDS, approves LendingC04 and calls supply(10_000e18).
// 6. Borrowers deposit GCOL as collateral and borrow USDS.

contract LendingC04 {
    uint256 public constant LTV_BPS = 7_500;
    uint256 public constant LIQ_THRESHOLD_BPS = 8_000;
    uint256 public constant LIQ_BONUS_BPS = 500;
    uint256 public constant BPS = 10_000;

    TokenC04 public immutable debtToken;
    TokenC04 public immutable collateralToken;
    AmmC04 public immutable priceSource;

    mapping(address => uint256) public supplied;
    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;
    uint256 public totalSupplied;
    uint256 public totalBorrowed;

    event Supply(address indexed account, uint256 amount);
    event WithdrawSupply(address indexed account, uint256 amount);
    event DepositCollateral(address indexed account, uint256 amount);
    event WithdrawCollateral(address indexed account, uint256 amount);
    event Borrow(address indexed account, uint256 amount);
    event Repay(address indexed payer, address indexed account, uint256 amount);
    event Liquidate(address indexed liquidator, address indexed account, uint256 repaid, uint256 seized);

    constructor(TokenC04 _debtToken, TokenC04 _collateralToken, AmmC04 _priceSource) {
        require(address(_priceSource.token0()) == address(_debtToken), "token0");
        require(address(_priceSource.token1()) == address(_collateralToken), "token1");
        debtToken = _debtToken;
        collateralToken = _collateralToken;
        priceSource = _priceSource;
    }

    function collateralPrice() public view returns (uint256) {
        (uint256 reserveDebt, uint256 reserveCollateral) = priceSource.getReserves();
        require(reserveCollateral > 0, "no liquidity");
        return (reserveDebt * 1e18) / reserveCollateral;
    }

    function collateralValue(address account) public view returns (uint256) {
        return (collateralOf[account] * collateralPrice()) / 1e18;
    }

    function maxBorrow(address account) public view returns (uint256) {
        return (collateralValue(account) * LTV_BPS) / BPS;
    }

    function isHealthy(address account) public view returns (bool) {
        return debtOf[account] * BPS <= collateralValue(account) * LIQ_THRESHOLD_BPS;
    }

    function supply(uint256 amount) external {
        require(amount > 0, "zero");
        require(debtToken.transferFrom(msg.sender, address(this), amount), "transfer");
        supplied[msg.sender] += amount;
        totalSupplied += amount;
        emit Supply(msg.sender, amount);
    }

    function withdrawSupply(uint256 amount) external {
        require(supplied[msg.sender] >= amount, "supplied");
        require(debtToken.balanceOf(address(this)) >= amount, "liquidity");
        supplied[msg.sender] -= amount;
        totalSupplied -= amount;
        require(debtToken.transfer(msg.sender, amount), "transfer");
        emit WithdrawSupply(msg.sender, amount);
    }

    function depositCollateral(uint256 amount) external {
        require(amount > 0, "zero");
        require(collateralToken.transferFrom(msg.sender, address(this), amount), "transfer");
        collateralOf[msg.sender] += amount;
        emit DepositCollateral(msg.sender, amount);
    }

    function withdrawCollateral(uint256 amount) external {
        require(collateralOf[msg.sender] >= amount, "collateral");
        collateralOf[msg.sender] -= amount;
        require(debtOf[msg.sender] <= maxBorrow(msg.sender), "undercollateralized");
        require(collateralToken.transfer(msg.sender, amount), "transfer");
        emit WithdrawCollateral(msg.sender, amount);
    }

    function borrow(uint256 amount) external {
        require(amount > 0, "zero");
        debtOf[msg.sender] += amount;
        totalBorrowed += amount;
        require(debtOf[msg.sender] <= maxBorrow(msg.sender), "undercollateralized");
        require(debtToken.transfer(msg.sender, amount), "transfer");
        emit Borrow(msg.sender, amount);
    }

    function repay(address account, uint256 amount) external {
        uint256 debt = debtOf[account];
        if (amount > debt) amount = debt;
        require(amount > 0, "zero");
        require(debtToken.transferFrom(msg.sender, address(this), amount), "transfer");
        debtOf[account] = debt - amount;
        totalBorrowed -= amount;
        emit Repay(msg.sender, account, amount);
    }

    function liquidate(address account, uint256 repayAmount) external {
        require(!isHealthy(account), "healthy");
        uint256 debt = debtOf[account];
        require(repayAmount > 0 && repayAmount <= debt / 2, "amount");
        uint256 seize = (repayAmount * 1e18 / collateralPrice()) * (BPS + LIQ_BONUS_BPS) / BPS;
        if (seize > collateralOf[account]) seize = collateralOf[account];
        require(debtToken.transferFrom(msg.sender, address(this), repayAmount), "transfer");
        debtOf[account] = debt - repayAmount;
        totalBorrowed -= repayAmount;
        collateralOf[account] -= seize;
        require(collateralToken.transfer(msg.sender, seize), "transfer");
        emit Liquidate(msg.sender, account, repayAmount, seize);
    }
}

contract AmmC04 {
    TokenC04 public immutable token0;
    TokenC04 public immutable token1;
    uint256 private reserve0;
    uint256 private reserve1;
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    event Swap(address indexed sender, address tokenIn, uint256 amountIn, uint256 amountOut);
    event AddLiquidity(address indexed provider, uint256 amount0, uint256 amount1, uint256 shares);

    constructor(TokenC04 _token0, TokenC04 _token1) {
        token0 = _token0;
        token1 = _token1;
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }

    function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 shares) {
        require(token0.transferFrom(msg.sender, address(this), amount0), "transfer0");
        require(token1.transferFrom(msg.sender, address(this), amount1), "transfer1");
        if (totalShares == 0) {
            shares = _sqrt(amount0 * amount1);
        } else {
            uint256 s0 = (amount0 * totalShares) / reserve0;
            uint256 s1 = (amount1 * totalShares) / reserve1;
            shares = s0 < s1 ? s0 : s1;
        }
        require(shares > 0, "shares");
        totalShares += shares;
        sharesOf[msg.sender] += shares;
        reserve0 += amount0;
        reserve1 += amount1;
        emit AddLiquidity(msg.sender, amount0, amount1, shares);
    }

    function removeLiquidity(uint256 shares) external returns (uint256 amount0, uint256 amount1) {
        require(sharesOf[msg.sender] >= shares && shares > 0, "shares");
        amount0 = (shares * reserve0) / totalShares;
        amount1 = (shares * reserve1) / totalShares;
        sharesOf[msg.sender] -= shares;
        totalShares -= shares;
        reserve0 -= amount0;
        reserve1 -= amount1;
        require(token0.transfer(msg.sender, amount0), "transfer0");
        require(token1.transfer(msg.sender, amount1), "transfer1");
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        return (amountInWithFee * reserveOut) / (reserveIn * 1000 + amountInWithFee);
    }

    function swap(address tokenIn, uint256 amountIn, uint256 minAmountOut) external returns (uint256 amountOut) {
        require(amountIn > 0, "zero");
        bool zeroForOne = tokenIn == address(token0);
        require(zeroForOne || tokenIn == address(token1), "token");
        (TokenC04 tIn, TokenC04 tOut, uint256 rIn, uint256 rOut) =
            zeroForOne ? (token0, token1, reserve0, reserve1) : (token1, token0, reserve1, reserve0);
        amountOut = getAmountOut(amountIn, rIn, rOut);
        require(amountOut >= minAmountOut && amountOut > 0, "slippage");
        require(tIn.transferFrom(msg.sender, address(this), amountIn), "transferIn");
        require(tOut.transfer(msg.sender, amountOut), "transferOut");
        if (zeroForOne) {
            reserve0 += amountIn;
            reserve1 -= amountOut;
        } else {
            reserve1 += amountIn;
            reserve0 -= amountOut;
        }
        emit Swap(msg.sender, tokenIn, amountIn, amountOut);
    }

    function _sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}

contract TokenC04 {
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
