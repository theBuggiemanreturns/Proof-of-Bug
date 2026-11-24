// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: DeflationaryToken together with SimplePair (MockToken is a helper)
  Deploy order:
    1. DeflationaryToken(10_000e18)            -> TKN (10,000e18 minted to deployer; deployer is owner and fee-exempt)
    2. MockToken("USD Stable", 18)              -> USD
    3. SimplePair(address(TKN), address(USD))   -> PAIR (token0 = TKN, token1 = USD)
    4. TKN.setPair(address(PAIR))               // owner call
  Setup (seed liquidity, deployer):
    - USD.mint(deployer, 1_000e18)
    - TKN.transfer(PAIR, 1_000e18); USD.transfer(PAIR, 1_000e18); PAIR.sync()   // reserves 1,000e18 / 1,000e18
    - TKN.transfer(0x2222222222222222222222222222222222222222, 2_000e18)         // trader holding
    - USD.mint(0x1111111111111111111111111111111111111111, 1_000e18)             // second trader
  Users: 0x1111..., 0x2222...
  Trading flow (no router): send the input token to PAIR, then call PAIR.swap(amount0Out, amount1Out, to).
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

interface ISyncable {
    function sync() external;
}

contract DeflationaryToken {
    string public constant name = "Deflationary Token";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    address public owner;
    address public pair;
    uint256 public sellBurnBps = 5000;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isExempt;

    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor(uint256 supply) {
        owner = msg.sender;
        isExempt[msg.sender] = true;
        balanceOf[msg.sender] = supply;
        totalSupply = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function setPair(address p) external {
        require(msg.sender == owner, "owner");
        require(pair == address(0), "set");
        pair = p;
        isExempt[p] = true;
    }

    function approve(address s, uint256 amount) external returns (bool) {
        allowance[msg.sender][s] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (to == pair && pair != address(0) && !isExempt[from]) {
            _sellBurn(amount * sellBurnBps / 10_000);
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }

    function _sellBurn(uint256 burnAmount) internal {
        if (burnAmount == 0) return;
        balanceOf[pair] -= burnAmount;
        totalSupply -= burnAmount;
        emit Transfer(pair, address(0), burnAmount);
        ISyncable(pair).sync();
    }
}

interface IToken {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract SimplePair {
    IToken public immutable token0;
    IToken public immutable token1;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 private unlocked = 1;

    modifier lock() {
        require(unlocked == 1, "locked");
        unlocked = 0;
        _;
        unlocked = 1;
    }

    constructor(address t0, address t1) {
        token0 = IToken(t0);
        token1 = IToken(t1);
    }

    function sync() external lock {
        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to) external lock {
        require(amount0Out > 0 || amount1Out > 0, "out");
        uint256 r0 = reserve0;
        uint256 r1 = reserve1;
        require(amount0Out < r0 && amount1Out < r1, "liquidity");
        if (amount0Out > 0) token0.transfer(to, amount0Out);
        if (amount1Out > 0) token1.transfer(to, amount1Out);

        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));
        uint256 in0 = b0 > r0 - amount0Out ? b0 - (r0 - amount0Out) : 0;
        uint256 in1 = b1 > r1 - amount1Out ? b1 - (r1 - amount1Out) : 0;
        require(in0 > 0 || in1 > 0, "input");
        uint256 adj0 = b0 * 1000 - in0 * 3;
        uint256 adj1 = b1 * 1000 - in1 * 3;
        require(adj0 * adj1 >= r0 * r1 * 1_000_000, "K");
        reserve0 = b0;
        reserve1 = b1;
    }
}
