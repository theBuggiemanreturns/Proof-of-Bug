// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: OrderBookC07
//
// DEPLOY:
// 1. TokenC07("Base", "BASE") and TokenC07("Quote", "QUOTE") from the deployer.
// 2. OrderBookC07(BASE, QUOTE).
// 3. Deployer mints BASE to makers and QUOTE to takers; each approves OrderBookC07.
// 4. Makers call place(amount, price) where price is QUOTE per 1e18 BASE; takers call fill.

contract OrderBookC07 {
    struct Order {
        address maker;
        uint128 amount;
        uint128 price;
        bool active;
    }

    uint256 public constant PRICE_SCALE = 1e18;

    TokenC07 public immutable base;
    TokenC07 public immutable quote;

    uint256 public nextOrderId = 1;
    mapping(uint256 => Order) public orders;

    event Placed(uint256 indexed id, address indexed maker, uint256 amount, uint256 price);
    event Filled(uint256 indexed id, address indexed taker, uint256 baseAmount, uint256 quoteAmount);
    event Cancelled(uint256 indexed id, uint256 refunded);
    event Modified(uint256 indexed id, uint256 newAmount, uint256 newPrice);

    constructor(TokenC07 _base, TokenC07 _quote) {
        base = _base;
        quote = _quote;
    }

    function place(uint128 amount, uint128 price) external returns (uint256 id) {
        require(amount > 0 && price > 0, "params");
        require(base.transferFrom(msg.sender, address(this), amount), "transfer");
        id = nextOrderId++;
        orders[id] = Order({maker: msg.sender, amount: amount, price: price, active: true});
        emit Placed(id, msg.sender, amount, price);
    }

    function quoteFor(uint256 id, uint256 baseAmount) public view returns (uint256) {
        uint256 cost = baseAmount * orders[id].price;
        return (cost + PRICE_SCALE - 1) / PRICE_SCALE;
    }

    function fill(uint256 id, uint128 baseAmount, uint256 maxQuote) external returns (uint256 quoteAmount) {
        Order storage o = orders[id];
        require(o.active, "inactive");
        require(baseAmount > 0 && baseAmount <= o.amount, "amount");
        quoteAmount = quoteFor(id, baseAmount);
        require(quoteAmount <= maxQuote, "slippage");
        o.amount -= baseAmount;
        if (o.amount == 0) {
            o.active = false;
        }
        require(quote.transferFrom(msg.sender, o.maker, quoteAmount), "quote transfer");
        require(base.transfer(msg.sender, baseAmount), "base transfer");
        emit Filled(id, msg.sender, baseAmount, quoteAmount);
    }

    function cancel(uint256 id) external {
        Order storage o = orders[id];
        require(o.maker == msg.sender, "maker");
        require(o.active, "inactive");
        o.active = false;
        uint256 refund = o.amount;
        require(base.transfer(msg.sender, refund), "transfer");
        emit Cancelled(id, refund);
    }

    function modify(uint256 id, uint128 newAmount, uint128 newPrice) external {
        Order storage o = orders[id];
        require(o.maker == msg.sender, "maker");
        require(newAmount > 0 && newPrice > 0, "params");
        uint128 current = o.amount;
        o.amount = newAmount;
        o.price = newPrice;
        if (newAmount > current) {
            require(base.transferFrom(msg.sender, address(this), newAmount - current), "transfer");
        } else if (newAmount < current) {
            require(base.transfer(msg.sender, current - newAmount), "transfer");
        }
        emit Modified(id, newAmount, newPrice);
    }
}

contract TokenC07 {
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
