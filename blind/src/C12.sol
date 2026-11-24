// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: AuctionHouseC12
//
// DEPLOY:
// 1. TokenC12("Lot Token", "LOT") from the deployer.
// 2. AuctionHouseC12(LOT).
// 3. Deployer mints LOT to sellers; sellers approve AuctionHouseC12 and call createAuction(amount, reserve, duration).
// 4. Bidders call bid{value: x}(id); anyone calls settle(id) after the end; everyone pulls ETH with withdraw().

contract AuctionHouseC12 {
    struct Auction {
        address seller;
        uint96 lotAmount;
        uint64 endTime;
        bool settled;
        address highestBidder;
        uint256 highestBid;
        uint256 reservePrice;
    }

    uint256 public constant MIN_INCREMENT_BPS = 500;
    uint256 public constant EXTENSION_WINDOW = 10 minutes;
    uint256 public constant MAX_DURATION = 30 days;

    TokenC12 public immutable lot;
    uint256 public nextAuctionId = 1;
    mapping(uint256 => Auction) public auctions;
    mapping(address => uint256) public pendingWithdrawals;

    uint256 private locked = 1;

    event AuctionCreated(uint256 indexed id, address indexed seller, uint256 amount, uint256 reserve, uint256 endTime);
    event BidPlaced(uint256 indexed id, address indexed bidder, uint256 amount, uint256 endTime);
    event AuctionSettled(uint256 indexed id, address winner, uint256 amount);
    event AuctionCancelled(uint256 indexed id);
    event Withdrawal(address indexed account, uint256 amount);

    constructor(TokenC12 _lot) {
        lot = _lot;
    }

    modifier nonReentrant() {
        require(locked == 1, "reentrant");
        locked = 2;
        _;
        locked = 1;
    }

    function createAuction(uint96 lotAmount, uint256 reservePrice, uint64 duration)
        external
        nonReentrant
        returns (uint256 id)
    {
        require(lotAmount > 0, "amount");
        require(duration > 0 && duration <= MAX_DURATION, "duration");
        uint256 beforeBal = lot.balanceOf(address(this));
        require(lot.transferFrom(msg.sender, address(this), lotAmount), "transfer");
        require(lot.balanceOf(address(this)) - beforeBal == lotAmount, "received");

        id = nextAuctionId++;
        auctions[id] = Auction({
            seller: msg.sender,
            lotAmount: lotAmount,
            endTime: uint64(block.timestamp) + duration,
            settled: false,
            highestBidder: address(0),
            highestBid: 0,
            reservePrice: reservePrice
        });
        emit AuctionCreated(id, msg.sender, lotAmount, reservePrice, block.timestamp + duration);
    }

    function minNextBid(uint256 id) public view returns (uint256) {
        Auction storage a = auctions[id];
        if (a.highestBid == 0) return a.reservePrice == 0 ? 1 : a.reservePrice;
        return a.highestBid + (a.highestBid * MIN_INCREMENT_BPS + 9_999) / 10_000;
    }

    function bid(uint256 id) external payable nonReentrant {
        Auction storage a = auctions[id];
        require(a.seller != address(0), "no auction");
        require(!a.settled, "settled");
        require(block.timestamp < a.endTime, "ended");
        require(msg.sender != a.seller, "seller");
        require(msg.value >= minNextBid(id), "bid too low");

        address previous = a.highestBidder;
        uint256 previousBid = a.highestBid;

        a.highestBidder = msg.sender;
        a.highestBid = msg.value;

        if (previous != address(0)) {
            pendingWithdrawals[previous] += previousBid;
        }

        if (a.endTime - block.timestamp < EXTENSION_WINDOW) {
            a.endTime = uint64(block.timestamp + EXTENSION_WINDOW);
        }
        emit BidPlaced(id, msg.sender, msg.value, a.endTime);
    }

    function settle(uint256 id) external nonReentrant {
        Auction storage a = auctions[id];
        require(a.seller != address(0), "no auction");
        require(!a.settled, "settled");
        require(block.timestamp >= a.endTime, "not ended");
        a.settled = true;

        if (a.highestBidder == address(0)) {
            require(lot.transfer(a.seller, a.lotAmount), "transfer");
            emit AuctionSettled(id, address(0), 0);
            return;
        }

        pendingWithdrawals[a.seller] += a.highestBid;
        require(lot.transfer(a.highestBidder, a.lotAmount), "transfer");
        emit AuctionSettled(id, a.highestBidder, a.highestBid);
    }

    function cancel(uint256 id) external nonReentrant {
        Auction storage a = auctions[id];
        require(msg.sender == a.seller, "seller");
        require(!a.settled, "settled");
        require(a.highestBidder == address(0), "has bids");
        a.settled = true;
        require(lot.transfer(a.seller, a.lotAmount), "transfer");
        emit AuctionCancelled(id);
    }

    function withdraw() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "nothing");
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        emit Withdrawal(msg.sender, amount);
    }
}

contract TokenC12 {
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
