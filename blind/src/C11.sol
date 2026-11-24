// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: StreamPayC11
//
// DEPLOY:
// 1. TokenC11("Payroll Dollar", "PUSD") from the deployer.
// 2. StreamPayC11(PUSD).
// 3. Deployer mints PUSD to payers; payers approve StreamPayC11 and call createStream.
// 4. Recipients call withdraw while a stream is running; payers may cancel.

contract StreamPayC11 {
    struct Stream {
        address sender;
        address recipient;
        uint128 deposit;
        uint128 withdrawn;
        uint256 ratePerSecond;
        uint40 startTime;
        uint40 stopTime;
        bool cancelled;
    }

    TokenC11 public immutable token;
    uint256 public nextStreamId = 1;
    mapping(uint256 => Stream) public streams;

    event StreamCreated(uint256 indexed id, address indexed sender, address indexed recipient, uint256 deposit, uint256 rate, uint256 start, uint256 stop);
    event Withdrawn(uint256 indexed id, address indexed recipient, uint256 amount);
    event Cancelled(uint256 indexed id, uint256 senderRefund, uint256 recipientPaid);

    constructor(TokenC11 _token) {
        token = _token;
    }

    function createStream(address recipient, uint256 ratePerSecond, uint40 startTime, uint40 stopTime)
        external
        returns (uint256 id)
    {
        require(recipient != address(0) && recipient != address(this), "recipient");
        require(ratePerSecond > 0, "rate");
        require(startTime >= block.timestamp, "start");
        require(stopTime > startTime, "stop");

        uint256 duration = uint256(stopTime) - startTime;
        uint128 deposit = uint128(ratePerSecond * duration);

        id = nextStreamId++;
        streams[id] = Stream({
            sender: msg.sender,
            recipient: recipient,
            deposit: deposit,
            withdrawn: 0,
            ratePerSecond: ratePerSecond,
            startTime: startTime,
            stopTime: stopTime,
            cancelled: false
        });

        require(token.transferFrom(msg.sender, address(this), deposit), "transfer");
        emit StreamCreated(id, msg.sender, recipient, deposit, ratePerSecond, startTime, stopTime);
    }

    function streamed(uint256 id) public view returns (uint256) {
        Stream storage s = streams[id];
        if (block.timestamp <= s.startTime) return 0;
        uint256 end = block.timestamp < s.stopTime ? block.timestamp : s.stopTime;
        return (end - s.startTime) * s.ratePerSecond;
    }

    function withdrawable(uint256 id) public view returns (uint256) {
        Stream storage s = streams[id];
        if (s.cancelled) return 0;
        return streamed(id) - s.withdrawn;
    }

    function withdraw(uint256 id, uint128 amount) external {
        Stream storage s = streams[id];
        require(msg.sender == s.recipient, "recipient");
        require(amount > 0 && amount <= withdrawable(id), "amount");
        s.withdrawn += amount;
        require(token.transfer(s.recipient, amount), "transfer");
        emit Withdrawn(id, s.recipient, amount);
    }

    function cancel(uint256 id) external {
        Stream storage s = streams[id];
        require(msg.sender == s.sender || msg.sender == s.recipient, "party");
        require(!s.cancelled, "cancelled");
        uint256 owedToRecipient = streamed(id) - s.withdrawn;
        uint256 refund = uint256(s.deposit) - s.withdrawn - owedToRecipient;
        s.cancelled = true;
        s.withdrawn += uint128(owedToRecipient);
        if (owedToRecipient > 0) require(token.transfer(s.recipient, owedToRecipient), "transfer");
        if (refund > 0) require(token.transfer(s.sender, refund), "transfer");
        emit Cancelled(id, refund, owedToRecipient);
    }
}

contract TokenC11 {
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
