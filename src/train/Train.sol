// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Training set for the families added from the 108-pattern cross-reference. Written by the
// rule author (so NOT used to score the engine: the blind set from an independent author is).
// `fixed_` switches between the buggy line and the fix.

interface IHookT06 { function onWithdraw(uint256 a) external; }

// T01 (INC-03, BND-02): a time lock. withdraw() checks the lock, its sibling withdrawTo() does not.
contract LockT01 {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public unlockAt;
    uint256 public constant LOCK = 100;
    bool public immutable fixed_;
    constructor(bool f) { fixed_ = f; }

    function deposit(uint256 a) external {
        balanceOf[msg.sender] += a;
        unlockAt[msg.sender] = block.timestamp + LOCK;
    }
    function withdraw(uint256 a) external {
        require(block.timestamp >= unlockAt[msg.sender], "LOCKED");
        balanceOf[msg.sender] -= a;
    }
    function withdrawTo(address to, uint256 a) external {
        if (fixed_) require(block.timestamp >= unlockAt[msg.sender], "LOCKED");
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
    }
}

// T02 (ACC-03): burnFrom never checks the allowance.
contract TokenT02 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    bool public immutable fixed_;
    constructor(bool f, address a, address b) {
        fixed_ = f;
        balanceOf[a] = 50; balanceOf[b] = 50; totalSupply = 100;
    }
    function approve(address s, uint256 v) external { allowance[msg.sender][s] = v; }
    function transfer(address to, uint256 v) external {
        balanceOf[msg.sender] -= v;
        balanceOf[to] += v;
    }
    function burnFrom(address from, uint256 v) external {
        if (fixed_ || from == msg.sender) {
            if (from != msg.sender) allowance[from][msg.sender] -= v;
        }
        balanceOf[from] -= v;
        totalSupply -= v;
    }
}

// T03 (GOV-01/VLT-06, BND-04): linear vesting that keeps paying after the vesting period ends.
contract VestingT03 {
    uint256 public total;
    uint256 public claimed;
    uint256 public start;
    uint256 public constant DURATION = 50;
    address public beneficiary;
    bool public immutable fixed_;
    constructor(bool f, address b) { fixed_ = f; beneficiary = b; total = 100; start = block.timestamp; }

    function vested() public view returns (uint256) {
        uint256 t = block.timestamp - start;
        if (fixed_ && t > DURATION) t = DURATION;
        return total * t / DURATION;
    }
    function claim() external returns (uint256 a) {
        require(msg.sender == beneficiary, "ONLY_BENEFICIARY");
        a = vested() - claimed;
        claimed += a;
    }
}

// T04 (ACD-02): cancelling an unfilled order takes a fast path that skips the `held` update.
contract EscrowT04 {
    mapping(address => uint256) public credit;
    mapping(address => uint256) public order;
    mapping(address => uint256) public filled;
    uint256 public held;
    bool public immutable fixed_;
    constructor(bool f) { fixed_ = f; }

    function place(uint256 a) external {
        order[msg.sender] += a;
        held += a;
    }
    function fill(address who, uint256 a) external {
        require(a <= order[who] - filled[who], "TOO_MUCH");
        filled[who] += a;
    }
    function cancel() external {
        uint256 rest = order[msg.sender] - filled[msg.sender];
        if (filled[msg.sender] == 0) {
            credit[msg.sender] += rest;
            order[msg.sender] = 0;
            if (fixed_) held -= rest;
            return;
        }
        credit[msg.sender] += rest;
        order[msg.sender] = filled[msg.sender];
        held -= rest;
    }
}

// T05 (GOV-02): votes can still be changed after the voting deadline through changeVote().
contract BallotT05 {
    mapping(address => uint256) public weight;
    mapping(address => uint256) public choice; // 0 none, 1 for, 2 against
    uint256 public votesFor;
    uint256 public votesAgainst;
    uint256 public deadline;
    bool public immutable fixed_;
    constructor(bool f, address a, address b) {
        fixed_ = f; weight[a] = 3; weight[b] = 2; deadline = block.timestamp + 30;
    }
    function vote(uint256 c) external {
        require(block.timestamp < deadline, "CLOSED");
        require(choice[msg.sender] == 0 && (c == 1 || c == 2), "BAD");
        choice[msg.sender] = c;
        if (c == 1) votesFor += weight[msg.sender]; else votesAgainst += weight[msg.sender];
    }
    function changeVote() external {
        if (fixed_) require(block.timestamp < deadline, "CLOSED");
        uint256 c = choice[msg.sender];
        require(c != 0, "NO_VOTE");
        uint256 w = weight[msg.sender];
        if (c == 1) { votesFor -= w; votesAgainst += w; choice[msg.sender] = 2; }
        else { votesAgainst -= w; votesFor += w; choice[msg.sender] = 1; }
    }
}

// T06 (EMG-01, REN-04): a transient-storage (EIP-1153) lock that only one entry point takes.
contract BankT06 {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public deposited;
    mapping(address => uint256) public paidOut;
    bool public immutable fixed_;
    constructor(bool f) { fixed_ = f; }

    modifier lock() {
        assembly { if tload(0) { revert(0, 0) } tstore(0, 1) }
        _;
        assembly { tstore(0, 0) }
    }
    function deposit(uint256 a) external lock {
        balanceOf[msg.sender] += a;
        deposited[msg.sender] += a;
    }
    function withdraw() external {
        if (fixed_) { assembly { if tload(0) { revert(0, 0) } tstore(0, 1) } }
        uint256 a = balanceOf[msg.sender];
        require(a > 0, "NOTHING");
        paidOut[msg.sender] += a;
        if (msg.sender.code.length > 0) IHookT06(msg.sender).onWithdraw(a);
        balanceOf[msg.sender] = 0;
        if (fixed_) { assembly { tstore(0, 0) } }
    }
}

// T07 (REN-01 with ETH): an ETH bank that pays out before it zeroes the balance.
contract EtherBankT07 {
    mapping(address => uint256) public balances;
    bool public immutable fixed_;
    constructor(bool f) { fixed_ = f; }

    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 a = balances[msg.sender];
        require(a > 0, "NOTHING");
        if (fixed_) balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "SEND");
        if (!fixed_) balances[msg.sender] = 0;
    }
}
