// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
DEPLOY
  Contract under test: TimeLockedSavings
  Constructor: none
  Setup:
    - 0x1111111111111111111111111111111111111111 calls deposit{value: 5 ether}(7 days)    // deposit id 0
    - 0x2222222222222222222222222222222222222222 is funded with 5 ether and has no deposit
  Users: 0x1111..., 0x2222... (either may be a contract with a receive/fallback function)
  Time: block.timestamp advances between transactions.
*/

contract TimeLockedSavings {
    struct Deposit {
        address owner;
        uint256 amount;
        uint64 unlockAt;
    }

    uint64 public constant MIN_DELAY = 1 days;
    uint64 public constant MAX_DELAY = 365 days;

    uint256 public nextId;
    uint256 public totalLocked;
    mapping(uint256 => Deposit) public deposits;

    event Deposited(uint256 indexed id, address indexed owner, uint256 amount, uint64 unlockAt);
    event Extended(uint256 indexed id, uint64 unlockAt);
    event OwnershipMoved(uint256 indexed id, address indexed from, address indexed to);
    event Withdrawn(uint256 indexed id, address indexed to, uint256 amount);

    function deposit(uint64 delay) external payable returns (uint256 id) {
        require(msg.value > 0, "value");
        require(delay >= MIN_DELAY && delay <= MAX_DELAY, "delay");
        id = nextId++;
        uint64 unlockAt = uint64(block.timestamp) + delay;
        deposits[id] = Deposit({owner: msg.sender, amount: msg.value, unlockAt: unlockAt});
        totalLocked += msg.value;
        emit Deposited(id, msg.sender, msg.value, unlockAt);
    }

    function topUp(uint256 id) external payable {
        Deposit storage d = deposits[id];
        require(d.owner == msg.sender, "owner");
        require(d.amount > 0, "closed");
        require(msg.value > 0, "value");
        d.amount += msg.value;
        totalLocked += msg.value;
    }

    function extend(uint256 id, uint64 newUnlockAt) external {
        Deposit storage d = deposits[id];
        require(d.owner == msg.sender, "owner");
        require(newUnlockAt > d.unlockAt, "earlier");
        require(newUnlockAt <= uint64(block.timestamp) + MAX_DELAY, "too far");
        d.unlockAt = newUnlockAt;
        emit Extended(id, newUnlockAt);
    }

    function moveOwnership(uint256 id, address to) external {
        Deposit storage d = deposits[id];
        require(d.owner == msg.sender, "owner");
        require(to != address(0), "zero");
        d.owner = to;
        emit OwnershipMoved(id, msg.sender, to);
    }

    function withdraw(uint256 id) external {
        Deposit storage d = deposits[id];
        require(d.owner == msg.sender, "owner");
        require(block.timestamp >= d.unlockAt, "locked");
        uint256 amount = d.amount;
        require(amount > 0, "empty");
        d.amount = 0;
        totalLocked -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send");
        emit Withdrawn(id, msg.sender, amount);
    }
}
