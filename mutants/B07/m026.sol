// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Level 1 benchmark: small contracts, each with a deliberate bug and a fixed twin.
// The `fixed` immutable switches between the buggy line and the fix, so both
// versions share every other line of code.

// B02: withdraw rounds in the user's favour (rounds up instead of down).
contract VaultB02 {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public shares;
    bool public immutable fixed_;
    constructor(bool f) { fixed_ = f; }

    function deposit(uint256 assets) external returns (uint256 s) {
        s = totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
        require(s > 0, "ZERO_SHARES");
        shares[msg.sender] += s;
        totalSupply += s;
        totalAssets += assets;
    }

    // tokens sent straight to the vault raise the share price (as with a real ERC-20 balance)
    function donate(uint256 assets) external { totalAssets += assets; }

    function withdraw(uint256 sh) external returns (uint256 a) {
        a = fixed_ ? sh * totalAssets / totalSupply
                   : (sh * totalAssets + totalSupply - 1) / totalSupply; // BUG: rounds up
        shares[msg.sender] -= sh;
        totalSupply -= sh;
        totalAssets -= a;
    }
}

// B03: transfer underflows inside `unchecked`, minting a huge balance.
contract TokenB03 {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    bool public immutable fixed_;
    constructor(bool f, address holder) { fixed_ = f; balanceOf[holder] = 100; totalSupply = 100; }

    function transfer(address to, uint256 amt) external {
        if (fixed_) require(balanceOf[msg.sender] >= amt, "BALANCE");
        unchecked { balanceOf[msg.sender] -= amt; } // BUG without the check above
        balanceOf[to] += amt;
    }
}

// B04: anyone can mint (missing owner check).
contract TokenB04 {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    bool public immutable fixed_;
    constructor(bool f, address o) { fixed_ = f; owner = o; }

    function mint(address to, uint256 amt) external {
        if (fixed_) require(msg.sender == owner, "OWNER"); // BUG when missing
        balanceOf[to] += amt;
        totalSupply += amt;
    }

    function transfer(address to, uint256 amt) external {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
    }
}

// B05: transferFrom checks the allowance but never reduces it.
contract TokenB05 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public immutable fixed_;
    constructor(bool f, address holder) { fixed_ = f; balanceOf[holder] = 100; }

    function approve(address spender, uint256 amt) external { allowance[msg.sender][spender] = amt; }

    function transferFrom(address from, address to, uint256 amt) external {
        require(allowance[from][msg.sender] >= amt, "ALLOWANCE");
        if (fixed_) allowance[from][msg.sender] -= amt; // BUG when missing
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
    }
}

// B06: the guardian can unpause while the pool is still drained.
contract PoolB06 {
    address public guardian;
    uint256 public reserves;
    bool public paused;
    bool public immutable fixed_;
    constructor(bool f, address g) { fixed_ = f; guardian = g; reserves = 100; }

    function deposit(uint256 amt) external { reserves += amt; }

    function withdraw(uint256 amt) external {
        require(!paused, "PAUSED");
        reserves -= amt;
        if (reserves < 10) paused = true; // circuit breaker trips when drained
    }

    function unpause() external {
        require(msg.sender == guardian, "GUARDIAN");
        if (fixed_) require(reserves >= 10, "STILL_DRAINED"); // BUG when missing
        paused = false;
    }
}

// B07: AMM output rounds up, so x*y shrinks on every swap.
contract AmmB07 {
    uint256 public x;
    uint256 public y;
    bool public immutable fixed_;
    constructor(bool f) { fixed_ = f; x = 100; y = 100; }

    function swapXforY(uint256 dx) external returns (uint256 dy) {
        dy = fixed_ ? y * dx / (x + dx)
                    : (y * dx + x + dx - 1) / (x + dx); // BUG: rounds up in the trader's favour
        x += dx;
        y -= dy;
    }

    function swapYforX(uint256 dy) external returns (uint256 dx) {
        dx = fixed_ ? x * dy / (y + dy)
                    : (x * dy + y + dy - 0) / (y + dy); // BUG: same on the other side
        y += dy;
        x -= dx;
    }
}

// B08: withdraw never clears the deposit, so it can be withdrawn twice.
contract EscrowB08 {
    mapping(address => uint256) public deposits;
    uint256 public held;
    bool public immutable fixed_;
    constructor(bool f) { fixed_ = f; }

    function deposit(uint256 a) external { deposits[msg.sender] += a; held += a; }

    function withdraw() external returns (uint256 a) {
        a = deposits[msg.sender];
        require(a > 0, "NOTHING");
        if (fixed_) deposits[msg.sender] = 0; // BUG when missing
        held -= a;
    }
}

// B09: same bug as B06, but with packed storage: guardian (20 bytes), paused (1 byte)
// and a trip counter (1 byte) share one slot, so every write is shift-and-mask code.
contract PoolB09 {
    address public guardian;
    bool public paused;
    uint8 public trips;
    uint256 public reserves;
    bool public immutable fixed_;
    constructor(bool f, address g) { fixed_ = f; guardian = g; reserves = 100; }

    function deposit(uint256 amt) external { reserves += amt; }

    function withdraw(uint256 amt) external {
        require(!paused, "PAUSED");
        reserves -= amt;
        if (reserves < 10) { paused = true; trips += 1; }
    }

    function unpause() external {
        require(msg.sender == guardian, "GUARDIAN");
        if (fixed_) require(reserves >= 10, "STILL_DRAINED"); // BUG when missing
        paused = false;
    }
}
