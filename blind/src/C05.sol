// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Main contract under test: VoucherClaimC05
//
// DEPLOY:
// 1. TokenC05("Incentive Token", "INC") from the deployer.
// 2. VoucherClaimC05(INC, signer) from the deployer (deployer becomes owner; signer is an off-chain key).
// 3. Deployer mints 1,000,000e18 INC to VoucherClaimC05.
// 4. The signer issues EIP-712 vouchers (account, amount, nonce, deadline); accounts call claim().

contract VoucherClaimC05 {
    bytes32 public constant CLAIM_TYPEHASH =
        keccak256("Claim(address account,uint256 amount,uint256 nonce,uint256 deadline)");
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 private constant HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    TokenC05 public immutable token;
    address public owner;
    address public signer;
    bool public paused;

    uint256 private immutable cachedChainId;
    bytes32 private immutable cachedDomainSeparator;

    mapping(address => mapping(uint256 => bool)) public nonceUsed;
    mapping(address => uint256) public totalClaimed;

    event Claimed(address indexed account, uint256 amount, uint256 nonce);
    event SignerUpdated(address indexed signer);
    event Paused(bool paused);

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    constructor(TokenC05 _token, address _signer) {
        require(_signer != address(0), "signer");
        token = _token;
        signer = _signer;
        owner = msg.sender;
        cachedChainId = block.chainid;
        cachedDomainSeparator = _buildDomainSeparator();
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes("VoucherClaim")), keccak256(bytes("1")), block.chainid, address(this))
        );
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == cachedChainId ? cachedDomainSeparator : _buildDomainSeparator();
    }

    function hashClaim(address account, uint256 amount, uint256 nonce, uint256 deadline) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, account, amount, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function claim(uint256 amount, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(!paused, "paused");
        require(block.timestamp <= deadline, "expired");
        require(!nonceUsed[msg.sender][nonce], "nonce used");
        require(uint256(s) <= HALF_ORDER, "bad s");
        require(v == 27 || v == 28, "bad v");

        address recovered = ecrecover(hashClaim(msg.sender, amount, nonce, deadline), v, r, s);
        require(recovered != address(0) && recovered == signer, "bad signature");

        nonceUsed[msg.sender][nonce] = true;
        totalClaimed[msg.sender] += amount;
        require(token.transfer(msg.sender, amount), "transfer");
        emit Claimed(msg.sender, amount, nonce);
    }

    function setSigner(address _signer) external onlyOwner {
        require(_signer != address(0), "signer");
        signer = _signer;
        emit SignerUpdated(_signer);
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit Paused(_paused);
    }

    function sweep(address to, uint256 amount) external onlyOwner {
        require(paused, "not paused");
        require(token.transfer(to, amount), "transfer");
    }
}

contract TokenC05 {
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
