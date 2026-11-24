// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {ERC20Wrapper} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Wrapper.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

contract SurveyAsset is ERC20 {
    constructor() ERC20("Survey Asset", "SA") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

// tokenized vault (SafeERC20, mulDiv rounding)
contract SurveyVault is ERC4626 {
    constructor(IERC20 asset_) ERC20("Survey Vault", "SVLT") ERC4626(asset_) {}
}

// wrapper token: depositFor / withdrawTo
contract SurveyWrapper is ERC20Wrapper {
    constructor(IERC20 u) ERC20("Survey Wrapped", "wSA") ERC20Wrapper(u) {}
}

// staking with SafeERC20 (low-level call, return data of any length), roles, pause, reentrancy guard
contract SurveyStaking is AccessControl, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    bytes32 public constant PAUSER = keccak256("PAUSER");
    IERC20 public immutable token;
    mapping(address => uint256) public staked;
    uint256 public totalStaked;
    constructor(IERC20 t) {
        token = t;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER, msg.sender);
    }
    function stake(uint256 a) external nonReentrant whenNotPaused {
        token.safeTransferFrom(msg.sender, address(this), a);
        staked[msg.sender] += a; totalStaked += a;
    }
    function unstake(uint256 a) external nonReentrant {
        staked[msg.sender] -= a; totalStaked -= a;
        token.safeTransfer(msg.sender, a);
    }
    function pause() external onlyRole(PAUSER) { _pause(); }
    function unpause() external onlyRole(PAUSER) { _unpause(); }
}

// NFTs: safeTransferFrom with bytes data, onERC721Received callbacks, approvals
contract SurveyNFT is ERC721 {
    uint256 public next;
    constructor() ERC721("Survey NFT", "SNFT") {}
    function mint(address to) external returns (uint256 id) { id = ++next; _safeMint(to, id); }
}

// multi-token: id/amount arrays, batch transfers, bytes data, receiver callbacks
contract SurveyMulti is ERC1155 {
    constructor() ERC1155("https://example.invalid/{id}.json") {}
    function mint(address to, uint256 id, uint256 amount) external { _mint(to, id, amount, ""); }
}

// minimal-proxy factory (CREATE / CREATE2 of clones)
contract SurveyCloneFactory {
    address public immutable implementation;
    address[] public clones;
    constructor(address impl) { implementation = impl; }
    function clone() external returns (address c) { c = Clones.clone(implementation); clones.push(c); }
    function cloneAt(bytes32 salt) external returns (address c) { c = Clones.cloneDeterministic(implementation, salt); clones.push(c); }
}

// a pool with a swap callback carrying bytes data (Uniswap-V2/V3 style), its own minimal pricing
interface ISwapCallee { function swapCallback(uint256 amountOut, bytes calldata data) external; }
contract SurveyCallbackPool {
    using SafeERC20 for IERC20;
    IERC20 public immutable token0;
    IERC20 public immutable token1;
    uint256 public reserve0;
    uint256 public reserve1;
    constructor(IERC20 t0, IERC20 t1) { token0 = t0; token1 = t1; }
    function sync() external { reserve0 = token0.balanceOf(address(this)); reserve1 = token1.balanceOf(address(this)); }
    // pays token1 first, calls back, then checks it received enough token0 (constant product)
    function swap(uint256 amount1Out, address to, bytes calldata data) external {
        require(amount1Out < reserve1, "liquidity");
        token1.safeTransfer(to, amount1Out);
        if (data.length > 0) ISwapCallee(to).swapCallback(amount1Out, data);
        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));
        require(b0 * b1 >= reserve0 * reserve1, "K");
        reserve0 = b0; reserve1 = b1;
    }
}
