// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// Survey corpus: OpenZeppelin 5.x building blocks as real projects use them. Each contract takes no
// constructor arguments, so the survey can deploy it alone. Not a benchmark: there are no planted bugs.
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Votes} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";
import {ERC20FlashMint} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20FlashMint.sol";
import {ERC1363} from "@openzeppelin/contracts/token/ERC20/extensions/ERC1363.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";

// plain token: mint by owner, burn, transfer, approve
contract SurveyToken is ERC20, ERC20Burnable, Ownable {
    constructor() ERC20("Survey", "SV") Ownable(msg.sender) {}
    function mint(address to, uint256 amount) external onlyOwner { _mint(to, amount); }
}

// EIP-2612 permit: EIP-712 domain, nonces, ecrecover
contract SurveyPermitToken is ERC20Permit {
    constructor() ERC20("Survey Permit", "SVP") ERC20Permit("Survey Permit") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

// governance votes: checkpoints (storage arrays), delegation, delegateBySig
contract SurveyVotesToken is ERC20, ERC20Permit, ERC20Votes {
    constructor() ERC20("Survey Votes", "SVV") ERC20Permit("Survey Votes") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
    function _update(address from, address to, uint256 v) internal override(ERC20, ERC20Votes) { super._update(from, to, v); }
    function nonces(address o) public view override(ERC20Permit, Nonces) returns (uint256) { return super.nonces(o); }
}

// flash loans: callback to the borrower with bytes data
contract SurveyFlashToken is ERC20FlashMint {
    constructor() ERC20("Survey Flash", "SVF") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

// ERC-1363: transferAndCall / approveAndCall with bytes data and receiver callbacks
contract SurveyCallToken is ERC1363 {
    constructor() ERC20("Survey 1363", "SV3") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

// multicall: bytes[] of calls run by delegatecall, results returned
contract SurveyMulticallToken is ERC20, Multicall {
    constructor() ERC20("Survey Multi", "SVM") {}
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

// two-step ownership
contract SurveyOwnable2Step is Ownable2Step {
    uint256 public value;
    constructor() Ownable(msg.sender) {}
    function set(uint256 v) external onlyOwner { value = v; }
}
