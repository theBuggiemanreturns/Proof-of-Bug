// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 * PROVENANCE
 *  protocol : Compound V2 Comptroller - distributeSupplierComp / distributeBorrowerComp
 *  source   : incident after Proposal 062 executed (29 Sept 2021), ~$80-90M COMP mis-accrued;
 *             patched by Proposal 064 "Fix COMP Accrual Bug" (passed 7 Oct 2021)
 *  finding  : n/a (incident). Root cause identified publicly by Mudit Gupta and Kurt Barry
 *             (">" used where ">=" was needed, in two places)
 *  severity : Critical (unbacked reward distribution)
 *  date     : 2021-09-29
 *  url      : https://www.theregister.com/2021/10/01/compound_crypto_bug/
 *             https://blocksec.com/blog/the-butterfly-effect-the-compound-security-incident-caused-by-a-bugfix
 *  pattern  : BND-01 strict vs inclusive comparison at an index boundary (CAT-16)
 *
 *  Root cause: Prop 62 set a market's supply index to compInitialIndex for markets that had
 *  never had COMP speed. A legacy supplier's index was 0, so the check
 *  `supplierIndex == 0 && supplyIndex > compInitialIndex` was false (the two were equal), the
 *  supplier index stayed 0, and the delta paid balance * compInitialIndex of COMP that was
 *  never emitted. Here, constructor state is that post-Prop-62 world: one legacy supplier,
 *  index == INITIAL_INDEX.
 *
 *  Fix: `>` -> `>=`, which the analyses above name as the fix. That Prop 064 shipped exactly
 *  this operator change (and not a different patch): UNVERIFIED. Cointelegraph quotes Prop 064
 *  as a patch that "pessimistically" allowed withdrawals until bad accruals were fixed, so it
 *  may have done more than flip the operator.
 *
 *  Simplified away: 1e36 Double math (INITIAL_INDEX = 10), block-based speeds (accrue() stands
 *  in), the borrow side (same bug, same fix), COMP transfers (compAccrued is the liability).
 */
contract CompoundProp62Distributor {
    bool public immutable fixed_;
    uint256 public constant INITIAL_INDEX = 10;
    uint256 public supplyIndex;
    uint256 public totalSupply;
    uint256 public compIssued;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public supplierIndex;
    mapping(address => uint256) public compAccrued;

    constructor(bool f, address legacySupplier) {
        fixed_ = f;
        balanceOf[legacySupplier] = 10; // supplied before rewards existed: supplierIndex == 0
        totalSupply = 10;
        supplyIndex = INITIAL_INDEX; // Prop 62 initialises the market index
    }

    // Stand-in for compSupplySpeed * elapsed blocks.
    function accrue(uint256 delta) external {
        supplyIndex += delta;
        compIssued += delta * totalSupply;
    }

    function distribute(address supplier) public {
        uint256 si = supplierIndex[supplier];
        supplierIndex[supplier] = supplyIndex;
        bool reset = fixed_
            ? (si == 0 && supplyIndex >= INITIAL_INDEX) // FIX (upstream): >=
            : (si == 0 && supplyIndex > INITIAL_INDEX); // BUG: strict > misses the equal case
        if (reset) si = INITIAL_INDEX;
        compAccrued[supplier] += balanceOf[supplier] * (supplyIndex - si);
    }

    function mint(uint256 amount) external {
        distribute(msg.sender);
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }
}
