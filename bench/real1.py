"""Real-bug batch 1 (supplied separately): recreations of five historical bugs.

Converted from the supplied cases_real.py. The rules are unchanged; only the deployment
format differs ({U0} is user 0, the address the supplied cases called 0x11).
"""

CASES = [
    dict(id="R01", title="Perennial: donation inflates share price so a deposit mints 0 shares", flag="fixed_",
         contracts=[dict(name="PerennialInflationVault", file="src/real/R01_PerennialInflation.sol",
                         args="abi.encode({fixed}, {U0})")],
         rules={"deposit_mints_nonzero_shares": lambda tx: tx.called("deposit") & tx.ok & (tx.arg(0) > 0) & (tx.ret == 0)},
         # hint for the unbounded proof: with donations not counted, shares and assets stay 1:1
         invariants={"one_to_one": lambda tx: tx.post("totalSupply") != tx.post("totalAssets")}),

    dict(id="R02", title="Parity multisig: initWallet re-callable, anyone becomes owner", flag="fixed_",
         contracts=[dict(name="ParityWallet", file="src/real/R02_ParityInitWallet.sol",
                         args="abi.encode({fixed}, {U0})")],
         rules={"only_owner_changes_owner": lambda tx: tx.ok & (tx.sender != tx.pre("owner"))
                & (tx.post("owner") != tx.pre("owner"))}),

    dict(id="R03", title="Hundred Finance: redeemUnderlying rounds shares-to-burn down", flag="fixed_",
         contracts=[dict(name="HundredRoundingMarket", file="src/real/R03_HundredRounding.sol",
                         args="abi.encode({fixed}, {U0})")],
         rules={"share_price_never_drops": lambda tx: tx.ok & (tx.post("totalShares") > 0)
                & (tx.post("totalAssets").wide() * tx.pre("totalShares")
                   < tx.pre("totalAssets").wide() * tx.post("totalShares"))}),

    dict(id="R04", title="Cover Protocol Blacksmith: write-off computed from stale cached pool", flag="fixed_",
         contracts=[dict(name="CoverStaleCacheFarm", file="src/real/R04_CoverStaleCache.sol",
                         args="abi.encode({fixed}, {U0})")],
         rules={"rewards_paid_le_funded": lambda tx: tx.ok & (tx.post("rewardsPaid") > tx.post("rewardsFunded"))}),

    dict(id="R05", title="Compound Prop 62: `>` instead of `>=` pays legacy suppliers unearned COMP", flag="fixed_",
         contracts=[dict(name="CompoundProp62Distributor", file="src/real/R05_CompoundProp62.sol",
                         args="abi.encode({fixed}, {U0})")],
         rules={"accrued_le_issued": lambda tx: tx.ok & (tx.post_sum("compAccrued") > tx.post("compIssued"))}),
]
