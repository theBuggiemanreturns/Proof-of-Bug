"""Level 1 benchmark: small single contracts. Each case has a buggy and a fixed variant.

Rules describe what a bug looks like. They were written per contract type, not tuned to
the exact buggy line (e.g. B08 checks the escrow's books balance, not "deposit was cleared").
{U0} is the first user's address, {fixed} the variant switch.
"""

L1 = "src/bench/Level1.sol"

CASES = [
    dict(id="B01", title="Vault: donation makes a deposit mint 0 shares", flag="patched",
         contracts=[dict(name="Vault", file="src/Vault.sol", args="abi.encode({fixed})")],
         rules={"deposit_mints_zero": lambda tx: tx.called("deposit") & tx.ok & (tx.arg(0) > 0) & (tx.ret == 0)}),

    dict(id="B02", title="Vault: withdraw rounds in the user's favour", flag="fixed_",
         contracts=[dict(name="VaultB02", file=L1, args="abi.encode({fixed})")],
         rules={"withdraw_overpays": lambda tx: tx.called("withdraw") & tx.ok
                & (tx.ret.wide() * tx.pre("totalSupply") > tx.arg(0).wide() * tx.pre("totalAssets"))}),

    dict(id="B03", title="Token: unchecked underflow in transfer", flag="fixed_",
         contracts=[dict(name="TokenB03", file=L1, args="abi.encode({fixed}, {U0})")],
         rules={"balance_above_supply": lambda tx: tx.ok & (
             (tx.post("balanceOf", tx.sender) > tx.post("totalSupply"))
             | (tx.post("balanceOf", tx.arg(0)) > tx.post("totalSupply")))},
         # hint for the unbounded proof: the balances add up to the supply
         invariants={"supply_is_sum": lambda tx: tx.post_sum("balanceOf") != tx.post("totalSupply")}),

    dict(id="B04", title="Token: anyone can mint", flag="fixed_",
         contracts=[dict(name="TokenB04", file=L1, args="abi.encode({fixed}, {U0})")],
         rules={"mint_by_non_owner": lambda tx: tx.ok & (tx.sender != tx.pre("owner"))
                & (tx.post("totalSupply") > tx.pre("totalSupply"))}),

    dict(id="B05", title="Token: transferFrom never spends the allowance", flag="fixed_",
         contracts=[dict(name="TokenB05", file=L1, args="abi.encode({fixed}, {U0})")],
         rules={"allowance_not_spent": lambda tx: tx.called("transferFrom") & tx.ok
                & (tx.post("allowance", tx.arg(0), tx.sender) + tx.arg(2) != tx.pre("allowance", tx.arg(0), tx.sender))}),

    dict(id="B06", title="Pool: unpause while still drained", flag="fixed_",
         contracts=[dict(name="PoolB06", file=L1, args="abi.encode({fixed}, {U0})")],
         rules={"unpaused_while_drained": lambda tx: tx.ok & (tx.pre("paused") != 0) & (tx.post("paused") == 0)
                & (tx.post("reserves") < 10)}),

    dict(id="B07", title="AMM: rounding lets x*y shrink", flag="fixed_",
         contracts=[dict(name="AmmB07", file=L1, args="abi.encode({fixed})")],
         rules={"k_decreased": lambda tx: tx.ok
                & (tx.post("x").wide() * tx.post("y") < tx.pre("x").wide() * tx.pre("y"))}),

    dict(id="B08", title="Escrow: withdraw twice", flag="fixed_",
         contracts=[dict(name="EscrowB08", file=L1, args="abi.encode({fixed})")],
         rules={"books_unbalanced": lambda tx: tx.ok & (tx.post_sum("deposits") != tx.post("held"))}),

    dict(id="B09", title="Packed storage: guardian and paused flag share a slot", flag="fixed_",
         contracts=[dict(name="PoolB09", file=L1, args="abi.encode({fixed}, {U0})")],
         rules={"unpaused_while_drained": lambda tx: tx.ok & (tx.pre("paused") != 0) & (tx.post("paused") == 0)
                & (tx.post("reserves") < 10),
                "guardian_changed": lambda tx: tx.ok & (tx.post("guardian") != tx.pre("guardian"))}),
]
