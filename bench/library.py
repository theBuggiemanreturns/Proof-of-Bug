"""Every known bug in the benchmarks, re-expressed as a family rule.

Each entry: case id -> list of (family, blanks). The family rule must catch the buggy
version, stay clean on the fixed version, and is then scored on mutants. This replaces
the hand-written per-case rules with grouped, reusable laws.
"""

LIBRARY = {
    "B01": [("nonzero_mint", dict(fn="deposit", amount_arg=0))],
    "B02": [("fair_redemption", dict(fn="withdraw", shares_arg=0, assets="totalAssets", shares="totalSupply"))],
    "B03": [("ledger", dict(accounts="balanceOf", total="totalSupply"))],
    "B04": [("authorized_increase", dict(amount="totalSupply", admin='pre("owner")'))],
    "B05": [("allowance_spent", dict(fn="transferFrom", allowance="allowance", owner_arg=0, amount_arg=2))],
    "B06": [("breaker_hold", dict(flag="paused", danger='post("reserves") < 10'))],
    "B07": [("product_monotone", dict(x="x", y="y"))],
    "B08": [("ledger", dict(accounts="deposits", total="held")),
            ("exit_all", dict(fn="withdraw", balance="deposits"))],
    "B09": [("breaker_hold", dict(flag="paused", danger='post("reserves") < 10')),
            ("authorized_change", dict(value='post("guardian")', before='pre("guardian")', admin='pre("guardian")'))],
    "M01": [("bounded_by", dict(amount='post("totalDeposits")', backing='post("FeeToken.balanceOf", A0)')),
            ("exit_amount", dict(fn="withdraw", amount_arg=0, balance="deposited"))],
    "M02": [("account_bounded_by", dict(taken='post("paidOut", u)', limit='post("deposited", u)'))],
    "M03": [("collateralized", dict(debt="debt", collateral="collateral", price='post("OracleM03.fairPrice")', ratio=2))],
    "R01": [("nonzero_mint", dict(fn="deposit", amount_arg=0))],
    "R02": [("authorized_change", dict(value='post("owner")', before='pre("owner")', admin='pre("owner")'))],
    "R03": [("share_price_monotone", dict(assets="totalAssets", shares="totalShares"))],
    "R04": [("bounded_by", dict(amount='post("rewardsPaid")', backing='post("rewardsFunded")'))],
    "R05": [("bounded_by", dict(amount='post_sum("compAccrued")', backing='post("compIssued")'))],
    **{f"H0{i}": [("bounded_by", dict(amount='post_sum("credit")', backing='post("totalPaid")'))] for i in range(5)},
}
