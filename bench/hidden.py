"""Hidden-ladder batch (supplied separately): one XRPL-style "credited more than paid"
overflow, hidden behind a different model limit in each case. Rule unchanged from the
supplied cases_hidden.py; {U0} is user 0 (the supplied cases used 0x11)."""

NO_MINT = lambda tx: tx.ok & (tx.post_sum("credit") > tx.post("totalPaid"))

CASES = [dict(id=f"H0{i}", title=t, flag="fixed_",
              contracts=[dict(name=f"XrpLikeH0{i}", file=f"src/hidden/{f}", args="abi.encode({fixed}, {U0})")],
              rules={"no_mint": NO_MINT})
         for i, (f, t) in enumerate([
             ("H00_Baseline.sol", "baseline: 2 makers, 3 tx"),
             ("H01_ThreeMakers.sol", "needs 3 distinct makers and 4 tx"),
             ("H02_DeepSequence.sol", "needs an 8-transaction setup"),
             ("H03_RealWidth.sol", "real unchecked uint64, lots >= 2^62"),
             ("H04_ManyOffers.sol", "one fill consumes 16 lots"),
         ])]
