"""Level 2 benchmark: several contracts calling each other.

{A0} is the primary contract's address (0x99), {A1} the second contract (0x98),
{U0}/{U1} the users. In M02 user 1 is a contract that can call back (an attacker).
"""

L2 = "src/bench/Level2.sol"

CASES = [
    dict(id="M01", title="Vault + fee-on-transfer token: vault books more than it holds", flag="fixed_",
         contracts=[dict(name="VaultM01", file=L2, args="abi.encode({fixed}, {A1})"),
                    dict(name="FeeToken", file=L2, args="abi.encode({U0}, {U1})")],
         rules={"vault_insolvent": lambda tx: tx.ok
                & (tx.post("totalDeposits") > tx.post("FeeToken.balanceOf", 0x99))}),

    dict(id="M02", title="Bank: reentrancy through the withdraw callback", flag="fixed_", attacker=1,
         contracts=[dict(name="BankM02", file=L2, args="abi.encode({fixed})")],
         rules={"paid_more_than_deposited": lambda tx: tx.ok
                & (tx.post("paidOut", tx.sender) > tx.post("deposited", tx.sender))}),

    dict(id="M03", title="Lending: borrows priced with a manipulable spot price", flag="fixed_",
         contracts=[dict(name="LendingM03", file=L2, args="abi.encode({fixed}, {A1})"),
                    dict(name="OracleM03", file=L2, args="''")],
         rules={"undercollateralised_at_fair_price": lambda tx: tx.ok
                & (tx.post("debt", tx.sender).wide() * 2
                   > tx.post("collateral", tx.sender).wide() * tx.post("OracleM03.fairPrice"))},
         # hint for the unbounded proof: every account is within its limit at the fair price
         invariants={"all_within_limit": lambda tx, u: tx.post("debt", u) * 2
                     > tx.post("collateral", u) * tx.post("OracleM03.fairPrice")}),
]
