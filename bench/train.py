"""Training set for the families added from the 108-pattern cross-reference (src/train).

Written by the same author as the rules, so these cases only check that the new families and
the engine features (time, transient storage) work. They are NOT evidence of how well the
engine finds bugs it was not shown: the blind set (bench/blind.py) is.
"""
from proofofbug.families import fill
from proofofbug.rulelang import rule_fn

T = "src/train/Train.sol"


def fam(**fills):
    return {name: rule_fn(fill(f, **p)[0]) for name, (f, p) in fills.items()}


CASES = [
    dict(id="T01", title="Time lock: withdrawTo skips the lock its sibling checks", flag="fixed_",
         contracts=[dict(name="LockT01", file=T, args="abi.encode({fixed})")],
         rules=fam(never_when=("never_when", dict(fn="withdrawTo", forbidden='now < pre("unlockAt", sender)')))),
    dict(id="T02", title="Token: burnFrom ignores the allowance", flag="fixed_",
         contracts=[dict(name="TokenT02", file=T, args="abi.encode({fixed}, {U0}, {U1})")],
         rules=fam(no_loss_beyond_allowance=("no_loss_beyond_allowance", dict(balance="balanceOf", allowance="allowance")))),
    dict(id="T03", title="Vesting keeps paying after the vesting period", flag="fixed_",
         contracts=[dict(name="VestingT03", file=T, args="abi.encode({fixed}, {U0})")],
         rules=fam(bounded_by=("bounded_by", dict(amount='post("claimed")', backing='post("total")')))),
    dict(id="T04", title="Escrow: fast-path cancel skips the held update", flag="fixed_",
         contracts=[dict(name="EscrowT04", file=T, args="abi.encode({fixed})")],
         rules=fam(in_sync=("in_sync", dict(a='post("held")', b='post_sum("order")')))),
    dict(id="T05", title="Ballot: votes change after the deadline", flag="fixed_",
         contracts=[dict(name="BallotT05", file=T, args="abi.encode({fixed}, {U0}, {U1})")],
         rules=fam(frozen_when=("frozen_when", dict(value='post("votesFor")', condition='now >= pre("deadline")')))),
    dict(id="T06", title="Bank: transient-storage lock missing on withdraw (reentrancy)", flag="fixed_", attacker=1,
         contracts=[dict(name="BankT06", file=T, args="abi.encode({fixed})")],
         rules=fam(account_bounded_by=("account_bounded_by", dict(taken='post("paidOut", u)', limit='post("deposited", u)')))),
]

CASES.append(
    dict(id="T07", title="ETH bank: pays before zeroing the balance (reentrancy with ETH)", flag="fixed_", attacker=1,
         contracts=[dict(name="EtherBankT07", file=T, args="abi.encode({fixed})")],
         rules=fam(bounded_by=("bounded_by", dict(amount='post_sum("balances")', backing='post("ETH", A0)')))))
