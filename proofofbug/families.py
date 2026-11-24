"""Rule families: general laws written once, filled in per contract.

A family is a template with named blanks. Filling the blanks (by a person or the AI agent)
produces rule text in the safe rule language (rulelang). Every rule broken by a known bug
should belong to a family; specific past bugs are kept as examples under their family.

Blank values are rule-language fragments: a variable reference such as
'post("totalAssets")', a function name such as 'deposit', or an argument index.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from .rulelang import compile_rule, RuleError


@dataclass
class Family:
    name: str
    law: str  # the general law in plain words
    blanks: dict  # blank -> what to put there
    template: str  # rule text with {blank} placeholders; TRUE when broken
    invariant: str = ""  # optional state invariant (hint for the prover), same placeholders
    examples: list = field(default_factory=list)  # known bugs that broke this law

    def fill(self, **params):
        missing = set(self.blanks) - set(params)
        if missing:
            raise RuleError(f"family {self.name} needs: {', '.join(sorted(missing))}")
        text = _subst(self.template, params)
        compile_rule(text)  # reject anything that is not a valid, safe rule
        inv = _subst(self.invariant, params) if self.invariant else ""
        if inv:
            compile_rule(inv)
        return text, inv


def _subst(template, params):
    """Fill blanks. A blank inside quotes is a name ("{accounts}") and is pasted as is; anywhere
    else it is an expression and is bracketed, so `now - {start}` with start = `a - b` means
    `now - (a - b)` (raw pasting gave `now - a - b`: found when a prover counterexample on the
    blind C02 broke an accrual rule on a correct contract)."""
    import re
    out = template
    for k, v in params.items():
        out = out.replace('"{' + k + '}"', '"\x00' + k + '\x00"')
        out = re.sub(r"\{" + re.escape(k) + r"\}", lambda _: f"({v})", out)
        out = out.replace('"\x00' + k + '\x00"', '"' + str(v) + '"')
    return out


FAMILIES = {f.name: f for f in [
    Family("ledger",
           "The per-account records add up to the recorded total.",
           {"accounts": "mapping of per-account amounts, e.g. balanceOf",
            "total": "the recorded total, e.g. totalSupply"},
           'ok and post_sum("{accounts}") != post("{total}")',
           invariant='post_sum("{accounts}") != post("{total}")'),
    Family("bounded_by",
           "Something owed or paid out never exceeds what backs it (no value from nothing).",
           {"amount": "rule expression for what is owed / paid out / credited",
            "backing": "rule expression for what backs it"},
           "ok and {amount} > {backing}",
           invariant="{amount} > {backing}"),
    Family("account_bounded_by",
           "For every account: what it took out never exceeds what it put in (or its limit).",
           {"taken": 'per-account amount out, using u, e.g. post("paidOut", u)',
            "limit": 'per-account limit, using u, e.g. post("deposited", u)'},
           "ok and {taken_sender} > {limit_sender}",
           invariant="{taken} > {limit}"),
    Family("nonzero_mint",
           "Paying something in always gets something back.",
           {"fn": "the deposit/mint function", "amount_arg": "index of the amount argument"},
           'called("{fn}") and ok and arg({amount_arg}) > 0 and ret == 0'),
    Family("fair_redemption",
           "Redeeming never pays more than the redeemed fraction of the pool.",
           {"fn": "the withdraw/redeem function", "shares_arg": "index of the shares argument",
            "assets": "pool assets variable", "shares": "total shares variable"},
           'called("{fn}") and ok and wide(ret) * pre("{shares}") > wide(arg({shares_arg})) * pre("{assets}")'),
    Family("share_price_monotone",
           "Assets per share never drop for the holders who remain.",
           {"assets": "pool assets variable", "shares": "total shares variable"},
           'ok and post("{shares}") > 0 and wide(post("{assets}")) * pre("{shares}") '
           '< wide(pre("{assets}")) * post("{shares}")'),
    Family("product_monotone",
           "A constant-product pool's x*y never shrinks.",
           {"x": "reserve x variable", "y": "reserve y variable"},
           'ok and wide(post("{x}")) * post("{y}") < wide(pre("{x}")) * pre("{y}")'),
    Family("authorized_change",
           "Only the admin can change a protected value.",
           {"value": "protected rule expression, e.g. post(\"owner\")",
            "before": "the same value before the call, e.g. pre(\"owner\")",
            "admin": 'who is allowed, e.g. pre("owner")'},
           "ok and sender != {admin} and {value} != {before}"),
    Family("authorized_increase",
           "Only the admin can increase a protected amount (e.g. supply).",
           {"amount": "variable", "admin": 'who is allowed, e.g. pre("owner")'},
           'ok and sender != {admin} and post("{amount}") > pre("{amount}")'),
    Family("allowance_spent",
           "Spending on someone's behalf uses up exactly that much allowance.",
           {"fn": "transferFrom-like function", "allowance": "allowance mapping (owner => spender => amount)",
            "owner_arg": "index of the owner argument", "amount_arg": "index of the amount argument"},
           'called("{fn}") and ok and post("{allowance}", arg({owner_arg}), sender) + arg({amount_arg}) '
           '!= pre("{allowance}", arg({owner_arg}), sender)'),
    Family("breaker_hold",
           "A tripped circuit breaker can't be reset while the danger remains.",
           {"flag": "paused flag variable", "danger": 'rule expression for the danger, e.g. post("reserves") < 10'},
           'ok and pre("{flag}") != 0 and post("{flag}") == 0 and {danger}'),
    Family("exact_effect",
           "A successful call changes a variable by exactly the amount it stands for.",
           {"fn": "the function", "value": 'variable reference after the call, e.g. post("totalAssets")',
            "before": 'the same before the call, e.g. pre("totalAssets")', "delta": "the expected increase, e.g. arg(0)"},
           'called("{fn}") and ok and {value} != {before} + {delta}'),
    Family("exact_decrease",
           "A successful call lowers a variable by exactly the amount it stands for.",
           {"fn": "the function", "value": 'variable after, e.g. post("held")', "before": 'variable before',
            "delta": "the expected decrease"},
           'called("{fn}") and ok and {value} + {delta} != {before}'),
    Family("no_side_effect",
           "A function leaves a variable it has no business changing untouched.",
           {"fn": "the function", "value": 'variable after, e.g. post("totalSupply")', "before": "variable before"},
           'called("{fn}") and ok and {value} != {before}'),
    Family("must_succeed",
           "A call that meets its stated conditions must not fail (nothing gets stuck or blocked).",
           {"fn": "the function", "condition": "rule expression saying when the call should work"},
           'called("{fn}") and reverted and ({condition})'),
    Family("exit_all",
           "Someone with funds in the system can always take them out (nothing gets stuck).",
           {"fn": "the withdraw-everything function (no amount argument)",
            "balance": "per-account balance mapping"},
           'called("{fn}") and reverted and pre("{balance}", sender) > 0'),
    Family("exit_amount",
           "Withdrawing part of your own balance always works (nothing gets stuck).",
           {"fn": "the withdraw(amount) function", "amount_arg": "index of the amount argument",
            "balance": "per-account balance mapping"},
           'called("{fn}") and reverted and arg({amount_arg}) > 0 and arg({amount_arg}) <= pre("{balance}", sender)'),
    Family("collateralized",
           "Every borrower stays within their limit at the fair price.",
           {"debt": "debt mapping", "collateral": "collateral mapping", "price": "fair price expression",
            "ratio": "debt multiplier in the limit (e.g. 2 for 50% LTV)"},
           'ok and wide(post("{debt}", sender)) * {ratio} > wide(post("{collateral}", sender)) * {price}',
           invariant='post("{debt}", u) * {ratio} > post("{collateral}", u) * {price}'),
    # ---- added from the 108-pattern cross-reference (see cross-reference.md) ----
    Family("no_third_party_loss",
           "Nobody loses what they hold in a call they did not make. "
           "(ACC-03, ACC-06, REN-02, EMG-03: missing or wrong authorization, unchecked callbacks)",
           {"balance": "per-account holdings mapping, e.g. balanceOf or deposits"},
           'ok and u != sender and post("{balance}", u) < pre("{balance}", u)'),
    Family("no_loss_beyond_allowance",
           "Someone else's call can take from you at most what you approved them for. "
           "(ACC-03, TOK-04, approval-drain incidents)",
           {"balance": "per-account holdings mapping", "allowance": "approval mapping (owner => spender => amount)"},
           'ok and u != sender and post("{balance}", u) + pre("{allowance}", u, sender) < pre("{balance}", u)'),
    Family("in_sync",
           "Two records that stand for the same value always change by the same amount. "
           "(ACD-01, ACD-02, ACD-03, INC-02, XCH-03, VLT-04: one path updates one record and not the other)",
           {"a": 'first record after the call, e.g. post("totalDeposits")',
            "b": 'second record after the call, e.g. post_sum("deposits") or post("Token.balanceOf", A0)'},
           'ok and {a} + {b_pre} != {a_pre} + {b}'),
    Family("frozen_when",
           "While a condition holds, a value cannot change (paused, finalized, closed, after a snapshot). "
           "(GOV-02, ACC-05, RUG-05, BND-02)",
           {"value": 'the value after the call, e.g. post("votes", sender)',
            "condition": 'when it is frozen, from the state before the call, e.g. pre("finalized") != 0 or now >= pre("deadline")'},
           'ok and ({condition}) and {value} != {value_pre}'),
    Family("never_when",
           "A function never succeeds when a condition says it must not "
           "(too early, too late, wrong caller, wrong state). Apply it to EVERY sibling entry point. "
           "(ACC-03, INC-03, BND-01, BND-02, LIQ-04)",
           {"fn": "the function", "forbidden": 'when it must fail, e.g. now < pre("unlockTime", sender)'},
           'called("{fn}") and ok and ({forbidden})'),
    Family("bounded_step",
           "A value moves by at most a limit in one call (fees, prices, rates, parameters). "
           "(ACC-05, RUG-03, ORC-01, ORC-06)",
           {"value": 'the value after the call, e.g. post("fee")', "limit": "largest allowed change in one call"},
           'ok and ({value} > {value_pre} + {limit} or {value_pre} > {value} + {limit})'),
    Family("monotone",
           "A counter, nonce or accumulated index only goes up. "
           "(SIG-02 nonces, GOV-01/VLT-06 reward and interest indices, cumulative totals)",
           {"value": 'the value after the call, e.g. post("rewardPerTokenStored")'},
           'ok and {value} < {value_pre}'),
    Family("rate_limited",
           "A protected value changes at most once per interval. (ACC-05 timelock bypass, LIQ-04)",
           {"value": 'the value after the call, e.g. post("multiplier")',
            "last": 'when it last changed, before the call, e.g. pre("lastUpdate")', "interval": "minimum time between changes"},
           'ok and {value} != {value_pre} and now < {last} + {interval}'),
    Family("accrual_bounded",
           "What is paid out over time never exceeds the rate times the time elapsed. (GOV-01, VLT-06, RND-04)",
           {"paid": 'total paid or accrued after the call, e.g. post("totalClaimed")',
            "rate": 'rate per second, e.g. post("rewardRate")', "start": 'when accrual started, e.g. post("startTime")'},
           'ok and now >= {start} and {paid} > wide({rate}) * (now - {start})'),
]}


PRE_FORM = {"in_sync": ("a", "b"), "frozen_when": ("value",), "bounded_step": ("value",), "monotone": ("value",),
            "rate_limited": ("value",)}


def to_pre(expr):
    """The same expression evaluated before the call (post -> pre, post_sum -> pre_sum)."""
    return expr.replace("post_sum(", "pre_sum(").replace("post(", "pre(")


def fill(family, **params):
    """Fill a family. Some families derive the before-the-call form of a blank automatically
    (blank_pre); account_bounded_by also gets a per-sender version of its blanks."""
    f = FAMILIES[family]
    if family in PRE_FORM:
        extra = {f"{b}_pre": to_pre(str(params[b])) for b in PRE_FORM[family] if b in params}
        params = dict(params, **extra)
        f = Family(f.name, f.law, dict(f.blanks, **{k: "" for k in extra}), f.template, f.invariant)
    if family == "account_bounded_by":
        params = dict(params, taken_sender=params["taken"].replace(", u)", ", sender)"),
                      limit_sender=params["limit"].replace(", u)", ", sender)"))
        f = Family(f.name, f.law, dict(f.blanks, taken_sender="", limit_sender=""), f.template, f.invariant)
    return f.fill(**params)


def catalog():
    """Plain-text catalog of families, for people and for the AI agent's prompt."""
    lines = []
    for f in FAMILIES.values():
        lines.append(f"- {f.name}: {f.law}")
        for b, d in f.blanks.items():
            lines.append(f"    {b}: {d}")
    return "\n".join(lines)
