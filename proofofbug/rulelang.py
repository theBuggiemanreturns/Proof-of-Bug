"""A small, safe language for rules.

Rules (and invariant hints) are written as expressions, e.g.

    ok and post_sum("credit") > post("totalPaid")
    called("deposit") and ok and arg(0) > 0 and ret == 0
    ok and wide(post("x")) * post("y") < wide(pre("x")) * pre("y")
    post("debt", u) * 2 > post("collateral", u) * post("OracleM03.fairPrice")      # per account u

An expression is TRUE when the transaction BREAKS the rule. Text is parsed with Python's
`ast` and only a whitelist of node types and names is accepted, so rule text from an AI
agent or a stranger can never run code. The same compiled rule works on all three engines
(bit-level circuit, real EVM traces, integer prover) because it only calls the shared
Tx interface: called, arg, pre, post, pre_sum, post_sum, sender, ret, ok, reverted, to, now.

`now` is the time of the call (block.timestamp). "ETH" is a pseudo mapping of ETH balances:
post("ETH", A0) is the contract's ETH after the call. In a transaction rule, `u` means "some
user account": the rule breaks if it breaks for any user (e.g. "nobody but the sender loses
balance"). In an invariant, `u` ranges over every account the model knows.
"""
from __future__ import annotations
import ast

ALLOWED_FUNCS = {"pre", "post", "pre_sum", "post_sum", "arg", "called", "wide", "implies"}
ALLOWED_NAMES = {"ok", "reverted", "sender", "ret", "to", "now", "u", "True", "False"}
CONST_NAMES = {**{f"U{i}": 0x31 + i for i in range(8)}, **{f"A{i}": 0x99 - i for i in range(16)}}
MAX_LEN = 1200  # a whole-system value (11 contracts) needs more than 600; still a whitelisted AST


class RuleError(ValueError):
    pass


def _check(node):
    ok_nodes = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.BinOp, ast.Add,
                ast.Sub, ast.Mult, ast.FloorDiv, ast.Compare, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq,
                ast.Call, ast.Name, ast.Load, ast.Constant)
    for n in ast.walk(node):
        if not isinstance(n, ok_nodes):
            raise RuleError(f"not allowed in a rule: {type(n).__name__}")
        if isinstance(n, ast.Call):
            if not isinstance(n.func, ast.Name) or n.func.id not in ALLOWED_FUNCS or n.keywords:
                raise RuleError(f"unknown function in a rule: {ast.unparse(n.func)}")
        if isinstance(n, ast.Name) and n.id not in ALLOWED_NAMES | ALLOWED_FUNCS | set(CONST_NAMES):
            raise RuleError(f"unknown name in a rule: {n.id}")
        if isinstance(n, ast.Constant) and not isinstance(n.value, (int, str)):
            raise RuleError("only integers and variable names are allowed as constants")
        if isinstance(n, ast.Compare) and len(n.ops) != 1:
            raise RuleError("chained comparisons are not allowed; use 'and'")


def compile_rule(text: str):
    """Returns (fn, per_user): fn(tx) or fn(tx, u) giving a Bit that is 1 when the rule breaks."""
    if len(text) > MAX_LEN:
        raise RuleError("rule too long")
    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError as e:
        raise RuleError(f"syntax error: {e.msg}") from None
    _check(tree)
    per_user = any(isinstance(n, ast.Name) and n.id == "u" for n in ast.walk(tree))

    def ev(n, tx, u):
        if isinstance(n, ast.Expression):
            return ev(n.body, tx, u)
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Name):
            if n.id in CONST_NAMES:
                return CONST_NAMES[n.id]
            if n.id == "u":
                return u
            if n.id in ("True", "False"):
                return n.id == "True"
            return getattr(tx, n.id)
        if isinstance(n, ast.BoolOp):
            vals = [ev(v, tx, u) for v in n.values]
            acc = vals[0]
            for v in vals[1:]:
                acc = (acc & v) if isinstance(n.op, ast.And) else (acc | v)
            return acc
        if isinstance(n, ast.UnaryOp):
            return ~ev(n.operand, tx, u)
        if isinstance(n, ast.BinOp):
            a, b = ev(n.left, tx, u), ev(n.right, tx, u)
            if isinstance(a, int) and not isinstance(b, int):
                if isinstance(n.op, ast.Add): return b + a
                if isinstance(n.op, ast.Mult): return b * a
                if isinstance(n.op, ast.Sub): return b.rsub(a)        # constant - value
                return b.rfloordiv(a)                                 # constant // value
            return {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
                    ast.FloorDiv: lambda: a // b}[type(n.op)]()
        if isinstance(n, ast.Compare):
            a, b, op = ev(n.left, tx, u), ev(n.comparators[0], tx, u), type(n.ops[0])
            if isinstance(a, int) and not isinstance(b, int):  # mirror so the rule value is on the left
                a, b = b, a
                op = {ast.Lt: ast.Gt, ast.Gt: ast.Lt, ast.LtE: ast.GtE, ast.GtE: ast.LtE}.get(op, op)
            return {ast.Lt: lambda: a < b, ast.LtE: lambda: a <= b, ast.Gt: lambda: a > b,
                    ast.GtE: lambda: a >= b, ast.Eq: lambda: a == b, ast.NotEq: lambda: a != b}[op]()
        if isinstance(n, ast.Call):
            f = n.func.id
            args = [ev(a, tx, u) for a in n.args]
            if f == "wide":
                return args[0].wide()
            if f == "implies":
                return args[0].implies(args[1])
            if f in ("pre", "post", "pre_sum", "post_sum", "called") and (not args or not isinstance(args[0], str)):
                raise RuleError(f"{f}() needs a variable or function name in quotes first")
            return getattr(tx, f)(*args)
        raise RuleError(f"unsupported: {type(n).__name__}")

    if per_user:
        return (lambda tx, u: ev(tree, tx, u)), True
    return (lambda tx: ev(tree, tx, None)), False


def _users(tx):
    m = getattr(tx, "m", None) or tx.p.m  # bit / concrete Tx carry the model; the prover's ZTx its Prover
    return m.user_addrs


def rule_fn(text: str):
    """A transaction rule fn(tx) -> 1 when broken. A rule that mentions u breaks when it breaks
    for at least one user account."""
    fn, per_user = compile_rule(text)
    if not per_user:
        return fn
    def any_user(tx):
        acc = None
        for u in _users(tx):
            b = fn(tx, u)
            acc = b if acc is None else (acc | b)
        return acc
    return any_user
