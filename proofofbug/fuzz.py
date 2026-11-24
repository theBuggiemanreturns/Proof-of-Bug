"""EVM fuzzing with magnitude-aware value dictionaries (any number size, no solver).

The third search method, next to the bit-level circuit (exhaustive up to a small width) and the
exact search (any width, but solvers choke on products of unknowns). It runs many random
transaction sequences directly on the real EVM and checks every rule on every trace, so every hit
is a real execution by construction. It cannot prove absence; it is good exactly where the other two
are weak: large numbers and non-linear arithmetic.

Values are drawn from a dictionary built from the contract itself, because bugs live at the
magnitudes the contract works with: every constant in the code, every value in the deployed state
(reserves, balances, rates, times), their neighbours, fractions and multiples, and powers of two
around every type boundary (2^k - 1, 2^k, 2^k + 1).
"""
from __future__ import annotations
import random


def _literals(node, out):
    if isinstance(node, dict):
        if node.get("nodeType") == "YulLiteral" and node.get("kind") == "number":
            try:
                out.add(int(node["value"], 0))
            except Exception:
                pass
        for v in node.values():
            _literals(v, out)
    elif isinstance(node, list):
        for v in node:
            _literals(v, out)


def dictionary(m):
    """Interesting values for this deployment."""
    base = set(range(0, 11)) | {100, 1000, 10_000}
    for con, _ in m.contracts:
        _literals(con.code, base)
    for (a, s), v in (m.init_trace or {}).items():
        if v and v < (1 << 200):
            base.add(v)
    out = set()
    for v in base:
        if v >= (1 << 256) or (v > (1 << 200) and v not in ((1 << 256) - 1,)):
            continue  # selectors, hashes and masks are not amounts
        out |= {v, v + 1, max(v - 1, 0), v // 2, v * 2, v // 10, v * 9 // 10, v // 100, v * 99 // 100, v * 3 // 2}
    for k in list(range(0, 257, 8)) + [63, 64, 95, 96, 111, 112, 127, 128, 159, 160, 255]:
        out |= {(1 << k) - 1, 1 << k, (1 << k) + 1}
    return sorted(x for x in out if 0 <= x < (1 << 256))


def sequences(m, n, k, seed=0):
    rnd = random.Random(seed)
    vals = dictionary(m)
    small = [v for v in vals if v < 1 << 16]
    times = sorted({v for v in vals if 0 < v < (1 << 40)} | {1, 2, 10, 60, 600, 3600, 86400, 604800})

    def value(t):
        if t.startswith("offset:"):  # an array's offset: mostly the standard encoding, sometimes not
            return int(t[7:]) if rnd.random() < 0.9 else rnd.choice([0, 32, 64, 96, 128, rnd.randrange(1 << 256)])
        if t.startswith("length:"):  # an array's length: within the words sent, sometimes past them
            n_ = int(t[7:])
            return rnd.randint(0, n_) if rnd.random() < 0.9 else rnd.choice([n_ + 1, rnd.randrange(1 << 256)])
        if t == "address":
            return rnd.choice(m.key_universe)
        if t == "bool":
            return rnd.randint(0, 1)
        if t.startswith("int") and rnd.random() < 0.4:  # a negative number: -v as the chain encodes it
            return (-rnd.choice([v for v in vals if 0 < v < (1 << 200)] or [1])) % (1 << 256)
        bits = int(t[4:]) if t.startswith("uint") and t != "uint" else 256
        pool = [v for v in vals if v < (1 << bits)]
        r = rnd.random()
        if r < 0.15:
            return rnd.choice(small)
        if r < 0.25:
            return rnd.randrange(1 << min(bits, 256))
        return rnd.choice(pool)

    seqs = []
    for _ in range(n):
        seq, now = [], 1
        for _ in range(k):
            a, name, sig, sel, types = rnd.choice(m.funcs)
            tx = {"to": a, "fn": name, "sig": sig, "selector": sel, "sender": rnd.choice(m.user_addrs),
                  "args": [value(t) for t in types], "hook": None,
                  "contract": None if a == m.contracts[0][1] else next(c.name for c, ad in m.contracts if ad == a)}
            if m.attacker is not None and rnd.random() < 0.4:
                ha, hn, hs, hsel, ht = rnd.choice([f for f in m.funcs if f[0] == m.contracts[0][1]])
                tx["hook"] = {"selector": hsel, "fn": hn, "args": [value(t) for t in ht]}
            if getattr(m, "uses_time", False):
                now += rnd.choice([0, 0, 1] + times)
                tx["time"] = min(now, (1 << 40) - 1)
            if sig in getattr(m, "payable", ()):
                tx["value"] = rnd.choice([0, 1] + [v for v in vals if v < (1 << 64)])
            seq.append(tx)
        seqs.append(seq)
    return seqs


def fuzz(m, cfg, rules, n=600, k=4, seed=0, log=print):
    """Run n random k-transaction sequences on the EVM; every rule is checked on every trace.
    Returns {rule: finding} (the shortest breaking prefix of the first sequence that breaks it)."""
    from . import evm
    from .check import rule_on_trace
    from .bench import fmt_tx
    seqs = sequences(m, n, k, seed)
    traces = evm.run(cfg, cfg["tag"] + "_fuzz", seqs, m.watch)
    found = {}
    for seq, tr in zip(seqs, traces):
        for name, fn in rules.items():
            if name in found:
                continue
            try:
                hit = rule_on_trace(m, fn, seq, tr)
            except Exception:
                continue
            if hit is not None:
                found[name] = {"width": f"fuzz {k}tx", "attack": [fmt_tx(x) for x in seq[:hit + 1]],
                               "reverted": [not s["ok"] for s in tr["txs"][:hit + 1]], "source": "fuzzing on the EVM"}
                log(f"    FINDING (fuzz) {name}: " + " -> ".join(found[name]["attack"]))
    return found
