"""Checks: differential test (circuit vs real EVM) and replay of counterexamples.

Rules are plain Python functions over a Tx. The same rule runs symbolically on the
circuit (to search) and concretely on real EVM traces (to confirm), with exact 256-bit
arithmetic in the concrete case.
"""
from __future__ import annotations
import random
from . import evm
from .symexec import mapping_slot, ETH_SLOT

U256 = (1 << 256) - 1


# ---------- concrete rule evaluation on real EVM traces ----------
class CBit:
    def __init__(self, b): self.b = bool(b)
    def __and__(self, o): return CBit(self.b and _cb(o))
    def __or__(self, o): return CBit(self.b or _cb(o))
    def __invert__(self): return CBit(not self.b)
    def implies(self, o): return CBit((not self.b) or _cb(o))


def _cb(o): return o.b if isinstance(o, CBit) else bool(o)
def _cw(o): return o.v if isinstance(o, CWord) else o


class CWord:
    """Concrete rule value: exact integer arithmetic (sums and products never wrap)."""
    def __init__(self, v): self.v = v
    def zext(self, n): return self
    def wide(self): return self
    def __add__(self, o): return CWord(self.v + _cw(o))
    def __sub__(self, o): return CWord(self.v - _cw(o))
    def rsub(self, k): return CWord(k - self.v)
    def rfloordiv(self, k): return CWord(k // self.v if self.v else 0)
    def __mul__(self, o): return CWord(self.v * _cw(o))
    def __floordiv__(self, o): return CWord(self.v // _cw(o) if _cw(o) else 0)
    def __lt__(self, o): return CBit(self.v < _cw(o))
    def __gt__(self, o): return CBit(self.v > _cw(o))
    def __le__(self, o): return CBit(self.v <= _cw(o))
    def __ge__(self, o): return CBit(self.v >= _cw(o))
    def __eq__(self, o): return CBit(self.v == _cw(o))
    def __ne__(self, o): return CBit(self.v != _cw(o))
    __hash__ = None


class CTx:
    def __init__(self, model, tx, step, pre):
        self.m, self._tx, self._pre, self._post = model, tx, pre, step["slots"]
        self.sender = CWord(tx["sender"])
        self.ret = CWord(step["ret"] if step["ok"] else 0)
        self.ok = CBit(step["ok"])
        self.reverted = CBit(not step["ok"])
        self.to = CWord(tx["to"])
        self.now = CWord(tx.get("time", 1))

    def called(self, name):
        cname = next(con.name for con, a in self.m.contracts if a == self._tx["to"])
        primary = self._tx["to"] == self.m.contracts[0][1]  # a bare name means the contract under test
        return CBit(name == f"{cname}.{self._tx['fn']}" or (primary and name == self._tx["fn"]))

    def arg(self, j): return CWord(self._tx["args"][j] if j < len(self._tx["args"]) else 0)

    def _read(self, store, var, keys):
        if var == "ETH":
            return CWord(store.get((_cw(keys[0]), ETH_SLOT), 0))
        con, a, v = self.m.resolve(var)
        field = keys[-1] if keys and isinstance(keys[-1], str) else None
        if field is not None:
            keys = keys[:-1]
        s = con.storage[v]
        for k in keys:
            s = mapping_slot(_cw(k), s)
        if field is not None:
            extra, f_off, f_bytes = con.field(v, len(keys), field)
            val = store.get((a, s + extra), 0)
            return CWord((val >> (8 * f_off)) & ((1 << (8 * f_bytes)) - 1))
        val = store.get((a, s), 0)
        if not keys:
            off, n = con.storage_offset[v], con.storage_bytes[v]
            val = (val >> (8 * off)) & ((1 << (8 * n)) - 1)
        return CWord(val)

    def pre(self, var, *keys): return self._read(self._pre, var, keys)
    def post(self, var, *keys): return self._read(self._post, var, keys)
    def _keys(self, var):
        return [a for _, a in self.m.contracts] + self.m.user_addrs if var == "ETH" else self.m.key_universe
    def pre_sum(self, var, *f): return CWord(sum(self._read(self._pre, var, (k,) + f).v for k in self._keys(var)))
    def post_sum(self, var, *f): return CWord(sum(self._read(self._post, var, (k,) + f).v for k in self._keys(var)))


def rule_on_trace(model, rule_fn, seq, trace):
    """Index of the first transaction where the real EVM breaks the rule, or None."""
    pre = trace["init"]
    for i, (tx, step) in enumerate(zip(seq, trace["txs"])):
        if rule_fn(CTx(model, tx, step, pre)).b:
            return i
        pre = step["slots"]
    return None


def replay(model, cfg, rule_fn, seq):
    trace = evm.run(cfg, cfg["tag"] + "_replay", [seq], model.watch)[0]
    return rule_on_trace(model, rule_fn, seq, trace), trace


# ---------- differential test ----------
def random_sequences(model, n, seed=1):
    rnd = random.Random(seed)
    M = (1 << model.W) - 1
    def amount():
        return rnd.choice([rnd.randint(0, M), rnd.randint(0, 20), rnd.randint(0, 3), M, M - 1])
    def arg(types, j):
        if j >= len(types):
            return 0  # past this call's own words: nothing is sent there (the model requires 0)
        t = types[j]
        if t.startswith("offset:") and rnd.random() < 0.8:
            return int(t[7:]) % (M + 1)
        if t.startswith("length:") and rnd.random() < 0.8:
            return rnd.randint(0, int(t[7:]) + 1)
        if t.startswith("blength:") and rnd.random() < 0.9:  # one of the allowed byte lengths
            return rnd.choice([int(x) for x in t[8:].split(",")])
        if j < len(types) and types[j] == "address" and rnd.random() < 0.9:
            return rnd.choice([k for k in model.key_universe if k < 1 << model.W])  # addresses the circuit can hold
        if j < len(types) and types[j] == "bool":
            return rnd.randint(0, 1)
        return amount()
    seqs, assigns = [], []
    for _ in range(n):
        a, seq, now, blk = {}, [], 1, 1
        for i in range(model.k):
            fi = rnd.randrange(len(model.funcs))
            u = rnd.randrange(model.users)
            to, name, sig, sel, types = model.funcs[fi]
            args = [arg(types, j) for j in range(model.maxargs)]
            a[f"tx{i}.fn"], a[f"tx{i}.sender"] = fi, u
            for j, v in enumerate(args):
                a[f"tx{i}.arg{j}"] = v
            his = {}
            for j in getattr(model, "raw_pos", []):  # raw bytes words: their top 4 bytes (a selector, often)
                his[j] = rnd.choice([0, rnd.randrange(1 << 32)] + [f[3] for f in model.funcs][:4])
                a[f"tx{i}.arg{j}.hi"] = his[j]
            tx = {"to": to, "fn": name, "sig": sig, "selector": sel, "sender": model.user_addrs[u],
                  "args": [model.evm_arg(t, v) | (his.get(j, 0) << 224 if t == "raw" else 0)
                           for j, (t, v) in enumerate(zip(types, args))], "hook": None}
            if model.attacker is not None and rnd.random() < 0.5:
                hj = rnd.randrange(len(model.hook_sels))
                hs = model.hook_sels[hj]
                htypes = next(f[4] for f in model.funcs if f[3] == hs)
                hargs = [arg(htypes, j) for j in range(model.maxargs)]
                a[f"tx{i}.hook_on"], a[f"tx{i}.hook_fn"] = 1, hj
                for j, v in enumerate(hargs):
                    a[f"tx{i}.hook_arg{j}"] = v
                tx["hook"] = {"selector": hs, "args": [model.evm_arg(t, v) for t, v in zip(htypes, hargs)]}
            if sig in getattr(model, "payable", ()):
                v = rnd.choice([0, 1, rnd.randint(0, 20), rnd.randint(0, M)])
                a[f"tx{i}.value"], tx["value"] = v, v
            if getattr(model, "uses_time", False):
                dt = min(rnd.choice([0, 1, rnd.randint(0, 20), rnd.randint(0, M)]), M - now)
                now += dt
                a[f"tx{i}.dt"], tx["time"] = dt, now
            if getattr(model, "uses_number", False):
                dn = min(rnd.choice([0, 1, rnd.randint(0, 20), rnd.randint(0, M)]), M - blk)
                blk += dn
                a[f"tx{i}.dn"], tx["block"] = dn, blk
            seq.append(tx)
        seqs.append(seq)
        assigns.append(a)
    return seqs, assigns


def window_match(ev, mv, W):
    """The bit-level circuit is a W-bit EVM: its value v stands for a 256-bit value near 0 (v itself)
    or, when its top bit is set, near 2^256 (negative numbers, the max-uint sentinel, a max approval
    after a decrement). A chain value ev agrees with the circuit when it is one of these."""
    low = mv & ((1 << W) - 1)
    if ev == mv or ev == low:
        return True
    return bool(low >> (W - 1) & 1) and ev == (low - (1 << W)) % (1 << 256)


def differential(model, cfg, n=300, seed=1):
    c = model.c
    seqs, assigns = random_sequences(model, n, seed)
    packed = {}
    for name, bits in c.inputs.items():
        packed[name] = [sum(((a.get(name, 0) >> i) & 1) << L for L, a in enumerate(assigns)) for i in range(len(bits))]
    val = c.simulate(packed, len(seqs))

    def out(name, L):
        v = model.out_const.get(name, 0)
        for b, p in zip(c.outputs[name], model.out_pos[name]):
            v |= ((val[b] >> L) & 1) << p
        return v

    def span(name):
        if not model.out_pos.get(name):
            return None  # a constant: must match exactly
        return sum(1 << p for p in model.out_pos[name])

    traces = evm.run(cfg, cfg["tag"] + "_diff", seqs, model.watch)
    compared, mismatches = 0, []
    for L, (seq, tr) in enumerate(zip(seqs, traces)):
        init = tr["init"]
        for i, step in enumerate(tr["txs"]):
            if not out(f"tx{i}.valid", L):
                break  # the circuit hit a width artefact (W-bit overflow); the EVM is 256-bit
            problems, out_of_range = [], False
            if out(f"tx{i}.reverted", L) != (0 if step["ok"] else 1):
                problems.append(("reverted", int(not step["ok"]), out(f"tx{i}.reverted", L)))
            elif step["ok"]:
                checks = [("ret", f"tx{i}.ret", step["ret"])] if step["retlen"] >= 32 else []
                for (a, s), ev in step["slots"].items():
                    name = f"tx{i}.s.{a}.{s}"
                    if name in c.outputs:
                        checks.append((f"slot {hex(a)}:{s}", name, ev))
                    elif ev != init.get((a, s), 0):
                        problems.append((f"slot {hex(a)}:{s} (untouched in circuit)", ev, init.get((a, s), 0)))
                for label, name, ev in checks:
                    mask = span(name)
                    mv = out(name, L)
                    if window_match(ev, mv, model.W):
                        continue
                    if mask is None:
                        problems.append((label, ev, mv))
                    else:
                        if ev & ~mask:
                            out_of_range = True
                        if ev & mask != mv:
                            problems.append((label, ev, mv))
            compared += 1
            if problems:
                mismatches.append({"seq": seq, "tx": i, "problems": problems})
                break
            if out_of_range:
                break  # real values left the modelled bit range; later steps may legitimately differ
    return {"sequences": n, "compared_txs": compared, "mismatches": mismatches}
