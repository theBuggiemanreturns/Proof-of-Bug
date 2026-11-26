"""Integer maths engine: unbounded proofs by induction, with a lemma library.

The bit-level engine (symexec + SAT) checks small numbers and a few transactions. This
engine runs the same Yul with values as exact mathematical integers (Z3 integer
arithmetic), then proves each rule by induction:

    from ANY state that satisfies the contract's invariants (and type limits),
    ANY single call of ANY function either reverts or keeps every rule.

If that holds, the rules hold for every number size and any number of transactions.

Soundness: every EVM operation is modelled exactly (add/sub wrap at 2^256, division by
the Euclid definition), or over-approximated (a product that can overflow becomes "the
product, or some other 256-bit value"; bitwise ops on two unknowns become a bounded
unknown). Over-approximation can only make a proof fail, never make a wrong proof pass.

Lemmas are pre-proven facts handed to the solver. Each one is checked here, once, by Z3
over unbounded integers before it may be used (see LEMMAS / check_lemmas).
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
import json
import z3

from .symexec import HASHES, ARRAY_SPAN, CHAIN_ID, copy_words, CONST_OPS, CONST_UNARY, keccak_int, mapping_slot, PANIC_SELECTOR, Unsupported, SymSlot, Selector, ETH_SLOT

M = 1 << 256
HALF = 1 << 255


# ------------------------------------------------------------------ lemma library
# name -> (description, statement builder returning (variables, hypotheses, conclusion))
def _lemma_euclid_bound():
    n, d, q, r = z3.Ints("n d q r")
    hyp = [n >= 0, d > 0, n == q * d + r, r >= 0, r < d]
    return [n, d, q, r], hyp, z3.And(q * d <= n, n < q * d + d, q >= 0)


def _lemma_floor_swap():
    # the constant-product step: paying floor(y*dx/(x+dx)) out keeps x*y from dropping
    x, y, dx, q, r = z3.Ints("x y dx q r")
    hyp = [x >= 0, y >= 0, dx >= 0, x + dx > 0, y * dx == q * (x + dx) + r, r >= 0, r < x + dx]
    return [x, y, dx, q, r], hyp, (x + dx) * (y - q) == x * y + r


def _lemma_product_monotone():
    a, b, c = z3.Ints("a b c")
    return [a, b, c], [a >= 0, b >= a, c >= 0], a * c <= b * c


LEMMAS = {
    # applied automatically to every division in the call being proven
    "euclid-bound": ("floor(n/d)*d <= n < floor(n/d)*d + d", _lemma_euclid_bound),
    # proven and stored; applied when a rule hint names them (not automatic yet)
    "floor-swap": ("(x+dx)*(y - floor(y*dx/(x+dx))) = x*y + remainder", _lemma_floor_swap),
    "product-monotone": ("0 <= a <= b and c >= 0 imply a*c <= b*c", _lemma_product_monotone),
}
_LEMMA_STATUS = {}


def check_lemmas(timeout_ms=20000):
    """Prove every lemma once over unbounded integers. Only proven lemmas may be used."""
    for name, (desc, build) in LEMMAS.items():
        if name in _LEMMA_STATUS:
            continue
        vs, hyp, concl = build()
        s = z3.Solver()
        s.set("timeout", timeout_ms)
        s.add(*hyp)
        s.add(z3.Not(concl))
        _LEMMA_STATUS[name] = s.check() == z3.unsat
    return dict(_LEMMA_STATUS)


# ------------------------------------------------------------------ value helpers
def is_c(v):
    return isinstance(v, int) and not isinstance(v, bool)


def zi(v):
    return z3.IntVal(v) if is_c(v) else v


OPTIONS_MAX = 32


def z_options_rest(v, depth=0):
    """(options, rest): options [(condition, constant)] and the condition `rest` (or None) under which the term
    is none of them, for if-then-else trees whose leaves are numbers or other terms (the Z3 form of
    symexec.Choice and its rest). None if the term has no constant option at all."""
    if not isinstance(v, z3.ExprRef) or is_c(v) or z3.is_int_value(v) or depth > 12:
        o = z_options(v, depth)
        return (o, None) if o is not None else None
    if z3.is_app_of(v, z3.Z3_OP_ITE):
        c, a, b = v.children()
        out, rests = [], []
        for cond, sub_ in ((c, a), (z3.Not(c), b)):
            r = z_options_rest(sub_, depth + 1)
            if r is None:
                rests.append(cond)  # this branch is an ordinary term: the rest
                continue
            o, rr = r
            out += [(z3.And(cond, ca) if ca is not True else cond, x) for ca, x in o]
            if rr is not None:
                rests.append(z3.And(cond, rr))
        if not out or len(out) > OPTIONS_MAX:
            return None
        return out, (z3.Or(*rests) if len(rests) > 1 else rests[0]) if rests else None
    o = z_options(v, depth)
    return (o, None) if o is not None else None


def z_options(v, depth=0):
    """[(condition, constant)] when a term can only be one of a few constants (if-then-else trees with
    number leaves, and +, -, *, % of such terms): the Z3 form of symexec.Choice. None otherwise."""
    if is_c(v):
        return [(True, v)]
    if not isinstance(v, z3.ExprRef) or depth > 12:
        return None
    if z3.is_int_value(v):
        return [(True, v.as_long())]
    if z3.is_app_of(v, z3.Z3_OP_ITE):
        c, a, b = v.children()
        oa, ob = z_options(a, depth + 1), z_options(b, depth + 1)
        if oa is None or ob is None:
            return None
        out = [(z3.And(c, ca) if ca is not True else c, x) for ca, x in oa] + \
              [(z3.And(z3.Not(c), cb) if cb is not True else z3.Not(c), x) for cb, x in ob]
        return out if len(out) <= OPTIONS_MAX else None
    ops = {z3.Z3_OP_ADD: lambda x, y: x + y, z3.Z3_OP_SUB: lambda x, y: x - y,
           z3.Z3_OP_MUL: lambda x, y: x * y, z3.Z3_OP_MOD: lambda x, y: x % y if y else 0}
    for op, f in ops.items():
        if z3.is_app_of(v, op) and len(v.children()) >= 2:
            acc = z_options(v.children()[0], depth + 1)
            for ch in v.children()[1:]:
                o2 = z_options(ch, depth + 1)
                if acc is None or o2 is None:
                    return None
                acc = [(c1 if c2 is True else (c2 if c1 is True else z3.And(c1, c2)), f(x1, x2))
                       for c1, x1 in acc for c2, x2 in o2]
                acc = [(c, x) for c, x in acc if c is True or not z3.is_false(z3.simplify(c))]
                if len(acc) > OPTIONS_MAX:
                    return None
            if any(x < 0 or x >= M for _, x in acc):  # the term relies on wrapping it does not show: no guess
                return None
            return acc
    return None


def _isbool(x):
    return isinstance(x, bool) or (isinstance(x, z3.ExprRef) and z3.is_bool(x))


class Z:
    """Builds terms, keeps side facts (definitions of fresh variables) and value bounds."""

    def __init__(self):
        self.facts = []
        self.n = 0
        # Caches keyed by Z3 term id. Each entry keeps its term alive and is checked on lookup:
        # Z3 reuses the id of a freed term for a new, different term, and a stale entry would hand
        # back the bound or condition of the wrong expression (found by the blind C07 run).
        self.ub = {}  # term id -> (term, inclusive upper bound)
        self.bits = {}  # term id -> (term, mask of bits that may be set)
        self.notes = set()
        self.divs = []  # (n, d, q, r) for every symbolic division, for lemma instantiation
        self.boolword = {}  # id of a 0/1 word built from a condition -> that condition

    def fresh(self, name, lo=0, hi=M - 1):
        self.n += 1
        v = z3.Int(f"{name}!{self.n}")
        self.facts += [v >= lo, v <= hi]
        self.set_ub(v, hi)
        return v

    # bounds
    def _get(self, cache, v, default):
        e = cache.get(v.get_id())
        return e[1] if e is not None and e[0].eq(v) else default

    def set_ub(self, v, ub, bits=None):
        if not is_c(v):
            mask = bits if bits is not None else (1 << ub.bit_length()) - 1
            # the same term may get several valid bounds: keep the tightest
            self.ub[v.get_id()] = (v, min(ub, self._get(self.ub, v, ub)))
            self.bits[v.get_id()] = (v, mask & self._get(self.bits, v, mask))
        return v

    def get_ub(self, v):
        return v if is_c(v) else self._get(self.ub, v, M - 1)

    def get_bits(self, v):
        return v if is_c(v) else self._get(self.bits, v, M - 1)

    # booleans
    def and_(self, a, b):
        if a is False or b is False: return False
        if a is True: return b
        if b is True: return a
        return z3.And(a, b)

    def or_(self, a, b):
        if a is True or b is True: return True
        if a is False: return b
        if b is False: return a
        return z3.Or(a, b)

    def not_(self, a):
        if a is True: return False
        if a is False: return True
        return z3.Not(a)

    def is_false(self, e):
        if e is False: return True
        if e is True: return False
        return z3.is_false(z3.simplify(e))

    def ite(self, c, a, b):
        if c is True: return a
        if c is False: return b
        if a is b: return a
        if isinstance(a, SymSlot) or isinstance(b, SymSlot):
            return a
        if _isbool(a) or _isbool(b):
            return self.ite_bool(c, a, b)
        if is_c(a) and is_c(b) and a == b:
            return a
        r = z3.If(c, zi(a), zi(b))
        return self.set_ub(r, max(self.get_ub(a), self.get_ub(b)), self.get_bits(a) | self.get_bits(b))

    def ite_bool(self, c, a, b):
        if c is True: return a
        if c is False: return b
        if a is b: return a
        if isinstance(a, bool) and isinstance(b, bool):
            if a == b: return a
            return c if a else self.not_(c)
        return z3.If(c, a, b)

    def truthy(self, v):
        if is_c(v): return v != 0
        if isinstance(v, (SymSlot, Selector)): raise Unsupported("hash/selector used as a condition")
        b = self._get(self.boolword, v, None)
        return b if b is not None else v != 0

    def word(self, b):
        """A 0/1 word from a condition; remembers the condition so `if word` reuses it exactly."""
        if isinstance(b, bool): return int(b)
        r = self.set_ub(z3.If(b, z3.IntVal(1), z3.IntVal(0)), 1, 1)
        self.boolword[r.get_id()] = (r, b)
        return r

    # arithmetic
    def add(self, a, b):
        s = zi(a) + zi(b)
        ub = self.get_ub(a) + self.get_ub(b)
        if ub < M:
            return self.set_ub(s, ub)
        return self.set_ub(z3.If(s < M, s, s - M), M - 1)

    def sub(self, a, b):
        d = zi(a) - zi(b)
        return self.set_ub(z3.If(zi(a) >= zi(b), d, d + M), M - 1)

    def mul(self, a, b):
        if is_c(a) and a == 0 or is_c(b) and b == 0: return 0
        p = zi(a) * zi(b)
        ub = self.get_ub(a) * self.get_ub(b)
        if ub < M:
            return self.set_ub(p, ub)
        h = self.fresh("mulwrap")  # the wrapped product: some 256-bit value (over-approximation)
        self.notes.add("a product that may exceed 2^256 is treated as unknown when it does")
        return self.set_ub(z3.If(p < M, p, h), M - 1)

    def divmod(self, a, b):
        if is_c(b):
            if b == 0: return 0, 0
            return self.set_ub(zi(a) / b, self.get_ub(a) // b), self.set_ub(zi(a) % b, min(b - 1, self.get_ub(a)))
        q, r = self.fresh("q"), self.fresh("r")
        a_, b_ = zi(a), b
        self.facts.append(z3.If(b_ == 0, z3.And(q == 0, r == 0),
                                z3.And(a_ == q * b_ + r, r < b_)))
        self.set_ub(q, self.get_ub(a))
        self.set_ub(r, min(self.get_ub(a), max(self.get_ub(b) - 1, 0)))
        self.divs.append((a_, b_, q, r))
        return q, r

    def lt(self, a, b):
        if is_c(a) and is_c(b): return a < b
        return zi(a) < zi(b)

    def eq(self, a, b):
        if is_c(a) and is_c(b): return a == b
        return zi(a) == zi(b)

    def signed(self, a):
        return z3.If(zi(a) >= HALF, zi(a) - M, zi(a)) if not is_c(a) else (a - M if a >= HALF else a)

    def slt(self, a, b):
        return self.signed(a) < self.signed(b)

    # bitwise
    def band(self, a, b):
        if is_c(a) and is_c(b): return a & b
        if is_c(a): a, b = b, a
        if is_c(b):
            bits = self.get_bits(a)
            if bits & b == bits: return a
            if bits & b == 0: return 0
            return self._mask(a, b & bits)
        h = self.fresh("and", hi=min(self.get_ub(a), self.get_ub(b)))
        self.facts += [h <= zi(a), h <= zi(b)]
        self.notes.add("bitwise and of two unknowns is approximated")
        return self.set_ub(h, min(self.get_ub(a), self.get_ub(b)), self.get_bits(a) & self.get_bits(b))

    def _mask(self, v, m):
        """v & m for a constant m, built from its runs of 1-bits (exact)."""
        out, ub, lo = 0, 0, 0
        terms = []
        while m >> lo:
            if not (m >> lo) & 1:
                lo += 1
                continue
            hi = lo
            while (m >> hi) & 1:
                hi += 1
            part = (zi(v) / (1 << lo)) % (1 << (hi - lo)) if lo else zi(v) % (1 << (hi - lo))
            terms.append(part * (1 << lo) if lo else part)
            lo = hi
        r = terms[0]
        for t in terms[1:]:
            r = r + t
        return self.set_ub(r, min(self.get_ub(v), m), m)

    def bor(self, a, b):
        if is_c(a) and is_c(b): return a | b
        if self.get_bits(a) & self.get_bits(b) == 0:  # disjoint fields (packing): or == +
            r = zi(a) + zi(b)
            return self.set_ub(r, self.get_ub(a) + self.get_ub(b), self.get_bits(a) | self.get_bits(b))
        hi = min(self.get_ub(a) + self.get_ub(b), M - 1)
        h = self.fresh("or", hi=hi)
        self.facts += [h >= zi(a), h >= zi(b), h <= zi(a) + zi(b)]
        self.notes.add("bitwise or of overlapping unknowns is approximated")
        return self.set_ub(h, hi, self.get_bits(a) | self.get_bits(b))

    def bxor(self, a, b):
        if is_c(a) and is_c(b): return a ^ b
        if self.get_bits(a) & self.get_bits(b) == 0:
            return self.bor(a, b)
        hi = min(self.get_ub(a) + self.get_ub(b), M - 1)
        h = self.fresh("xor", hi=hi)
        self.facts.append(h <= zi(a) + zi(b))
        self.notes.add("bitwise xor of overlapping unknowns is approximated")
        return self.set_ub(h, hi, self.get_bits(a) | self.get_bits(b))

    def bnot(self, a):
        if is_c(a): return (M - 1) ^ a
        return self.set_ub(M - 1 - zi(a), M - 1)

    def shl(self, k, v):
        if is_c(v): return (v << k) % M if k < 256 else 0
        if k >= 256: return 0
        if self.get_bits(v) << k < M:
            return self.set_ub(zi(v) * (1 << k), self.get_ub(v) << k, self.get_bits(v) << k)
        return self.set_ub((zi(v) * (1 << k)) % M, M - 1)

    def shr(self, k, v):
        if is_c(v): return v >> k if k < 256 else 0
        if k >= 256: return 0
        if k == 0: return v
        return self.set_ub(zi(v) / (1 << k), self.get_ub(v) >> k, self.get_bits(v) >> k)


# ------------------------------------------------------------------ execution
@dataclass
class ZEnv:
    fn_sel: object  # selector int (one function per proof query) or None for a word
    args: list
    caller: object
    calldatasize: int = 4
    selector_word: object = None
    timestamp: object = 0
    callvalue: object = 0
    number: object = 1
    origin: object = None


class ZWorld:
    def __init__(self, z, codes, storage, key_universe, max_depth=3, max_unroll=64):
        self.rest_cuts = set()  # builtins where paths were left out (an address none of its known values)
        self.z, self.codes, self.storage = z, codes, storage
        self.key_universe = key_universe
        self.max_depth, self.max_unroll = max_depth, max_unroll
        self.assume = []  # conditions the proof assumes (keys inside the key universe, ...)
        self.bounded_loops = False  # search mode: cut loops at max_unroll instead of giving up
        self.loops_cut = 0
        self.pre = None  # the starting state; slots first read during the call are added to it
        # ETH, the same world the bit-level engine models: every account's balance is the pseudo
        # storage slot ETH_SLOT of that account (contracts and users alike)
        self.eth_on = False
        self.eth_users = []
        self.attackers = set()
        self.callbacks_skipped = False  # an attacker received ETH and its callback was not explored
        self.transient = {}  # EIP-1153 transient storage {address: {slot: value}}: empty at each transaction start

    def possible(self, cond, timeout_ms=3000):
        """Can cond hold, given everything known so far (value bounds and assumptions)? False only
        when the solver proves it cannot; a timeout counts as possible."""
        if cond is False:
            return False
        if cond is True:
            return True
        s = z3.Solver()
        s.set("timeout", timeout_ms)
        s.add(*[f for f in self.z.facts if f is not True])
        s.add(*[a for a in self.assume if a is not True])
        s.add(cond)
        return s.check() != z3.unsat

    def eth(self, a):
        st = self.storage.setdefault(a, {})
        if ETH_SLOT not in st:
            if self.pre is None:
                return 0
            v = self.z.fresh(f"eth{hex(a)}")  # arbitrary starting state: an unknown balance
            st[ETH_SLOT] = v
            self.pre.setdefault(a, {})[ETH_SLOT] = v
        return st[ETH_SLOT]

    def eth_of(self, who):
        """The balance of a possibly symbolic account."""
        z = self.z
        known = sorted(set(self.codes) | set(self.eth_users))
        if is_c(who):
            return self.eth(who) if who in known else 0
        acc = 0
        for k in known:
            acc = z.ite(z.eq(who, k), self.eth(k), acc)
        return acc

    def eth_move(self, cond, frm, to, v):
        """Move v wei from account frm to account to (None: out of the modelled world) where cond
        holds; the caller has checked frm can pay. frm/to may be symbolic users."""
        z = self.z
        if cond is False or (is_c(v) and v == 0):
            return
        known = sorted(set(self.codes) | set(self.eth_users))
        for k in known:
            out = cond if (is_c(frm) and frm == k) else (False if is_c(frm) else z.and_(cond, z.eq(frm, k)))
            inn = False if to is None else (cond if (is_c(to) and to == k) else
                                             (False if is_c(to) else z.and_(cond, z.eq(to, k))))
            if out is False and inn is False:
                continue
            b = self.eth(k)
            new = z.ite(out, z.sub(b, v), b) if out is not False else b
            new = z.ite(inn, z.add(new, v), new) if inn is not False else new
            self.storage.setdefault(k, {})[ETH_SLOT] = new

    def eth_snapshot(self):
        return {k: self.eth(k) for k in sorted(set(self.codes) | set(self.eth_users))}

    def eth_restore(self, cond, before):
        for k, old in before.items():
            st = self.storage.setdefault(k, {})
            if st.get(ETH_SLOT, 0) is not old:
                st[ETH_SLOT] = self.z.ite(cond, old, st.get(ETH_SLOT, 0))


class ZScope:
    def __init__(self, parent=None):
        self.vars, self.parent = {}, parent

    def lookup(self, name):
        f = self
        while f is not None:
            if name in f.vars:
                return f
            f = f.parent
        raise Unsupported(f"unknown variable {name}")


class ZExec:
    FLAGS = ("halted", "reverted", "leave", "brk", "cont")

    def __init__(self, world, address, env, depth=0, gate=True, static=False):
        self.w, self.z = world, world.z
        self.address, self.env, self.depth, self.gate, self.static = address, env, depth, gate, static
        self.code = world.codes[address]
        self.memory, self.memraw = {}, {}
        self.pc = [True]
        self.halted = self.reverted = self.leave = self.brk = self.cont = False
        self.outer_dead = False  # inside an internal function: the caller had already left/broken
        self.ret_words, self.ret_size, self.ret_sizes = [], 0, set()
        self.panics = {}
        self.rd_words, self.rd_size = [], 0
        self.opt = True  # while a builtin runs once per option of a computed address/size: that option's condition

    @property
    def storage(self):
        return self.w.storage[self.address]

    @property
    def local_active(self):
        z = self.z
        return z.and_(self.opt, z.not_(z.or_(z.or_(z.or_(self.halted, self.leave), z.or_(self.brk, self.cont)),
                                             self.outer_dead)))

    @property
    def active(self):
        z = self.z
        return z.and_(z.and_(self.gate, self.pc[-1]), self.local_active)

    def guard(self):
        z = self.z
        # not outer_dead: where the caller has already left, it never reads this frame's local values,
        # so local writes need no guard there (reverts and storage writes do: see local_active)
        return z.and_(self.opt, z.not_(z.or_(self.leave, z.or_(self.brk, self.cont))))

    # --- branch state
    def _flags(self):
        return {"bits": {k: getattr(self, k) for k in self.FLAGS}, "panics": dict(self.panics),
                "ret": (self.ret_words, self.ret_size)}

    def snapshot(self, scope):
        scopes, s = [], scope
        while s is not None:
            scopes.append((s, dict(s.vars)))
            s = s.parent
        return {"mem": dict(self.memory), "vars": scopes, "rd": (self.rd_words, self.rd_size), "flags": self._flags()}

    def restore(self, snap):
        self.memory = dict(snap["mem"])
        for sc, old in snap["vars"]:
            sc.vars.update(old)
        self.rd_words, self.rd_size = snap["rd"]
        for k, v in snap["flags"]["bits"].items():
            setattr(self, k, v)
        self.panics = dict(snap["flags"]["panics"])
        self.ret_words, self.ret_size = snap["flags"]["ret"]

    def capture(self, snap):
        return {"mem": dict(self.memory), "vars": [(sc, dict(sc.vars)) for sc, _ in snap["vars"]],
                "rd": (self.rd_words, self.rd_size), "flags": self._flags()}

    def _merge_list(self, cond, new, old):
        n = max(len(new), len(old))
        return [self.z.ite(cond, new[i] if i < len(new) else 0, old[i] if i < len(old) else 0) for i in range(n)]

    def merge(self, snap, branches):
        z = self.z
        mem = dict(snap["mem"])
        for cond, st in branches:
            for a in set(mem) | set(st["mem"]):
                b, n = mem.get(a, 0), st["mem"].get(a, 0)
                if n is not b:
                    if a == 0x40 and is_c(n) and is_c(b):
                        mem[a] = max(n, b)  # free memory pointer (see symexec.merge)
                    else:
                        mem[a] = z.ite(cond, n, b)
        self.memory = mem
        for idx, (sc, old) in enumerate(snap["vars"]):
            cur = dict(old)
            for cond, st in branches:
                new = st["vars"][idx][1]
                for k in old:
                    if new.get(k, old[k]) is not old[k]:
                        cur[k] = z.ite(cond, new[k], cur[k])
            sc.vars.update(cur)
        words, size = snap["rd"]
        bits = dict(snap["flags"]["bits"])
        panics = dict(snap["flags"]["panics"])
        rw, rs = snap["flags"]["ret"]
        for cond, st in branches:
            w2, s2 = st["rd"]
            if w2 is not words:
                words = self._merge_list(cond, w2, words)
            if s2 is not size:
                size = z.ite(cond, s2, size)
            fl = st["flags"]
            for k in self.FLAGS:
                if fl["bits"][k] is not bits[k]:
                    bits[k] = z.ite_bool(cond, fl["bits"][k], bits[k])
            for code in set(panics) | set(fl["panics"]):
                a, b = fl["panics"].get(code, False), panics.get(code, False)
                if a is not b:
                    panics[code] = z.ite_bool(cond, a, b)
            w3, s3 = fl["ret"]
            if w3 is not rw:
                rw = self._merge_list(cond, w3, rw)
            if s3 is not rs:
                rs = z.ite(cond, s3, rs)
        self.rd_words, self.rd_size = words, size
        for k, v in bits.items():
            setattr(self, k, v)
        self.panics, self.ret_words, self.ret_size = panics, rw, rs

    # --- run
    def run(self):
        snap = {a: dict(s) for a, s in self.w.storage.items()}
        tsnap = {a: dict(s) for a, s in self.w.transient.items()}
        self.block(self.code.block, ZScope())
        if self.reverted is not False:
            for a, cur in self.w.transient.items():
                old = tsnap.get(a, {})
                for s in set(old) | set(cur):
                    if old.get(s, 0) is not cur.get(s, 0):
                        cur[s] = self.z.ite(self.reverted, old.get(s, 0), cur.get(s, 0))
            pre = self.w.pre or {}
            for a, cur in self.w.storage.items():
                old = snap.get(a, {})
                for s in set(old) | set(cur):
                    # a slot first read during the call (arbitrary starting state) started as its pre value
                    o = old[s] if s in old else pre.get(a, {}).get(s, 0)
                    if o is not cur.get(s, 0):
                        cur[s] = self.z.ite(self.reverted, o, cur.get(s, 0))
        return self

    def block(self, blk, scope):
        saved = dict(self.memraw)
        sc = ZScope(scope)
        for st in blk["statements"]:
            self.stmt(st, sc)
            if self.z.is_false(self.local_active):
                break
        self.memraw = saved

    def stmt(self, st, f):
        t, z = st["nodeType"], self.z
        if t == "YulBlock":
            self.block(st, f)
        elif t == "YulFunctionDefinition":
            pass
        elif t == "YulVariableDeclaration":
            names = [v["name"] for v in st["variables"]]
            vals = self.expr_multi(st["value"], f, len(names)) if st.get("value") else [0] * len(names)
            for n, v in zip(names, vals):
                f.vars[n] = v
        elif t == "YulAssignment":
            names = [v["name"] for v in st["variableNames"]]
            vals = self.expr_multi(st["value"], f, len(names))
            g = self.guard()
            for n, v in zip(names, vals):
                fr = f.lookup(n)
                fr.vars[n] = z.ite(g, v, fr.vars[n])
        elif t == "YulExpressionStatement":
            self.expr_multi(st["expression"], f, None)
        elif t == "YulIf":
            cond = z.truthy(self.expr(st["condition"], f))
            live = self.local_active
            if z.is_false(z.and_(live, cond)):
                return
            if z.is_false(z.and_(live, z.not_(cond))):
                cond = True
            snap = self.snapshot(f)
            self.with_pc(cond, lambda: self.block(st["body"], f))
            if cond is not True:
                self.merge(snap, [(cond, self.capture(snap))])
        elif t == "YulSwitch":
            self.switch(st, f)
        elif t == "YulForLoop":
            self.for_loop(st, f)
        elif t == "YulBreak":
            self.brk = z.or_(self.brk, self.local_active)
        elif t == "YulContinue":
            self.cont = z.or_(self.cont, self.local_active)
        elif t == "YulLeave":
            self.leave = z.or_(self.leave, self.local_active)
        else:
            raise Unsupported(f"statement {t}")

    def with_pc(self, cond, fn):
        p = self.z.and_(self.pc[-1], cond)
        if self.z.is_false(p):
            return
        self.pc.append(p)
        try:
            fn()
        finally:
            self.pc.pop()

    def switch(self, st, f):
        z = self.z
        e = self.expr(st["expression"], f)
        taken, cases = False, []
        for case in st["cases"]:
            if case["value"] == "default":
                cond = z.not_(taken)
            else:
                k = self.literal(case["value"])
                if isinstance(e, Selector):
                    if self.env.fn_sel is not None:
                        m = (self.env.fn_sel == k)
                    else:
                        m = z.eq(z.shr(224, self.env.selector_word), k)
                elif is_c(e):
                    m = e == k
                else:
                    m = z.eq(e, k)
                cond = z.and_(m, z.not_(taken))
                taken = z.or_(taken, m)
            cases.append((cond, case["body"]))
        snap = self.snapshot(f)
        branches = []
        for cond, body in cases:
            if z.is_false(cond):
                continue
            self.restore(snap)
            self.with_pc(cond, lambda b=body: self.block(b, f))
            branches.append((cond, self.capture(snap)))
        if len(branches) == 1 and branches[0][0] is True:
            return
        self.restore(snap)
        self.merge(snap, branches)

    def for_loop(self, st, f):
        z = self.z
        outer = ZScope(f)
        for s in st["pre"]["statements"]:
            self.stmt(s, outer)
        saved_brk, saved_cont = self.brk, self.cont
        self.brk = False
        # the running path is carried forward unmerged (loop counters stay exact); exits are joined after
        loop_pc, entry, exits = True, self.snapshot(outer), []
        for _ in range(self.w.max_unroll):
            cond = z.truthy(self.expr(st["condition"], outer))
            go = z.and_(cond, z.not_(self.brk))
            stop = z.and_(loop_pc, z.not_(go))
            if not z.is_false(stop):
                exits.append((stop, self.capture(entry)))
            loop_pc = z.and_(loop_pc, go)
            if z.is_false(z.and_(self.pc[-1], loop_pc)):
                break
            # a symbolic bound: ask the solver whether this iteration can run at all (e.g. a
            # require(xs.length == 2) before the loop); the loop's real bound, not its shape, decides
            if not (go is True) and not self.w.possible(z.and_(self.active, loop_pc)):
                break
            self.pc.append(z.and_(self.pc[-1], loop_pc))
            try:
                self.cont = False
                self.block(st["body"], outer)
                self.cont = False
                self.block(st["post"], outer)
            finally:
                self.pc.pop()
        else:
            cond = z.truthy(self.expr(st["condition"], outer))
            more = z.and_(self.active, z.and_(loop_pc, z.and_(cond, z.not_(self.brk))))
            if not z.is_false(more) and self.w.possible(more):
                if not self.w.bounded_loops:
                    # a PROOF may never assume a loop stops: that assumption could be false and prove anything
                    raise Unsupported(f"a loop may run more than {self.w.max_unroll} times")
                # a SEARCH may: it then only explores paths where the loop ends in time (every attack is
                # replayed on the EVM, so this can miss a bug but never invent one); it is reported
                self.w.assume.append(z.not_(more))
                self.w.loops_cut += 1
        if exits:
            self.merge(self.snapshot(outer), exits)
        self.brk, self.cont = saved_brk, saved_cont

    # --- mappings
    def keccak(self, a):
        z = self.z
        p, n = a
        if not (is_c(p) and is_c(n)) or n % 32:
            raise Unsupported("keccak256 over a computed or unaligned memory range")
        opts = [(True, [])]
        for i in range(n // 32):
            v = self.memraw.get(p + 32 * i, self.memory.get(p + 32 * i, 0))
            new = []
            for cond, words in opts:
                if is_c(v):
                    new.append((cond, words + [v]))
                elif isinstance(v, SymSlot):
                    for c2, sl in v.options:
                        new.append((z.and_(cond, c2), words + [sl]))
                else:
                    for kk in self.w.key_universe:
                        new.append((z.and_(cond, z.eq(v, kk)), words + [kk]))
            opts = new
        slots = [(cond, keccak_int(b"".join(w.to_bytes(32, "big") for w in words))) for cond, words in opts]
        HASHES.update(sl for _, sl in slots)
        if len(slots) == 1 and slots[0][0] is True:
            return slots[0][1]
        return SymSlot(slots)

    def _array_slots(self, bases, off):
        """As symexec: base + off over offsets 0..ARRAY_SPAN-1; a path past them is assumed away
        (note_outside), the array bound being a reported limit like the key universe."""
        z, opts = self.z, []
        for cond, base in bases:
            for j in range(ARRAY_SPAN):
                cc = z.and_(cond, z.eq(off, j))
                if not z.is_false(cc):
                    opts.append((cc, (base + j) % M))
        return SymSlot(opts)

    def note_outside(self, sym):
        z = self.z
        covered = False
        for cond, _ in sym.options:
            covered = z.or_(covered, cond)
        self.w.assume.append(z.not_(z.and_(self.active, z.not_(covered))))

    # --- expressions
    def literal(self, lit):
        v = lit["value"]
        if lit["kind"] == "number": return int(v, 0) % M
        if lit["kind"] == "bool": return 1 if v == "true" else 0
        if lit["kind"] == "string":
            b = v.encode()
            if len(b) > 32: raise Unsupported("string literal > 32 bytes")
            return int.from_bytes(b.ljust(32, b"\0"), "big")
        raise Unsupported(f"literal {lit['kind']}")

    def expr(self, e, f):
        return self.expr_multi(e, f, 1)[0]

    def expr_multi(self, e, f, n):
        t = e["nodeType"]
        if t == "YulLiteral": return [self.literal(e)]
        if t == "YulIdentifier": return [f.lookup(e["name"]).vars[e["name"]]]
        name = e["functionName"]["name"]
        if name == "loadimmutable":
            key = e["arguments"][0]["value"]
            if key not in self.code.immutables:
                raise Unsupported(f"immutable {key} of {self.code.name} has no value")
            return [self.code.immutables[key]]
        if name in self.code.functions:
            args = [self.expr(a, f) for a in e["arguments"]]
            return self.call_user(self.code.functions[name], args)
        if name == "shr" and len(e["arguments"]) == 2:
            a0, a1 = e["arguments"]
            if (a0["nodeType"] == "YulLiteral" and self.literal(a0) == 224 and a1["nodeType"] == "YulFunctionCall"
                    and a1["functionName"]["name"] == "calldataload"
                    and a1["arguments"][0]["nodeType"] == "YulLiteral" and self.literal(a1["arguments"][0]) == 0):
                return [Selector()]
        args = [self.expr(a, f) for a in reversed(e["arguments"])][::-1]
        r = self.builtin(name, args)
        return [r] if n != 0 else []

    def call_user(self, fn, args):
        fr = ZScope(None)
        for p, a in zip(fn.get("parameters", []), args):
            fr.vars[p["name"]] = a
        rets = [r["name"] for r in fn.get("returnVariables", [])]
        for r in rets:
            fr.vars[r] = 0
        z = self.z
        saved = (self.leave, self.brk, self.cont, self.outer_dead)
        self.outer_dead = z.or_(self.outer_dead, z.or_(self.leave, z.or_(self.brk, self.cont)))
        self.leave = self.brk = self.cont = False
        self.block(fn["body"], fr)
        self.leave, self.brk, self.cont, self.outer_dead = saved
        return [fr.vars[r] for r in rets]

    PLACES = {"mload": (0,), "mstore": (0,), "calldatacopy": (0, 1, 2), "returndatacopy": (0, 1, 2),
              "mcopy": (0, 1, 2), "keccak256": (0, 1), "return": (0, 1), "call": (3, 4, 5, 6),
              "staticcall": (2, 3, 4, 5), "calldataload": (0,)}
    RANGES = {"mload": [(0, 32)], "mstore": [(0, 32)], "keccak256": [(0, "1")], "calldatacopy": [(0, "2")],
              "returndatacopy": [(0, "2")], "mcopy": [(0, "2"), (1, "2")], "return": [(0, "1")],
              "revert": [(0, "1")], "call": [(3, "4"), (5, "6")], "staticcall": [(2, "3"), (4, "5")]}
    MEMORY_LIMIT = 1 << 24  # as symexec: memory this far out is an out-of-gas revert

    def _per_option(self, name, a):
        """A builtin whose address/size arguments are each one of a few constants (z_options): run it once
        per consistent combination under that combination's condition (part of every local guard) and
        join the results, as symexec._per_option. None if an argument is not of that form."""
        import itertools
        z = self.z
        places = [i for i in self.PLACES[name] if i < len(a) and not is_c(a[i])]
        if not places:
            return None
        cols, rests = [], []
        for i in places:
            r = z_options_rest(a[i]) if not isinstance(a[i], (SymSlot, Selector)) else None
            if r is None or (len(r[0]) < 2 and r[1] is None):
                return None
            cols.append(r[0])
            if r[1] is not None:
                rests.append(r[1])
        if rests:
            # an address or size that is none of its known values here (e.g. after a call that returned nothing):
            # the search leaves those paths out (counted); a proof cannot, so it refuses
            if not self.w.bounded_loops:
                raise Unsupported(f"{name} at an address that is not one of its known values on some path")
            rc = z3.Or(*rests) if len(rests) > 1 else rests[0]
            self.w.assume.append(z.not_(z.and_(self.active, rc)))
            self.w.rest_cuts.add(name)
        combos = []
        for pick in itertools.product(*cols):
            conds = [c for c, _ in pick if c is not True]
            cond = z3.And(*conds) if len(conds) > 1 else (conds[0] if conds else True)
            if cond is not True and z3.is_false(z3.simplify(cond)):
                continue
            args = list(a)
            for i, (_, x) in zip(places, pick):
                args[i] = x
            combos.append((cond, args))
            if len(combos) > 4 * OPTIONS_MAX:
                return None
        saved, rets, rds = self.opt, [], []
        try:
            for cond, args in combos:
                self.opt = z.and_(saved, cond)
                rd0 = (self.rd_words, self.rd_size)
                rets.append((cond, self.builtin(name, args)))
                rds.append((cond, self.rd_words, self.rd_size))
                if name in ("call", "staticcall"):
                    self.rd_words, self.rd_size = rd0
        finally:
            self.opt = saved
        if not rets:
            return 0
        if name in ("call", "staticcall"):
            _, words, size = rds[-1]
            for cond, w_, s_ in rds[-2::-1]:
                words = self._merge_list(cond, w_, words)
                size = z.ite(cond, s_, size)
            self.rd_words, self.rd_size = words, size
        if name == "keccak256":
            opts = []
            for cond, r in rets:
                if isinstance(r, SymSlot):
                    opts += [(z.and_(cond, c2), sl) for c2, sl in r.options]
                else:
                    opts.append((cond, r))
            return SymSlot([(cc, sl) for cc, sl in opts if not z.is_false(cc)])
        acc = rets[-1][1]
        for cond, r in rets[-2::-1]:
            acc = z.ite(cond, r, acc)
        return acc

    def _out_of_gas(self, name, a):
        for oi, si in self.RANGES[name]:
            off = a[oi] if oi < len(a) else 0
            size = a[int(si)] if isinstance(si, str) and int(si) < len(a) else si
            if is_c(off) and is_c(size) and size > 0 and off + size > self.MEMORY_LIMIT:
                return True
        return False

    def builtin(self, name, a):
        z = self.z
        if name in CONST_OPS and all(is_c(x) for x in a): return CONST_OPS[name](*a)
        if name in CONST_UNARY and is_c(a[0]): return CONST_UNARY[name](a[0])
        if name in self.PLACES:
            r = self._per_option(name, a)
            if r is not None:
                return r
        if name in self.RANGES and self._out_of_gas(name, a):
            la = self.local_active  # memory this far out: out of gas, the call reverts
            self.reverted, self.halted = z.or_(self.reverted, la), z.or_(self.halted, la)
            return 0
        if name in ("memoryguard",): return a[0]
        if name == "pop": return 0
        if name == "add" and any(isinstance(x, SymSlot) for x in a):
            sym = [x for x in a if isinstance(x, SymSlot)]
            other = [x for x in a if not isinstance(x, SymSlot)]
            if len(sym) == 1 and is_c(other[0]): return sym[0].shifted(other[0])
            if len(sym) == 1 and not isinstance(other[0], Selector):
                return self._array_slots(sym[0].options, other[0])  # an element of an array under a mapping
            raise Unsupported("arithmetic on a hashed storage slot")
        if name == "add" and len(a) == 2 and any(is_c(x) and x in HASHES for x in a) \
                and any(not is_c(x) and not isinstance(x, (SymSlot, Selector)) for x in a):
            h = next(x for x in a if is_c(x) and x in HASHES)
            other = next(x for x in a if x is not h)
            return self._array_slots([(True, h)], other)  # keccak(p) + i: an element of a dynamic array
        if name == "keccak256": return self.keccak(a)
        for x in a:
            if isinstance(x, (SymSlot, Selector)) and name not in ("sload", "sstore", "mstore"):
                raise Unsupported(f"hashed slot or selector used in {name}")
        if name == "add": return z.add(a[0], a[1])
        if name == "sub": return z.sub(a[0], a[1])
        if name == "mul": return z.mul(a[0], a[1])
        if name in ("div", "mod"):
            q, r = z.divmod(a[0], a[1])
            return q if name == "div" else r
        if name == "mulmod":  # (x * y) % d with the exact (512-bit) product, as the EVM does
            if is_c(a[0]) and is_c(a[1]) and is_c(a[2]):
                return (a[0] * a[1]) % a[2] if a[2] else 0
            p = zi(a[0]) * zi(a[1])
            z.set_ub(p, z.get_ub(a[0]) * z.get_ub(a[1]))
            return z.divmod(p, a[2])[1]
        if name == "and": return z.band(a[0], a[1])
        if name == "or": return z.bor(a[0], a[1])
        if name == "xor": return z.bxor(a[0], a[1])
        if name == "not": return z.bnot(a[0])
        if name == "iszero": return z.word(z.not_(z.truthy(a[0])))
        if name == "eq": return z.word(z.eq(a[0], a[1]))
        if name == "lt": return z.word(z.lt(a[0], a[1]))
        if name == "gt": return z.word(z.lt(a[1], a[0]))
        if name == "slt": return z.word(z.slt(a[0], a[1]))
        if name == "sgt": return z.word(z.slt(a[1], a[0]))
        if name in ("shl", "shr"):
            if not is_c(a[0]): raise Unsupported("shift by a computed amount")
            return getattr(z, name)(a[0], a[1])
        if name == "sar":
            if is_c(a[0]) and z.get_bits(a[1]) < HALF: return z.shr(a[0], a[1])
            raise Unsupported("arithmetic shift of a possibly negative value")
        if name == "byte" and is_c(a[0]):
            return z.band(z.shr(8 * (31 - a[0]), a[1]), 0xFF) if a[0] < 32 else 0
        if name == "exp" and is_c(a[1]):
            r = 1
            for _ in range(a[1]):
                r = z.mul(r, a[0])
            return r
        if name == "callvalue": return self.env.callvalue
        if name == "timestamp": return self.env.timestamp
        if name == "number": return self.env.number
        if name == "chainid": return CHAIN_ID
        if name == "origin": return self.env.origin if self.env.origin is not None else self.env.caller
        if name == "caller": return self.env.caller
        if name == "calldatasize": return self.env.calldatasize
        if name == "address": return self.address
        if name == "gas": return 10_000_000
        if name in ("selfbalance", "balance") and self.w.eth_on:
            return self.w.eth(self.address) if name == "selfbalance" else self.w.eth_of(a[0])
        if name in ("selfbalance", "balance", "coinbase", "prevrandao",
                    "difficulty", "gasprice", "basefee", "blobbasefee", "blockhash", "gaslimit", "extcodehash"):
            raise Unsupported(f"{name}() is not modelled")
        if name == "calldataload":
            off = a[0]
            if not is_c(off):
                # an offset read from calldata (ABI-encoded arrays): one of the calldata words, 0 past the end
                acc, hit = 0, False
                for i, wd in enumerate(self.env.args):
                    h = z.eq(off, 4 + 32 * i)
                    acc = z.ite(h, wd, acc)
                    hit = z.or_(hit, h)
                odd = z.and_(z.lt(off, self.env.calldatasize), z.not_(hit))
                if self.w.bounded_loops:  # search: unaligned reads are left out (every attack is replayed on the EVM)
                    self.w.assume.append(z.not_(z.and_(self.active, odd)))
                else:  # proof: an unmodelled read may be anything (sound)
                    acc = z.ite(odd, z.fresh("calldata"), acc)
                return acc
            if off < 4 or (off - 4) % 32: raise Unsupported("calldataload at an unaligned offset")
            i = (off - 4) // 32
            return self.env.args[i] if i < len(self.env.args) else 0
        if name == "extcodesize":
            has = False
            for addr in self.w.codes:
                has = z.or_(has, z.eq(a[0], addr))
            return z.word(has)
        if name == "returndatasize": return self.rd_size
        if name == "returndatacopy":
            dst, off, size = a
            if not all(is_c(x) for x in (dst, off)) or off % 32:
                raise Unsupported("returndatacopy with computed arguments")
            n = (size + 31) // 32 if is_c(size) else len(self.rd_words)
            for i in range(n):
                k = off // 32 + i
                self._mstore(dst + 32 * i, self.rd_words[k] if k < len(self.rd_words) else 0)
            return 0
        if name == "sload":
            if isinstance(a[0], SymSlot):
                self.note_outside(a[0])
                acc = 0
                for cond, sl in a[0].options:
                    acc = z.ite(cond, self._sload(sl), acc)
                return acc
            if not is_c(a[0]): raise Unsupported("sload at a computed slot")
            return self._sload(a[0])
        if name == "sstore":
            act = self.active
            if self.static:
                la = self.local_active
                self.reverted, self.halted = z.or_(self.reverted, la), z.or_(self.halted, la)
                return 0
            if isinstance(a[0], SymSlot):
                self.note_outside(a[0])
                for cond, sl in a[0].options:
                    self.storage[sl] = z.ite(z.and_(act, cond), a[1], self._sload(sl))
                return 0
            if not is_c(a[0]): raise Unsupported("sstore at a computed slot")
            self.storage[a[0]] = z.ite(act, a[1], self._sload(a[0]))
            return 0
        if name in ("tload", "tstore"):
            if not is_c(a[0]): raise Unsupported(f"{name} at a computed slot")
            t = self.w.transient.setdefault(self.address, {})
            if name == "tload":
                return t.get(a[0], 0)
            if self.static:
                la = self.local_active
                self.reverted, self.halted = z.or_(self.reverted, la), z.or_(self.halted, la)
                return 0
            t[a[0]] = z.ite(self.active, a[1], t.get(a[0], 0))
            return 0
        if name == "calldatacopy":
            dst, off, size = a
            if not all(is_c(x) for x in (dst, off, size)):
                raise Unsupported("calldatacopy with computed arguments")
            words = copy_words(off, size, self.env.args, base=4, mask=lambda v, rem: v)
            for i, w_ in enumerate(words):
                if i == len(words) - 1 and size % 32:
                    self._partial_store(dst + 32 * i, w_, size % 32)
                else:
                    self._mstore(dst + 32 * i, w_)
            return 0
        if name == "mcopy":
            dst, src, size = a
            if not all(is_c(x) for x in (dst, src, size)):
                raise Unsupported("mcopy with computed arguments")
            n = (size + 31) // 32
            words = [self.memraw.get(src + 32 * i, self.memory.get(src + 32 * i, 0)) for i in range(n)]
            for i, w_ in enumerate(words):
                if i == n - 1 and size % 32:
                    self._partial_store(dst + 32 * i, w_, size % 32)
                else:
                    self._mstore(dst + 32 * i, w_)
            return 0
        if name in ("log0", "log1", "log2", "log3", "log4"):
            return 0  # events change no state
        if name == "mload":
            if not is_c(a[0]): raise Unsupported("mload at a computed address")
            return self.memory.get(a[0], 0)
        if name == "mstore":
            if not is_c(a[0]): raise Unsupported("mstore at a computed address")
            self._mstore(a[0], a[1])
            return 0
        if name in ("call", "staticcall"):
            if name == "call":
                _, to, value, inp, insize, out, outsize = a
                if not (is_c(value) and value == 0) and not self.w.eth_on: raise Unsupported("calls that send ETH")
            else:
                _, to, inp, insize, out, outsize = a
                value = 0
            return self.ext_call(to, inp, insize, out, outsize, name == "staticcall" or self.static, value)
        if name in ("revert", "invalid"):
            la = self.local_active
            if name == "revert" and self.memraw.get(0) == PANIC_SELECTOR and is_c(self.memraw.get(4)):
                code = self.memraw[4]
                self.panics[code] = z.or_(self.panics.get(code, False), la)
            self.reverted, self.halted = z.or_(self.reverted, la), z.or_(self.halted, la)
            return 0
        if name == "return":
            la = self.local_active
            p, size = a
            if not (is_c(p) and is_c(size)): raise Unsupported("return with a computed range")
            words = [self.memory.get(p + 32 * i, 0) for i in range((size + 31) // 32)]
            self.ret_words = self._merge_list(la, words, self.ret_words)
            self.ret_size = z.ite(la, size, self.ret_size)
            if not z.is_false(la):
                self.ret_sizes.add(size)
            self.halted = z.or_(self.halted, la)
            return 0
        if name == "stop":
            self.halted = z.or_(self.halted, self.local_active)
            return 0
        raise Unsupported(f"builtin {name}")

    def _sload(self, slot):
        st = self.storage
        if slot not in st:
            if self.w.pre is None:
                return 0
            # in an arbitrary starting state an unlisted slot holds an unknown value, not 0
            v = self.z.fresh(f"{self.code.name}.slot{hex(slot)[:10]}")
            st[slot] = v
            self.w.pre[self.address][slot] = v
        return st[slot]

    def _partial_store(self, addr, v, rem):
        """Write the first `rem` bytes of v at addr; the rest of that memory word keeps what it held."""
        if isinstance(v, (SymSlot, Selector)):
            raise Unsupported("a hashed slot copied in part")
        z, k = self.z, 8 * (32 - rem)
        old = self.memory.get(addr, 0)
        if isinstance(old, SymSlot):
            old = 0
        hi = z.shl(k, z.shr(k, v))  # v's first rem bytes, in place
        lo = z.sub(old, z.shl(k, z.shr(k, old)))  # old's last 32 - rem bytes
        self._mstore(addr, (hi + lo) if is_c(hi) and is_c(lo) else z.add(hi, lo))

    def _mstore(self, addr, v):
        if self.opt is not True:
            # one option of a computed address: a guarded write, and no raw record another option could read
            if isinstance(v, (SymSlot, Selector)):
                raise Unsupported("a hashed slot stored at a computed memory address")
            self.memraw.pop(addr, None)
            old = self.memory.get(addr, 0)
            self.memory[addr] = self.z.ite(self.guard(), v, 0 if isinstance(old, SymSlot) else old)
            return
        if addr == 0x40 and not is_c(v) and not isinstance(v, SymSlot):
            # the free memory pointer only has to point past everything allocated: its proven upper
            # bound is as good as the value itself for Solidity-generated (memory-safe) code
            ub = self.z.get_ub(v)
            if ub < (1 << 64):
                v = ub
        self.memraw[addr] = v
        if isinstance(v, SymSlot):
            self.memory.pop(addr, None)
        else:
            old = self.memory.get(addr, 0)
            self.memory[addr] = self.z.ite(self.guard(), v, 0 if isinstance(old, SymSlot) else old)

    def ext_call(self, to, inp, insize, out, outsize, static, value=0):
        z, w = self.z, self.w
        if isinstance(to, int) and 1 <= to <= 0x11:
            raise Unsupported(f"precompile at address {to} (e.g. ecrecover) is not modelled")
        if not all(is_c(x) for x in (inp, insize, out, outsize)):
            raise Unsupported("call with a computed memory range")
        act = self.active
        pays = not (is_c(value) and value == 0)
        if pays and static:
            raise Unsupported("staticcall with value")
        # a call that sends more ETH than this contract has fails without running (as in the bit engine)
        enough = z.not_(z.lt(w.eth(self.address), value)) if pays else True
        success, rd_words, rd_size, matched = False, [], 0, False
        for t in w.codes:
            cond = (to == t) if is_c(to) else z.eq(to, t)
            go = z.and_(act, cond)
            if z.is_false(go):
                continue
            matched = z.or_(matched, cond)
            if self.depth + 1 > w.max_depth:
                w.assume.append(z.not_(go))
                continue
            go = z.and_(go, enough)
            before = w.eth_snapshot() if pays else {}
            if pays:
                w.eth_move(go, self.address, t, value)
            args = [self.memraw.get(inp + 4 + 32 * i, self.memory.get(inp + 4 + 32 * i, 0))
                    for i in range(max(0, (insize - 4) // 32))]
            sel = self.memraw.get(inp, self.memory.get(inp, 0))
            env = ZEnv(sel >> 224 if is_c(sel) else None, args, self.address, insize, sel,
                       timestamp=self.env.timestamp, callvalue=value, number=self.env.number,
                       origin=self.env.origin if self.env.origin is not None else self.env.caller)
            callee = ZExec(w, t, env, self.depth + 1, gate=go, static=static).run()
            ok = z.not_(callee.reverted)
            if pays:  # the callee's own revert does not undo the value sent before it ran
                w.eth_restore(z.and_(go, callee.reverted), before)
            ok = z.and_(ok, enough)
            size = next(iter(callee.ret_sizes)) if len(callee.ret_sizes) == 1 else (
                0 if not callee.ret_sizes else callee.ret_size)
            success = z.or_(success, z.and_(cond, ok))
            rd_words = self._merge_list(cond, callee.ret_words, rd_words)
            rd_size = z.ite(cond, size, rd_size)
        # anything else is an account without code: the call succeeds and only receives the ETH
        # (a model user gets it, anyone else takes it out of the world). An attacker contract is
        # treated the same way here: its callback is explored by the bit-level search, not here.
        nomatch = z.not_(matched)
        if pays:
            go = z.and_(z.and_(act, nomatch), enough)
            if not z.is_false(go):
                if w.attackers and (not is_c(to) or to in w.attackers):
                    w.callbacks_skipped = True
                users = [u for u in w.eth_users]
                hit = False
                for u in users:
                    hit = z.or_(hit, (to == u) if is_c(to) else z.eq(to, u))
                # pay the user it reaches, or remove the ETH from the world
                for u in users:
                    hu = z.and_(go, (to == u) if is_c(to) else z.eq(to, u))
                    if not z.is_false(hu):
                        w.eth_move(hu, self.address, u, value)
                w.eth_move(z.and_(go, z.not_(hit)), self.address, None, value)
        success = z.or_(success, z.and_(nomatch, enough))
        self.rd_words, self.rd_size = rd_words, rd_size
        for i in range(outsize // 32):
            if i < len(rd_words):
                self._mstore(out + 32 * i, z.ite(success, rd_words[i], self.memory.get(out + 32 * i, 0)))
        return z.word(success)


def world_eth(world, m):
    """Give an integer world the ETH model of the bit-level model m (same accounts, same switch)."""
    if getattr(m, "eth_on", False):
        world.eth_on = True
        world.eth_users = list(m.user_addrs)
        world.attackers = {m.attacker} if getattr(m, "attacker", None) is not None else set()


def pay_in(world, caller, to, cv):
    """A transaction's value moves from the caller to the called contract before it runs; the caller
    must own it (otherwise the chain rejects the transaction). Returns the balances to restore if
    the call reverts (empty when nothing is paid)."""
    if is_c(cv) and cv == 0:
        return {}
    z = world.z
    world.assume.append(zi(cv) <= zi(world.eth_of(caller)))
    before = world.eth_snapshot()
    world.eth_move(True, caller, to, cv)
    return before


# ------------------------------------------------------------------ rules over integers
class ZBit:
    def __init__(self, e): self.e = e
    def __and__(self, o): return ZBit(_and(self.e, _zb(o)))
    def __or__(self, o): return ZBit(_or(self.e, _zb(o)))
    def __invert__(self): return ZBit(_not(self.e))
    def implies(self, o): return (~self) | o


def _zb(o): return o.e if isinstance(o, ZBit) else bool(o)
def _and(a, b): return False if a is False or b is False else (b if a is True else (a if b is True else z3.And(a, b)))
def _or(a, b): return True if a is True or b is True else (b if a is False else (a if b is False else z3.Or(a, b)))
def _not(a): return (not a) if isinstance(a, bool) else z3.Not(a)
def _zw(o): return o.e if isinstance(o, ZWord) else zi(o)


class ZWord:
    """A rule value in the proof engine: an exact mathematical integer."""
    def __init__(self, e): self.e = zi(e)
    def zext(self, n): return self
    def wide(self): return self
    def __add__(self, o): return ZWord(self.e + _zw(o))
    def __sub__(self, o): return ZWord(self.e - _zw(o))
    def rsub(self, k): return ZWord(zi(k) - self.e)
    def rfloordiv(self, k): return ZWord(z3.If(self.e == 0, 0, zi(k) / self.e))
    def __mul__(self, o): return ZWord(self.e * _zw(o))
    def __floordiv__(self, o):
        d = _zw(o)
        return ZWord(z3.If(d == 0, 0, self.e / d))
    def __lt__(self, o): return ZBit(self.e < _zw(o))
    def __gt__(self, o): return ZBit(self.e > _zw(o))
    def __le__(self, o): return ZBit(self.e <= _zw(o))
    def __ge__(self, o): return ZBit(self.e >= _zw(o))
    def __eq__(self, o): return ZBit(self.e == _zw(o))
    def __ne__(self, o): return ZBit(self.e != _zw(o))
    __hash__ = None


class ZTx:
    def __init__(self, prover, fn_name, contract_name, args, caller, ret, reverted, pre, post, probe=None):
        self.p, self._fn, self._cn = prover, fn_name, contract_name
        self._args, self._pre, self._post = args, pre, post
        self.sender = ZWord(caller)
        self.ret = ZWord(ret)
        self.ok = ZBit(_not(reverted))
        self.reverted = ZBit(reverted)
        self.probe = probe  # set of accessed features, when probing a rule's shape
        self._now = ZWord(0)

    def _touch(self, what):
        if self.probe is not None:
            self.probe.add(what)

    @property
    def now(self):
        self._touch("arg")  # the call's time is an input of the call, not part of the state
        return self._now

    def called(self, name):
        self._touch("called")
        primary = self._cn == self.p.m.contracts[0][0].name  # a bare name means the contract under test
        return ZBit(name == f"{self._cn}.{self._fn}" or (primary and name == self._fn))

    def arg(self, j):
        self._touch("arg")
        return ZWord(self._args[j] if j < len(self._args) else 0)

    def pre(self, var, *keys):
        self._touch("pre")
        return self.p.read(self._pre, var, keys)

    def post(self, var, *keys): return self.p.read(self._post, var, keys)
    def pre_sum(self, var, *field):
        self._touch("pre")
        return self.p.total(self._pre, var, *field)
    def post_sum(self, var, *field): return self.p.total(self._post, var, *field)


# ------------------------------------------------------------------ the prover
class Prover:
    def __init__(self, model):
        """model: a bit-level proofofbug.model.Model (reused for contracts, addresses, layout)."""
        self.m = model
        self.z = None
        # every function, a function with dynamic arguments once per calldata variant (yul.length_variants,
        # as in every engine): a rule is proven for it only when it is proven for every variant
        from .yul import length_variants
        self.funcs_v = []
        for f in model.funcs:
            lv = length_variants(f[4])
            self.funcs_v += [f] if lv is None else [f[:4] + (vt,) for vt in lv[0]]

    def read(self, store, var, keys):
        if var == "ETH":
            if not getattr(self.m, "eth_on", False):
                raise Unsupported("ETH balances (the contracts do not handle ETH)")
            who = keys[0].e if isinstance(keys[0], ZWord) else keys[0]
            known = sorted({a for _, a in self.m.contracts} | set(self.m.user_addrs))
            z = self.z
            if is_c(who):
                return ZWord(store.get(who, {}).get(ETH_SLOT, 0))
            acc = 0
            for k in known:
                acc = z.ite(z.eq(who, k), store.get(k, {}).get(ETH_SLOT, 0), acc)
            return ZWord(acc)
        con, a, v = self.m.resolve(var)
        z = self.z
        field = keys[-1] if keys and isinstance(keys[-1], str) else None
        if field is not None:
            keys = keys[:-1]
            extra, f_off, f_bytes = con.field(v, len(keys), field)
        opts = [(True, con.storage[v])]
        for k in keys:
            new = []
            for cond, s in opts:
                kv = k.e if isinstance(k, ZWord) else k
                if is_c(kv):
                    new.append((cond, mapping_slot(kv, s)))
                elif isinstance(kv, z3.ArithRef) and z3.is_int_value(z3.simplify(kv)):
                    new.append((cond, mapping_slot(z3.simplify(kv).as_long(), s)))
                else:
                    for kk in self.m.key_universe:
                        new.append((z.and_(cond, kv == kk), mapping_slot(kk, s)))
            opts = new
        if field is not None:
            opts = [(cond, s_ + extra) for cond, s_ in opts]
        acc = 0
        for cond, s in opts:
            acc = z.ite(cond, store[a].get(s, 0), acc)
        if field is not None:
            if f_off or f_bytes < 32:
                acc = z.band(z.shr(8 * f_off, acc), (1 << (8 * f_bytes)) - 1)
        elif not keys:
            off, n = con.storage_offset[v], con.storage_bytes[v]
            if off or n < 32:
                acc = z.band(z.shr(8 * off, acc), (1 << (8 * n)) - 1)
        return ZWord(acc)

    def total(self, store, var, *field):
        acc = ZWord(0)
        for kk in self.m.key_universe:
            acc = acc + self.read(store, var, (kk,) + field)
        return acc

    def fresh_state(self, pinned):
        """Arbitrary storage respecting each variable's type (field sizes), except pinned slots."""
        z, m = self.z, self.m
        storage = {}
        if getattr(m, "eth_on", False):  # every account holds an arbitrary balance
            for a in sorted({a for _, a in m.contracts} | set(m.user_addrs)):
                storage.setdefault(a, {})[ETH_SLOT] = z.fresh(f"eth{hex(a)}")
        for con, a in m.contracts:
            st = storage.setdefault(a, {})
            by_slot = {}
            for var, slot in con.storage.items():
                by_slot.setdefault(slot, []).append(var)
            for var, base in con.storage.items():
                depth = con.mapping_depth(var)
                t = con.storage_types[var]
                for _ in range(depth):
                    t = con.types[t]["value"]
                nbytes = int(con.types.get(t, {}).get("numberOfBytes", 32))
                hi = 1 if "bool" in con.types.get(t, {}).get("label", "") else (1 << (8 * nbytes)) - 1
                if depth == 0:
                    if base in st:
                        continue
                    fields = by_slot[base]
                    val = None
                    for fv in fields:
                        ft = con.types.get(con.storage_types[fv], {})
                        fhi = 1 if "bool" in ft.get("label", "") else (1 << (8 * con.storage_bytes[fv])) - 1
                        part = z.shl(8 * con.storage_offset[fv], z.fresh(f"{con.name}.{fv}", hi=fhi))
                        val = part if val is None else z.bor(val, part)
                    st[base] = val
                elif depth == 1:
                    for k in m.key_universe:
                        st[mapping_slot(k, base)] = z.fresh(f"{con.name}.{var}[{hex(k)}]", hi=hi)
                else:
                    for k1 in m.key_universe:
                        for k2 in m.key_universe:
                            st[mapping_slot(k2, mapping_slot(k1, base))] = z.fresh(
                                f"{con.name}.{var}[{hex(k1)}][{hex(k2)}]", hi=hi)
        for (a, s), v in pinned.items():
            storage[a][s] = v
        return storage

    def run_function(self, f, pinned):
        """Execute one call of function f from an arbitrary state. Returns (tx, pre, post, assumptions)."""
        m = self.m
        self.z = z = Z()
        pre = self.fresh_state(pinned)
        storage = {a: dict(s) for a, s in pre.items()}
        world = ZWorld(z, m.world.codes, storage, m.key_universe)
        world.pre = pre
        world_eth(world, m)
        a, name, sig, sel, types = f
        args = []
        for j, ty in enumerate(types):
            if str(ty).startswith("const:"):  # a known offset or length of this calldata variant
                v = int(ty[6:])
            elif ty == "address":
                v = z.fresh(f"arg{j}", hi=(1 << 160) - 1)
            elif ty == "bool":
                v = z.fresh(f"arg{j}", hi=1)
            else:
                v = z.fresh(f"arg{j}")
            args.append(v)
        caller = z.fresh("caller", hi=max(m.user_addrs))
        world.assume.append(z3.Or(*[caller == u for u in m.user_addrs]))
        # any time at all: from an arbitrary state the clock is unconstrained (sound over-approximation)
        now = z.fresh("now", hi=(1 << 64) - 1)
        blk = z.fresh("block", hi=(1 << 64) - 1)  # block number: as unconstrained as the clock
        # a payable function receives any amount the caller owns
        cv = z.fresh("callvalue") if sig in getattr(m, "payable", ()) else 0
        before = pay_in(world, caller, a, cv)
        env = ZEnv(sel, args, caller, calldatasize=4 + 32 * len(types), timestamp=now, callvalue=cv, number=blk)
        ex = ZExec(world, a, env).run()
        if before:
            world.eth_restore(ex.reverted, before)
        ret = ex.ret_words[0] if ex.ret_words else 0
        cname = next(c.name for c, addr in m.contracts if addr == a)
        tx = ZTx(self, name, cname, args, caller, ret, ex.reverted, pre, storage)
        tx._now = ZWord(now)
        return tx, pre, storage, world.assume, z

    def shape(self, rule):
        """Which parts of a transaction a rule looks at. A rule that only reads the state after
        the call is a state invariant, which induction may assume holds before the call."""
        probe = set()
        self.z = Z()
        dummy = {a: {} for _, a in self.m.contracts}
        tx = ZTx(self, "", "", [0] * 8, 0, 0, False, dummy, dummy, probe=probe)
        rule(tx)
        return probe

    def discover(self, init, timeout=10):
        """Find simple invariants automatically: 'this plain variable keeps its deployed value'.
        Every plain slot starts as a candidate. Each round, every function runs from a state in
        which all remaining candidates hold (their values are substituted), and any candidate a
        function can change is dropped. What survives is inductive, so it is a proven invariant
        and may be substituted in the main proof (it also makes call targets concrete)."""
        cands = dict(init)
        changed = True
        while changed and cands:
            changed = False
            for f in self.funcs_v:
                try:
                    tx, pre, post, assume, z = self.run_function(f, cands)
                except Unsupported:
                    continue
                for key, v in list(cands.items()):
                    a, s = key
                    st, _ = self._solve(list(z.facts) + [x for x in assume if x is not True]
                                        + [zi(post[a].get(s, 0)) != v], timeout)
                    if st != "proven":
                        del cands[key]
                        changed = True
        return cands

    def _hint_instances(self, hints):
        """Invariant hints: fn(tx) or fn(tx, user) returning 1 when broken; per-user hints are
        instantiated for every account in the key universe."""
        import inspect
        out = {}
        for name, fn in (hints or {}).items():
            if len(inspect.signature(fn).parameters) == 2:
                for u in self.m.key_universe:
                    out[f"{name}[{hex(u)}]"] = (lambda f_, u_: (lambda tx: f_(tx, u_)))(fn, u)
            else:
                out[name] = fn
        return out

    def prove(self, rules, init=None, timeout=60, lemmas=True, invariants=None):
        """Prove every rule by induction. Returns {rule: {"status", "detail", "seconds", "lemmas"}}.
        `invariants` are extra facts (hints) proven together with the rules and then assumed."""
        hints = self._hint_instances(invariants)
        if hints and init is not None:  # a hint must hold in the deployed state before it can be used
            from .check import CTx
            for hn, hf in hints.items():
                ctx = CTx(self.m, {"to": self.m.contracts[0][1], "fn": "", "args": [], "sender": 0},
                          {"slots": init, "ok": True, "ret": 0}, init)
                if hf(ctx).b:
                    raise ValueError(f"invariant hint {hn} does not hold in the deployed state")
        all_rules = dict(rules)
        all_rules.update({f"hint:{n}": f for n, f in hints.items()})
        rules = all_rules
        results = {n: {"status": "proven", "detail": [], "seconds": 0.0, "lemmas": set(), "notes": set(),
                       "invariants": []} for n in rules}
        if self.m.attacker is not None:
            for r in results.values():
                r["status"], r["detail"] = "unsupported", ["attacker callbacks are not modelled in the integer engine yet"]
            return results
        lemma_ok = check_lemmas() if lemmas else {}
        kept = self.discover(init or {})
        invariants = {n: r for n, r in rules.items() if not (self.shape(r) & {"pre", "arg", "called"})}
        for r in results.values():
            r["invariants"] = [f"{self._slot_name(a, s)} == {v}" for (a, s), v in kept.items()]
        for f in self.funcs_v:
            try:
                tx, pre, post, assume, z = self.run_function(f, kept)
            except Unsupported as e:
                for r in results.values():
                    r["status"] = "unsupported"
                    r["detail"].append(f"{f[1]}: {e}")
                continue
            # induction hypothesis: proven invariants are substituted (kept); every rule that is a
            # state invariant is assumed to hold before the call
            hyp = []
            for iname, irule in invariants.items():
                before = ZTx(self, "", "", [], 0, 0, False, pre, pre)
                hyp.append(_not(irule(before).e))
            # vacuity check: the assumptions must allow at least one successful call, otherwise
            # "no counterexample" would be true for the wrong reason
            ctx_ok = list(z.facts) + [x for x in assume if x is not True] + [h for h in hyp if h is not True]
            st_v, _ = self._solve(ctx_ok + [_not(tx.reverted.e)], timeout)
            if st_v == "proven":  # unsat: no successful call is possible under the assumptions
                st_r, _ = self._solve(list(z.facts) + [_not(tx.reverted.e)], timeout)
                if st_r != "proven":  # but without them a successful call exists: assumptions too strong
                    for r in results.values():
                        if r["status"] == "proven":
                            r["status"] = "vacuous"
                        r["detail"].append(f"{f[1]}: the proof's assumptions rule out every successful call")
                    continue
            for rname, rule in rules.items():
                if results[rname]["status"] in ("unsupported", "vacuous"):
                    continue
                bad = rule(tx).e
                if bad is False:
                    continue
                t0 = time.time()
                status, used, detail = self._check(z, assume, hyp, bad, timeout, lemma_ok if lemmas else {})
                res = results[rname]
                res["seconds"] = round(res["seconds"] + time.time() - t0, 3)
                res["lemmas"] |= used
                res["notes"] |= z.notes
                if status != "proven":
                    order = {"proven": 0, "timeout": 1, "not inductive": 2}
                    if order.get(status, 0) >= order.get(res["status"], 0):
                        res["status"] = status
                    res["detail"].append(f"{f[1]}: {detail}")
        for r in results.values():
            r["lemmas"], r["notes"] = sorted(r["lemmas"]), sorted(r["notes"])
        # rules were proven assuming the hints; if any hint failed, those proofs don't count
        failed = [n for n, r in results.items() if n.startswith("hint:") and r["status"] != "proven"]
        out = {}
        for n, r in results.items():
            if n.startswith("hint:"):
                continue
            if failed and r["status"] == "proven":
                r["status"] = "not inductive"
                r["detail"].append("relied on hints that were not proven: " + ", ".join(failed))
            r["hints"] = {k[5:]: results[k]["status"] for k in results if k.startswith("hint:")}
            out[n] = r
        return out

    def _slot_name(self, a, s):
        for con, addr in self.m.contracts:
            if addr == a:
                names = [v for v, sl in con.storage.items() if sl == s and con.mapping_depth(v) == 0]
                if names:
                    return f"{con.name}.{'+'.join(names)}"
        return f"{hex(a)}:{s}"

    def _check(self, z, assume, hyp, bad, timeout, lemma_ok):
        """Is there a state and call where the rule breaks? First plain, then with lemmas."""
        base = list(z.facts) + [x for x in assume if x is not True] + [h for h in hyp if h is not True] + [bad]
        status, detail = self._solve(base, timeout / 2 if lemma_ok else timeout)
        if status != "timeout" or not lemma_ok:
            return status, set(), detail
        # retry with lemma instances: for every division in this call, the Euclid bounds,
        # and for every pair of divisions sharing a numerator shape, the floor-swap identity
        extra, used = [], set()
        if lemma_ok.get("euclid-bound"):
            for n, d, q, r in z.divs:
                extra += [z3.Implies(d > 0, z3.And(q * d <= n, n < q * d + d))]
                used.add("euclid-bound")
        status, detail = self._solve(base + extra, timeout / 2)
        return status, used, detail

    @staticmethod
    def _solve(constraints, timeout):
        s = z3.Solver()
        s.set("timeout", int(timeout * 1000))
        s.add(*[c for c in constraints if c is not True])
        if any(c is False for c in constraints):
            return "proven", ""
        r = s.check()
        if r == z3.unsat:
            return "proven", ""
        if r == z3.sat:
            mdl = s.model()
            shown = ", ".join(f"{d.name()}={mdl[d]}" for d in sorted(mdl.decls(), key=lambda d: d.name())
                              if "!" in d.name() and not d.name().startswith(("mulwrap", "q!", "r!", "and!", "or!", "xor!")))
            # the call itself (arguments, caller, time, value) as data, so the counterexample can be
            # replayed on the real EVM from a reachable state (see proofofbug.cexreplay)
            call = {}
            for d in mdl.decls():
                base = d.name().split("!")[0]
                if base.startswith("arg") or base in ("caller", "now", "block", "callvalue"):
                    try:
                        call[base] = mdl[d].as_long()
                    except Exception:
                        pass
            Prover.last_cex = call
            return "not inductive", f"breaks from state {shown[:300]} || CALL {json.dumps(call)}"
        return "timeout", "no answer within the budget"
