"""Symbolic execution of Yul into a NAND circuit.

Values
  A value is a Python int (a constant, folded with exact 256-bit EVM semantics) or a
  symbolic word. Symbolic words keep their real bit positions inside the 256-bit EVM
  word: a list of W signals means bits 0..W-1; a dict {bit position: signal} can hold
  bits anywhere (packed storage fields, shifted values). Arithmetic (add, mul, div...)
  works on the low W bits ("a W-bit EVM"), while bitwise operations, constant shifts and
  comparisons are exact, so Solidity's packing code (shift, mask, or) is modelled exactly.

Control flow
  Every branch is evaluated; writes are guarded by the current `active` signal, so the
  circuit selects the right result. Calls between contracts run the callee's code as a
  nested frame over a shared world of storage, with rollback if the callee reverts.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from .circuit import Circuit, FALSE, TRUE

U256 = (1 << 256) - 1
PANIC_SELECTOR = 0x4E487B71 << 224


class Unsupported(Exception):
    pass


def s256(v):
    return v - (1 << 256) if v >> 255 else v


CONST_OPS = {
    "add": lambda a, b: (a + b) & U256, "sub": lambda a, b: (a - b) & U256,
    "mul": lambda a, b: (a * b) & U256, "div": lambda a, b: a // b if b else 0,
    "mod": lambda a, b: a % b if b else 0,
    "sdiv": lambda a, b: (abs(s256(a)) // abs(s256(b)) * (1 if (s256(a) < 0) == (s256(b) < 0) else -1)) & U256 if b else 0,
    "exp": lambda a, b: pow(a, b, 1 << 256),
    "lt": lambda a, b: int(a < b), "gt": lambda a, b: int(a > b),
    "slt": lambda a, b: int(s256(a) < s256(b)), "sgt": lambda a, b: int(s256(a) > s256(b)),
    "eq": lambda a, b: int(a == b), "and": lambda a, b: a & b, "or": lambda a, b: a | b,
    "xor": lambda a, b: a ^ b, "shl": lambda s, v: (v << s) & U256 if s < 256 else 0,
    "shr": lambda s, v: v >> s if s < 256 else 0, "sar": lambda s, v: (s256(v) >> min(s, 256)) & U256,
    "byte": lambda i, v: (v >> (8 * (31 - i))) & 0xFF if i < 32 else 0,
    "signextend": lambda b, x: (s256(x << (248 - 8 * b) & U256) >> (248 - 8 * b)) & U256 if b < 31 else x,
}
CONST_UNARY = {"iszero": lambda a: int(a == 0), "not": lambda a: U256 ^ a}


# Every storage slot hash an engine computed (mapping slots, array bases): adding an unknown offset to one of
# these is an array element access (keccak(p) + i), resolved over ARRAY_SPAN offsets like mapping keys over the
# key universe; a path that reaches past them is left out and reported, never guessed.
HASHES = set()
ARRAY_SPAN = 16  # slots an array element offset may reach (e.g. 4 elements of a 4-slot struct; reported)


def keccak_int(data: bytes) -> int:
    from Crypto.Hash import keccak
    h = keccak.new(digest_bits=256)
    h.update(data)
    return int.from_bytes(h.digest(), "big")


def mapping_slot(key: int, base: int) -> int:
    """Solidity storage slot of mapping[key] for a mapping at slot `base`."""
    return keccak_int(key.to_bytes(32, "big") + base.to_bytes(32, "big"))


@dataclass
class SymSlot:
    """A storage slot that depends on a symbolic mapping key: one concrete slot per
    possible key in the key universe, each with the condition under which it is the one."""
    options: list  # [(condition signal, slot int)]

    def shifted(self, k):
        return SymSlot([(c, (sl + k) & U256) for c, sl in self.options])


@dataclass
class Selector:
    """The value of shr(224, calldataload(0)): which function was called."""
    pass


CHOICE_MAX = 128  # most options a Choice keeps; past that the value is an ordinary circuit value (dead-path
# combinations, e.g. a fee read as an offset on a path that reverts, push correlated values past 32)


@dataclass(eq=False)
class Choice:
    """A value that is one of a few known constants: [(condition, int)], the conditions mutually exclusive
    and covering every path on which the value exists. It arises where branches that computed different
    constants join (a length, an offset, the free memory pointer, a return size). Memory, copies, hashes,
    calls and returns then act once per option under its condition (Exec.builtin), so a length or address
    that is "5 or 7" is never treated as an unknown number; everything else sees the exact circuit value
    (Vals.as_dict). The same idea as SymSlot, for numbers."""
    options: list  # [(condition, int, source)]: source = ((source id, value), ...) it was computed from
    bits: dict = None  # the circuit value, built once when first needed
    # (condition, value): where the value is none of the constants, it is this ordinary value (e.g. what a
    # call that returned nothing left in memory). Exact everywhere; a builtin that needs a known address or
    # size leaves that region's paths out and counts them (World.rest_cuts), it never guesses there.
    rest: tuple = None


def choice_rest(v):
    return v.rest if isinstance(v, Choice) else None


_SOURCES = [0]


def new_source(c, conds):
    """A Choice that is an input of its own (e.g. a bytes length): [(condition, value)]. Its options
    remember the source, so values computed from the same source are combined consistently (a pointer and
    a size that both follow one length are not 'any pointer with any size')."""
    _SOURCES[0] += 1
    sid = _SOURCES[0]
    return make_choice(c, [(cond, v, ((sid, v),)) for cond, v in conds])


def _merge_src(a, b):
    d = dict(a)
    for k, v in b:
        if d.get(k, v) != v:
            return None  # two different values of one source: this combination cannot happen
        d[k] = v
    return tuple(sorted(d.items()))


def choice_opts(v):
    """The options (condition, constant, source) of a constant or a Choice; None for any other value."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return [(TRUE, v, ())]
    if isinstance(v, Choice):
        return v.options
    return None


def make_choice(c, opts, rest=None):
    """Join (condition, constant[, source]) options into a constant, a Choice, or None when there are too
    many. Options with the same constant merge: their conditions are or-ed, their sources keep what they
    agree on. `rest` = (condition, value) where it is none of them."""
    if rest is not None and rest[0] == FALSE:
        rest = None
    by = {}
    for o in opts:
        cond, x, src = o if len(o) == 3 else (o[0], o[1], ())
        if cond == FALSE:
            continue
        if x in by:
            c0, s0 = by[x]
            by[x] = (c.or_(c0, cond), tuple(kv for kv in s0 if kv in src))
        else:
            by[x] = (cond, tuple(src))
    if not by:
        return rest[1] if rest is not None else 0
    if len(by) == 1 and rest is None:  # every path that has the value has this one
        return next(iter(by))
    if len(by) > CHOICE_MAX:
        return None
    return Choice([(cond, x, src) for x, (cond, src) in by.items()], rest=rest)


# ---------------------------------------------------------------- value layer
ETH_SLOT = (1 << 256) - 1  # an account's ETH balance is kept as this pseudo storage slot


def eth_get(world, a):
    return world.storage.setdefault(a, {}).get(ETH_SLOT, 0)


def eth_move(vals, world, cond, frm, to, v):
    """Move v wei from frm to to (None: out of the modelled world) where cond holds. The caller
    has checked frm can pay. A receiver going past 2^W is a width artefact."""
    c = vals.c
    if cond == FALSE or (isinstance(v, int) and v == 0):
        return
    vw = vals.word(v)
    st = world.storage.setdefault(frm, {})
    st[ETH_SLOT] = vals.mux(cond, c.sub(vals.word(eth_get(world, frm)), vw)[0], st.get(ETH_SLOT, 0))
    if to is not None:
        tt = world.storage.setdefault(to, {})
        new, carry = c.add(vals.word(eth_get(world, to)), vw)
        world.flag(c.and_(cond, carry))
        tt[ETH_SLOT] = vals.mux(cond, new, tt.get(ETH_SLOT, 0))


def eth_restore(vals, world, cond, before):
    """Undo ETH moves where cond holds: before = {address: balance}."""
    for a, old in before.items():
        st = world.storage.setdefault(a, {})
        if st.get(ETH_SLOT, 0) is not old:
            st[ETH_SLOT] = vals.mux(cond, old, st.get(ETH_SLOT, 0))


def copy_words(off, size, words, base=4, mask=None):
    """calldatacopy over word-structured calldata (selector, then 32-byte words): the words copied
    from byte offset `off`, `size` bytes, past the end reading 0, as on the EVM. Only word-aligned
    copies are modelled; a final partial word is copied only when it is a known number (its bytes
    beyond `size` are cleared, as the EVM copies exactly `size` bytes into zeroed scratch)."""
    if size == 0:
        return []
    if off < base or (off - base) % 32:
        raise Unsupported("calldatacopy at an unaligned offset")
    first, n, rem = (off - base) // 32, (size + 31) // 32, size % 32
    out = [words[first + i] if first + i < len(words) else 0 for i in range(n)]
    if rem:
        last = out[-1]
        if not isinstance(last, int):
            if mask is None:
                raise Unsupported("calldatacopy of a partial word with a computed value")
            out[-1] = mask(last, rem)  # its first `rem` bytes, the rest cleared
        else:
            out[-1] = last >> (8 * (32 - rem)) << (8 * (32 - rem))
    return out


def type_bound(v):
    """2^k - 1, 2^k and the signed bounds for a Solidity integer type of k bits: comparisons with
    these are overflow/range guards. A W-bit model never reaches them, exactly as it never overflows
    uint256 (that is the width artefact rule), so they do not ask for a wider model."""
    for k in range(8, 257, 8):
        if v in ((1 << k) - 1, 1 << k, (1 << (k - 1)) - 1, 1 << (k - 1)):
            return True
    return False


class Vals:
    """Operations on values (int | list of W signals | {position: signal})."""

    width_need = 0  # largest constant (in bits) compared against a value that only has W bits
    width_why = ""
    magnitude = set()  # behaviour above W bits the model cannot reach (casts, narrow-type range checks)
    # addresses outside the model's universe (the deployer/test runner): every sender and address
    # argument is a universe address, so comparing one with these is exactly false at any width
    identities = {0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496}

    def __init__(self, c: Circuit, W: int):
        self.c, self.W = c, W

    def as_dict(self, v):
        if isinstance(v, int):
            return {p: TRUE for p in range(v.bit_length()) if (v >> p) & 1}
        if isinstance(v, Choice):  # exact: exactly one option's condition (or the rest's) holds
            if v.bits is None:
                top = max(x.bit_length() for _, x, _ in v.options)
                bits = {p: [cond for cond, x, _ in v.options if (x >> p) & 1] for p in range(top)}
                if v.rest is not None:
                    rc, rv = v.rest
                    for p, s in self.as_dict(rv).items():
                        bits.setdefault(p, []).append(self.c.and_(rc, s))
                v.bits = {p: s for p, ss in bits.items() if (s := self.c.any_(ss)) != FALSE}
            return v.bits
        if isinstance(v, list):
            return {i: b for i, b in enumerate(v) if b != FALSE}
        if isinstance(v, dict):
            return v
        if isinstance(v, SymSlot):
            raise Unsupported("a hashed storage slot is used as a number")
        raise Unsupported("function selector used outside the dispatcher")

    def norm(self, d):
        d = {p: s for p, s in d.items() if s != FALSE}
        if all(s == TRUE for s in d.values()):
            return sum(1 << p for p in d)
        if all(p < self.W for p in d):
            return [d.get(i, FALSE) for i in range(self.W)]
        return d

    def word(self, v):
        """The low W bits, for arithmetic. Higher bits are dropped (W-bit EVM)."""
        if isinstance(v, int):
            return Circuit.const_word(v, self.W)
        if isinstance(v, list):
            return v
        d = self.as_dict(v)
        return [d.get(i, FALSE) for i in range(self.W)]

    def truthy(self, v):
        if isinstance(v, int):
            return TRUE if v else FALSE
        return self.c.any_(list(self.as_dict(v).values()))

    def bit(self, b):
        return b if b in (FALSE, TRUE) else [b] + [FALSE] * (self.W - 1)

    def mux(self, s, a, b, keep=False):
        """s ? a : b. Known constants on both sides stay known (a Choice). With keep (memory and return
        data, where offsets and pointers live), or when one side already is a Choice, a side that is an
        ordinary value becomes the Choice's rest instead of turning the whole value into an unknown."""
        if s == TRUE:
            return a
        if s == FALSE:
            return b
        if isinstance(a, int) and isinstance(b, int) and a == b:
            return a
        if isinstance(a, SymSlot) or isinstance(b, SymSlot):
            return a  # a hashed slot is only meaningful on the path that computed it
        oa, ob = choice_opts(a), choice_opts(b)
        general = lambda v: isinstance(v, (list, dict))
        if oa is not None or ob is not None:
            ns = self.c.not_(s)
            if oa is None and not ((keep or isinstance(b, Choice)) and general(a)):
                oa = None
            elif ob is None and not ((keep or isinstance(a, Choice)) and general(b)):
                ob = None
            else:
                opts, rests = [], []
                for side, cond, v, o in ((a, s, a, oa), (b, ns, b, ob)):
                    if o is None:
                        rests.append((cond, v))  # this whole side is an ordinary value
                    else:
                        # provenance: these options exist only where s is (or is not) true, so a value derived from
                        # the other side of the same s can never be combined with them (see _combos)
                        tag = (("s", s), 1 if side is a else 0)
                        for cc, x, sr in o:
                            m_ = _merge_src(sr, (tag,))
                            if m_ is not None:  # an option from the other side of this same s cannot exist here
                                opts.append((self.c.and_(cond, cc), x, m_))
                        r = choice_rest(v)
                        if r is not None:
                            rests.append((self.c.and_(cond, r[0]), r[1]))
                rest = None
                if len(rests) == 1:
                    rest = rests[0]
                elif len(rests) == 2:
                    rest = (self.c.or_(rests[0][0], rests[1][0]), self._plain_mux(s, rests[0][1], rests[1][1]))
                ch = make_choice(self.c, opts, rest)
                if ch is not None:
                    return ch
        return self._plain_mux(s, a, b)

    def _plain_mux(self, s, a, b):
        if isinstance(a, int) and isinstance(b, int) and a == b:
            return a
        if isinstance(a, list) and isinstance(b, list):
            return self.c.wmux(s, a, b)
        da, db = self.as_dict(a), self.as_dict(b)
        return self.norm({p: self.c.mux(s, da.get(p, FALSE), db.get(p, FALSE)) for p in set(da) | set(db)})

    def bitop(self, op, a, b):
        c = self.c
        if isinstance(a, list) and isinstance(b, list):
            return {"and": c.wand, "or": c.wor, "xor": c.wxor}[op](a, b)
        da, db = self.as_dict(a), self.as_dict(b)
        if op == "and":
            for k_, v_ in ((a, b), (b, a)):
                # a mask 2^k - 1 on a computed value is a truncating cast (uint128(x)...): above W bits the
                # model cannot see it cut anything off (C11's bug lived there). Address masks are routine.
                if isinstance(k_, int) and not isinstance(v_, int) and k_ & (k_ + 1) == 0 \
                        and self.W < k_.bit_length() < 256 and k_.bit_length() != 160:
                    Vals.magnitude.add(f"truncation to {k_.bit_length()} bits (a cast)")
            return self.norm({p: c.and_(da[p], db[p]) for p in set(da) & set(db)})
        f = c.or_ if op == "or" else c.xor
        return self.norm({p: f(da.get(p, FALSE), db.get(p, FALSE)) for p in set(da) | set(db)})

    def bnot(self, a):
        d = self.as_dict(a)
        return self.norm({p: self.c.not_(d.get(p, FALSE)) for p in range(256)})

    def shift_const(self, op, k, v):
        d = self.as_dict(v)
        if op == "shl":
            return self.norm({p + k: s for p, s in d.items() if p + k < 256})
        out = {p - k: s for p, s in d.items() if p >= k}
        if op == "sar":
            sign = d.get(255, FALSE)
            for p in range(max(0, 256 - k), 256):
                out[p] = sign
        return self.norm(out)

    def _pressure(self, a, b):
        """A comparison of a W-bit unknown with a constant wider than W bits is decided by
        width alone (e.g. amt >= 2^62 is always false). Record how wide the model must be."""
        for x, y in ((a, b), (b, a)):
            if isinstance(x, int) and not isinstance(y, int) and type_bound(x) and self.W < x.bit_length() < 256 \
                    and x.bit_length() not in (160, 161):
                # a range guard for a narrower type (e.g. uint128): the model cannot reach it; say so
                Vals.magnitude.add(f"range check of a {x.bit_length() if x & (x + 1) == 0 else x.bit_length() - 1}-bit type")
            if isinstance(x, int) and not isinstance(y, int) and self.W < x.bit_length() <= 200 \
                    and x not in Vals.identities and not type_bound(x):
                if all(p < self.W for p in self.as_dict(y)):
                    if x.bit_length() > Vals.width_need:
                        Vals.width_why = f"comparison with constant {x:#x}"
                    Vals.width_need = max(Vals.width_need, x.bit_length())

    def _aligned(self, a, b):
        self._pressure(a, b)
        da, db = self.as_dict(a), self.as_dict(b)
        pos = sorted(set(da) | set(db))
        return [da.get(p, FALSE) for p in pos], [db.get(p, FALSE) for p in pos], pos

    def eq(self, a, b):
        x, y, _ = self._aligned(a, b)
        return self.c.iszero(self.c.wxor(x, y)) if x else TRUE

    def ult(self, a, b):
        if isinstance(a, list) and isinstance(b, list):
            return self.c.lt(a, b)
        self._pressure(a, b)
        x, y, _ = self._aligned(a, b)
        return self.c.lt(x, y) if x else FALSE

    def slt(self, a, b):
        da, db = self.as_dict(a), self.as_dict(b)
        if all(p < self.W for p in list(da) + list(db)):
            return self.c.slt(self.word(a), self.word(b))  # W-bit signed, as in a W-bit EVM
        pos = sorted(set(da) | set(db) | {255})
        x = [da.get(p, FALSE) for p in pos]
        y = [db.get(p, FALSE) for p in pos]
        return self.c.slt(x, y)

    def extract(self, v, offset_bytes, nbytes):
        """A packed field: (v >> 8*offset) & (2^(8*nbytes) - 1)."""
        if isinstance(v, int):
            return (v >> (8 * offset_bytes)) & ((1 << (8 * nbytes)) - 1)
        v = self.shift_const("shr", 8 * offset_bytes, v) if offset_bytes else v
        if nbytes >= 32:
            return v
        return self.bitop("and", v, (1 << (8 * nbytes)) - 1)


# ---------------------------------------------------------------- world
@dataclass
class Code:
    """A deployed contract the circuit can execute."""
    name: str
    block: dict  # Yul AST of the deployed code
    immutables: dict  # loadimmutable id -> value
    functions: dict = field(default_factory=dict)  # Yul function name -> definition


@dataclass
class TxEnv:
    """Inputs of one call frame."""
    fn_onehot: dict  # selector -> signal; None means: compare the selector word
    args: list  # calldata words after the selector
    caller: object
    calldatasize: int = 4
    selector_word: object = None
    callvalue: object = 0
    timestamp: object = 0
    number: object = 1  # block.number: a clock like the timestamp (each transaction may advance it)
    origin: object = None  # tx.origin: the transaction's sender (None: this frame's caller is it)
    fn_args: dict = None  # selector -> that function's own calldata words (dynamic arguments laid out)
    fn_cds: dict = None  # selector -> that function's calldata size


# The chain every model and every replay runs on (Foundry's default chain id): block.chainid is this
# constant, exactly as on the EVM that confirms each finding.
CHAIN_ID = 31337


@dataclass
class Hook:
    """What an attacker contract does when it is called: optionally make one call back
    into the contract that called it, with a solver-chosen function and arguments."""
    on: int
    fn_onehot: dict
    args: list
    used: int = FALSE


class World:
    def __init__(self, c, W, codes: dict, storage: dict, key_universe, attackers=(), max_depth=3, max_unroll=8):
        self.c, self.W = c, W
        self.codes = codes  # address -> Code
        self.storage = storage  # address -> {slot: value}
        for a in codes:
            self.storage.setdefault(a, {})
        self.transient = {a: {} for a in codes}  # EIP-1153: cleared at the start of every transaction
        self.eth_on = False  # ETH balances modelled (set by the Model when a contract handles ETH)
        self.eth_users = []  # accounts without code that can hold ETH
        self.key_universe = list(key_universe)
        self.attackers = set(attackers)
        self.max_depth, self.max_unroll = max_depth, max_unroll
        self.artefact = FALSE  # width overflow, unroll limit, key outside universe, call depth
        self.unroll_hit = False  # some loop may run longer than max_unroll
        self.rest_cuts = set()  # builtins where an address/size outside its known constants left paths out
        self.unroll_signals = []
        self.hook = None  # Hook for the current transaction
        self.hook_fired = FALSE
        for code in codes.values():
            if not code.functions:
                _collect_functions(code.block, code.functions)

    def flag(self, sig):
        self.artefact = self.c.or_(self.artefact, sig)


def _collect_functions(node, out):
    if isinstance(node, dict):
        if node.get("nodeType") == "YulFunctionDefinition":
            out[node["name"]] = node
        for v in node.values():
            _collect_functions(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect_functions(v, out)


class Scope:
    def __init__(self, parent=None):
        self.vars = {}
        self.parent = parent

    def lookup(self, name):
        f = self
        while f is not None:
            if name in f.vars:
                return f
            f = f.parent
        raise Unsupported(f"unknown variable {name}")


# ---------------------------------------------------------------- one call frame
class Exec(Vals):
    def __init__(self, world: World, address: int, env: TxEnv, depth=0, pc0=TRUE, static=False):
        super().__init__(world.c, world.W)
        self.world, self.address, self.env = world, address, env
        self.code = world.codes[address]
        self.depth, self.static = depth, static
        self.memory, self.memraw = {}, {}
        self.enum_depth = 0  # > 0 while a builtin runs once per option of a Choice (see _per_option)
        self.opt = TRUE  # that option's condition: part of every local guard (TRUE otherwise)
        self.cur_args, self.cur_cds = None, None  # inside a function with its own calldata words
        self.gate = pc0  # "this frame runs at all": applied to storage writes and global flags only
        self.pc = [TRUE]  # path condition inside this frame; frame flags (reverted...) are relative to it
        self.halted = self.reverted = self.leave = self.brk = self.cont = FALSE
        self.outer_dead = FALSE  # inside an internal function: the caller had already left/broken
        self.ret_words, self.ret_size = [], 0
        self.ret_sizes = set()  # constant sizes of every reachable return statement
        self.panics = {}
        self.rd_words, self.rd_size = [], 0  # return data of the last call this frame made

    @property
    def storage(self):
        return self.world.storage[self.address]

    @property
    def active(self):
        """Absolute: this statement really executes (used for storage and global effects)."""
        return self.c.and_(self.c.and_(self.gate, self.pc[-1]), self.local_active)

    @property
    def local_active(self):
        """Relative to the current branch being taken: execution has not stopped. Frame-local
        state (flags, memory, variables) is merged with the branch condition where branches
        rejoin, so the condition itself is not repeated here."""
        c = self.c
        return c.and_(self.opt, c.not_(c.or_(c.or_(c.or_(self.halted, self.leave), c.or_(self.brk, self.cont)),
                                             self.outer_dead)))

    def guard(self):
        """Guard for frame-local state (memory, variables, return-data registers).
        Branch conditions are applied when branches rejoin (see merge); a revert/return ends
        the frame so later local writes are irrelevant; only leave/break/continue matter."""
        c = self.c
        # not outer_dead: where the caller has already left, it never reads this frame's local values,
        # so local writes need no guard there (reverts and storage writes do: see local_active)
        return c.and_(self.opt, c.not_(c.or_(self.leave, c.or_(self.brk, self.cont))))

    def snapshot(self, scope):
        scopes, s = [], scope
        while s is not None:
            scopes.append((s, dict(s.vars)))
            s = s.parent
        return {"mem": dict(self.memory), "vars": scopes, "rd": (self.rd_words, self.rd_size),
                "flags": self._flags()}

    FLAGS = ("halted", "reverted", "leave", "brk", "cont")

    def _flags(self):
        return {"bits": {k: getattr(self, k) for k in self.FLAGS}, "panics": dict(self.panics),
                "ret": (self.ret_words, self.ret_size)}

    def restore(self, snap):
        self.memory = dict(snap["mem"])
        for sc, old in snap["vars"]:
            for k, v in old.items():
                sc.vars[k] = v
        self.rd_words, self.rd_size = snap["rd"]
        for k, v in snap["flags"]["bits"].items():
            setattr(self, k, v)
        self.panics = dict(snap["flags"]["panics"])
        self.ret_words, self.ret_size = snap["flags"]["ret"]

    def capture(self, snap):
        return {"mem": dict(self.memory), "vars": [(sc, dict(sc.vars)) for sc, _ in snap["vars"]],
                "rd": (self.rd_words, self.rd_size), "flags": self._flags()}

    def merge(self, snap, branches):
        """Join point: start from the state before the branches and select each branch's
        result under its (mutually exclusive) condition."""
        mem = dict(snap["mem"])
        for cond, st in branches:
            for a in set(mem) | set(st["mem"]):
                b, n = mem.get(a, 0), st["mem"].get(a, 0)
                if n is not b:
                    on, ob = choice_opts(n), choice_opts(b)
                    if a == 0x40 and on is not None and ob is not None and choice_rest(n) is None \
                            and choice_rest(b) is None:
                        # free memory pointer: known positions (constants or choices of them) join to the
                        # largest. Solidity never reads unwritten memory past it, so results are unchanged
                        # (only gas is), and later allocations stay at known addresses
                        mem[a] = max(x for _, x, _ in on + ob)
                    else:
                        mem[a] = self.mux(cond, n, b, keep=True)
        self.memory = mem
        for idx, (sc, old) in enumerate(snap["vars"]):
            cur = dict(old)
            for cond, st in branches:
                new = st["vars"][idx][1]
                for k in old:
                    if new.get(k, old[k]) is not old[k]:
                        cur[k] = self.mux(cond, new[k], cur[k])
            for k, v in cur.items():
                sc.vars[k] = v
        words, size = snap["rd"]
        for cond, st in branches:
            w2, s2 = st["rd"]
            if w2 is not words:
                n = max(len(w2), len(words))
                words = [self.mux(cond, w2[i] if i < len(w2) else 0, words[i] if i < len(words) else 0)
                         for i in range(n)]
            if s2 is not size:
                size = self.mux(cond, s2, size)
        self.rd_words, self.rd_size = words, size
        # frame flags: stopped / reverted / left / break / continue, panics, return data
        bits = dict(snap["flags"]["bits"])
        panics = dict(snap["flags"]["panics"])
        rw, rs = snap["flags"]["ret"]
        for cond, st in branches:
            fl = st["flags"]
            for k in self.FLAGS:
                if fl["bits"][k] != bits[k]:
                    bits[k] = self.c.mux(cond, fl["bits"][k], bits[k])
            for code in set(panics) | set(fl["panics"]):
                a, b = fl["panics"].get(code, FALSE), panics.get(code, FALSE)
                if a != b:
                    panics[code] = self.c.mux(cond, a, b)
            w2, s2 = fl["ret"]
            if w2 is not rw:
                n = max(len(w2), len(rw))
                rw = [self.mux(cond, w2[i] if i < len(w2) else 0, rw[i] if i < len(rw) else 0) for i in range(n)]
            if s2 is not rs:
                rs = self.mux(cond, s2, rs)
        for k, v in bits.items():
            setattr(self, k, v)
        self.panics, self.ret_words, self.ret_size = panics, rw, rs

    def run(self):
        snap = {a: dict(s) for a, s in self.world.storage.items()}
        tsnap = {a: dict(s) for a, s in self.world.transient.items()}
        self.block(self.code.block, Scope())
        if self.panics.get(0x11, FALSE) != FALSE:
            # an overflow panic is a width artefact only if some add/mul exceeded W bits here
            self.world.flag(self.c.and_(self.gate, self.c.and_(self.panics[0x11], self.panics.get("wrap", FALSE))))
        if self.reverted != FALSE:  # roll back every contract's storage on revert
            for a, cur in self.world.storage.items():
                old = snap.get(a, {})
                for s in set(old) | set(cur):
                    if old.get(s, 0) is not cur.get(s, 0):
                        cur[s] = self.mux(self.reverted, old.get(s, 0), cur.get(s, 0))
            for a, cur in self.world.transient.items():
                old = tsnap.get(a, {})
                for s in set(old) | set(cur):
                    if old.get(s, 0) is not cur.get(s, 0):
                        cur[s] = self.mux(self.reverted, old.get(s, 0), cur.get(s, 0))
        return self

    # ---------- statements ----------
    def block(self, blk, scope):
        saved_raw = dict(self.memraw)
        sc = Scope(scope)
        for st in blk["statements"]:
            self.stmt(st, sc)
            if self.active == FALSE:
                break
        self.memraw = saved_raw

    def stmt(self, st, f):
        t = st["nodeType"]
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
            act = self.guard()
            for n, v in zip(names, vals):
                fr = f.lookup(n)
                fr.vars[n] = self.mux(act, v, fr.vars[n])
        elif t == "YulExpressionStatement":
            self.expr_multi(st["expression"], f, None)
        elif t == "YulIf":
            cond = self.truthy(self.expr(st["condition"], f))
            live = self.local_active
            if self.c.and_(live, cond) == FALSE:
                return  # can't run on any path that is still alive
            if self.c.and_(live, self.c.not_(cond)) == FALSE:
                cond = TRUE  # always runs on every path still alive (e.g. after `if iszero(ok) { revert }`)
            snap = self.snapshot(f)
            self.with_pc(cond, lambda: self.block(st["body"], f))
            if cond != TRUE:
                self.merge(snap, [(cond, self.capture(snap))])
        elif t == "YulSwitch":
            self.switch(st, f)
        elif t == "YulForLoop":
            self.for_loop(st, f)
        elif t == "YulBreak":
            self.brk = self.c.or_(self.brk, self.local_active)
        elif t == "YulContinue":
            self.cont = self.c.or_(self.cont, self.local_active)
        elif t == "YulLeave":
            self.leave = self.c.or_(self.leave, self.local_active)
        else:
            raise Unsupported(f"statement {t}")

    def with_pc(self, cond, fn):
        p = self.c.and_(self.pc[-1], cond)
        if p == FALSE:
            return
        self.pc.append(p)
        try:
            fn()
        finally:
            self.pc.pop()

    def switch(self, st, f):
        e = self.expr(st["expression"], f)
        taken = FALSE
        cases = []
        for case in st["cases"]:
            if case["value"] == "default":
                cond = self.c.not_(taken)
            else:
                k = self.literal(case["value"])
                if isinstance(e, Selector):
                    if self.env.fn_onehot is not None:
                        m = self.env.fn_onehot.get(k, FALSE)
                    else:
                        m = self.eq(self.shift_const("shr", 224, self.env.selector_word), k)
                elif isinstance(e, int):
                    m = TRUE if e == k else FALSE
                else:
                    m = self.eq(e, k)
                cond = self.c.and_(m, self.c.not_(taken))
                taken = self.c.or_(taken, m)
            cases.append((cond, case["body"]))
        snap = self.snapshot(f)
        branches = []
        entry = isinstance(e, Selector) and self.depth == 0  # the transaction's own entry point
        for (cond, body), case in zip(cases, st["cases"]):
            if cond == FALSE:
                continue
            # a function with dynamic arguments runs once per variant of its calldata (each with known
            # offsets and lengths), as separate branches of this switch: the merge below joins them
            runs = [(cond, None)]
            if isinstance(e, Selector) and self.env.fn_args and case["value"] != "default":
                own = self.env.fn_args.get(self.literal(case["value"]))
                if own is not None:
                    runs = [(self.c.and_(cond, vc), words) for vc, words in own]
            for rc, words in runs:
                if rc == FALSE:
                    continue
                self.restore(snap)
                saved_cd = (self.cur_args, self.cur_cds)
                if words is not None:
                    self.cur_args, self.cur_cds = words, self.env.fn_cds[self.literal(case["value"])]
                try:
                    self.with_pc(rc, lambda b=body: self.block(b, f))
                except Unsupported as ex:
                    # name the entry point that reached it, so that one function can be left out (bench.build)
                    if entry and case["value"] != "default" and getattr(ex, "entry", None) is None:
                        ex.entry = (self.address, self.literal(case["value"]))
                    raise
                finally:
                    self.cur_args, self.cur_cds = saved_cd
                branches.append((rc, self.capture(snap)))
        if len(branches) == 1 and branches[0][0] == TRUE:
            return
        self.restore(snap)
        self.merge(snap, branches)

    def for_loop(self, st, f):
        outer = Scope(f)
        for s in st["pre"]["statements"]:
            self.stmt(s, outer)
        saved_brk, saved_cont = self.brk, self.cont
        self.brk = FALSE
        loop_pc = self.pc[-1]
        # The running path is carried forward unmerged: inside iteration n every earlier iteration ran, so
        # the counter is exactly n (a constant: storage arrays indexed by it stay exact slots). Where the
        # loop may stop, the state is captured, and the exits are joined once after the loop.
        entry, exits = self.snapshot(outer), []
        for _ in range(self.world.max_unroll):
            cond = self.truthy(self.expr(st["condition"], outer))
            go = self.c.and_(cond, self.c.not_(self.brk))
            stop = self.c.and_(loop_pc, self.c.not_(go))
            if stop != FALSE:
                exits.append((stop, self.capture(entry)))
            loop_pc = self.c.and_(loop_pc, go)
            if loop_pc == FALSE:
                break
            self.pc.append(loop_pc)
            try:
                self.cont = FALSE
                self.block(st["body"], outer)
                self.cont = FALSE
                self.block(st["post"], outer)
            finally:
                self.pc.pop()
        else:
            cond = self.truthy(self.expr(st["condition"], outer))
            # only a path that is still running (not reverted or returned) can run past the limit
            hit = self.c.and_(self.active, self.c.and_(self.c.and_(loop_pc, cond), self.c.not_(self.brk)))
            if hit != FALSE:
                self.world.unroll_hit = True
                self.world.unroll_signals.append(hit)  # checked later: is running past the limit reachable?
            self.world.flag(hit)
        if exits:
            self.merge(self.snapshot(outer), exits)
        self.brk, self.cont = saved_brk, saved_cont

    # ---------- mappings ----------
    def keccak(self, a):
        p, n = a
        if not (isinstance(p, int) and isinstance(n, int)) or n % 32:
            raise Unsupported("keccak256 over a computed or unaligned memory range")
        opts = [(TRUE, [])]
        for i in range(n // 32):
            addr = p + 32 * i
            v = self.memraw.get(addr, self.memory.get(addr, 0))
            new = []
            for cond, words in opts:
                if isinstance(v, int):
                    new.append((cond, words + [v]))
                elif isinstance(v, SymSlot):
                    for c2, sl in v.options:
                        cc = self.c.and_(cond, c2)
                        if cc != FALSE:
                            new.append((cc, words + [sl]))
                else:
                    for kk in self.world.key_universe:
                        cc = self.c.and_(cond, self.eq(v, kk))
                        if cc != FALSE:
                            new.append((cc, words + [kk]))
            opts = new
            if len(opts) > 1024:
                raise Unsupported("too many mapping key combinations")
        slots = [(cond, keccak_int(b"".join(w.to_bytes(32, "big") for w in words))) for cond, words in opts]
        HASHES.update(sl for _, sl in slots)
        if len(slots) == 1 and slots[0][0] == TRUE:
            return slots[0][1]
        return SymSlot(slots)

    def _array_slots(self, bases, off):
        """Slots base + off for an unknown offset: one option per offset 0..ARRAY_SPAN-1 (sload/sstore flag a
        path whose offset is past them, as for mapping keys outside the universe)."""
        opts = []
        for cond, base in bases:
            for j in range(ARRAY_SPAN):
                cc = self.c.and_(cond, self.eq(off, j))
                if cc != FALSE:
                    opts.append((cc, (base + j) & U256))
        return SymSlot(opts)

    def note_outside(self, sym):
        covered = self.c.any_([cond for cond, _ in sym.options])
        self.world.flag(self.c.and_(self.active, self.c.not_(covered)))

    # ---------- expressions ----------
    def literal(self, lit):
        v = lit["value"]
        if lit["kind"] == "number":
            return int(v, 0) & U256
        if lit["kind"] == "bool":
            return 1 if v == "true" else 0
        if lit["kind"] == "string":
            b = v.encode()
            if len(b) > 32:
                raise Unsupported("string literal > 32 bytes")
            return int.from_bytes(b.ljust(32, b"\0"), "big")
        raise Unsupported(f"literal {lit['kind']}")

    def expr(self, e, f):
        return self.expr_multi(e, f, 1)[0]

    def expr_multi(self, e, f, n):
        t = e["nodeType"]
        if t == "YulLiteral":
            return [self.literal(e)]
        if t == "YulIdentifier":
            return [f.lookup(e["name"]).vars[e["name"]]]
        if t != "YulFunctionCall":
            raise Unsupported(f"expression {t}")
        name = e["functionName"]["name"]
        if name == "loadimmutable":
            key = e["arguments"][0]["value"]
            if key not in self.code.immutables:
                raise Unsupported(f"immutable {key} of {self.code.name} has no value")
            return [self.code.immutables[key]]
        if name in self.code.functions:
            args = [self.expr(a, f) for a in e["arguments"]]
            return self.call_user(self.code.functions[name], args)
        if name == "shr" and len(e["arguments"]) == 2:  # shr(224, calldataload(0))
            a0, a1 = e["arguments"]
            if (a0["nodeType"] == "YulLiteral" and self.literal(a0) == 224 and a1["nodeType"] == "YulFunctionCall"
                    and a1["functionName"]["name"] == "calldataload"
                    and a1["arguments"][0]["nodeType"] == "YulLiteral" and self.literal(a1["arguments"][0]) == 0):
                return [Selector()]
        args = [self.expr(a, f) for a in reversed(e["arguments"])][::-1]  # EVM evaluates right to left
        r = self.builtin(name, args)
        return [r] if n != 0 else []

    def call_user(self, fn, args):
        fr = Scope(None)
        for p, a in zip(fn.get("parameters", []), args):
            fr.vars[p["name"]] = a
        rets = [r["name"] for r in fn.get("returnVariables", [])]
        for r in rets:
            fr.vars[r] = 0
        # the callee only runs where the caller is still running: an internal function called
        # after the caller's `leave`/`break` (on some path) must not revert or write on that path
        c = self.c
        saved = (self.leave, self.brk, self.cont, self.outer_dead)
        self.outer_dead = c.or_(self.outer_dead, c.or_(self.leave, c.or_(self.brk, self.cont)))
        self.leave = self.brk = self.cont = FALSE
        self.block(fn["body"], fr)
        self.leave, self.brk, self.cont, self.outer_dead = saved
        return [fr.vars[r] for r in rets]

    # ---------- builtins ----------
    # where a builtin needs a known number (an address, offset or size), by argument position
    PLACES = {"mload": (0,), "mstore": (0,), "mstore8": (0,), "codecopy": (0, 1, 2), "keccak256": (0, 1),
              "return": (0, 1),
              "sload": (0,), "sstore": (0,), "tload": (0,), "tstore": (0,), "calldataload": (0,)}

    # memory ranges each builtin touches: (offset index, size index or a fixed size)
    RANGES = {"mload": [(0, 32)], "mstore": [(0, 32)], "mstore8": [(0, 1)], "keccak256": [(0, "1")],
              "calldatacopy": [(0, "2")], "returndatacopy": [(0, "2")], "codecopy": [(0, "2")],
              "mcopy": [(0, "2"), (1, "2")], "return": [(0, "1")], "revert": [(0, "1")],
              "call": [(3, "4"), (5, "6")], "staticcall": [(2, "3"), (4, "5")], "delegatecall": [(2, "3"), (4, "5")],
              "log0": [(0, "1")], "log1": [(0, "1")], "log2": [(0, "1")], "log3": [(0, "1")], "log4": [(0, "1")]}
    MEMORY_LIMIT = 1 << 24  # 16 MB: memory expansion past this costs far more than a block's gas

    def _out_of_gas(self, name, a):
        for oi, si in self.RANGES[name]:
            off = a[oi] if oi < len(a) else 0
            size = a[int(si)] if isinstance(si, str) and int(si) < len(a) else si
            if isinstance(off, int) and isinstance(size, int) and size > 0 and off + size > self.MEMORY_LIMIT:
                return True
        return False

    def _combos(self, a, places):
        """Every consistent combination of the options of the Choice arguments at these places, with its
        condition and source (None if there are none, or too many). Combinations that give one source two
        values are impossible and left out."""
        import itertools
        cols = [choice_opts(a[i]) if i < len(a) and isinstance(a[i], Choice) else None for i in places]
        if not any(cols):
            return None
        # the same value in two places takes the same option in both: enumerate it once
        pl = [i for i in places if i < len(a)]
        uniq = []
        for i in pl:
            if not any(a[i] is a[j] for j in uniq):
                uniq.append(i)
        sets = [choice_opts(a[i]) if isinstance(a[i], Choice) else [(TRUE, a[i], ())] for i in uniq]
        out = []
        for upick in itertools.product(*sets):
            pick = tuple(upick[next(k for k, j in enumerate(uniq) if a[j] is a[i])] for i in pl)
            src = ()
            for _, _, sr in pick:
                src = _merge_src(src, sr)
                if src is None:
                    break
            if src is None:
                continue
            cond = TRUE
            for cc, _, _ in pick:
                cond = self.c.and_(cond, cc)
            if cond == FALSE:
                continue
            args = list(a)
            for i, (_, x, _) in zip(pl, pick):
                args[i] = x
            out.append((cond, args, src))
            if len(out) > 4 * CHOICE_MAX:
                return None
        return out

    def _per_option(self, name, combos):
        """Run a builtin once per option, each under its condition; join what it returns."""
        rets, rds = [], []
        saved = self.opt
        self.enum_depth += 1
        try:
            for cond, args, src_ in combos:
                # the option's condition joins every guard: memory writes, returns, halts, storage, calls
                self.opt = self.c.and_(saved, cond)
                if self.opt == FALSE:
                    continue
                rd0 = (self.rd_words, self.rd_size)
                rets.append((cond, self.builtin(name, args), src_))
                rds.append((cond, self.rd_words, self.rd_size))
                if name in ("call", "staticcall", "delegatecall"):
                    self.rd_words, self.rd_size = rd0  # each option starts from the same return data
        finally:
            self.opt = saved
            self.enum_depth -= 1
        if not rets:
            return 0
        if name in ("call", "staticcall", "delegatecall"):  # each option's return data, under its condition
            (_, words, size) = rds[-1]
            for cond, w_, s_ in rds[-2::-1]:
                n = max(len(words), len(w_))
                words = [self.mux(cond, w_[i] if i < len(w_) else 0, words[i] if i < len(words) else 0, keep=True)
                         for i in range(n)]
                size = self.mux(cond, s_, size)
            self.rd_words, self.rd_size = words, size
        if name in ("mload", "sload", "calldataload"):
            # a value read once per option keeps that option's provenance (where it came from), so values read at
            # correlated addresses combine consistently later
            opts, rest = [], []
            for cond, r, src in rets:
                o = choice_opts(r)
                if o is None:
                    rest.append((cond, r))
                    continue
                for cc, x, sr in o:
                    m_ = _merge_src(src, sr)
                    if m_ is not None:
                        opts.append((self.c.and_(cond, cc), x, m_))
                rr = choice_rest(r)
                if rr is not None:
                    rest.append((self.c.and_(cond, rr[0]), rr[1]))
            if opts:
                rv = None
                if rest:
                    rv = rest[-1][1]
                    for cc, v in rest[-2::-1]:
                        rv = self._plain_mux(cc, v, rv)
                    rv = (self.c.any_([cc for cc, _ in rest]), rv)
                ch = make_choice(self.c, opts, rv)
                if ch is not None:
                    return ch
        if name == "keccak256":  # one hashed slot per option: a SymSlot over all of them
            opts = []
            for cond, r, _ in rets:
                if isinstance(r, SymSlot):
                    opts += [(self.c.and_(cond, c2), sl) for c2, sl in r.options]
                else:
                    opts.append((cond, r))
            return SymSlot([(cc, sl) for cc, sl in opts if cc != FALSE])
        acc = rets[-1][1]
        for cond, r, _ in rets[-2::-1]:
            acc = self.mux(cond, r, acc, keep=True)
        return acc

    def builtin(self, name, a):
        c = self.c
        if name in CONST_OPS and all(isinstance(x, int) for x in a):
            return CONST_OPS[name](*a)
        if name in CONST_UNARY and isinstance(a[0], int):
            return CONST_UNARY[name](a[0])
        if (name in CONST_OPS or name in CONST_UNARY) and any(isinstance(x, Choice) for x in a) \
                and all(choice_opts(x) is not None for x in a):
            # arithmetic on known constants stays known: once per combination of options
            combos = self._combos(a, tuple(range(len(a))))
            if combos is not None:
                f = CONST_OPS.get(name) or CONST_UNARY[name]
                rests = [choice_rest(x) for x in a if choice_rest(x) is not None]
                rest = None
                if rests:  # where any argument is in its rest: the ordinary circuit, on the exact values
                    rv = self.builtin(name, [self.norm(dict(self.as_dict(x))) if isinstance(x, Choice) else x for x in a])
                    rest = (c.any_([r[0] for r in rests]), rv)
                ch = make_choice(c, [(cond, f(*args), src) for cond, args, src in combos], rest)
                if ch is not None:
                    return ch
        if name in ("mcopy", "calldatacopy", "returndatacopy") and any(isinstance(x, Choice) for x in a[:3]):
            return self._copy_choice(name, a)
        if name in self.PLACES and name in self.RANGES:
            # a size option past 16 MB is an out-of-gas revert under its condition: drop it before combining
            a = list(a)
            for _, si in self.RANGES[name]:
                if isinstance(si, str) and int(si) < len(a) and isinstance(a[int(si)], Choice):
                    ch = a[int(si)]
                    big = [cc for cc, x, _ in ch.options if x > self.MEMORY_LIMIT]
                    if big:
                        la = c.and_(self.local_active, c.any_(big))
                        self.reverted, self.halted = c.or_(self.reverted, la), c.or_(self.halted, la)
                        keep = [(cc, x, sr) for cc, x, sr in ch.options if x <= self.MEMORY_LIMIT]
                        nv = make_choice(c, keep, ch.rest) if keep else (ch.rest[1] if ch.rest else 0)
                        a[int(si)] = nv if nv is not None else ch
        if name in self.PLACES:
            combos = self._combos(a, self.PLACES[name])
            if combos is not None:
                rests = [choice_rest(a[i]) for i in self.PLACES[name] if i < len(a) and choice_rest(a[i]) is not None]
                if rests:
                    # an address or size that is none of its known constants here: the path is left out, as for a
                    # mapping key outside the universe (counted and reported), never guessed
                    rc = c.any_([r[0] for r in rests])
                    self.world.flag(c.and_(self.active, rc))
                    self.world.rest_cuts.add(name)
                return self._per_option(name, combos)
        if name in self.RANGES and self._out_of_gas(name, a):
            # memory this far out costs more gas than any block holds: the transaction runs out of gas
            la = self.local_active
            self.reverted = c.or_(self.reverted, la)
            self.halted = c.or_(self.halted, la)
            return 0
        if name == "memoryguard":
            return a[0]
        if name == "pop":
            return 0
        if name == "add" and any(isinstance(x, SymSlot) for x in a):
            sym = [x for x in a if isinstance(x, SymSlot)]
            other = [x for x in a if not isinstance(x, SymSlot)]
            if len(sym) == 1 and isinstance(other[0], int):
                return sym[0].shifted(other[0])
            if len(sym) == 1 and not isinstance(other[0], Selector):
                return self._array_slots(sym[0].options, other[0])  # an element of an array under a mapping
            raise Unsupported("arithmetic on a hashed storage slot")
        if name == "add" and len(a) == 2 and any(isinstance(x, int) and x in HASHES for x in a) \
                and any(not isinstance(x, (int, SymSlot, Selector)) for x in a):
            h = next(x for x in a if isinstance(x, int) and x in HASHES)
            other = next(x for x in a if x is not h)
            return self._array_slots([(TRUE, h)], other)  # keccak(p) + i: an element of a dynamic array
        if name == "keccak256":
            return self.keccak(a)
        if name in ("add", "sub", "mul", "div", "mod"):
            # a constant operand wider than W bits (e.g. 1e18 scaling) cannot be represented: the model
            # must be at least that wide for this arithmetic to mean anything
            for v in a[:2]:
                if isinstance(v, int) and self.W < v.bit_length() <= 200 and v not in Vals.identities \
                        and not type_bound(v) and not all(isinstance(x, int) for x in a[:2]):
                    if v.bit_length() > Vals.width_need:
                        Vals.width_why = f"{name} with constant {v:#x}"
                    Vals.width_need = max(Vals.width_need, v.bit_length())
            # an input with bits above W (e.g. from shl(1, x), which is how solc writes x * 2)
            # loses them here: that is a width effect, exactly like a carry out of add
            for v in a[:2]:
                if not isinstance(v, (int, list)):
                    hi = [b for i, b in self.as_dict(v).items() if i >= self.W]
                    if hi:
                        self._note_wrap(c.any_(hi))
            x, y = self.word(a[0]), self.word(a[1])
            if name == "add":
                r, carry = c.add(x, y)
                self._note_wrap(carry)
                return r
            if name == "sub": return c.sub(x, y)[0]
            if name == "mul":
                # sound over-approximation of "the product needs more than W bits":
                # some x_i * y_j with i + j >= W - 1 is set
                Wn = len(x)
                self._note_wrap(c.any_([c.and_(x[i], y[j]) for i in range(Wn) for j in range(Wn) if i + j >= Wn - 1]))
                return c.mul(x, y)
            q, r = c.divmod(x, y)
            return q if name == "div" else r
        if name == "mulmod":  # (x * y) % d with the exact 2W-bit product, as the EVM does
            if all(isinstance(x, int) for x in a):
                return (a[0] * a[1]) % a[2] if a[2] else 0
            x, y, d = self.word(a[0]), self.word(a[1]), self.word(a[2])
            n = 2 * len(x)
            prod = c.mul(x + [FALSE] * len(x), y + [FALSE] * len(y))
            return c.divmod(prod[:n], d + [FALSE] * len(d))[1][:len(x)]
        if name in ("and", "or", "xor"):
            return self.bitop(name, a[0], a[1])
        if name == "not":
            return self.bnot(a[0])
        if name == "iszero":
            return self.bit(c.not_(self.truthy(a[0])))
        if name == "eq":
            return self.bit(self.eq(a[0], a[1]))
        if name == "lt":
            return self.bit(self.ult(a[0], a[1]))
        if name == "gt":
            return self.bit(self.ult(a[1], a[0]))
        if name == "slt":
            return self.bit(self.slt(a[0], a[1]))
        if name == "sgt":
            return self.bit(self.slt(a[1], a[0]))
        if name in ("shl", "shr", "sar"):
            s, v = a
            if isinstance(s, int):
                return self.shift_const(name, min(s, 256), v)
            return getattr(c, name)(self.word(v), self.word(s))
        if name == "byte" and isinstance(a[0], int):
            return self.extract(a[1], 31 - a[0], 1) if a[0] < 32 else 0
        if name == "exp" and isinstance(a[1], int):
            r, base = 1, a[0]
            for _ in range(a[1]):
                r = self.builtin("mul", [r, base])
            return r
        # ----- environment -----
        if name == "callvalue": return self.env.callvalue
        if name == "caller": return self.env.caller
        if name == "calldatasize": return self.cur_cds if self.cur_cds is not None else self.env.calldatasize
        if name == "timestamp": return self.env.timestamp
        if name == "number": return self.env.number
        if name == "chainid": return CHAIN_ID
        if name == "origin": return self.env.origin if self.env.origin is not None else self.env.caller
        if name == "address": return self.address
        if name == "gas": return 10_000_000
        if name in ("selfbalance", "balance"):
            if not self.world.eth_on:
                raise Unsupported("ETH balances are not modelled")
            if name == "selfbalance":
                return eth_get(self.world, self.address)
            who = a[0]
            known = list(self.world.codes) + list(self.world.eth_users)
            if isinstance(who, int):
                return eth_get(self.world, who) if who in known else 0
            acc = 0
            for k in known:
                acc = self.mux(self.eq(who, k), eth_get(self.world, k), acc)
            return acc
        if name == "calldataload":
            off = a[0]
            if not isinstance(off, int):
                # an offset read from calldata (ABI-encoded arrays): one of the calldata words, 0 past
                # the end; a read inside the calldata that is not one of its words (unaligned, or over
                # the selector) is not modelled: such paths are left out (width-artefact rule)
                c, acc, hit = self.c, 0, FALSE
                for i, wd in enumerate(self.calldata_words()):
                    h = self.eq(off, 4 + 32 * i)
                    acc = self.mux(h, wd, acc)
                    hit = c.or_(hit, h)
                odd = c.and_(self.ult(off, self.cur_cds if self.cur_cds is not None else self.env.calldatasize),
                             c.not_(hit))
                self.world.flag(c.and_(self.active, odd))
                return acc
            if off < 4 or (off - 4) % 32:
                raise Unsupported("calldataload at an unaligned offset")
            i = (off - 4) // 32
            cd = self.calldata_words()
            return cd[i] if i < len(cd) else 0
        if name == "extcodesize":
            has = FALSE
            for addr in list(self.world.codes) + sorted(self.world.attackers):
                has = c.or_(has, self.eq(a[0], addr))
            return self.bit(has)
        if name == "returndatasize":
            return self.rd_size
        if name == "returndatacopy":
            dst, off, size = a
            if not all(isinstance(x, int) for x in (dst, off, size)) or off % 32:
                raise Unsupported("returndatacopy with computed arguments")
            for i in range((size + 31) // 32):
                k = off // 32 + i
                self._mstore(dst + 32 * i, self.rd_words[k] if k < len(self.rd_words) else 0)
            return 0
        # ----- storage / memory -----
        if name == "sload":
            if isinstance(a[0], SymSlot):
                self.note_outside(a[0])
                acc = 0
                for cond, sl in a[0].options:
                    acc = self.mux(cond, self.storage.get(sl, 0), acc)
                return acc
            if not isinstance(a[0], int):
                raise Unsupported("sload at a computed slot that is not a mapping access")
            return self.storage.get(a[0], 0)
        if name == "sstore":
            act = self.active
            if self.static:  # a write inside staticcall reverts in the EVM
                la = self.local_active
                self.reverted = c.or_(self.reverted, la)
                self.halted = c.or_(self.halted, la)
                return 0
            if isinstance(a[0], SymSlot):
                self.note_outside(a[0])
                for cond, sl in a[0].options:
                    self.storage[sl] = self.mux(c.and_(act, cond), a[1], self.storage.get(sl, 0))
                return 0
            if not isinstance(a[0], int):
                raise Unsupported("sstore at a computed slot that is not a mapping access")
            self.storage[a[0]] = self.mux(act, a[1], self.storage.get(a[0], 0))
            return 0
        if name in ("tload", "tstore"):
            if not isinstance(a[0], int):
                raise Unsupported(f"{name} at a computed slot")
            t = self.world.transient[self.address]
            if name == "tload":
                return t.get(a[0], 0)
            if self.static:
                la = self.local_active
                self.reverted = c.or_(self.reverted, la)
                self.halted = c.or_(self.halted, la)
                return 0
            t[a[0]] = self.mux(self.active, a[1], t.get(a[0], 0))
            return 0
        if name == "calldatacopy":
            dst, off, size = a
            if not all(isinstance(x, int) for x in (dst, off, size)):
                raise Unsupported("calldatacopy with computed arguments")
            keep = lambda v, rem: v  # the whole source word: _partial_store keeps only its first rem bytes
            ws = copy_words(off, size, self.calldata_words(), base=4, mask=keep)
            for i, w_ in enumerate(ws):
                if i == len(ws) - 1 and size % 32:
                    self._partial_store(dst + 32 * i, w_, size % 32)
                else:
                    self._mstore(dst + 32 * i, w_)
            return 0
        if name == "mcopy":
            dst, src, size = a
            if not all(isinstance(x, int) for x in (dst, src, size)):
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
            if not isinstance(a[0], int):
                raise Unsupported("mload at a computed address")
            return self.memory.get(a[0], 0)
        if name == "mstore":
            if not isinstance(a[0], int):
                raise Unsupported("mstore at a computed address")
            self._mstore(a[0], a[1])
            return 0
        # ----- calls -----
        if name in ("call", "staticcall"):
            if name == "call":
                _, to, value, inp, insize, out, outsize = a
                if not (isinstance(value, int) and value == 0) and not self.world.eth_on:
                    raise Unsupported("calls that send ETH")
            else:
                _, to, inp, insize, out, outsize = a
                value = 0
            return self.ext_call(to, inp, insize, out, outsize, static=(name == "staticcall") or self.static,
                                 value=value)
        # ----- halting -----
        if name in ("revert", "invalid"):
            act = self.local_active
            if name == "revert" and self.memraw.get(0) == PANIC_SELECTOR and isinstance(self.memraw.get(4), int):
                code = self.memraw[4]
                self.panics[code] = c.or_(self.panics.get(code, FALSE), act)
            self.reverted = c.or_(self.reverted, act)
            self.halted = c.or_(self.halted, act)
            return 0
        if name == "return":
            act = self.local_active
            p, size = a
            if not isinstance(p, int) or not isinstance(size, int):
                raise Unsupported("return with a computed memory range")
            words = [self.memory.get(p + 32 * i, 0) for i in range((size + 31) // 32)]
            n = max(len(words), len(self.ret_words))
            self.ret_words = [self.mux(act, words[i] if i < len(words) else 0,
                                       self.ret_words[i] if i < len(self.ret_words) else 0) for i in range(n)]
            self.ret_size = self.mux(act, size, self.ret_size)
            if act != FALSE:
                self.ret_sizes.add(size)
            self.halted = c.or_(self.halted, act)
            return 0
        if name == "stop":
            self.halted = c.or_(self.halted, self.local_active)
            return 0
        raise Unsupported(f"builtin {name}")

    def _note_wrap(self, sig):
        """Record that a W-bit add/mul may have exceeded W bits on this path. Only then is an
        overflow panic a width artefact; a panic without it (e.g. 0 - 5) is a real revert."""
        if sig != FALSE:
            act = self.local_active
            self.panics["wrap"] = self.c.or_(self.panics.get("wrap", FALSE), self.c.and_(act, sig))

    def _partial_store(self, addr, v, rem):
        """Write the first `rem` bytes of v at addr: the rest of that memory word keeps what it held
        (the EVM copies exactly the bytes asked for)."""
        if isinstance(v, (SymSlot, Selector)):
            raise Unsupported("a hashed slot copied in part")
        cut = 8 * (32 - rem)  # bit positions >= cut are the first rem bytes
        old = self.memory.get(addr, 0)
        if isinstance(old, SymSlot):
            old = 0
        dv, do = self.as_dict(v), self.as_dict(old)
        self._mstore(addr, self.norm({**{p: s for p, s in do.items() if p < cut},
                                      **{p: s for p, s in dv.items() if p >= cut}}))

    def calldata_words(self):
        return self.cur_args if self.cur_args is not None else self.env.args

    def _mstore(self, addr, v):
        if self.enum_depth:
            # one option of a computed address: a guarded write. The raw (unguarded) record that hashing
            # reads first must not keep a value another option wrote
            if isinstance(v, (SymSlot, Selector)):
                raise Unsupported("a hashed slot stored at a computed memory address")
            self.memraw.pop(addr, None)
            old = self.memory.get(addr, 0)
            self.memory[addr] = self.mux(self.guard(), v, 0 if isinstance(old, SymSlot) else old, keep=True)
            return
        self.memraw[addr] = v
        if isinstance(v, SymSlot):
            self.memory.pop(addr, None)
        else:
            old = self.memory.get(addr, 0)
            self.memory[addr] = self.mux(self.guard(), v, 0 if isinstance(old, SymSlot) else old, keep=True)

    # ---------- calls between contracts ----------
    def ext_call(self, to, inp, insize, out, outsize, static, value=0):
        c, w = self.c, self.world
        if isinstance(to, int) and 1 <= to <= 0x11:
            raise Unsupported(f"precompile at address {to} (e.g. ecrecover) is not modelled")
        for x in (inp, insize, out, outsize):
            if not isinstance(x, (int, Choice)):
                raise Unsupported("call with a computed memory range")
        # pointers and sizes that are one of a few known values (Choice): the input is read once per option and
        # merged, the callee runs ONCE (dispatching on the selector's options), the output is written per option.
        # A rest (none of the known values) is left out, as everywhere; options past 16 MB run out of gas.
        for x in (inp, insize, out, outsize):
            r = choice_rest(x)
            if r is not None:
                self.world.flag(c.and_(self.active, r[0]))
                self.world.rest_cuts.add("call")
        oog = FALSE
        for po_, so_ in ((self._opts2(inp), self._opts2(insize)), (self._opts2(out), self._opts2(outsize))):
            for cp, pv in po_:
                for cs, sv in so_:
                    if sv > 0 and pv + sv > self.MEMORY_LIMIT:
                        oog = c.or_(oog, c.and_(cp, cs))
        if oog != FALSE:
            la = c.and_(self.local_active, oog)
            self.reverted, self.halted = c.or_(self.reverted, la), c.or_(self.halted, la)
        act = c.and_(self.active, c.not_(oog))
        pays = not (isinstance(value, int) and value == 0)
        if pays and static:
            raise Unsupported("staticcall with value")
        # a call that sends more ETH than this contract has fails (returns 0) without running
        enough = c.not_(c.lt(self.word(eth_get(w, self.address)), self.word(value))) if pays else TRUE
        targets = list(w.codes) + sorted(w.attackers)
        success, rd_words, rd_size = FALSE, [], 0
        matched = FALSE
        for t in targets:
            cond = TRUE if to == t else (FALSE if isinstance(to, int) else self.eq(to, t))
            go = c.and_(act, cond)
            if go == FALSE:
                continue
            matched = c.or_(matched, cond)
            if self.depth + 1 > w.max_depth:
                w.flag(go)
                continue
            go = c.and_(go, enough)
            before = {self.address: eth_get(w, self.address), t: eth_get(w, t)} if pays else {}
            if pays:
                eth_move(self, w, go, self.address, t, value)
            if t in w.codes:
                args, sel = self._call_input(inp, insize)
                onehot = self._sel_onehot(sel)
                env = TxEnv(onehot, args, self.address, calldatasize=insize, selector_word=sel,
                            timestamp=self.env.timestamp, callvalue=value, number=self.env.number,
                            origin=self.env.origin if self.env.origin is not None else self.env.caller)
                callee = Exec(w, t, env, self.depth + 1, pc0=go, static=static).run()
                ok = c.not_(callee.reverted)
                if pays:
                    eth_restore(self, w, c.and_(go, callee.reverted), before)
                words = callee.ret_words
                # returndatasize only shapes memory on the success path, where it is the size
                # the callee returns; on a revert the caller just bubbles the revert up
                size = next(iter(callee.ret_sizes)) if len(callee.ret_sizes) == 1 else (
                    0 if not callee.ret_sizes else callee.ret_size)
            else:  # attacker contract: may call back into us once per transaction
                ok, words, size = TRUE, [], 0
                h = w.hook
                if h is not None:
                    fire = c.and_(c.and_(go, h.on), c.not_(w.hook_fired))
                    w.hook_fired = c.or_(w.hook_fired, fire)
                    if fire != FALSE:
                        env = TxEnv(h.fn_onehot, h.args, t, calldatasize=4 + 32 * len(h.args),
                                    timestamp=self.env.timestamp, number=self.env.number,
                                    origin=self.env.origin if self.env.origin is not None else self.env.caller)
                        Exec(w, self.address, env, self.depth + 2, pc0=fire).run()  # its failure is ignored
            success = c.or_(success, c.and_(c.and_(cond, enough), ok))
            n = max(len(rd_words), len(words))
            rd_words = [self.mux(cond, words[i] if i < len(words) else 0, rd_words[i] if i < len(rd_words) else 0, keep=True)
                        for i in range(n)]
            rd_size = self.mux(cond, size, rd_size, keep=True)
        # anything else is an account without code: the call succeeds and does nothing
        # (except receive the ETH sent: a known user gets it, anyone else takes it out of the world)
        nomatch = c.not_(matched)
        if pays:
            go = c.and_(c.and_(act, nomatch), enough)
            eth_move(self, w, go, self.address, None, value)
            for u in w.eth_users:
                if u in w.attackers:
                    continue
                hit = c.and_(go, TRUE if to == u else (FALSE if isinstance(to, int) else self.eq(to, u)))
                if hit != FALSE:
                    st = w.storage.setdefault(u, {})
                    new, carry = c.add(self.word(eth_get(w, u)), self.word(value))
                    w.flag(c.and_(hit, carry))
                    st[ETH_SLOT] = self.mux(hit, new, st.get(ETH_SLOT, 0))
        success = c.or_(success, c.and_(nomatch, enough))
        self.rd_words, self.rd_size = rd_words, rd_size
        if isinstance(out, int) and isinstance(outsize, int):
            for i in range(outsize // 32):
                if i < len(rd_words):
                    self._mstore(out + 32 * i, self.mux(success, rd_words[i], self.memory.get(out + 32 * i, 0)))
        else:  # the output range per option, each under its own condition
            saved = self.opt
            self.enum_depth += 1
            try:
                for cond, (o_, s_), _ in (self._combos([out, outsize], (0, 1)) or []):
                    self.opt = c.and_(saved, cond)
                    if self.opt == FALSE or (s_ > 0 and o_ + s_ > self.MEMORY_LIMIT):
                        continue
                    for i in range(s_ // 32):
                        if i < len(rd_words):
                            self._mstore(o_ + 32 * i, self.mux(success, rd_words[i], self.memory.get(o_ + 32 * i, 0),
                                                               keep=True))
            finally:
                self.opt = saved
                self.enum_depth -= 1
        return self.bit(success)

    def _copy_choice(self, name, a):
        """mcopy / calldatacopy / returndatacopy whose destination, source or size is one of a few known values:
        source word i is read once (merged over the source options), then written at each destination option
        under "this destination, and the size reaches word i" (a size ending inside the word writes its first
        bytes only). The cost is destinations x words, never destinations x sources x sizes. Exact; rest paths are
        left out (counted); a range past 16 MB is an out-of-gas revert."""
        c = self.c
        dst, src, size = a[:3]
        for x in (dst, src, size):
            r = choice_rest(x)
            if r is not None:
                self.world.flag(c.and_(self.active, r[0]))
                self.world.rest_cuts.add(name)
        dopts, sopts, zopts = self._opts2(dst), self._opts2(src), self._opts2(size)
        oog = FALSE
        for cd, d in dopts:
            for cz, z_ in zopts:
                if z_ > 0 and d + z_ > self.MEMORY_LIMIT:
                    oog = c.or_(oog, c.and_(cd, cz))
        zopts = [(cz, z_) for cz, z_ in zopts if z_ <= self.MEMORY_LIMIT]
        if oog != FALSE:
            la = c.and_(self.local_active, oog)
            self.reverted, self.halted = c.or_(self.reverted, la), c.or_(self.halted, la)
        if not zopts:
            return 0
        n = (max(z_ for _, z_ in zopts) + 31) // 32

        def source(i):  # word i of the source, merged over the source options
            acc = None
            for cs, s in sopts[::-1]:
                if name == "mcopy":
                    v = self.memraw.get(s + 32 * i, self.memory.get(s + 32 * i, 0))
                elif name == "calldatacopy":
                    if s < 4 or (s - 4) % 32:
                        raise Unsupported("calldatacopy at an unaligned offset")
                    cd_ = self.calldata_words()
                    k = (s - 4) // 32 + i
                    v = cd_[k] if k < len(cd_) else 0
                else:
                    if s % 32:
                        raise Unsupported("returndatacopy at an unaligned offset")
                    k = s // 32 + i
                    v = self.rd_words[k] if k < len(self.rd_words) else 0
                acc = v if acc is None else self.mux(cs, v, acc, keep=True)
            return 0 if acc is None else acc

        words = [source(i) for i in range(n)]
        saved = self.opt
        self.enum_depth += 1
        try:
            for cd, d in dopts:
                for i in range(n):
                    full = c.any_([cz for cz, z_ in zopts if z_ >= 32 * (i + 1) and not (z_ > 0 and d + z_ > self.MEMORY_LIMIT)])
                    if full != FALSE:
                        self.opt = c.and_(saved, c.and_(cd, full))
                        if self.opt != FALSE:
                            self._mstore(d + 32 * i, words[i])
                    for cz, z_ in zopts:
                        if 32 * i < z_ < 32 * (i + 1) and not (d + z_ > self.MEMORY_LIMIT):
                            self.opt = c.and_(saved, c.and_(cd, cz))
                            if self.opt != FALSE:
                                self._partial_store(d + 32 * i, words[i], z_ - 32 * i)
        finally:
            self.opt = saved
            self.enum_depth -= 1
        return 0

    def _opts2(self, v):
        """[(condition, constant)] of a constant or a Choice (its rest is handled by the caller)."""
        return [(TRUE, v)] if isinstance(v, int) else [(cc, x) for cc, x, _ in v.options]

    def _call_input(self, inp, insize):
        """A call's calldata words and selector word, read from memory once per option of the input pointer and
        merged (each word keeps its known values where it has them); words past the input size are 0."""
        sizes = [x for _, x in self._opts2(insize) if x <= self.MEMORY_LIMIT]
        n = max([max(0, (s - 4) // 32) for s in sizes] + [0])
        def word(addr_opts, off):
            acc = None
            for cond, p in addr_opts[::-1]:
                v = self.memraw.get(p + off, self.memory.get(p + off, 0))
                acc = v if acc is None else self.mux(cond, v, acc, keep=True)
            return 0 if acc is None else acc
        po = self._opts2(inp)
        args = []
        for i in range(n):
            w_ = word(po, 4 + 32 * i)
            if not isinstance(insize, int) or insize < 4 + 32 * (i + 1):
                inside = self.ult(4 + 32 * i, insize) if not isinstance(insize, int) else FALSE
                w_ = self.mux(inside, w_, 0, keep=True)  # past this call's own size: nothing was sent
            args.append(w_)
        return args, word(po, 0)

    def _sel_onehot(self, sel):
        """The callee's dispatch: one selector (a constant), several (a Choice: each under its condition; its rest
        is left out), or None (an unknown word: the callee compares it)."""
        if isinstance(sel, int):
            return {(sel >> 224): TRUE}
        if isinstance(sel, Choice):
            oh = {}
            for cc, x, _ in sel.options:
                k = x >> 224
                oh[k] = self.c.or_(oh.get(k, FALSE), cc)
            if sel.rest is not None:
                self.world.flag(self.c.and_(self.active, sel.rest[0]))
                self.world.rest_cuts.add("call selector")
            return oh
        return None
