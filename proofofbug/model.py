"""k-transaction model of one or more contracts, bug rules, and the SAT bug search."""
from __future__ import annotations
from .circuit import Circuit, FALSE, TRUE, TIMEOUT
from .symexec import World, Code, Exec, TxEnv, Hook, Vals, mapping_slot, ETH_SLOT, eth_get, eth_move, eth_restore, \
    make_choice, CHOICE_MAX

SENDER_BASE = 0x31   # user u has address 0x31 + u (clear of the EVM precompile range)
PRIMARY_ADDR = 0x99  # first contract; further contracts get 0x98, 0x97, ...


# ---------- rule language ----------
class Bit:
    def __init__(self, m, s): self.m, self.s = m, s
    def __and__(self, o): return Bit(self.m, self.m.c.and_(self.s, _bit(self.m, o)))
    def __or__(self, o): return Bit(self.m, self.m.c.or_(self.s, _bit(self.m, o)))
    def __invert__(self): return Bit(self.m, self.m.c.not_(self.s))
    def implies(self, o): return (~self) | o


class Word:
    """A W-bit value in a rule. .wide() doubles the width so products cannot wrap."""
    def __init__(self, m, v): self.m, self.v = m, m.c.const_word(v, m.W) if isinstance(v, int) else v
    def _xy(self, o):
        y = o.v if isinstance(o, Word) else self.m.c.const_word(o, len(self.v))
        n = max(len(self.v), len(y))
        return self.v + [FALSE] * (n - len(self.v)), y + [FALSE] * (n - len(y))
    def zext(self, n): return Word(self.m, self.v + [FALSE] * (n - len(self.v)))
    def wide(self): return self.zext(2 * self.m.W)
    def __add__(self, o):  # exact: one extra bit, so sums (e.g. of all balances) never wrap
        x, y = self._xy(o)
        return Word(self.m, self.m.c.add(x + [FALSE], y + [FALSE])[0])
    def __sub__(self, o): return Word(self.m, self.m.c.sub(*self._xy(o))[0])
    def rsub(self, k): return Word(self.m, k) - self
    def rfloordiv(self, k): return Word(self.m, k) // self
    def __mul__(self, o):  # exact: the product gets the width of both factors
        x, y = self._xy(o)
        n = len(x) + len(y)
        return Word(self.m, self.m.c.mul(x + [FALSE] * (n - len(x)), y + [FALSE] * (n - len(y))))
    def __floordiv__(self, o): return Word(self.m, self.m.c.divmod(*self._xy(o))[0])
    def __lt__(self, o): return Bit(self.m, self.m.c.lt(*self._xy(o)))
    def __gt__(self, o): x, y = self._xy(o); return Bit(self.m, self.m.c.lt(y, x))
    def __le__(self, o): return ~(self > o)
    def __ge__(self, o): return ~(self < o)
    def __eq__(self, o): return Bit(self.m, self.m.c.eq(*self._xy(o)))
    def __ne__(self, o): return ~(self == o)
    __hash__ = None


def _bit(m, o):
    if isinstance(o, Bit): return o.s
    if isinstance(o, bool): return TRUE if o else FALSE
    raise TypeError(o)


class Tx:
    """One transaction as seen by a rule."""
    def __init__(self, m, i, called, args, caller, ret, reverted, to, pre, post, now=1):
        self.m, self.i = m, i
        self.now = Word(m, now)
        self._called, self._args, self._pre, self._post = called, args, pre, post
        self.sender = Word(m, m.vals.word(caller))
        self.ret = Word(m, m.vals.word(ret))
        self.reverted = Bit(m, reverted)
        self.ok = ~self.reverted
        self.to = Word(m, m.vals.word(to))

    def called(self, fn_name): return Bit(self.m, self._called.get(fn_name, FALSE))
    def arg(self, j): return Word(self.m, self._args[j])
    def pre(self, var, *keys): return self.m.read(self._pre, var, keys)
    def post(self, var, *keys): return self.m.read(self._post, var, keys)
    def pre_sum(self, var, *field): return self.m.total(self._pre, var, *field)
    def post_sum(self, var, *field): return self.m.total(self._post, var, *field)


def _uses(node, builtin):
    """Does a Yul AST call the given builtin anywhere?"""
    if isinstance(node, dict):
        if node.get("nodeType") == "YulFunctionCall" and node.get("functionName", {}).get("name") == builtin:
            return True
        return any(_uses(v, builtin) for v in node.values())
    if isinstance(node, list):
        return any(_uses(v, builtin) for v in node)
    return False


# ---------- model ----------
class Model:
    def __init__(self, contracts, W=8, k=3, users=2, attacker=None, init_storage=None,
                 include_view=False, max_unroll=8, max_depth=3, extra_keys=()):
        """contracts: list of (Contract, immutables {name: value}); the first is the primary one.
        attacker: index of the user that is a contract able to call back (reentrancy), or None.
        init_storage: {address: {slot: value}} (e.g. read from a real deployment)."""
        self.W, self.k, self.users = W, k, users
        self.c = c = Circuit()
        self.vals = Vals(c, W)
        self.contracts = []  # (Contract, address)
        codes = {}
        for n, (con, imm) in enumerate(contracts):
            addr = PRIMARY_ADDR - n
            self.contracts.append((con, addr))
            codes[addr] = Code(con.name, con.code, {con.immutable_ids[k_]: v for k_, v in (imm or {}).items()})
        self.contract = self.contracts[0][0]
        self.by_name = {con.name: (con, addr) for con, addr in self.contracts}
        self.user_addrs = [SENDER_BASE + u for u in range(users)]
        self.attacker = None if attacker is None else SENDER_BASE + attacker
        # mappings keyed by ids (orders, streams, auctions...): ids 1..8 are in the universe too
        ids = [i for i in range(1, 9)] if any(con.uint_keyed() for con, _ in self.contracts) else []
        # every account the deployment uses is in the universe, the deployer too (it is not controlled by
        # the solver, but what it holds counts: sums over accounts, balances it keeps after setup)
        deployer = sorted(Vals.identities)
        self.key_universe = self.user_addrs + [0] + [a for _, a in self.contracts] + list(extra_keys) + \
            [i for i in ids if i not in extra_keys] + [d for d in deployer if d not in extra_keys]
        storage = {a: dict((init_storage or {}).get(a, {})) for _, a in self.contracts}
        self.world = w = World(c, W, codes, storage, self.key_universe,
                               attackers=[self.attacker] if self.attacker else [], max_depth=max_depth,
                               max_unroll=max_unroll)
        # ETH: modelled when some contract can receive or read ETH. Balances live in the pseudo
        # slot ETH_SLOT; users start with the balance the EVM run gave them (bench: 2^(W-1)).
        self.payable = {f[2] for con, a in self.contracts for f in [(a,) + x for x in con.functions(include_view)]
                        if f[2] in con.payable}
        self.eth_on = bool(self.payable) or any(con.has_receive or _uses(con.code, "selfbalance")
                                                or _uses(con.code, "balance") for con, _ in self.contracts)
        if self.eth_on:
            w.eth_on, w.eth_users = True, list(self.user_addrs)
            for u in self.user_addrs:
                w.storage[u] = dict((init_storage or {}).get(u, {}))
        # every function the solver may call: (address, name, signature, selector, arg types)
        self.funcs = [(a, f[0], f[1], f[2], f[3]) for con, a in self.contracts for f in con.functions(include_view)]
        self.hook_sels = sorted({f[3] for f in self.funcs})
        nf, nh = len(self.funcs), len(self.hook_sels)
        fbits, hbits = max(1, (nf - 1).bit_length()), max(1, (nh - 1).bit_length())
        sbits = max(1, (users - 1).bit_length())
        self.maxargs = max([len(f[4]) for f in self.funcs] + [0])
        # some function takes a dynamic array (its calldata has offsets and lengths the solver chooses)
        self.arrays = any(str(t).startswith(("length:", "blength:", "offset:")) for f in self.funcs for t in f[4])
        # word positions that carry raw bytes (bytes/string content): their top 4 bytes are inputs too
        self.raw_pos = sorted({j for f in self.funcs for j, t in enumerate(f[4]) if t == "raw"})
        self.length_cuts = set()  # functions run with fewer argument lengths than modelled (reported)
        self.out_pos, self.out_const = {}, {}
        valid = TRUE
        self.txs = []
        # time: only when some contract reads block.timestamp. Deployment happens at time 1 (the
        # Foundry default); each transaction moves the clock forward by a solver-chosen step
        # (possibly 0), never backwards and never past 2^W.
        self.uses_time = any(_uses(con.code, "timestamp") for con, _ in self.contracts)
        # block number: the same kind of clock (deployment at block 1, each transaction may move it on)
        self.uses_number = any(_uses(con.code, "number") for con, _ in self.contracts)
        now = c.const_word(1, W)
        blk = c.const_word(1, W)
        for i in range(k):
            fn = c.new_input(f"tx{i}.fn", fbits)
            if nf < (1 << fbits):
                valid = c.and_(valid, c.lt(fn, c.const_word(nf, fbits)))
            sid = c.new_input(f"tx{i}.sender", sbits)
            if users < (1 << sbits):
                valid = c.and_(valid, c.lt(sid, c.const_word(users, sbits)))
            caller = c.const_word(self.user_addrs[0], W)
            for u in range(1, users):
                caller = c.wmux(c.eq(sid, c.const_word(u, sbits)), c.const_word(self.user_addrs[u], W), caller)
            args = [c.new_input(f"tx{i}.arg{j}", W) for j in range(self.maxargs)]
            his = {j: c.new_input(f"tx{i}.arg{j}.hi", 32) for j in self.raw_pos}
            value = c.new_input(f"tx{i}.value", W) if self.payable else None
            w.hook, w.hook_fired = None, FALSE
            if self.attacker is not None:
                hon = c.new_input(f"tx{i}.hook_on", 1)[0]
                hfn = c.new_input(f"tx{i}.hook_fn", hbits)
                if nh < (1 << hbits):
                    valid = c.and_(valid, c.lt(hfn, c.const_word(nh, hbits)))
                hargs = [c.new_input(f"tx{i}.hook_arg{j}", W) for j in range(self.maxargs)]
                w.hook = Hook(hon, {s: c.eq(hfn, c.const_word(j, hbits)) for j, s in enumerate(self.hook_sels)}, hargs)
            if self.uses_time:
                now, carry = c.add(now, c.new_input(f"tx{i}.dt", W))
                valid = c.and_(valid, c.not_(carry))
            if self.uses_number:
                blk, carry = c.add(blk, c.new_input(f"tx{i}.dn", W))
                valid = c.and_(valid, c.not_(carry))
            w.transient = {a_: {} for a_ in w.transient}
            pre = {a: dict(s) for a, s in w.storage.items()}
            w.artefact = FALSE
            called, reverted, ret, to = {}, FALSE, 0, 0
            for con, a in self.contracts:
                onehot, cond, pay, cds = {}, FALSE, FALSE, 4 + 32 * self.maxargs
                fn_args, fn_cds = {}, {}
                for j, f in enumerate(self.funcs):
                    if f[0] != a:
                        continue
                    hit = c.eq(fn, c.const_word(j, fbits))
                    onehot[f[3]] = hit
                    variants, ok = self._call_words(f, args, his)
                    if variants is not None:  # dynamic arguments: this function's own calldata, per variant
                        fn_args[f[3]], fn_cds[f[3]] = variants, 4 + 32 * len(f[4])
                        valid = c.and_(valid, c.or_(c.not_(hit), ok))
                    if self.arrays:  # exact calldata: this call's own size, the words past it are 0 (as on the EVM)
                        cds = self.vals.mux(hit, 4 + 32 * len(f[4]), cds)
                        for k_ in range(len(f[4]), self.maxargs):
                            valid = c.and_(valid, c.not_(c.and_(hit, c.not_(self.vals.eq(args[k_], 0)))))
                    cond = c.or_(cond, hit)
                    if f[2] in self.payable:
                        pay = c.or_(pay, hit)
                    called[f"{con.name}.{f[1]}"] = hit
                    if a == self.contracts[0][1]:  # a bare name means the contract under test (A0)
                        called[f[1]] = c.or_(called.get(f[1], FALSE), hit)
                if cond == FALSE:
                    continue
                cv, before = 0, {}
                if pay != FALSE:
                    cv = self.vals.mux(pay, value, 0)
                    bal = self.vals.word(self._sender_eth(caller))
                    # the sender must own what it sends (otherwise the EVM rejects the transaction)
                    valid = c.and_(valid, c.not_(c.and_(cond, c.lt(bal, self.vals.word(cv)))))
                    before = {a: eth_get(w, a), **{u: eth_get(w, u) for u in self.user_addrs}}
                    for u in self.user_addrs:
                        eth_move(self.vals, w, c.and_(cond, self.vals.eq(caller, u)), u, a, cv)
                env = TxEnv(onehot, args, caller, calldatasize=cds,
                            timestamp=now if self.uses_time else 1, callvalue=cv,
                            number=blk if self.uses_number else 1, fn_args=fn_args or None, fn_cds=fn_cds or None)
                ex = Exec(w, a, env, depth=0, pc0=cond).run()
                if before:
                    eth_restore(self.vals, w, c.and_(cond, ex.reverted), before)
                reverted = c.or_(reverted, c.and_(cond, ex.reverted))
                ret = self.vals.mux(cond, ex.ret_words[0] if ex.ret_words else 0, ret)
                to = self.vals.mux(cond, a, to)
            valid = c.and_(valid, c.not_(w.artefact))
            post = {a: dict(s) for a, s in w.storage.items()}
            self.txs.append(Tx(self, i, called, args, caller, ret, reverted, to, pre, post,
                               now if self.uses_time else 1))
            self._out(f"tx{i}.valid", [valid])
            self._out(f"tx{i}.reverted", [reverted])
            self._out(f"tx{i}.ret", ret)
            for a, st in post.items():
                for s, v in st.items():
                    self._out(f"tx{i}.s.{a}.{s}", v)
        self.valid = valid
        c.outputs["valid"] = [valid]
        eth_slots = {(a, ETH_SLOT) for a in list(codes) + self.user_addrs} if self.eth_on else set()
        self.watch = sorted(set(self.candidate_slots()) | {(a, s) for a, st in w.storage.items() for s in st} | eth_slots)
        self.rules = {}

    def _sender_eth(self, caller):
        acc = 0
        for u in self.user_addrs:
            acc = self.vals.mux(self.vals.eq(caller, u), eth_get(self.world, u), acc)
        return acc

    def _out(self, name, v):
        """Record an output; values keep their bit positions (packed storage)."""
        if isinstance(v, int):
            self.c.outputs[name], self.out_pos[name], self.out_const[name] = [], [], v
        elif name.endswith(("valid", "reverted")):
            self.c.outputs[name], self.out_pos[name], self.out_const[name] = v, [0], 0
        else:
            d = self.vals.as_dict(v)
            pos = sorted(d)
            self.c.outputs[name] = [d[p] for p in pos]
            self.out_pos[name], self.out_const[name] = pos, 0

    # ---------- storage access for rules ----------
    def resolve(self, var):
        """'var' (primary contract) or 'Contract.var' -> (contract, address, var)."""
        if "." in var:
            cname, v = var.split(".", 1)
            con, a = self.by_name[cname]
            return con, a, v
        return self.contracts[0][0], self.contracts[0][1], var

    def read(self, store, var, keys):
        """Value of var[keys...] in a storage snapshot; symbolic keys range over the key universe.
        "ETH" is a pseudo mapping: ETH(address) = that account's ETH balance."""
        c = self.c
        if var == "ETH":
            if not self.eth_on:
                raise KeyError("ETH: no contract here handles ETH")
            (k,) = keys
            known = [a for _, a in self.contracts] + self.user_addrs
            if isinstance(k, int):
                return Word(self, self.vals.word(store.get(k, {}).get(ETH_SLOT, 0)))
            acc = 0
            for a in known:
                acc = self.vals.mux(c.eq(k.v, c.const_word(a, self.W)), store.get(a, {}).get(ETH_SLOT, 0), acc)
            return Word(self, self.vals.word(acc))
        con, a, v = self.resolve(var)
        field = keys[-1] if keys and isinstance(keys[-1], str) else None
        if field is not None:
            keys = keys[:-1]
            extra, f_off, f_bytes = con.field(v, len(keys), field)
        opts = [(TRUE, con.storage[v])]
        for k in keys:
            new = []
            for cond, s in opts:
                if isinstance(k, int):
                    new.append((cond, mapping_slot(k, s)))
                else:
                    for kk in self.key_universe:
                        new.append((c.and_(cond, c.eq(k.v, c.const_word(kk, self.W))), mapping_slot(kk, s)))
            opts = new
        if field is not None:
            opts = [(cond, s_ + extra) for cond, s_ in opts]
        acc = 0
        for cond, s in opts:
            acc = self.vals.mux(cond, store[a].get(s, 0), acc)
        if field is not None:  # a struct member may share its slot with others
            acc = self.vals.extract(acc, f_off, f_bytes)
        elif not keys:  # a plain variable may share its slot with others (packed storage)
            acc = self.vals.extract(acc, con.storage_offset[v], con.storage_bytes[v])
        return Word(self, self.vals.word(acc))

    def total(self, store, var, *field):
        acc = Word(self, 0)
        if var == "ETH":
            for a in [a for _, a in self.contracts] + self.user_addrs:
                acc = acc + self.read(store, "ETH", (a,))
            return acc
        for kk in self.key_universe:
            acc = acc + self.read(store, var, (kk,) + field)
        return acc

    def candidate_slots(self):
        """Every storage slot the model can touch: plain variables plus mapping entries for
        each key in the key universe (one or two levels deep), as (address, slot)."""
        from .symexec import ARRAY_SPAN
        out = set()
        for con, a in self.contracts:
            for var, base in con.storage.items():
                # every slot the value can occupy, at any nesting: structs, mappings (every key in the universe),
                # dynamic arrays and long bytes (length + the first ARRAY_SPAN data slots), see Contract.type_slots
                out |= {(a, s) for s in con.type_slots(con.storage_types[var], base, self.key_universe, ARRAY_SPAN)}
        return sorted(out)

    # ---------- rules and search ----------
    def add_rule(self, name, fn):
        """fn(tx) -> Bit: 1 when transaction tx breaks the rule."""
        c = self.c
        hit = FALSE
        for tx in self.txs:
            hit = c.or_(hit, fn(tx).s)
        self.rules[name] = c.and_(self.valid, hit)
        c.outputs[f"rule:{name}"] = [self.rules[name]]
        c.outputs["bug"] = [c.any_(self.rules.values())]

    def gate_count(self, output="bug"):
        return len(self.c.used_gates_for(self.c.outputs[output]))

    def nargs_of(self, sel):
        return next(len(f[4]) for f in self.funcs if f[3] == sel)

    def _call_words(self, f, args, his):
        """The calldata of a call whose arguments include dynamic types, as variants [(condition, words)]
        (yul.length_variants, the same for every engine): one per combination of the lengths it is sent
        with, every offset and length a known number, so the function body runs once per variant as
        separate branches and nothing downstream is a computed size. Raw bytes words are the low W bits and
        the top 4 bytes. `ok` says the inputs are one of the variants. None if no argument is dynamic."""
        from .yul import length_variants
        lv = length_variants(f[4])
        if lv is None:
            return None, TRUE
        vts, slots, note = lv
        if note:
            self.length_cuts.add(f"{f[2]}: {note}")
        c, variants = self.c, []
        for vt in vts:
            words, cond = [], TRUE
            for j, t in enumerate(vt):
                if t.startswith("const:"):
                    words.append(int(t[6:]))
                    if j in slots:
                        cond = c.and_(cond, self.vals.eq(args[j], int(t[6:])))
                elif t == "raw":
                    d = {p: b for p, b in enumerate(args[j]) if b != FALSE}
                    d.update({224 + q: b for q, b in enumerate(his[j]) if b != FALSE})
                    words.append(self.vals.norm(d))
                else:
                    words.append(args[j])
            variants.append((cond, words))
        return variants, c.any_([cc for cc, _ in variants])

    def evm_arg(self, t, v):
        """The 256-bit value the EVM receives for a W-bit circuit input. The circuit is a W-bit EVM:
        its negative numbers (top bit set) are the chain's negative numbers, so a signed ABI type is
        sign-extended; everything else is zero-extended (as before)."""
        t = str(t)
        if t.startswith("offset:"):  # a known offset: the model always sends exactly this
            return int(t[7:])
        if t.startswith("int") and v >> (self.W - 1) & 1:
            return (v - (1 << self.W)) % (1 << 256)
        return v

    def decode(self, assign):
        seq, now, blk = [], 1, 1
        for i in range(self.k):
            a, name, sig, sel, types = self.funcs[assign[f"tx{i}.fn"]]
            tx = {"to": a, "fn": name, "sig": sig, "selector": sel,
                  "contract": next(con.name for con, ad in self.contracts if ad == a) if a != self.contracts[0][1] else None,
                  "sender": self.user_addrs[assign[f"tx{i}.sender"]],
                  "args": [self.evm_arg(t, assign[f"tx{i}.arg{j}"]) | (assign.get(f"tx{i}.arg{j}.hi", 0) << 224
                                                                        if t == "raw" else 0)
                           for j, t in enumerate(types)], "hook": None}
            if self.uses_time:
                now += assign[f"tx{i}.dt"]
                tx["time"] = now
            if getattr(self, "uses_number", False):
                blk += assign[f"tx{i}.dn"]
                tx["block"] = blk
            if sig in self.payable:
                tx["value"] = assign[f"tx{i}.value"]
            if self.attacker is not None and assign.get(f"tx{i}.hook_on"):
                hs = self.hook_sels[assign[f"tx{i}.hook_fn"]]
                hname = next(f[1] for f in self.funcs if f[3] == hs)
                htypes = next(f[4] for f in self.funcs if f[3] == hs)
                tx["hook"] = {"selector": hs, "fn": hname,
                              "args": [self.evm_arg(t, assign[f"tx{i}.hook_arg{j}"]) for j, t in enumerate(htypes)]}
            seq.append(tx)
        return seq

    def hunt(self, rule, timeout=None):
        """None: no attack exists within this model. (assignment, sequence): an attack.
        TIMEOUT: the budget ran out first."""
        a = self.c.solve({f"rule:{rule}": 1}, timeout=timeout)
        if a is None or a == TIMEOUT:
            return a
        return a, self.decode(a)
