"""Exact multi-transaction attack search (any number size).

The bit-level engine gives every number the same width W, so one large constant (1e18, a 1000e18
pool, a 2^127 rate) makes every word wide and the circuit explodes. This engine works on exact
integers instead (the same Z3 model the prover uses: every EVM word is an integer in [0, 2^256)
with exact wrap-around), so the size of the numbers does not change the size of the problem.

It searches k transactions from the REAL deployed state (not from an arbitrary state, as the
prover's induction does): at step i the solver chooses one function, its arguments (full 256-bit),
the caller (a model user) and the time (never going back). Each function is executed symbolically
from the state before step i; the states are merged by the chosen function, exactly as the circuit
merges them. A rule breaks if it breaks at some step for the chosen function.

Every attack it returns is replayed on the real EVM before it counts, so a modelling mistake can
make it miss a bug but never report a fake one. What it does not model (ETH balances, attacker
callbacks, loops longer than the unroll limit) raises Unsupported, never a silent guess.
"""
from __future__ import annotations
import z3
from .intproof import Z, ZWorld, ZExec, ZEnv, ZTx, ZWord, Prover, zi, world_eth, pay_in
from .symexec import Unsupported, ETH_SLOT

MAX_TIME = (1 << 40) - 1
LOOP_LIMIT = 64


class ExactSearch:
    def __init__(self, model):
        """model: a bit-level Model built from the deployment (used for layout, code and the deployed state)."""
        self.m = model
        self.excluded = {}  # function -> why it is left out of the search
        self.loops_cut = set()  # functions explored only on paths where their loops end in time

    def _deployed(self):
        """The deployed state, ETH balances included (contracts and users) when the contracts handle ETH."""
        eth = getattr(self.m, "eth_on", False)
        st = {a: {} for _, a in self.m.contracts}
        if eth:
            for u in self.m.user_addrs:
                st.setdefault(u, {})
        for (a, s), v in self.m.init_trace.items():
            if a in st and (s != ETH_SLOT or eth):
                st[a][s] = v
        if eth:
            for a in st:
                st[a].setdefault(ETH_SLOT, 0)
        return st

    def build(self, rules, k):
        """Symbolic k-step execution. Returns (z, constraints, fires, decode-info)."""
        m = self.m
        z = Z()
        prover = Prover(m)
        prover.z = z
        state = self._deployed()
        funcs = m.funcs
        nf = len(funcs)
        maxargs = max([len(f[4]) for f in funcs] + [0])
        cons, fires, steps = [], [], []
        prev_now = 1
        for i in range(k):
            sel = z3.Int(f"step{i}.fn")
            cons += [sel >= 0, sel < nf]
            caller = z3.Int(f"step{i}.caller")
            cons.append(z3.Or(*[caller == u for u in m.user_addrs]))
            now = z3.Int(f"step{i}.now")
            cons += [now >= prev_now, now <= MAX_TIME]
            prev_now = now
            value = z3.Int(f"step{i}.value")  # wei sent with the call (payable functions only)
            cons += [value >= 0, value < (1 << 256)]
            args = []
            for j in range(maxargs):
                v = z3.Int(f"step{i}.arg{j}")
                cons += [v >= 0, v < (1 << 256)]
                z.set_ub(v, (1 << 256) - 1)
                args.append(v)
            posts = []
            for j, (a, name, sig, sel_word, types) in enumerate(funcs):
                go = sel == j
                fargs = []
                for t, v in zip(types, args):  # the ABI decoder rejects out-of-range inputs; keep them valid
                    if t == "address":
                        cons.append(z3.Implies(go, v < (1 << 160)))
                    elif t == "bool":
                        cons.append(z3.Implies(go, v <= 1))
                    elif t.startswith("uint") and t != "uint256":
                        cons.append(z3.Implies(go, v < (1 << int(t[4:]))))
                    fargs.append(v)
                storage = {ad: dict(s) for ad, s in state.items()}
                world = ZWorld(z, m.world.codes, storage, m.key_universe, max_unroll=LOOP_LIMIT)
                world.bounded_loops = True  # search mode: paths where a loop ends within LOOP_LIMIT steps
                world_eth(world, m)
                payable = sig in getattr(m, "payable", ())
                cv = value if payable else 0
                try:
                    before = pay_in(world, caller, a, cv) if payable else {}
                    env = ZEnv(sel_word, fargs, caller, calldatasize=4 + 32 * len(types), timestamp=now, callvalue=cv)
                    ex = ZExec(world, a, env, gate=go).run()
                    if before:
                        world.eth_restore(ex.reverted, before)
                    if world.callbacks_skipped:
                        self.excluded.setdefault(f"{a:#x}.{name}", "sends ETH to the attacker contract: its callback is "
                                                 "explored by the bit-level search only")
                except Unsupported as e:
                    # this function cannot be modelled exactly: the search does without it (reported)
                    self.excluded.setdefault(f"{a:#x}.{name}", str(e))
                    cons.append(z3.Not(go))
                    continue
                cons += [z3.Implies(go, x) for x in world.assume if x is not True]
                if world.loops_cut:
                    self.loops_cut.add(f"{name} (loops cut at {LOOP_LIMIT} iterations)")
                ret = ex.ret_words[0] if ex.ret_words else 0
                cname = next(c.name for c, ad in m.contracts if ad == a)
                tx = ZTx(prover, name, cname, fargs, caller, ret, ex.reverted, state, storage)
                tx._now = ZWord(now)
                posts.append((go, storage, tx))
            # the state after step i: the chosen function's result
            new = {}
            for ad in state:
                slots = set(state[ad])
                for _, st, _ in posts:
                    slots |= set(st[ad])
                new[ad] = {}
                for s in slots:
                    v = state[ad].get(s, 0)
                    for go, st, _ in posts:
                        w = st[ad].get(s, 0)
                        if w is not v:
                            v = z.ite(go, w, v)
                    new[ad][s] = v
            steps.append({"sel": sel, "caller": caller, "now": now, "args": args, "txs": posts, "value": value})
            if not posts:
                raise Unsupported("no function can be modelled exactly")
            for name, fn in rules.items():
                for go, _, tx in posts:
                    hit = fn(tx).e
                    if hit is not False:
                        fires.append((name, i, z3.And(go, hit) if hit is not True else go))
            state = new
        cons += list(z.facts)
        return z, cons, fires, steps

    def hunt(self, rules, k, timeout=60):
        """Returns ("found", rule name, sequence) / ("clean", None, None) / ("timeout", None, None)."""
        z, cons, fires, steps = self.build(rules, k)
        if not fires:
            return "clean", None, None
        s = z3.Solver()
        s.set("timeout", int(timeout * 1000))
        s.add(*[c for c in cons if c is not True])
        s.add(z3.Or(*[f for _, _, f in fires]))
        r = s.check()
        if r == z3.unsat:
            return "clean", None, None
        if r != z3.sat:
            return "timeout", None, None
        mdl = s.model()
        val = lambda e: mdl.eval(e, model_completion=True).as_long()
        seq = []
        for st in steps:
            j = val(st["sel"])
            a, name, sig, sel_word, types = self.m.funcs[j]
            tx = {"to": a, "fn": name, "sig": sig, "selector": sel_word, "sender": val(st["caller"]),
                  "args": [val(v) for v in st["args"][:len(types)]], "hook": None,
                  "contract": None if a == self.m.contracts[0][1] else next(c.name for c, ad in self.m.contracts if ad == a)}
            if getattr(self.m, "uses_time", False):
                tx["time"] = val(st["now"])
            if sig in getattr(self.m, "payable", ()):
                tx["value"] = val(st["value"])
            seq.append(tx)
        hit = next(n for n, i, f in fires if z3.is_true(mdl.eval(f, model_completion=True)))
        return "found", hit, seq


def exact_hunt(m, cfg, rules, depths=(1, 2, 3), timeout=60, log=print):
    """Search every rule with the exact engine and confirm each attack on the EVM.
    rules: {name: fn}. Returns ({rule: finding}, {rule: [(label, status)]}, {excluded function: why})."""
    from . import evm
    from .check import rule_on_trace
    from .bench import fmt_tx
    found, status = {}, {n: [] for n in rules}
    eng = ExactSearch(m)
    for k in depths:
        open_ = {n: f for n, f in rules.items() if n not in found}
        while open_:
            try:
                st, name, seq = eng.hunt(open_, k, timeout)
            except Unsupported as e:
                for n in open_:
                    status[n].append((f"exact {k}tx", f"unsupported: {e}"))
                return found, status, eng.excluded
            if st == "timeout" and len(open_) > 1:
                # all rules at once was too hard: each rule alone is a much smaller problem
                log(f"    exact search {k}tx: combined query timed out, trying {len(open_)} rules one by one")
                for n in list(open_):
                    sub, (st1, name1, seq1) = {n: open_[n]}, (None, None, None)
                    try:
                        st1, name1, seq1 = eng.hunt(sub, k, timeout)
                    except Unsupported as e:
                        status[n].append((f"exact {k}tx", f"unsupported: {e}"))
                        continue
                    if st1 == "found":
                        _confirm_exact(m, cfg, rules, name1, seq1, k, found, status, log)
                    else:
                        status[n].append((f"exact {k}tx", st1))
                break
            if st != "found":
                for n in open_:
                    status[n].append((f"exact {k}tx", st))
                break
            _confirm_exact(m, cfg, rules, name, seq, k, found, status, log)
            open_.pop(name, None)
    excl = dict(eng.excluded)
    for fn in sorted(eng.loops_cut):
        excl[fn] = "only paths where its loops end in time were searched"
    return found, status, excl


def _confirm_exact(m, cfg, rules, name, seq, k, found, status, log):
    """Replay an exact-search attack on the EVM; only a confirmed one becomes a finding."""
    from . import evm
    from .check import rule_on_trace
    from .bench import fmt_tx
    trace = evm.run(cfg, cfg["tag"] + "_exact", [seq], m.watch)[0]
    hit = rule_on_trace(m, rules[name], seq, trace)
    from . import trail
    trail.record("exact search", f"{k}tx at 256 bits", [name], seq, trace, m, {name: hit})
    if hit is None:  # the model and the chain disagree: report, never claim
        status[name].append((f"exact {k}tx", "not confirmed on the EVM"))
        log(f"    exact search: {name} at {k}tx NOT confirmed on the EVM (dropped)")
        return False
    found[name] = {"width": f"exact {k}tx", "attack": [fmt_tx(x) for x in seq[:hit + 1]],
                   "reverted": [not s_["ok"] for s_ in trace["txs"][:hit + 1]], "source": "exact search"}
    status[name].append((f"exact {k}tx", "bug"))
    log(f"    FINDING (exact) {name} at {k}tx: " + " -> ".join(found[name]["attack"]))
    return True
