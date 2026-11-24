"""Benchmark runner: every case's buggy variant must be caught and confirmed on the real
EVM; every fixed variant must come out clean. Prints a scoreboard and writes JSON.

A case lists its contracts in deployment order; the first is the primary contract at
0x99, the next at 0x98, and so on. Constructor arguments are Solidity expressions in
which {fixed} becomes true/false and {A0}, {A1}... become contract addresses.
"""
from __future__ import annotations
import json, sys, time, importlib, os
from .yul import compile_contract
from .model import Model, PRIMARY_ADDR, SENDER_BASE
from . import check, evm


def library_rules(case):
    """Swap a case's hand-written rules for its family rules (bench/library.py)."""
    from .families import fill
    from .rulelang import compile_rule, rule_fn
    from bench.library import LIBRARY
    rules, invs = {}, dict(case.get("invariants") or {})
    for fam, params in LIBRARY.get(case["id"], []):
        text, inv = fill(fam, **params)
        rules[f"{fam}"] = rule_fn(text)
        if inv:
            invs[f"{fam}_inv"] = compile_rule(inv)[0]
    return dict(case, rules=rules, invariants=invs, rule_text={f: fill(f, **p)[0] for f, p in LIBRARY.get(case["id"], [])})


def fmt_tx(x):
    s = f"{x['contract'] + '.' if x.get('contract') else ''}{x['fn']}({', '.join(map(str, x['args']))}) from {hex(x['sender'])}"
    if x.get("value"):
        s += f" sending {x['value']} wei"
    if "time" in x:
        s += f" at t={x['time']}"
    if "block" in x:
        s += f" in block {x['block']}"
    if x.get("hook"):
        s += f" [attacker calls back {x['hook']['fn']}({', '.join(map(str, x['hook']['args']))})]"
    return s


def build(case, fixed, root, W, k, users, max_unroll=8):
    flag = "true" if fixed else "false"
    subst = {"fixed": flag, **{f"A{i}": f"address({hex(PRIMARY_ADDR - i)})" for i in range(16)},
             **{f"U{i}": f"address({hex(SENDER_BASE + i)})" for i in range(8)}}
    specs, deploys = [], []
    import copy
    for i, ct in enumerate(case["contracts"]):
        con = compile_contract(ct["file"], ct["name"], root=root)
        if ct.get("alias"):  # two instances of one contract (e.g. two tokens) need distinct names in rules
            con = copy.copy(con)
            con.name = ct["alias"]
        imm = {case["flag"]: int(fixed)} if case.get("flag") in con.immutable_ids else {}
        specs.append((con, imm))
        deploys.append((ct["name"], PRIMARY_ADDR - i, ct.get("args", "''").format(**subst)))
    attacker = case.get("attacker")
    cfg = {"root": root, "imports": ["../../" + ct["file"] for ct in case["contracts"]], "deploys": deploys,
           "attacker": None if attacker is None else SENDER_BASE + attacker,
           "bytecode": {ct["name"]: con.bytecode for ct, (con, _) in zip(case["contracts"], specs)},
           "order": case.get("order"),  # deployment order (contract indices), if not the address order
           "setup": [x.format(**subst) for x in case.get("setup", [])],  # calls made after deployment
           # setup calls that must run right after one deployment (index -> statements), and contracts
           # the system creates itself at their model address (e.g. a pool its factory deploys)
           "after": {int(i): [x.format(**subst) for x in xs] for i, xs in case.get("after", {}).items()},
           "created": [i for i, ct in enumerate(case["contracts"]) if ct.get("created")],
           "deployer": case.get("deployer", "").format(**subst) or None}  # who deploys (default: the runner)
    extra = tuple(case.get("extra_keys", ()))  # addresses the deployment uses besides users/contracts
    probe = Model(specs, W=W, k=0, users=users, attacker=attacker, max_unroll=max_unroll, extra_keys=extra)
    if probe.eth_on:  # every user starts with half the word range in ETH; cases may fund contracts
        cfg["eth"] = [(u, 1 << (W - 1)) for u in probe.user_addrs] + \
                     [(PRIMARY_ADDR - i, amt) for i, amt in case.get("fund", {}).items()]
    cfg["tag"] = f"{case['id']}_{'fix' if fixed else 'bug'}"
    tr0 = evm.run(cfg, cfg["tag"] + "_init", [[]], probe.watch)[0]
    init = tr0["init"]
    # every immutable takes the value the real deployment wrote into the code
    for i, (con, imm) in enumerate(specs):
        code = tr0.get("code", {}).get(PRIMARY_ADDR - i, "")
        names = {v: k for k, v in con.immutable_ids.items()}
        for ident, (start, length) in con.immutable_refs.items():
            if ident in names and names[ident] not in imm and code:
                imm[names[ident]] = int(code[2 + 2 * start: 2 + 2 * (start + length)], 16)
    init_storage = {}
    for (a, s), v in init.items():
        if v:
            init_storage.setdefault(a, {})[s] = v
    mk = lambda kk: Model(specs, W=W, k=kk, users=users, attacker=attacker, init_storage=init_storage,
                          max_unroll=max_unroll, extra_keys=extra)
    m = isolate(case, specs, mk, cfg["tag"], k)
    m.excluded = {f"{con.name}.{sig}": why for con, _ in specs for sig, why in con.excluded.items()}
    m.init_trace = init
    for name, fn in case["rules"].items():
        m.add_rule(name, fn)
    too_big = {f"{hex(a)}:{s}": v for (a, s), v in init.items() if v >> W and (a, s) in probe.watch
               and not _packed(m, a, s)}
    return m, cfg, too_big


_ISOLATED = {}  # case tag -> {(contract, signature): why}: probes run once per case, not per build


def isolate(case, specs, mk, tag, k):
    """One function the engines cannot model must not stop every other function from being searched.
    Build the model the caller asked for (k transactions); when it raises Unsupported, the error names
    the transaction's entry point that reached the instruction (symexec.switch). That function is left
    out with its reason (Contract.excluded) and the model is built again, until it builds. Each one left
    out is reported as a coverage gap: it is not searched, and the verdict says so.
    The exact model the search uses is the one checked, so a function that only reaches the wall after
    other transactions (e.g. a withdrawal after a deposit) is found too. Exclusions are kept per case,
    so every build of the case (any k, any engine) sees the same set of functions."""
    from .symexec import Unsupported
    found = _ISOLATED.setdefault(tag, {})

    def apply():
        for con, _ in specs:
            con.excluded = {sig: why for (n, sig), why in found.items() if n == con.name}

    while True:
        apply()
        try:
            return mk(k)
        except Unsupported as e:
            ent = getattr(e, "entry", None)
            if ent is None:  # not inside any transaction's function (e.g. a fallback): cannot be isolated
                raise
            addr, sel = ent
            i = PRIMARY_ADDR - addr
            if not 0 <= i < len(specs):
                raise
            con = specs[i][0]
            sig = next((s for s, v in con.selectors.items() if v == sel and s not in con.excluded), None)
            if sig is None:
                raise
            found[(con.name, sig)] = str(e)


def _packed(m, a, s):
    con = next((c for c, addr in m.contracts if addr == a), None)
    if con is None or s == (1 << 256) - 1:  # a user's account or an ETH balance: never packed
        return False
    return sum(1 for v, sl in con.storage.items() if sl == s) > 1


def deployed_width(m):
    """The width the deployed state needs: every value must lie in one of the circuit's two windows,
    near 0 (plus 2 bits of headroom so it can grow) or within 2^(W-1) of 2^256 (max-uint sentinels).
    Addresses (the address universe, the deployer) and hashes are identities, not amounts."""
    from .symexec import Vals, ETH_SLOT
    ids = set(m.key_universe) | set(Vals.identities)
    need = 8
    for (a, s), v in m.init_trace.items():
        if not v or v in ids:
            continue
        top = (1 << 256) - v
        if v >= 1 << 255 and top < 1 << 200:
            need = max(need, top.bit_length() + 1)  # near 2^256: the top window
        elif v < 1 << 128:  # wider values are packed fields/addresses, or beyond any feasible circuit
            need = max(need, v.bit_length() + 2)
    return need


def auto_bounds(case, root, W, k, users, max_unroll=8, log=print):
    """Choose model bounds from the contract itself instead of fixed defaults:
    users >= the most address arguments any function takes; numbers wide enough for every
    constant the code compares inputs against; loops unrolled as far as they can run."""
    from .symexec import Vals
    from .yul import compile_contract
    nusers = users
    for ct in case["contracts"]:
        con = compile_contract(ct["file"], ct["name"], root=root)
        for f in con.functions():
            nusers = max(nusers, sum(1 for t in f[3] if t == "address"))
    for _ in range(6):
        Vals.width_need = 0
        # two transactions, so code that needs some prior state (an order, a deposit) is reached too
        m, _, _ = build(case, False, root, W, 2, nusers, max_unroll)
        changed = False
        if Vals.width_need >= W:
            W = Vals.width_need + 2
            changed = True
        dep = deployed_width(m)
        if dep > W:  # the deployed state itself (balances, reserves, supplies) must fit the model
            W = dep
            changed = True
        if m.world.unroll_hit and max_unroll < 64:
            max_unroll *= 2
            changed = True
        if not changed:
            break
    if (W, nusers, max_unroll) != (case.get("W", W), users, 8):
        log(f"      auto bounds for {case['id']}: width {W} bits, {nusers} users, loops unrolled to {max_unroll}")
    return W, nusers, max_unroll


def run_variant(case, fixed, root, widths, k, users, ndiff, budget, depths=None, max_unroll=8):
    """Search every rule over a ladder of (transactions, width) settings, each solve within
    `budget` seconds. A rule is settled by a confirmed attack; otherwise its status per step
    is kept ("clean", "timeout")."""
    from .circuit import TIMEOUT
    from .symexec import Vals
    t0 = time.time()
    users = case.get("users", users)
    Vals.width_need = 0
    depths = depths or [case.get("k", k)]
    m, cfg, too_big = build(case, fixed, root, widths[0], depths[0], users, max_unroll)
    base_gates, t_build = m.gate_count(), time.time() - t0
    coverage = []
    if m.world.unroll_hit:
        coverage.append(f"a loop can run past the unroll limit ({max_unroll})")
    if Vals.width_need >= widths[-1]:
        coverage.append(f"code compares inputs with {Vals.width_need}-bit constants but the model has {widths[-1]} bits")
    diff = check.differential(m, cfg, n=ndiff)
    status = {name: [] for name in case["rules"]}  # rule -> [(label, "clean"|"timeout"|"bug"|"unconfirmed", s)]
    findings = {}
    first = True
    for kk in depths:
        for W in widths:
            open_rules = [n for n in case["rules"] if not status[n] or status[n][-1][1] == "clean"]
            if not open_rules:
                break
            if not first:
                m, cfg, _ = build(case, fixed, root, W, kk, users, max_unroll)
            first = False
            for name in open_rules:
                fn = case["rules"][name]
                t = time.time()
                r = m.hunt(name, timeout=budget)
                dt = round(time.time() - t, 2)
                label = f"{kk}tx/{W}bit"
                if r is None:
                    status[name].append((label, "clean", dt))
                elif r == TIMEOUT:
                    status[name].append((label, "timeout", dt))
                else:
                    seq = r[1]
                    hit, trace = check.replay(m, cfg, fn, seq)
                    steps = trace["txs"]
                    upto = hit + 1 if hit is not None else len(seq)
                    shown = [x for x, st in zip(seq[:upto], steps[:upto]) if st["ok"]]
                    status[name].append((label, "bug" if hit is not None else "unconfirmed", dt))
                    findings[name] = {"width": label, "confirmed": hit is not None, "attack": [fmt_tx(x) for x in shown]}
    # unbounded proof by induction (integer engine): all sizes, any number of transactions
    from .intproof import Prover
    t1 = time.time()
    try:
        m0, _, _ = build(case, fixed, root, widths[0], 1, users, max_unroll)
        induct = Prover(m0).prove(case["rules"], init=m0.init_trace, timeout=min(budget, 60),
                                  invariants=case.get("invariants"))
    except Exception as e:
        induct = {n: {"status": "error", "detail": [f"{type(e).__name__}: {e}"[:200]], "lemmas": [], "invariants": []}
                  for n in case["rules"]}
    t_induct = round(time.time() - t1, 2)
    statuses = [r["status"] for r in induct.values()]
    induction = "PROVEN" if all(x == "proven" for x in statuses) else next(x for x in statuses if x != "proven")
    confirmed = any(f["confirmed"] for f in findings.values())
    unconfirmed = any(not f["confirmed"] for f in findings.values())
    if not fixed:
        verdict = "CAUGHT" if confirmed else ("FALSE ALARM" if unconfirmed else "MISSED")
    else:
        verdict = "STILL BUGGY" if confirmed else ("FALSE ALARM" if unconfirmed else "CLEAN")
    if coverage and verdict in ("MISSED", "CLEAN"):
        verdict = "INCOMPLETE"  # the model could not reach part of the behaviour: no claim made
    ok = (verdict == "CAUGHT") if not fixed else (verdict == "CLEAN")
    # how far each rule is proven clean, e.g. "<=12" or "8, 12:timeout"
    proof = {}
    for name, st in status.items():
        if any(x[1] in ("bug", "unconfirmed") for x in st):
            continue
        cleans = [w for w, s_, _ in st if s_ == "clean"]
        touts = [w for w, s_, _ in st if s_ == "timeout"]
        proof[name] = (f"clean up to {cleans[-1]}" if cleans else "") + (f", timeout at {touts[0]}" if touts else "")
    return {"case": case["id"], "variant": "fixed" if fixed else "buggy", "verdict": verdict, "pass": ok,
            "gates": base_gates, "build_s": round(t_build, 2), "total_s": round(time.time() - t0, 2),
            "diff_compared": diff["compared_txs"], "diff_mismatches": len(diff["mismatches"]),
            "diff_first_mismatch": diff["mismatches"][0] if diff["mismatches"] else None,
            "init_out_of_range": too_big, "status": status, "proof": proof,
            "induction": induction, "induction_detail": induct, "induction_s": t_induct,
            "unsound_proof": (not fixed) and induction == "PROVEN",  # a buggy version must never be proven
            "coverage": coverage,
            "findings": [dict(rule=n, **f) for n, f in findings.items()]}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("suites", nargs="*", default=["bench.level1"])
    ap.add_argument("--only", default=None)
    ap.add_argument("-W", type=int, default=8, help="base width (differential test runs here)")
    ap.add_argument("--ladder", default="", help="extra widths to try after the base, e.g. 10,12,16")
    ap.add_argument("--budget", type=float, default=120, help="seconds per solver call")
    ap.add_argument("--auto", action="store_true", help="choose users/width/loop bounds from the contract")
    ap.add_argument("--depths", default="", help="transaction-depth ladder, e.g. 3,5,8")
    ap.add_argument("--rules", default="case", choices=["case", "library"],
                    help="case: each case's own rules; library: the family rules from bench/library.py")
    ap.add_argument("-k", type=int, default=3)
    ap.add_argument("--users", type=int, default=2)
    ap.add_argument("--diff", type=int, default=200)
    a = ap.parse_args(argv)
    root = os.getcwd()
    cases = [c for s in a.suites for c in importlib.import_module(s).CASES]
    if a.rules == "library":
        cases = [library_rules(c) for c in cases]
    results, auto_cache = [], {}
    print(f"{'case':5} {'variant':7} {'verdict':12} {'all sizes':14} {'gates':>6} {'diff':>9} {'time':>6}  attack / notes")
    for case in cases:
        if a.only and case["id"] not in a.only.split(","):
            continue
        for fixed in (False, True):
            try:
                W0, users, unroll = a.W, a.users, 8
                if a.auto:
                    if not fixed or case["id"] not in auto_cache:
                        auto_cache[case["id"]] = auto_bounds(case, root, a.W, a.k, a.users)
                    W0, users, unroll = auto_cache[case["id"]]
                widths = [W0] + [int(w) for w in a.ladder.split(",") if w and int(w) > W0]
                depths = [int(d) for d in a.depths.split(",") if d] or None
                r = run_variant(case, fixed, root, widths, a.k, users, a.diff, a.budget, depths, unroll)
            except Exception as e:  # report and keep going
                r = {"case": case["id"], "variant": "fixed" if fixed else "buggy", "verdict": "ERROR",
                     "pass": False, "error": f"{type(e).__name__}: {e}"[:400]}
            results.append(r)
            if r["verdict"] == "ERROR":
                print(f"{r['case']:5} {r['variant']:7} {'ERROR':12} {'':14} {'':>6} {'':>9} {'':>6}  {r['error']}")
                continue
            f0 = next((f for f in r["findings"] if f.get("attack")), None)
            note = (f"[{f0['width']}] " + " -> ".join(f0["attack"])) if f0 else ""
            if r["proof"]:
                note = "; ".join(f"{p}" for p in r["proof"].values()) + ("  " + note if note else "")
            if r["diff_mismatches"]:
                note = f"DIFF MISMATCH {r['diff_first_mismatch']['problems']} " + note
            if r.get("coverage"):
                note = "COVERAGE GAP: " + "; ".join(r["coverage"]) + ("  " + note if note else "")
            if r["init_out_of_range"]:
                note = f"init values exceed {a.W} bits! " + note
            diff = f"{r['diff_compared']}/{r['diff_mismatches']}"
            ind = r["induction"]
            if r.get("unsound_proof"):
                ind = "UNSOUND!"
            lem = sorted({l for d in r["induction_detail"].values() for l in d.get("lemmas", [])})
            if ind == "PROVEN" and lem:
                ind += "+lemma"
            print(f"{r['case']:5} {r['variant']:7} {r['verdict']:12} {ind:14} {r['gates']:>6} {diff:>9} {r['total_s']:>5.1f}s  {note}")
    passed = sum(r["pass"] for r in results)
    nb = sum(1 for r in results if r["variant"] == "buggy")
    print(f"\nscore: {passed}/{len(results)} variants correct  "
          f"(buggy caught+confirmed: {sum(r['pass'] for r in results if r['variant']=='buggy')}/{nb}, "
          f"fixed clean: {sum(r['pass'] for r in results if r['variant']=='fixed')}/{len(results) - nb})")
    fixed_rows = [r for r in results if r["variant"] == "fixed" and r["verdict"] != "ERROR"]
    print(f"fixed versions proven for all sizes and any number of transactions: "
          f"{sum(r['induction'] == 'PROVEN' for r in fixed_rows)}/{len(fixed_rows)}")
    print(f"buggy versions wrongly proven (must be 0): {sum(bool(r.get('unsound_proof')) for r in results)}")
    print("diff column = transactions compared against the real EVM / mismatches")
    os.makedirs("gg-out", exist_ok=True)
    json.dump(results, open("gg-out/bench-results.json", "w"), indent=1, default=str)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
