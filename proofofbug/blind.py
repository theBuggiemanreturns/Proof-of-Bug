"""Blind evaluation (see BLIND_PROTOCOL.md).

    python -m proofofbug.blind prompts             # write blind/prompts/<id>.txt for the rule writer
    python -m proofofbug.blind run [--only C01]    # validate proposals, hunt, write BLIND_VERDICTS.md
    python -m proofofbug.blind commit              # print the sha256 of BLIND_VERDICTS.md

Cases come from blind/cases.py (contracts and deployment taken from the author's DEPLOY notes);
rules come only from blind/proposals/<id>.json (the independent rule writer). Nothing here
knows which contracts are buggy.

Verdict per contract:
  FLAGGED     some proposed rule is broken by a sequence the real EVM confirms (the attack is shown)
  CLEAN       no proposed rule breaks within the searched bounds (and PROVEN if the integer
              engine proves every rule for all sizes)
  INCOMPLETE  the model could not cover part of the behaviour (no claim either way)
  UNSUPPORTED the engine cannot model the contract (named feature)
"""
from __future__ import annotations
import argparse, hashlib, importlib, json, os, sys, time


ROUND = "blind"  # the round folder (round 1 = "blind"); set with --round


def rdir(root, *parts):
    return os.path.join(root, ROUND, *parts)


def outdir(root):
    return os.path.join(root, "gg-out", ROUND)


def verdict_file(root):
    return os.path.join(root, "BLIND_VERDICTS.md") if ROUND == "blind" else rdir(root, "VERDICTS.md")


def load_cases(root):
    import importlib.util
    sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(f"{ROUND}_cases", rdir(root, "cases.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CASES


REVIEW_TASK = """You are the independent RULE REVIEWER. Another AI wrote the safety rules below for this contract;
a solver will search for transaction sequences that break them, and a broken rule is reported as a bug.
So a WRONG rule (one that also breaks on correct behaviour) becomes a false alarm, and a MISSING rule
lets a bug through. You have no answer key. For every rule, check:
  - does every argument index, variable and function name mean what the rule assumes?
  - does it over-claim? (e.g. "the contract never holds token X" ignores that anyone can send tokens;
    "this call always succeeds" must state every condition: balances, approvals, pauses, deadlines)
  - is it implied by the code's intent, or only by the code as written? (rules must state the INTENT)
  - is an important property of some function not covered at all?
Reply with one JSON object: {"drop": [{"name": ..., "why": ...}], "fix": [<a full rule object with the
same name, corrected>], "add": [<new rule objects>]}. Rule objects use the same schema as the rules below.
Leave correct rules alone."""


def review_prompt(case, root, proposals):
    from .agent import RULE_LANGUAGE
    from .families import catalog
    t = open(rdir(root, "prompts", f"{case['id']}.txt")).read()
    contract = t[t.index("Contracts (the first is the one under test):"):]
    return (REVIEW_TASK + "\n\nFamilies:\n" + catalog() + "\n\n" + RULE_LANGUAGE + "\n\n" + contract +
            "\n\nRULES TO REVIEW:\n" + json.dumps(proposals, indent=1))


def apply_review(proposals, review):
    """The rule writer's proposals with the reviewer's drops, fixes and additions applied (recorded)."""
    drop = {d["name"] for d in review.get("drop", [])}
    fixes = {f["name"]: f for f in review.get("fix", [])}
    rules = [fixes.get(r["name"], r) for r in proposals.get("rules", []) if r["name"] not in drop]
    have = {r["name"] for r in rules}
    rules += [a for a in review.get("add", []) if a["name"] not in have]
    invs = proposals.get("invariants", [])  # a drop may name an invariant too
    kept_invs = [i for i in invs if i["name"] not in drop]
    rev = {"dropped": sorted(drop), "fixed": sorted(fixes), "added": [a["name"] for a in review.get("add", [])]}
    if len(kept_invs) < len(invs):
        rev["dropped_invariants"] = sorted(i["name"] for i in invs if i["name"] in drop)
    return {"rules": rules, "invariants": kept_invs, "review": rev}


def deployment_note(case):
    """Who is where and what the deployment did: context any rule writer would have. (The frozen
    agent prompt shows contract sources but not addresses, aliases or setup.)"""
    from .model import PRIMARY_ADDR, SENDER_BASE
    subst = {**{f"A{i}": f"A{i}" for i in range(16)}, **{f"U{i}": f"U{i}" for i in range(8)}, "fixed": "true"}
    lines = ["Deployment of this case (A0 is the contract under test):"]
    for i, ct in enumerate(case["contracts"]):
        nm = ct.get("alias") or ct["name"]
        lines.append(f"  A{i} = {nm}" + (f"  (an instance of {ct['name']}; write its storage as \"{nm}.var\")"
                                          if ct.get("alias") else ""))
    lines.append("  Users U0, U1, U2... are the accounts the solver controls (any of them can call anything).")
    if case.get("attacker") is not None:
        lines.append(f"  U{case['attacker']} is a contract: when the contract under test calls it (e.g. sends it ETH) it may call"
                     " back into the contract once per transaction, with any function and arguments.")
    dep = case.get("deployer")
    lines.append(f"  Deployer / owner / minter: {dep.format(**subst) if dep else 'the deployer, an account the solver does NOT control'}.")
    if case.get("extra_keys"):
        lines.append("  Other addresses in play: " + ", ".join(hex(k) for k in case["extra_keys"]))
    if case.get("setup"):
        lines.append("  Setup run once after deployment (Solidity, `this` = the deployer):")
        lines += ["    " + x.format(**subst) for x in case["setup"]]
    return "\n".join(lines)


def cmd_prompts(root, cases):
    from .agent import prompt
    os.makedirs(rdir(root, "prompts"), exist_ok=True)
    for case in cases:
        text = prompt(case, root) + "\n\n" + deployment_note(case)
        open(rdir(root, "prompts", f"{case['id']}.txt"), "w").write(text)
        print(f"{case['id']}: {len(text)} chars")


def validate_names(case, root, rules):
    """Keep rules that compile and name only things that exist (agent steps 1-2). Nothing is
    dropped for firing: on a blind contract a firing rule is the finding."""
    from .bench import build
    from .agent import unknown_functions
    kept, rejected = {}, []

    def try_build(names):
        return build(dict(case, rules={n: rules[n][1] for n in names}), True, root, 8, 1, case.get("users", 2))[0]

    def check(names):
        # One build checks a whole group; a failing group is split in halves, so the cost grows with the
        # number of bad rules, not with the number of rules (a big system takes ~20 s per build).
        # Same outcome as building every rule alone: rules do not affect each other's build.
        try:
            m = try_build(names)
        except Exception as e:
            if len(names) > 1:
                h = len(names) // 2
                check(names[:h]); check(names[h:])
                return
            n = names[0]
            if isinstance(e, KeyError):
                rejected.append((n, f"names something that does not exist: {e}"))
            else:  # any other problem with this one rule: reject it, never the case
                rejected.append((n, f"cannot be evaluated: {type(e).__name__}: {e}"))
            return
        for n in names:
            text, fn = rules[n]
            bad = unknown_functions(m, text)
            if bad:
                rejected.append((n, f"names functions that do not exist: {', '.join(bad)}"))
            else:
                kept[n] = (text, fn)

    if rules:
        check(list(rules))
    order = list(rules)
    rejected.sort(key=lambda r: order.index(r[0]))
    return {n: kept[n] for n in order if n in kept}, rejected


def hunt_case(case, root, kept, invs, budget, depths, ladder, log):
    """Search all kept rules over a ladder of depths and widths. One solve asks whether ANY open
    rule can break; a hit is replayed once on the real EVM and every open rule is checked on that
    trace. Per-rule solves are used only when the combined solve times out or is not confirmed."""
    from .bench import build, auto_bounds, fmt_tx
    from .circuit import TIMEOUT
    from .check import differential, rule_on_trace
    from . import evm
    from .symexec import Vals
    W, users, unroll = auto_bounds(dict(case, rules={}), root, 8, 3, case.get("users", 2), log=lambda *_: None)
    widths = [W] + [w for w in ladder if w > W]
    rules = {n: f for n, (_, f) in kept.items()}
    status = {n: [] for n in rules}
    findings, unconfirmed = {}, {}
    rec = {"bounds": {"width": widths, "users": users, "unroll": unroll, "depths": depths}, "coverage": [], "limits": []}
    # 1. fuzzing on the real EVM with values from the contract itself: any number size, cheap
    from .fuzz import fuzz
    m_small, cfg_small, _ = build(dict(case, rules=rules), True, root, 8, 1, users, unroll)
    # record only: the attack surface (callable functions, storage) for the report's coverage map
    rec["surface"] = {"functions": sorted({(f"{c.name}." if a != m_small.contracts[0][1] else "") + f[1]
                                           for f in m_small.funcs for c, a in m_small.contracts if a == f[0]}),
                      "storage": {c.name: list(c.storage) for c, _ in m_small.contracts}}
    from .yul import ARRAY_MAX
    arr = sorted({f[2] for f in m_small.funcs if any(str(t).startswith("length:") for t in f[4])})
    if arr:  # a bound on what the caller sends: searches AND proofs only cover arrays this short
        rec["limits"].append(f"array arguments of at most {ARRAY_MAX} elements ({', '.join(arr)})")
    t0 = time.time()
    for n, f in fuzz(m_small, cfg_small, rules, n=FUZZ_SEQUENCES, k=4, seed=1, log=log).items():
        findings[n] = f
        status[n].append(("fuzz 4tx", "bug"))
    log(f"  {case['id']} fuzz: {len(findings)} rules broken ({time.time()-t0:.0f}s)")
    # 2. bit-level search: exhaustive within each width (and the only one with ETH and callbacks)
    Vals.magnitude = set()
    first = True
    for d in depths:
        for w in widths:
            open_ = [n for n in rules if n not in findings and n not in unconfirmed]
            if not open_:
                break
            Vals.width_need = 0
            t0 = time.time()
            if _too_big(case, root, w, d, users, unroll, rules, open_):
                rec["coverage"].append(f"bit-level search skipped at {d}tx/{w}bit: the circuit would not fit in memory")
                log(f"  {case['id']} {d}tx/{w}bit: skipped (circuit too large for this machine)")
                continue
            m, cfg, _ = build(dict(case, rules={n: rules[n] for n in open_}), True, root, w, d, users, unroll)
            log(f"  {case['id']} {d}tx/{w}bit: {len(open_)} rules, {m.gate_count()} gates, built in {time.time()-t0:.0f}s")
            if first:
                diff = differential(m, cfg, n=150)
                rec["diff"] = {"compared": diff["compared_txs"], "mismatches": len(diff["mismatches"]),
                               "first": diff["mismatches"][0] if diff["mismatches"] else None}
                if m.world.unroll_hit and _unroll_reachable(m, budget):
                    rec["coverage"].append(f"a loop can run past the unroll limit ({unroll})")
                first = False
            if Vals.width_need > widths[-1]:
                rec["coverage"].append(f"needs {Vals.width_need}-bit numbers ({Vals.width_why}); searched up to {widths[-1]}")
            label = f"{d}tx/{w}bit"
            pending = list(open_)
            while pending:
                m.c.outputs["any_open"] = [m.c.any_([m.rules[n] for n in pending])]
                t0 = time.time()
                r = m.c.solve({"any_open": 1}, timeout=budget)
                dt = round(time.time() - t0, 1)
                if r is None:
                    for n in pending:
                        status[n].append((label, "clean", dt))
                    log(f"    all {len(pending)} open rules hold at {label} ({dt}s)")
                    break
                if r == TIMEOUT:
                    log(f"    combined search timed out at {label}; trying rules one by one")
                    for n in pending:
                        r1 = m.hunt(n, timeout=budget)
                        if r1 is None:
                            status[n].append((label, "clean", budget))
                        elif r1 == TIMEOUT:
                            status[n].append((label, "timeout", budget))
                        else:
                            _confirm(m, cfg, rules, [n], r1[1], label, findings, unconfirmed, status, log)
                    break
                seq = m.decode(r)
                hit = _confirm(m, cfg, rules, pending, seq, label, findings, unconfirmed, status, log)
                if not hit:  # the circuit's attack is not real on the EVM: isolate the rule(s) involved
                    for n in pending:
                        r1 = m.hunt(n, timeout=budget)
                        if r1 not in (None, TIMEOUT):
                            if not _confirm(m, cfg, rules, [n], r1[1], label, findings, unconfirmed, status, log):
                                unconfirmed[n] = {"width": label, "attack": [fmt_tx(x) for x in r1[1]]}
                                status[n].append((label, "not confirmed on the EVM"))
                pending = [n for n in pending if n not in findings and n not in unconfirmed]
    rec["magnitude"] = sorted(Vals.magnitude)  # behaviour above the searched width (casts, range checks)
    # 3. exact search from the deployed state: any number size, k transactions
    from .exact import exact_hunt
    # an attack the circuit found but the EVM rejected only says the circuit is unreliable for this
    # rule at this width: the rule stays open for the exact (full-size) search and the prover
    open_ = {n: rules[n] for n in rules if n not in findings}
    if open_:
        t0 = time.time()
        found, est, excl = exact_hunt(m_small, cfg_small, open_, depths=EXACT_DEPTHS, timeout=budget, log=log)
        findings.update(found)
        for n, st in est.items():
            status[n] += st
        # paths the exact search left to the bit-level engine are still searched (within its width):
        # a limit; functions no full-size engine models at all are missing coverage
        lim = {k: v for k, v in excl.items() if "explored by the bit-level search" in v}
        miss = {k: v for k, v in excl.items() if k not in lim}
        if lim:
            rec["limits"].append("attacker callbacks searched by the bit-level engine only (its width): " + ", ".join(lim))
        if miss:
            rec["coverage"].append("exact search could not model: " + "; ".join(f"{k} ({v})" for k, v in miss.items()))
        log(f"  {case['id']} exact search: {len(found)} rules broken ({time.time()-t0:.0f}s)")
    # 4. the integer prover for the rules that held (proofs for every size and any number of steps)
    from .intproof import Prover
    held = {n: rules[n] for n in rules if n not in findings}
    proof = {}
    if held:
        try:
            m0, cfg0, _ = build(dict(case, rules=held), True, root, widths[0], 1, users, unroll)
            hints, dropped = {n: f for n, (_, f) in invs.items()}, []
            for _ in range(4):  # helper invariants that do not hold are dropped, the rest proved again
                try:
                    res = Prover(m0).prove(held, init=m0.init_trace, timeout=min(budget, 60), invariants=hints or None)
                except ValueError as e:  # a hint already false in the deployed state
                    bad = str(e).split("invariant hint ")[1].split(" ")[0].split("[")[0]
                    hints.pop(bad, None); dropped.append(bad)
                    continue
                bad = set()
                for v in res.values():
                    for d in v["detail"]:
                        if d.startswith("relied on hints that were not proven: "):
                            bad |= {h.strip()[5:].split("[")[0] for h in d.split(": ", 1)[1].split(",")}
                if not bad:
                    break
                for b in bad:
                    hints.pop(b, None); dropped.append(b)
            proof = {n: v["status"] for n, v in res.items() if not n.startswith("hint:")}
            rec["hints_dropped"] = dropped
            from .trail import name_raw_slots
            rec["proof_detail"] = name_raw_slots(m0, {n: {k: v.get(k) for k in ("status", "detail", "lemmas", "invariants")}
                                                      for n, v in res.items()})  # record only: what each proof used or why it failed
            # 5. a counterexample to induction that also breaks the rule from the real deployed state
            #    is a real attack: replay each on the EVM
            from .cexreplay import replay_cex
            ni = {n: held[n] for n, v in proof.items() if v == "not inductive"}
            if ni:
                alone = Prover(m0).prove(ni, init=m0.init_trace, timeout=min(budget, 60))
                det = {n: v["detail"] for n, v in alone.items() if not n.startswith("hint:") and v["status"] == "not inductive"}
                for n, f in replay_cex(m0, cfg0, ni, det, log=log).items():
                    f["width"] = "prover counterexample, 1tx"
                    findings[n] = f
                    status[n].append(("prover counterexample", "bug"))
        except Exception as e:
            proof = {n: f"error: {type(e).__name__}: {str(e)[:120]}" for n in held}
    rec.update({"status": status, "findings": findings, "unconfirmed": unconfirmed, "proof": proof})
    return rec


FUZZ_SEQUENCES = 800
EXACT_DEPTHS = (1, 2, 3)
MAX_GATES = 6_000_000  # a larger circuit, its CNF and two racing solvers do not fit in 15 GB


def _unroll_reachable(m, budget):
    """Is running a loop past the unroll limit possible at all? The syntactic check only sees that
    the loop condition is symbolic; the solver decides whether the code bounds it (an over-
    approximation: it ignores the other conditions of the sequence, so 'unreachable' is certain)."""
    from .circuit import TIMEOUT
    m.c.outputs["unroll_reach"] = [m.c.any_(m.world.unroll_signals)]
    r = m.c.solve({"unroll_reach": 1}, timeout=budget)
    return r is not None  # a solution or a timeout: keep the honest note


def _too_big(case, root, w, d, users, unroll, rules, open_):
    """Estimate the circuit size from a 1-transaction build before building d transactions."""
    from .bench import build
    m1, _, _ = build(dict(case, rules={n: rules[n] for n in open_}), True, root, w, 1, users, unroll)
    return m1.gate_count() * d > MAX_GATES


def _confirm(m, cfg, rules, names, seq, label, findings, unconfirmed, status, log):
    """Replay one attack on the EVM and check every named rule on that trace."""
    from .bench import fmt_tx
    from .check import rule_on_trace
    from . import evm
    trace = evm.run(cfg, cfg["tag"] + "_replay", [seq], m.watch)[0]
    hit_any, hits = False, {}
    for n in names:
        hit = rule_on_trace(m, rules[n], seq, trace)
        hits[n] = hit
        if hit is not None:
            shown = [x for x, st in zip(seq[:hit + 1], trace["txs"][:hit + 1]) if st["ok"] or x is seq[hit]]
            findings[n] = {"width": label, "attack": [fmt_tx(x) for x in seq[:hit + 1]],
                           "reverted": [not st["ok"] for st in trace["txs"][:hit + 1]]}
            status[n].append((label, "bug", 0))
            log(f"    FINDING {n} at {label}: " + " -> ".join(findings[n]["attack"]))
            hit_any = True
    from . import trail
    # the circuit claims at least one of `names` breaks; rules it did not break on the EVM are
    # recorded as rejected only when nothing was confirmed (then the claim as a whole was false)
    shown = hits if not hit_any else {n: h for n, h in hits.items() if h is not None}
    trail.record("bit-level search", f"{label} (circuit width {m.W} bits)", list(shown), seq, trace, m, shown)
    return hit_any


def cmd_run(root, cases, only, budget, depths, ladder):
    from .agent import materialize
    from .symexec import Unsupported
    for case in cases:
        if only and case["id"] not in only.split(","):
            continue
        t0 = time.time()
        from . import trail
        trail.reset()
        lines = []  # the run log, kept in the record for the report
        log = lambda *a: (print(*a, flush=True), lines.append(" ".join(map(str, a))))
        pfile = rdir(root, "proposals", f"{case['id']}.json")
        rec = {"id": case["id"]}
        try:
            proposals = json.load(open(pfile))
            rules, invs, rejected = materialize(proposals)
            rec["rejected"] = [list(r) for r in rejected]
            kept, rej2 = validate_names(case, root, rules)
            rec["rejected"] += [list(r) for r in rej2]
            # invariants are name-checked the same way (a bad one would break every proof)
            from .rulelang import rule_fn
            inv_ok, rej3 = validate_names(case, root, {n: (t, rule_fn(t)) for n, (t, _) in invs.items()})
            rec["rejected"] += [["invariant " + r[0], r[1]] for r in rej3]
            invs = {n: invs[n] for n in inv_ok}
            rec["rules"] = {n: t for n, (t, _) in kept.items()}
            log(f"{case['id']}: {len(kept)} rules kept, {len(rec['rejected'])} rejected")
            rec.update(hunt_case(case, root, kept, invs, budget, depths, ladder, log))
            if rec["findings"]:
                rec["verdict"] = "FLAGGED"
            elif rec["coverage"] or any(any(s[1] == "timeout" for s in st) and not any(s[1] == "clean" for s in st)
                                        for st in rec["status"].values()):
                rec["verdict"] = "INCOMPLETE"
            else:
                rec["verdict"] = "CLEAN"
        except Unsupported as e:
            rec["verdict"], rec["unsupported"] = "UNSUPPORTED", str(e)
        except Exception as e:  # report, never guess
            import traceback
            rec["verdict"], rec["error"] = "ERROR", f"{type(e).__name__}: {e}"[:400]
            rec["trace"] = traceback.format_exc()[-1500:]
        rec["seconds"] = round(time.time() - t0, 1)
        rec["log"], rec["trail"] = lines, list(trail.TRAIL)
        os.makedirs(outdir(root), exist_ok=True)
        json.dump(rec, open(os.path.join(outdir(root), f"{case['id']}.json"), "w"), indent=1, default=str)
        print(f"{case['id']}: {rec['verdict']}  ({rec['seconds']}s)", flush=True)


def cmd_verdicts(root):
    import glob
    results = {}
    for f in sorted(glob.glob(os.path.join(outdir(root), "*.json"))):
        r = json.load(open(f))
        results[r["id"]] = r
    write_verdicts(root, results)
    return results


def _triage(root):
    """The rule writer's verdicts on each confirmed counterexample: {(case, rule): (verdict, why)}."""
    import glob
    out = {}
    for f in sorted(glob.glob(rdir(root, "triage_[0-9]*.json"))):
        for t in json.load(open(f))["triage"]:
            out[(t["case"], t["rule"])] = (t["verdict"], t["why"])
    return out


def classify(cid, r, tri):
    """The verdict for one case record and its evidence line (also used by report.py)."""
    for cv in list(r.get("coverage", [])):
        if "explored by the bit-level search only" in cv and cv.count("(") == cv.count("explored by the bit-level"):
            r["coverage"].remove(cv)
            r.setdefault("limits", []).append("attacker callbacks searched by the bit-level engine only (its width): "
                                              + cv.split(": ", 1)[1].split(" (")[0])
    v = r["verdict"]
    proven = [n for n, x in r.get("proof", {}).items() if x == "proven"]
    nrules = len(r.get("rules", {}))
    touts = sorted({n for n, st in r.get("status", {}).items() if st and st[-1][1] == "timeout"})
    real = {n: f for n, f in r.get("findings", {}).items() if tri.get((cid, n), ("?",))[0] == "real_bug"}
    wrong = [n for n in r.get("findings", {}) if tri.get((cid, n), ("?",))[0] == "rule_wrong"]
    pending = [n for n in r.get("findings", {}) if (cid, n) not in tri]
    if real:
        verdict = "BUGGY"
        ev = "; ".join(f"`{n}`: " + " -> ".join(f["attack"]) + f" (triage: {tri[(cid, n)][1]})" for n, f in real.items())
    elif v in ("UNSUPPORTED", "ERROR"):
        verdict = v
        ev = r.get("unsupported") or r.get("error") or ""
    else:
        depth = sorted({x[0] for st in r.get("status", {}).values() for x in st if x[1] == "clean"})
        held = [n for n in r.get("rules", {}) if n not in r.get("findings", {})]
        # a rule is covered at full width if the exact search found it clean, or it is proven
        full = [n for n in held if r.get("proof", {}).get(n) == "proven" or
                any(x[0].startswith("exact") and x[1] == "clean" for x in r.get("status", {}).get(n, []))]
        # a rule no engine covered: no proof and no clean search at all (timeouts, circuit attacks
        # the EVM rejected, unsupported). One such rule leaves the case INCOMPLETE.
        uncovered = [n for n in held if n not in full and
                     not any(x[1] == "clean" for x in r.get("status", {}).get(n, []))]
        if uncovered or r.get("coverage"):
            verdict = "INCOMPLETE"
        elif r.get("limits"):
            verdict = "NO BUG FOUND WITHIN LIMITS"
        elif len(full) == len(held) or not r.get("magnitude"):
            verdict = "NO BUG FOUND"
        else:
            verdict = "NO BUG FOUND WITHIN LIMITS"
        ev = (f"{nrules} rules; no real counterexample (searched {', '.join(depth) or 'nothing'}); "
              f"proven for all sizes: {len(proven)}/{nrules}")
        if touts:
            ev += f"; search timed out on {len(touts)}"
        if uncovered:
            ev += f"; not covered by any engine: {', '.join(uncovered)}"
        if r.get("coverage"):
            ev += "; coverage: " + "; ".join(r["coverage"])
        if r.get("limits"):
            ev += "; limits: " + "; ".join(r["limits"])
        if r.get("magnitude"):
            ev += f"; behaviour above the bit-level width: {', '.join(r['magnitude'])}; full-width (exact or proven) for {len(full)}/{len(held)} rules"
    if r.get("unconfirmed"):  # circuit attacks the EVM rejected: the circuit is unreliable there
        ev += "; bit-level attacks not reproduced on the EVM (rule kept open for the exact search and prover): " + \
              ", ".join(f"{n} ({next((x[1] for x in r['status'].get(n, []) if x[0].startswith('exact') or x[0] == 'proof'), 'no other engine')})"
                        for n in r["unconfirmed"] if n not in r.get("findings", {}))
    if wrong:
        ev += f"; rule-writer errors (triaged rule_wrong): {', '.join(wrong)}"
    if pending:
        ev += f"; NOT YET TRIAGED: {', '.join(pending)}"
    if r.get("diff"):
        ev += f"; circuit vs EVM: {r['diff']['compared']} txs, {r['diff']['mismatches']} mismatches"
    return verdict, ev


def write_verdicts(root, results):
    # a sealed verdict file (its hash was sent to the author) must never change again
    if os.path.exists(rdir(root, "VERDICTS.sha256")):
        raise SystemExit(f"{verdict_file(root)} is sealed ({rdir(root, 'VERDICTS.sha256')}); refusing to overwrite it")
    tri = _triage(root)
    lines = ["# Blind verdicts (committed before the answer key is revealed)", "",
             "Rules: written by an independent rule-writer session from the frozen agent prompt"
             + (" (FREEZE.txt v3)." if ROUND == "blind" else ", then checked by an independent reviewer session."),
             "Every counterexample below was replayed on the real EVM (Foundry). The rule writer then triaged",
             f"each one as `real_bug` or `rule_wrong` ({ROUND}/triage_*.json). The operator did not judge them.",
             f"Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}. Engine changes after receipt: "
             + ("BLIND_LOG.md." if ROUND == "blind" else f"{ROUND}/LOG.md."), "",
             "Verdicts: BUGGY = at least one confirmed counterexample triaged as a real bug; NO BUG FOUND = no real",
             "counterexample within the searched bounds (with how many rules are also proven for all sizes);",
             "NO BUG FOUND WITHIN LIMITS = as NO BUG FOUND, but the contract behaves differently at sizes the",
             "search could not reach (listed); INCOMPLETE = part of the search timed out or did not fit;",
             "UNSUPPORTED = the engine cannot model it.", "",
             "| Case | Verdict | Evidence |", "|---|---|---|"]
    for cid in sorted(results):
        verdict, ev = classify(cid, results[cid], tri)
        lines.append(f"| {cid} | {verdict} | {ev.replace('|', '/')[:1500]} |")
    open(verdict_file(root), "w").write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["prompts", "run", "verdicts", "commit"])
    ap.add_argument("--only", default="")
    ap.add_argument("--round", default="blind", help="round folder (round 1 = blind)")
    ap.add_argument("--budget", type=int, default=60)
    ap.add_argument("--depths", default="3,5,8")
    ap.add_argument("--ladder", default="16,24")
    a = ap.parse_args(argv)
    root = os.getcwd()
    global ROUND
    ROUND = a.round
    if a.cmd == "commit":  # seal the verdicts: from now on they cannot be regenerated
        h = hashlib.sha256(open(verdict_file(root), "rb").read()).hexdigest()
        if not os.path.exists(rdir(root, "VERDICTS.sha256")):
            open(rdir(root, "VERDICTS.sha256"), "w").write(f"{h}  {os.path.relpath(verdict_file(root), root)}\n")
        print(h)
        return
    if a.cmd == "verdicts":
        cmd_verdicts(root)
        return
    cases = load_cases(root)
    if a.cmd == "prompts":
        cmd_prompts(root, cases)
    else:
        cmd_run(root, cases, a.only, a.budget, [int(x) for x in a.depths.split(",")],
                [int(x) for x in a.ladder.split(",") if x])


if __name__ == "__main__":
    sys.exit(main())
