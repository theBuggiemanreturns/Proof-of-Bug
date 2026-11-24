"""Mutation testing: how strong is a set of rules?

We make many deliberately broken copies ("mutants") of a correct contract, each with one
small change of the kind real bugs are made of: a flipped comparison, + for -, a deleted
`require`, a deleted state update, an off-by-one constant, two statements swapped. Then:

  killed      some rule finds an attack on the mutant, confirmed on the real EVM
  survived    no rule fires, but the mutant really behaves differently from the original
              on the EVM: a blind spot, or a harmless change (e.g. a stricter check)
  equivalent  no observable difference from the original on random transactions: ignored

Rule strength = killed / (killed + survived). Survivors are listed so people (or the AI
agent) can see exactly which kinds of breakage the rules don't notice.
"""
from __future__ import annotations
import os, re, random, time, hashlib
from . import check, evm
from .circuit import TIMEOUT

REL = [("<=", "<"), (">=", ">"), ("<", "<="), (">", ">="), ("==", "!="), ("!=", "==")]
ARITH = [(" + ", " - "), (" - ", " + "), (" * ", " / "), (" / ", " * ")]
COMPOUND = [("+=", "-="), ("-=", "+=")]


def _contract_span(src, name):
    m = re.search(rf"\bcontract\s+{re.escape(name)}\b[^{{]*{{", src)
    if not m:
        raise ValueError(f"contract {name} not found")
    depth, i = 1, m.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        i += 1
    return m.start(), i


def _code_part(line):
    """The line without a trailing // comment."""
    k = line.find("//")
    return line if k < 0 else line[:k]


def _in_function(lines, idx):
    """Is line idx inside a function body (not the constructor, not a declaration)?"""
    depth, inside = 0, False
    for j in range(idx, -1, -1):
        code = _code_part(lines[j])
        depth += code.count("}") - code.count("{")
        if depth < 0 and re.search(r"\bfunction\b", code):
            return True
        if depth < 0 and re.search(r"\bconstructor\b", code):
            return False
        if depth < 0:
            depth = 0  # a nested block opening (if/for): keep looking outward
    return False


def mutants(src, name):
    """All single-change mutants of contract `name` inside `src`: [(id, description, new_src)]."""
    a, b = _contract_span(src, name)
    body = src[a:b]
    lines = body.split("\n")
    out = []

    def add(desc, new_lines):
        new_body = "\n".join(new_lines)
        out.append((desc, src[:a] + new_body + src[b:]))

    for i, line in enumerate(lines):
        code = _code_part(line)
        if not code.strip():
            continue
        # where on this line mutations may happen: a statement line inside a function body, or
        # the body of a one-line function `function f(..) .. { body }`
        if re.search(r"\bfunction\b", code):
            lb, rb = code.find("{"), code.rfind("}")
            if lb < 0 or rb < lb:
                continue
            lo, hi = lb + 1, rb
        elif _in_function(lines, i) and not re.search(r"\bmapping\b|\bevent\b|\bconstructor\b", code):
            lo, hi = 0, len(code)
        else:
            continue
        region = code[lo:hi]
        tag = f"line {i + 1}: {region.strip()[:70]}"

        def sub(s0, e0, new):  # replace region[s0:e0]
            nl = list(lines)
            nl[i] = line[:lo + s0] + new + line[lo + e0:]
            return nl

        for old, new in REL:
            for m in re.finditer(re.escape(old), region):
                s0, e0 = m.start(), m.end()
                if region[max(0, s0 - 1):s0] in ("<", ">", "=", "!") or region[e0:e0 + 1] in ("<", ">", "="):
                    continue
                add(f"{tag} | '{old}' -> '{new}'", sub(s0, e0, new))
        for old, new in ARITH + COMPOUND:
            for m in re.finditer(re.escape(old), region):
                add(f"{tag} | '{old.strip()}' -> '{new.strip()}'", sub(m.start(), m.end(), new))
        # statements on the line: remove a require, or remove a state update
        for m in re.finditer(r"[^;{}]+;", region):
            stmt = m.group(0).strip()
            if stmt.startswith("require("):
                add(f"{tag} | require removed: {stmt[:40]}", sub(m.start(), m.end(), " /* require removed */"))
            elif re.fullmatch(r"[\w\[\]\.\(\) ,]+\s*(=|\+=|-=)\s*[^=].*;", stmt) and not stmt.startswith(
                    ("uint", "int", "bool", "address", "return", "(")):
                add(f"{tag} | state update removed: {stmt[:40]}", sub(m.start(), m.end(), " /* update removed */"))
        m = re.match(r"(\s*)if \((.*)\)(.*)$", region)
        if m and m.group(2).count("(") == m.group(2).count(")"):
            add(f"{tag} | condition negated", sub(0, len(region), f"{m.group(1)}if (!({m.group(2)})){m.group(3)}"))
        for m in re.finditer(r"(?<![\w.])(\d+)(?![\w.])", region):
            n = int(m.group(1))
            if n > 1000:
                continue
            for k2 in (n + 1, n - 1):
                if k2 >= 0:
                    add(f"{tag} | constant {n} -> {k2}", sub(m.start(), m.end(), str(k2)))
        # swap two consecutive statements on one line, or with the next line (ordering bugs)
        stmts = list(re.finditer(r"[^;{}]+;", region))
        for x, y in zip(stmts, stmts[1:]):
            if not y.group(0).strip().startswith(("return", "require")):
                new_region = region[:x.start()] + " " + y.group(0).strip() + " " + x.group(0).strip() + region[y.end():]
                add(f"{tag} | swapped two statements", sub(0, len(region), new_region))
        st = region.strip()
        if lo == 0 and st.endswith(";") and i + 1 < len(lines):
            nxt = _code_part(lines[i + 1]).strip()
            if nxt.endswith(";") and not nxt.startswith(("return", "require")) and not st.startswith("return"):
                if len(line) - len(line.lstrip()) == len(lines[i + 1]) - len(lines[i + 1].lstrip()):
                    nl = list(lines)
                    nl[i], nl[i + 1] = lines[i + 1], lines[i]
                    add(f"{tag} | swapped with the next statement", nl)
    # dedupe identical sources
    seen, uniq = set(), []
    for desc, s in out:
        h = hashlib.sha1(s.encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            uniq.append((desc, s))
    return [(f"m{j:03d}", d, s) for j, (d, s) in enumerate(uniq)]


def run_case(case, root, rules=None, max_mutants=40, seed=7, W=8, k=3, users=2, budget=20, ndiff=60, log=print):
    """Mutate the case's primary contract (fixed variant) and score `rules` (default: the case's)."""
    from .bench import build
    rules = rules or case["rules"]
    primary = case["contracts"][0]
    src = open(os.path.join(root, primary["file"])).read()
    allm = mutants(src, primary["name"])
    rnd = random.Random(seed)
    chosen = allm if len(allm) <= max_mutants else sorted(rnd.sample(allm, max_mutants))
    mdir = os.path.join(root, "mutants", case["id"])
    os.makedirs(mdir, exist_ok=True)
    base_case = dict(case, rules=rules)
    m0, cfg0, _ = build(base_case, True, root, W, k, users)
    seqs, _ = check.random_sequences(m0, ndiff, seed)
    base_traces = evm.run(cfg0, f"{case['id']}_mut_base", seqs, m0.watch)
    results = []
    for mid, desc, msrc in chosen:
        t0 = time.time()
        path = os.path.join("mutants", case["id"], f"{mid}.sol")
        open(os.path.join(root, path), "w").write(msrc)
        mcase = dict(base_case, id=f"{case['id']}_{mid}",
                     contracts=[dict(c, file=path) if c["file"] == primary["file"] else c for c in case["contracts"]])
        try:
            m, cfg, _ = build(mcase, True, root, W, k, users)
        except Exception as e:
            results.append({"id": mid, "change": desc, "status": "not compiled", "why": str(e)[:120]})
            continue
        killed_by = []
        for name, fn in rules.items():
            r = m.hunt(name, timeout=budget)
            if r is None or r == TIMEOUT:
                continue
            hit, _ = check.replay(m, cfg, fn, r[1])
            if hit is not None:
                killed_by.append(name)
        if killed_by:
            status = "killed"
        else:  # does the mutant behave differently from the original at all?
            tr = evm.run(cfg, f"{case['id']}_{mid}_eq", seqs, m0.watch)
            differs = any(_trace_key(a) != _trace_key(b) for a, b in zip(base_traces, tr))
            status = "survived" if differs else "equivalent"
        results.append({"id": mid, "change": desc, "status": status, "killed_by": killed_by,
                        "seconds": round(time.time() - t0, 1)})
        log(f"   {mid} {status:10} {desc[:90]}{'  <- ' + ','.join(killed_by) if killed_by else ''}")
    return results, len(allm)


def _trace_key(tr):
    return [(t["ok"], t["ret"] if t["ok"] else 0, tuple(sorted(t["slots"].items()))) for t in tr["txs"]]


def score(results):
    k = sum(r["status"] == "killed" for r in results)
    s = sum(r["status"] == "survived" for r in results)
    return k, s, (k / (k + s) if k + s else None)
