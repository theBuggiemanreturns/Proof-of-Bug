"""Step-by-step reports: every rule, every engine's claim, how each claim was confirmed or thrown out.

    python -m proofofbug.report --round round2_posthoc            # all cases
    python -m proofofbug.report --round round2_posthoc --only R05

Writes ROUND/reports/<case>.md, ROUND/reports/INDEX.md and ROUND/reports/REVIEW_PROMPT.txt.

The engines are machines: they only search what the rules say. The report lays out everything they
did so that a reviewer (a person or an AI agent) can see what was NOT asked: functions and storage no
rule talks about, rules only searched a few steps deep, findings that could combine, triage calls
that look wrong. A reviewer's new rule ideas go back through the machine like any other rule; the
report itself never turns a guess into a finding.
"""
import argparse
import glob
import json
import os
import re

from . import blind

REVIEW_PROMPT = """You are the REPORT REVIEWER for a bug-finding machine. Four engines (a fuzzer on the
real EVM, a bit-level circuit search, an exact 256-bit search, an induction prover) tried to break the
safety rules in the attached report. Every attack they claimed was replayed on the real EVM; the
report shows each claim, the EVM's answer, and the rule writer's triage. The engines are not
intelligent: they only check the rules they were given, within the bounds stated.

Read the contract source and the report. Do NOT re-run anything; reason from the evidence. Answer:
1. MISSED: properties the rules do not express. Use the coverage map: functions or storage no rule
   names, and behaviours (economic, ordering, rounding, access, cross-contract) nobody asked about.
2. COMBINATIONS: two or more findings, or a finding plus a weak spot, that together make a worse
   attack than either alone. Say the sequence.
3. TRIAGE: any `rule_wrong` call that looks like a real bug, or a `real_bug` that looks like a
   rule error. Quote the evidence (which values changed in which transaction).
4. SHALLOW COVERAGE: rules only searched to a small depth and not proven, where a longer sequence
   plausibly breaks them. Say why.
5. LIMITS: any stated limit (number width, array length, callbacks) that hides a plausible attack.

For every point give NEW RULES in the rule JSON format the report uses ({"name", "family": "custom",
"params": {}, "expr", "why"}), so the machine can test them. A point without a rule is an opinion; the
machine decides. Reply with one JSON object:
{"missed": [...], "combinations": [...], "triage": [...], "shallow": [...], "limits": [...],
 "new_rules": [<rule objects>]}"""


def _load(path, default=None):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return default


def _md(x):
    return str(x).replace("|", "\\|").replace("\n", " ")


def _rule_mentions(text):
    """Function names (called("f")) and storage names (pre/post("v" ...)) a rule text mentions."""
    fns = set(re.findall(r'called\("([^"]+)"\)', text))
    vars_ = set(re.findall(r'(?:pre|post|pre_sum|post_sum)\("([^"]+)"', text))
    return fns, vars_


def _signed(text):
    """Annotate numbers in the top half of uint256 with their value as a signed number: the
    EVM has no negative numbers, so -5 is sent as 2^256 - 5."""
    def f(mo):
        v = int(mo.group(0))
        return f"{v} (= {v - (1 << 256)} if signed)" if (1 << 255) <= v < (1 << 256) else mo.group(0)
    return re.sub(r"\d{70,78}", f, str(text))


def _src_files(case):
    return sorted({c["file"] for c in case.get("contracts", []) if c.get("file")})


def case_report(case, rec, props, tri, review_raw):
    cid = case["id"]
    L = [f"# {cid}: step-by-step report", ""]
    verdict, ev = blind.classify(cid, json.loads(json.dumps(rec)), tri) if rec else ("NOT RUN", "")
    L += [f"**Verdict: {verdict}**", "", f"Evidence line (as in VERDICTS.md): {ev}", ""]

    # 1. what was tested
    L += ["## 1. What was tested", ""]
    L.append("Source: " + ", ".join(f"`{f}`" for f in _src_files(case)))
    L.append("")
    L.append("Deployment (what the machine set up before searching):")
    L.append("")
    for c in case.get("contracts", []):
        L.append(f"- deploy `{c['name']}` from `{c.get('file')}` with constructor args `{c.get('args', '')}`")
    for st in case.get("setup", []):
        L.append(f"- `{st}`")
    L.append(f"- users: {case.get('users', 2)}; attacker contract: "
             + ("none" if case.get("attacker") is None else f"user U{case['attacker']} is a contract that can call back"))
    L.append("")
    L.append("Names in the evidence: A0, A1, ... are the deployed contracts in the order above; U0, U1, ... are the "
             "users; `deployer` is the test harness that deployed everything. In transaction arguments addresses "
             "appear as plain numbers: " + ", ".join(f"U{i} = {0x31 + i}" for i in range(case.get("users", 2) + 1))
             + ", " + ", ".join(f"{c['name']} (A{i}) = {0x99 - i}" for i, c in enumerate(case.get("contracts", []))) + ".")
    L.append("")
    if rec is None:
        L += ["**This case has no run record.**", ""]
        return "\n".join(L) + "\n"
    if rec.get("verdict") in ("UNSUPPORTED", "ERROR"):
        L += [f"## The run stopped: {rec['verdict']}", "", "```", rec.get("unsupported") or rec.get("error") or "", "```", ""]
        if rec.get("trace"):
            L += ["Traceback (end):", "", "```", rec["trace"], "```", ""]

    # 2. the rules
    rules = rec.get("rules", {})
    why = {r["name"]: r.get("why", "") for r in (props or {}).get("rules", [])}
    fam = {r["name"]: r.get("family", "") for r in (props or {}).get("rules", [])}
    rv = (props or {}).get("review", {})
    L += ["## 2. The rules (what must always be true)", "",
          "Written by an independent rule-writer session, then checked by a reviewer session. A rule is written "
          "as the condition that means it is BROKEN: the machine looks for a transaction where it is true.", ""]
    if rv:
        L.append(f"Review: dropped {rv.get('dropped') or 'none'}; fixed {rv.get('fixed') or 'none'}; added {rv.get('added') or 'none'}.")
        if review_raw:
            for d in review_raw.get("drop", []):
                L.append(f"- dropped `{d.get('name')}`: {d.get('why', '')}")
        L.append("")
    L += ["| Rule | Family | Broken when | Why it should hold |", "|---|---|---|---|"]
    for n, t in rules.items():
        L.append(f"| `{n}` | {fam.get(n, '')} | `{_md(t)}` | {_md(why.get(n, ''))} |")
    if rec.get("rejected"):
        L += ["", "Rules the machine refused before searching (bad names or syntax):", ""]
        for r in rec["rejected"]:
            L.append(f"- `{r[0]}`: {r[1] if len(r) > 1 else ''}")
    invs = (props or {}).get("invariants", [])
    if invs:
        L += ["", "Helper invariants offered to the prover (used only if proven):", ""]
        for i in invs:
            dropped = i["name"] in rec.get("hints_dropped", [])
            L.append(f"- `{i['name']}`: `{i['expr']}` ({i.get('why', '')})" + (" **dropped: did not hold or could not be proven**" if dropped else ""))
    L.append("")

    # 3. search settings and the model check
    b = rec.get("bounds", {})
    L += ["## 3. How hard the machine looked", ""]
    L.append(f"- bit-level circuit width(s): {b.get('width')} bits; transactions per search: {b.get('depths')}; "
             f"users: {b.get('users')}; loops unrolled up to {b.get('unroll')} times")
    L.append("- fuzzer: random sequences of 4 transactions on the real EVM (numbers of any size)")
    L.append("- exact search: 1, 2 and 3 transactions from the deployed state at full 256-bit size")
    L.append("- prover: induction over any number of transactions from any state the rules allow")
    d = rec.get("diff")
    if d:
        L.append(f"- model check: {d['compared']} random transactions run on both the circuit and the real EVM; "
                 f"{d['mismatches']} disagreements" + (f" (first: `{_md(d['first'])}`)" if d.get("first") else ""))
    for x in rec.get("limits", []):
        L.append(f"- LIMIT: {x}")
    for x in rec.get("coverage", []):
        L.append(f"- COVERAGE GAP: {x}")
    if rec.get("magnitude"):
        L.append(f"- behaviour above the circuit width (checked only by the full-size engines): {', '.join(rec['magnitude'])}")
    L.append(f"- run time: {rec.get('seconds')} s")
    L.append("")

    # 4. per-rule step log
    st, proof, findings = rec.get("status", {}), rec.get("proof", {}), rec.get("findings", {})
    L += ["## 4. Every rule, engine by engine", "",
          "Each step is one engine's answer, in the order they ran. `clean` = searched and not broken within "
          "that bound; `bug` = an attack that the real EVM confirmed; `not confirmed on the EVM` = the engine "
          "claimed an attack and the real EVM showed it false (see section 6); `proven` = holds for every "
          "number size and any number of transactions.", "",
          "| Rule | Steps | Proof | Final |", "|---|---|---|---|"]
    for n in rules:
        steps = "; ".join(f"{s[0]}: {s[1]}" + (f" ({s[2]}s)" if len(s) > 2 and s[2] else "") for s in st.get(n, [])) or "none"
        pr = proof.get(n, "")
        if n in findings:
            t = tri.get((cid, n))
            final = f"BROKEN, triage: **{t[0]}**" if t else "BROKEN, not triaged yet"
        elif pr == "proven":
            final = "holds (proven)"
        elif any(s[1] == "clean" for s in st.get(n, [])):
            final = "holds within the searched bounds (not proven)"
        else:
            final = "**not covered by any engine**"
        L.append(f"| `{n}` | {_md(steps)} | {_md(pr)} | {final} |")
    L.append("")

    # 5. findings with evidence and triage
    trail = rec.get("trail", [])
    L += ["## 5. Findings: attacks the real EVM confirmed", ""]
    if not findings:
        L += ["None.", ""]
    for n, f in findings.items():
        t = tri.get((cid, n))
        L += [f"### `{n}`", "", f"Rule: `{rules.get(n, '')}`", "",
              f"Found by: {f.get('source') or 'bit-level search'} ({f.get('width', '')})", "", "Attack:", ""]
        for i, tx in enumerate(f.get("attack", [])):
            rv_ = f.get("reverted", [])
            L.append(f"{i + 1}. `{_signed(tx)}`" + (" (reverted: no effect)" if i < len(rv_) and rv_[i] else ""))
        evd = next((e for e in trail if n in e.get("rules", {}) and e["rules"][n].startswith("confirmed")), None)
        if evd:
            L += ["", "What the real EVM did (values that changed, before -> after):", ""]
            for i, s_ in enumerate(evd.get("evm", [])):
                if "error" in s_:
                    L.append(f"- {s_['error']}")
                    continue
                ch = ", ".join(f"{k}: {a} -> {b_}" for k, (a, b_) in s_["changed"].items()) or "nothing changed"
                L.append(f"- tx {i + 1}{' (reverted)' if s_['reverted'] else ''}: {ch}")
        L += ["", f"Triage by the rule writer: **{t[0]}**: {t[1]}" if t else "Triage: **not triaged yet**", ""]

    # 6. claims thrown out
    rejected = [e for e in trail if any(v.startswith("rejected") for v in e.get("rules", {}).values())]
    L += ["## 6. Claims thrown out (how each false alarm was disproved)", "",
          "An engine claimed these attacks; replaying them on the real EVM showed the rule still holds, so "
          "none of them is reported as a bug. The engine that made the claim is unreliable there, so the rule "
          "stayed open for the other engines (their results are in section 4).", ""]
    if not rejected:
        L += ["None: every claimed attack was confirmed." if trail else
              "No record (this run predates the audit trail; section 4 still shows `not confirmed on the EVM` steps).", ""]
    for e in rejected:
        L.append(f"- **{e['engine']}**, {e['where']}: claimed {', '.join(f'`{r}`' for r, v in e['rules'].items() if v.startswith('rejected'))}")
        for i, s_ in enumerate(e.get("evm", [])):
            if "error" in s_:
                L.append(f"    - {s_['error']}")
                continue
            ch = ", ".join(f"{k}: {a} -> {b_}" for k, (a, b_) in s_["changed"].items()) or "nothing changed"
            L.append(f"    - tx {i + 1} `{_signed(s_['tx'])}`{' REVERTED' if s_['reverted'] else ''}: {ch}")
    L.append("")
    if rec.get("unconfirmed"):
        L += ["Bit-level attacks kept as `unconfirmed` (the circuit claimed them, the EVM did not reproduce them):", ""]
        for n, u in rec["unconfirmed"].items():
            L.append(f"- `{n}` at {u.get('width')}: " + " -> ".join(f"`{_signed(x)}`" for x in u.get("attack", [])))
        L.append("")

    # 7. proofs
    pd = rec.get("proof_detail", {})
    L += ["## 7. Proofs", ""]
    auto = sorted({str(i) for d_ in pd.values() for i in (d_.get("invariants") or [])})
    if auto:
        L += ["Facts the prover established first and then relied on (values no transaction can change):", ""]
        L += [f"- `{x[:160]}`" for x in auto] + [""]
    if not proof:
        L += ["No rule reached the prover (all were broken first) or the prover did not run.", ""]
    for n, p in proof.items():
        dd = pd.get(n, {})
        extra = []
        if dd.get("lemmas"):
            extra.append("lemmas used: " + ", ".join(dd["lemmas"]))
        det = [x for x in (dd.get("detail") or []) if x][:3]
        if p != "proven" and det:
            extra.append("why: " + " / ".join(map(str, det))[:500])
        L.append(f"- `{n}`: **{p}**" + (" (" + "; ".join(extra) + ")" if extra else ""))
    hp = [n for n in pd if n.startswith("hint:")]
    if hp:
        L.append(f"- helper invariants proven and used: {', '.join(h[5:] for h in hp if pd[h].get('status') == 'proven') or 'none'}")
    L.append("")

    # 8. coverage map: what no rule talks about
    surf = rec.get("surface")
    L += ["## 8. Coverage map: what the rules talk about", "",
          "Rules that name no function apply to every call. A function or storage variable no rule names is "
          "checked only by those general rules: that is where a reviewer should look first.", ""]
    if not surf:
        L += ["No record (this run predates the coverage map).", ""]
    else:
        fn_rules, var_rules, general = {}, {}, []
        primary = case["contracts"][0]["name"] if case.get("contracts") else ""
        for n, t in rules.items():
            fns, vs = _rule_mentions(t)
            if not fns:
                general.append(n)
            for f_ in fns:
                fn_rules.setdefault(f_, []).append(n)
            for v in vs:
                key = v if "." in v else f"{primary}.{v}"
                if n not in var_rules.setdefault(key, []):
                    var_rules[key].append(n)
        L.append(f"General rules (apply to every call): {', '.join(f'`{g}`' for g in general) or 'none'}")
        L += ["", "| Function | Rules that name it |", "|---|---|"]
        for f_ in surf["functions"]:
            rs = fn_rules.get(f_, [])
            L.append(f"| `{f_}` | {', '.join(f'`{r}`' for r in rs) if rs else '**none: general rules only**'} |")
        L += ["", "| Storage | Rules that read it |", "|---|---|"]
        for con, vs in surf["storage"].items():
            for v in vs:
                rs = var_rules.get(f"{con}.{v}", [])
                L.append(f"| `{con}.{v}` | {', '.join(f'`{r}`' for r in rs) if rs else '**none**'} |")
        L.append("")

    # 9. full run log
    if rec.get("log"):
        L += ["## 9. Raw run log", "", "```"] + rec["log"] + ["```", ""]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", required=True)
    ap.add_argument("--only")
    ap.add_argument("--root", default=".")
    ap.add_argument("--records", help="folder of run records (default gg-out/ROUND)")
    a = ap.parse_args(argv)
    blind.ROUND = a.round
    root = a.root
    cases = blind.load_cases(root)
    tri = blind._triage(root)
    recdir = a.records or blind.outdir(root)
    out = blind.rdir(root, "reports")
    os.makedirs(out, exist_ok=True)
    index = [f"# Reports: {a.round}", "", "One file per case. Each shows the rules, every engine's answer, every attack "
             "with the real EVM's evidence, every false claim and how it was disproved, the proofs, and a coverage map. "
             "`REVIEW_PROMPT.txt` is the task for an AI reviewer (give it the report and the contract source).", "",
             "| Case | Verdict | Rules | Broken | Proven | Claims thrown out |", "|---|---|---|---|---|---|"]
    for case in cases:
        cid = case["id"]
        if a.only and cid not in a.only.split(","):
            continue
        rec = _load(os.path.join(recdir, f"{cid}.json"))
        props = _load(blind.rdir(root, "proposals", f"{cid}.json"))
        review = _load(blind.rdir(root, "reviews", f"{cid}.json"))
        text = case_report(case, rec, props, tri, review)
        open(os.path.join(out, f"{cid}.md"), "w").write(text)
        if rec:
            v, _ = blind.classify(cid, json.loads(json.dumps(rec)), tri)
            thrown = sum(1 for e in rec.get("trail", []) if any(x.startswith("rejected") for x in e.get("rules", {}).values()))
            index.append(f"| [{cid}]({cid}.md) | {v} | {len(rec.get('rules', {}))} | {len(rec.get('findings', {}))} | "
                         f"{sum(1 for x in rec.get('proof', {}).values() if x == 'proven')} | "
                         f"{thrown if rec.get('trail') is not None else 'not recorded'} |")
        else:
            index.append(f"| [{cid}]({cid}.md) | NOT RUN | | | | |")
        print(f"{cid}: report written")
    open(os.path.join(out, "INDEX.md"), "w").write("\n".join(index) + "\n")
    open(os.path.join(out, "REVIEW_PROMPT.txt"), "w").write(REVIEW_PROMPT + "\n")


if __name__ == "__main__":
    main()
