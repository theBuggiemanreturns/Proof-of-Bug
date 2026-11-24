"""The AI rule agent: the AI proposes rules, the machine decides which ones are kept.

    python -m proofofbug.agent bench.level1 --only B01 --api                 # ask Claude
    python -m proofofbug.agent bench.level1 --only B01 --proposals p.json    # proposals from a file

Pipeline for every proposed rule:
  1. compile   it must be valid in the safe rule language (or a valid family fill)
  2. bind      every variable / function it names must exist in the contract
  3. honest    it must not fire on the contract as intended (the fixed version); if it
               fires and the attack is confirmed on the EVM, that is reported as a finding
  4. bug       does the set catch the known buggy version (when there is one)?
  5. mutants   how many deliberately broken copies each rule catches (its fingerprint)
  6. prune     rules with identical fingerprints are duplicates: one is kept
The report gives the final rule set and its strength before/after.
"""
from __future__ import annotations
import argparse, importlib, json, os, sys
from .families import FAMILIES, fill, catalog
from .rulelang import compile_rule, rule_fn, RuleError

RULE_LANGUAGE = """Rule language (an expression that is TRUE when a transaction BREAKS the rule):
  ok / reverted                  did the call succeed
  called("fn")                   the transaction called function fn ("Contract.fn" for another contract)
  arg(i)                         i-th argument of the call;  sender  the caller;  ret  first return value
  now                            the time of the call (block.timestamp)
  pre("var", key...) / post(...) storage before / after the call; keys for mappings (e.g. sender, arg(0), U0)
  pre_sum("map") / post_sum(...) sum of a mapping over all accounts
  pre("orders", arg(0), "amount") a struct field: keys first, then the field name in quotes;
                                 post_sum("userInfo", "amount") sums one field over all accounts
                                 (mappings keyed by ids, e.g. order ids 1, 2, 3..., take ids as keys)
  wide(x)                        use for products so they never overflow
  and, or, not, + - * //, < <= > >= == !=   (no chained comparisons)
  "Contract.var" reads another contract's storage; A0, A1 are contract addresses, U0, U1 users.
  pre("ETH", x) / post("ETH", x) the ETH balance of account x (e.g. A0 the contract, sender)
  u in a rule means "any user": the rule breaks if it breaks for some user, e.g.
    ok and u != sender and post("balanceOf", u) < pre("balanceOf", u)   (someone else lost balance)
  Invariants (state facts that always hold) may use u for "every account", e.g.
    post("debt", u) * 2 > post("collateral", u) * post("price")   (TRUE when broken)"""

SCHEMA = {
    "type": "object",
    "properties": {
        "rules": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "family": {"type": "string", "description": "a family name from the catalog, or 'custom'"},
                "params": {"type": "object", "additionalProperties": {"type": "string"}},
                "expr": {"type": "string", "description": "rule-language expression, for family 'custom'"},
                "why": {"type": "string"},
            },
            "required": ["name", "family", "params", "expr", "why"],
            "additionalProperties": False}},
        "invariants": {"type": "array", "items": {
            "type": "object",
            "properties": {"name": {"type": "string"}, "expr": {"type": "string"}, "why": {"type": "string"}},
            "required": ["name", "expr", "why"],
            "additionalProperties": False}},
    },
    "required": ["rules", "invariants"],
    "additionalProperties": False,
}


def context(case, root):
    from .yul import compile_contract
    parts = []
    for ct in case["contracts"]:
        con = compile_contract(ct["file"], ct["name"], root=root)
        src = open(os.path.join(root, ct["file"])).read()
        from .mutation import _contract_span
        a, b = _contract_span(src, ct["name"])
        storage = ", ".join(f"{v} ({con.storage_types[v].replace('t_', '')})" for v in con.storage)
        funcs = ", ".join(f[1] for f in con.functions())
        parts.append(f"### {ct['name']}\nstorage: {storage}\nfunctions: {funcs}\n```solidity\n{src[a:b]}\n```")
    return "\n\n".join(parts)


def prompt(case, root):
    return f"""You are writing safety rules for smart contracts. A solver searches for transaction
sequences that break your rules, and every rule is then checked by machine: it must not fire on
the contract as intended, and it is scored by how many deliberately broken copies of the contract
it catches. Rules that fire on correct behaviour are thrown away, so state what must ALWAYS hold.

Prefer filling a rule family (a general law) over a custom rule. Cover every function: what each
must change, by how much, what it must never change, who may call it, and what can never be
created from nothing. Also give invariants (state facts) that make the rules provable.

Checklist (from ~900 public audit findings; each item names the families that express it):
- Sibling entry points (deposit/mint, withdraw/withdrawTo/redeem, vote/changeVote, create/update/
  cancel): every check one sibling enforces, write it as a rule for EVERY sibling (never_when,
  frozen_when, no_third_party_loss). Every amount one sibling takes in, its reverse must give back.
- Early returns / fast paths: every record the slow path updates must also move on the fast path
  (in_sync, ledger).
- Two records that stand for the same value (a total and the sum of a mapping, booked assets and
  a token balance): in_sync, ledger, bounded_by.
- Value from nothing: rounding in the caller's favour, first deposit, donations, paying more than
  was funded or than time allows (fair_redemption, share_price_monotone, nonzero_mint, bounded_by,
  accrual_bounded).
- Who can move whose funds: no_third_party_loss, no_loss_beyond_allowance, authorized_change.
- Time: locks, deadlines, vesting, voting windows, rate limits (never_when, frozen_when,
  rate_limited, accrual_bounded); counters and indices that must only rise (monotone).
- Liveness: an honest user can always get their funds out (exit_all, exit_amount, must_succeed).

Families (fill every blank; blank values are rule-language fragments or names):
{catalog()}

{RULE_LANGUAGE}

Contracts (the first is the one under test):
{context(case, root)}"""


def propose_api(case, root):
    """Ask Claude for proposals (needs ANTHROPIC_API_KEY or an `ant auth login` profile)."""
    import anthropic
    client = anthropic.Anthropic()
    response = client.beta.messages.create(
        model="claude-opus-5-5",
        max_tokens=16000,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        thinking={"type": "adaptive"},
        output_config={"effort": "high", "format": {"type": "json_schema", "schema": SCHEMA}},
        messages=[{"role": "user", "content": prompt(case, root)}],
    )
    if response.stop_reason == "refusal":
        raise RuntimeError(f"the model declined: {response.stop_details}")
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)


def materialize(proposals):
    """Turn proposals into compiled rules. Returns (rules {name: (text, fn)}, invariants, rejected)."""
    rules, invs, rejected = {}, {}, []
    for p in proposals.get("rules", []):
        try:
            if p["family"] == "custom":
                text = p["expr"]
            else:
                if p["family"] not in FAMILIES:
                    raise RuleError(f"unknown family {p['family']}")
                text, inv = fill(p["family"], **p["params"])
                if inv:
                    invs[f"{p['name']}_inv"] = (inv, compile_rule(inv)[0])
            rules[p["name"]] = (text, rule_fn(text))
        except (RuleError, KeyError, IndexError, ValueError) as e:
            rejected.append((p.get("name", "?"), "does not compile", str(e)))
    for p in proposals.get("invariants", []):
        try:
            invs[p["name"]] = (p["expr"], compile_rule(p["expr"])[0])
        except RuleError as e:
            rejected.append((p["name"], "invariant does not compile", str(e)))
    return rules, invs, rejected


def validate(case, root, proposals, max_mutants=25, budget=20, log=print, W=8, users=2):
    from .bench import build
    from .check import replay
    from .circuit import TIMEOUT
    from .mutation import run_case, score
    rules, invs, rejected = materialize(proposals)
    log(f"{len(rules)} rules compiled, {len(rejected)} rejected at compile time")
    # 2+3: bind and honest-usage on the intended (fixed) version
    kept, findings, holds = {}, [], []
    for name, (text, fn) in rules.items():
        try:
            m, cfg, _ = build(dict(case, rules={name: fn}), True, root, W, 3, users)
        except KeyError as e:
            rejected.append((name, "names something that doesn't exist", str(e)))
            continue
        bad_names = unknown_functions(m, text)
        if bad_names:
            rejected.append((name, f"names functions that don't exist: {', '.join(bad_names)}", text))
            continue
        if m.gate_count(f"rule:{name}") == 0:
            # the names are real, so the contract can't break this rule at all: it already holds
            # by construction. Keep it: a broken copy of the contract may well break it.
            kept[name] = (text, fn)
            holds.append(name)
            continue
        r = m.hunt(name, timeout=budget)
        if r is None or r == TIMEOUT:
            kept[name] = (text, fn)
            continue
        hit, _ = replay(m, cfg, fn, r[1])
        if hit is None:
            rejected.append((name, "fires in the model but not on the real EVM", text))
        else:
            findings.append((name, text, [f"{t['fn']}({t['args']})" for t in r[1][:hit + 1]]))
            rejected.append((name, "fires on the intended contract (bad rule, or a real finding: see findings)", text))
    log(f"{len(kept)} rules pass the honest-usage check")
    # 4: does the set catch the known bug?
    caught = None
    if case.get("flag"):
        m, cfg, _ = build(dict(case, rules={n: f for n, (_, f) in kept.items()}), False, root, W, 3, users)
        caught = []
        for name, (text, fn) in kept.items():
            r = m.hunt(name, timeout=budget)
            if r not in (None, TIMEOUT) and replay(m, cfg, fn, r[1])[0] is not None:
                caught.append(name)
    # 5: mutants
    res, total = run_case(dict(case), root, rules={n: f for n, (_, f) in kept.items()},
                          max_mutants=max_mutants, budget=budget, log=lambda *_: None, W=W, users=users)
    k, s, rate = score(res)
    fp = {n: frozenset(r["id"] for r in res if n in r.get("killed_by", [])) for n in kept}
    # 6: prune duplicates (same non-empty fingerprint): keep family rules first, then shorter
    groups = {}
    for n in sorted(kept, key=lambda n: (rules_family(proposals, n) == "custom", len(kept[n][0]))):
        groups.setdefault(fp[n], []).append(n)
    final = {}
    for f, names in groups.items():
        if not f:
            for n in names:  # catches no mutant: keep only if it catches the known bug
                if caught and n in caught:
                    final[n] = kept[n][0]
            continue
        final[names[0]] = kept[names[0]][0]
    return {"rejected": rejected, "findings": findings, "holds_by_construction": holds, "kept": {n: t for n, (t, _) in kept.items()},
            "caught_known_bug": caught, "mutants": {"killed": k, "survived": s, "strength": rate},
            "fingerprints": {n: sorted(v) for n, v in fp.items()}, "final": final,
            "survivors": [r for r in res if r["status"] == "survived"], "invariants": {n: t for n, (t, _) in invs.items()}}


def unknown_functions(m, text):
    import ast
    names = {f[1] for f in m.funcs if f[0] == m.contracts[0][1]} | \
        {f"{c.name}.{f[1]}" for c, a in m.contracts for f in m.funcs if f[0] == a}
    used = [n.args[0].value for n in ast.walk(ast.parse(text, mode="eval"))
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "called" and n.args
            and isinstance(n.args[0], ast.Constant)]
    return [u for u in used if u not in names]


def rules_family(proposals, name):
    return next((p["family"] for p in proposals.get("rules", []) if p["name"] == name), "custom")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("suite")
    ap.add_argument("--only", required=True)
    ap.add_argument("--api", action="store_true", help="ask Claude for proposals")
    ap.add_argument("--proposals", help="JSON file with proposals (same format the API returns)")
    ap.add_argument("--show-prompt", action="store_true")
    ap.add_argument("--max", type=int, default=25)
    a = ap.parse_args(argv)
    root = os.getcwd()
    case = next(c for c in importlib.import_module(a.suite).CASES if c["id"] == a.only)
    if a.show_prompt:
        print(prompt(case, root))
        return
    proposals = propose_api(case, root) if a.api else json.load(open(a.proposals))
    from .bench import auto_bounds
    W, users, _ = auto_bounds(case, root, 8, 3, case.get("users", 2))
    rep = validate(case, root, proposals, max_mutants=a.max, W=W, users=users)
    print(f"\n{case['id']}: kept {len(rep['kept'])}, final after pruning {len(rep['final'])}")
    for n, why, d in rep["rejected"]:
        print(f"  rejected {n}: {why}")
    for n in rep["holds_by_construction"]:
        print(f"  holds by construction on this contract (kept): {n}")
    for n, t, attack in rep["findings"]:
        print(f"  FINDING {n} fires on the intended contract: {' -> '.join(attack)}")
    if rep["caught_known_bug"] is not None:
        print(f"  known bug caught by: {', '.join(rep['caught_known_bug']) or 'NONE'}")
    m = rep["mutants"]
    print(f"  mutants: killed {m['killed']}, survived {m['survived']} -> strength "
          f"{m['strength']:.0%}" if m["strength"] is not None else "  mutants: none scoreable")
    for n, t in rep["final"].items():
        print(f"  FINAL {n}: {t}   (catches {len(rep['fingerprints'][n])} mutants)")
    for r in rep["survivors"]:
        print(f"  blind spot: {r['change'][:100]}")
    os.makedirs("gg-out", exist_ok=True)
    json.dump(rep, open(f"gg-out/agent-{case['id']}.json", "w"), indent=1, default=str)


if __name__ == "__main__":
    sys.exit(main())
