"""Turn the integer prover's counterexamples into real attacks.

When the prover says a rule is "not inductive", Z3 has found a call (arguments, caller, time) that
breaks the rule from SOME state, with exact 256-bit numbers. That state may be unreachable, so the
call alone proves nothing. But many rules depend mostly on the call itself (e.g. "the stored
deposit equals rate x duration"), and then the same call breaks the rule from the real deployed
state too. This module replays each such call on the real EVM from the deployed state and checks
the rule on the real trace: a hit is a confirmed finding at full width, exactly like a bounded-
search finding, and it reaches values (2^127...) no narrow bit-level model can.

Added AFTER the blind answer key was revealed (C11 was missed although the prover had the
counterexample); results from it are reported separately and do not change the blind score.
"""
from __future__ import annotations
import json, re


def calls_from_detail(details):
    """(function name, call dict) for every 'fn: breaks from state ... || CALL {...}' line."""
    out = []
    for d in details:
        m = re.match(r"(\w+): breaks from state .* \|\| CALL (\{.*\})$", d)
        if m:
            out.append((m.group(1), json.loads(m.group(2))))
    return out


def replay_cex(m, cfg, rules, proof_details, log=print):
    """rules: {name: fn}; proof_details: {name: [detail lines]}. Returns {rule: finding}."""
    from . import evm
    from .check import rule_on_trace
    from .bench import fmt_tx
    found = {}
    primary = m.contracts[0][1]
    for name, details in proof_details.items():
        for fname, call in calls_from_detail(details):
            f = next((f for f in m.funcs if f[1] == fname and f[0] == primary), None) or \
                next((f for f in m.funcs if f[1] == fname), None)
            if f is None:
                continue
            a, nm, sig, sel, types = f
            sender = call.get("caller")
            if sender not in m.user_addrs:
                sender = m.user_addrs[0]
            args = [call.get(f"arg{j}", 0) for j in range(len(types))]
            tx = {"to": a, "fn": nm, "sig": sig, "selector": sel, "sender": sender, "args": args, "hook": None,
                  "contract": None if a == primary else next(c.name for c, ad in m.contracts if ad == a)}
            now = call.get("now")
            if getattr(m, "uses_time", False) and now is not None:
                tx["time"] = max(1, now)
            if sig in getattr(m, "payable", ()):
                tx["value"] = call.get("callvalue", 0)
            trace = evm.run(cfg, cfg["tag"] + "_cex", [[tx]], m.watch)[0]
            hit = rule_on_trace(m, rules[name], [tx], trace)
            from . import trail
            trail.record("prover counterexample", "1tx from the deployed state", [name], [tx], trace, m, {name: hit})
            log(f"    {name} via {fname}: {'CONFIRMED on the EVM' if hit is not None else 'not reproducible from the deployed state'}")
            if hit is not None:
                found[name] = {"attack": [fmt_tx(tx)], "source": "integer prover counterexample, replayed on the EVM"}
                break
    return found
