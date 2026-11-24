"""Audit trail: every claim an engine makes, and what the real EVM said about it.

Record-keeping only. Nothing here changes what any engine searches or decides; the run reads
nothing back from the trail. Each entry is one claim ("this sequence breaks these rules") with
the EVM's answer per transaction (reverted or not, which storage values changed) and the outcome
("confirmed" or "rejected: the rule holds on the real trace"). The report (report.py) turns the
trail into a step-by-step document a person or an AI reviewer can check.
"""
from .model import SENDER_BASE, PRIMARY_ADDR
from .symexec import ETH_SLOT, mapping_slot, Vals

TRAIL = []          # entries of the case being run; blind.py resets and stores it per case
MAX_ENTRIES = 400   # a pathological run must not produce an unreadable record


def reset():
    TRAIL.clear()


def _addr_names(m):
    names = {a: con.name for con, a in m.contracts}
    for i in range(8):
        names.setdefault(SENDER_BASE + i, f"U{i}")
        names.setdefault(PRIMARY_ADDR - i, f"A{i}")
    for x in Vals.identities:
        names.setdefault(x, "deployer")
    return names


def addr(m, a):
    return _addr_names(m).get(a, hex(a)) if isinstance(a, int) else str(a)


def slot_names(m):
    """(address, slot) -> readable name: Contract.var, Contract.var[key], Contract.var[k1][k2],
    with +j for the j-th slot of a multi-slot value, and Contract.ETH for ETH balances."""
    if getattr(m, "_trail_names", None) is not None:
        return m._trail_names
    an, out = _addr_names(m), {}
    for con, a in m.contracts:
        for var, base in con.storage.items():
            d, n = con.mapping_depth(var), con.value_slots(var)
            sfx = lambda j: f"+{j}" if j else ""
            if d == 0:
                for j in range(n):
                    out[(a, base + j)] = f"{con.name}.{var}{sfx(j)}"
            elif d == 1:
                for k in m.key_universe:
                    for j in range(n):
                        out[(a, mapping_slot(k, base) + j)] = f"{con.name}.{var}[{an.get(k, hex(k))}]{sfx(j)}"
            else:
                for k1 in m.key_universe:
                    for k2 in m.key_universe:
                        for j in range(n):
                            out[(a, mapping_slot(k2, mapping_slot(k1, base)) + j)] = \
                                f"{con.name}.{var}[{an.get(k1, hex(k1))}][{an.get(k2, hex(k2))}]{sfx(j)}"
    for a, nm in an.items():
        out[(a, ETH_SLOT)] = f"{nm}.ETH"
    m._trail_names = out
    return out


def evidence(m, seq, trace, upto=None):
    """Per transaction: the call, whether it reverted, and every watched value that changed."""
    from .bench import fmt_tx
    names = slot_names(m)
    pre, steps = trace["init"], []
    n = len(seq) if upto is None else upto + 1
    for tx, st in list(zip(seq, trace["txs"]))[:n]:
        post = st["slots"]
        ch = {}
        for key in set(pre) | set(post):
            a, b = pre.get(key, 0), post.get(key, 0)
            if a != b:
                ch[names.get(tuple(key) if not isinstance(key, tuple) else key, f"{hex(key[0])}:{key[1]}")] = [str(a), str(b)]
        steps.append({"tx": fmt_tx(tx), "reverted": not st["ok"], "changed": dict(sorted(ch.items()))})
        pre = post
    return steps


def record(engine, where, rules, seq, trace, m, hits):
    """One claim and the EVM's answer. hits: {rule: index of the breaking tx or None}."""
    if len(TRAIL) >= MAX_ENTRIES:
        if len(TRAIL) == MAX_ENTRIES:
            TRAIL.append({"engine": "trail", "note": f"more than {MAX_ENTRIES} claims; the rest were not recorded"})
        return
    try:
        last = max([h for h in hits.values() if h is not None], default=None)
        ev = evidence(m, seq, trace, last)
    except Exception as e:  # the trail must never break a run
        ev = [{"error": f"{type(e).__name__}: {e}"[:200]}]
    TRAIL.append({"engine": engine, "where": where,
                  "rules": {r: ("confirmed: breaks at tx %d" % (h + 1) if h is not None
                                else "rejected: the rule holds on the real EVM trace") for r, h in hits.items()},
                  "evm": ev})


def note(engine, where, text):
    if len(TRAIL) < MAX_ENTRIES:
        TRAIL.append({"engine": engine, "where": where, "note": text})


def name_raw_slots(m, obj):
    """Replace raw "0xADDR:SLOT" storage references in proof details with readable names."""
    import json, re
    names = slot_names(m)
    def f(mo):
        return names.get((int(mo.group(1), 16), int(mo.group(2))), mo.group(0))
    try:
        return json.loads(re.sub(r"0x([0-9a-fA-F]+):(\d+)", f, json.dumps(obj, default=str)))
    except Exception:
        return obj
