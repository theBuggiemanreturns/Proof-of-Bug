"""Export netlists + the solver's attack into compact JSON for the gate viewer."""
import json, sys
sys.path.insert(0, '.')
from gates import Netlist

def load(path, top):
    raw = json.load(open(path))["modules"][top]
    n = Netlist(path, top)
    return raw, n

def compact(path, top, labels=None):
    """Small circuit: gates as [kind, a, b, out] with wire ids renumbered."""
    raw, n = load(path, top)
    ids = {"0": 0, "1": 1}
    w = lambda b: ids.setdefault(b, len(ids))
    ins = [{"name": k, "bits": [w(b) for b in p[1]]} for k, p in n.ports.items() if p[0] == "input"]
    gates = [[0 if k == "NAND" else 1, w(i[0]), w(i[-1]), w(o)] for k, i, o in n.gates]
    outs = [{"name": k, "bits": [w(b) for b in p[1]]} for k, p in n.ports.items() if p[0] == "output"]
    return {"inputs": ins, "outputs": outs, "gates": gates, "nwires": len(ids)}

def big(path, top, cex):
    raw, n = load(path, top)
    nn = raw["netnames"]
    # simulate every wire under the counterexample
    v = {"0": 0, "1": 1}
    for k, (d, bits) in n.ports.items():
        if d == "input":
            for i, b in enumerate(bits): v[b] = (cex[k] >> i) & 1
    for kind, ins, out in n.gates: v[out] = 1 - (v[ins[0]] & v[ins[-1]])
    sig = lambda name: sum(v[b] << i for i, b in enumerate(nn[name]["bits"]))
    # region = the latest transaction whose inputs this gate depends on
    sup = {}
    for k, (d, bits) in n.ports.items():
        if d == "input":
            for b in bits: sup[b] = 1 << int(k[-1])
    for kind, ins, out in n.gates:
        sup[out] = 0
        for i in ins: sup[out] |= sup.get(i, 0)
    labels = ["tx1 · donate/deposit #1", "tx2 · deposit #2", "tx3 · deposit #3 + bug check"]
    region = [max((t for t in range(3) if sup[o] >> t & 1), default=0) for k, i, o in n.gates]
    depth = {}
    for kind, ins, out in n.gates:
        depth[out] = 1 + max(depth.get(i, 0) for i in ins)
    gates = [[depth[o], region[gi], v[o]] for gi, (k, i, o) in enumerate(n.gates)]
    idx = {g[2]: gi for gi, g in enumerate(n.gates)}
    edges = [[idx[i], gi] for gi, (k, ins, o) in enumerate(n.gates) for i in set(ins) if i in idx]
    # per-tx state, from the reference model (the circuit matches it: see the differential test)
    steps, ta, ts = [], 0, 0
    for i in range(3):
        op, amt = cex[f"op{i}"], cex[f"amt{i}"]
        sh = 0 if op else (amt if ts == 0 else amt * ts // ta)
        steps.append({"op": op, "amt": amt, "ta": ta, "ts": ts, "shares": sh,
                      "zero_mint": int(op == 0 and amt > 0 and sh == 0)})
        ta += amt; ts += sh
    return {"gates": gates, "edges": edges, "labels": labels, "steps": steps,
            "out": n.simulate(cex)}

cex = {"op0": 1, "amt0": 120, "op1": 0, "amt1": 7, "op2": 0, "amt2": 16}
data = {"zero_mint": compact("viz/zero_mint.json", "zero_mint"),
        "full_adder": compact("viz/full_adder.json", "full_adder"),
        "vault": big("netlist_0.json", "vault", cex)}
s = json.dumps(data, separators=(",", ":"))
open("viz/data.json", "w").write(s)
print(len(s), "bytes;", data["vault"]["steps"], data["vault"]["out"])
from collections import Counter
print(Counter(g[1] for g in data["vault"]["gates"]), data["vault"]["labels"], max(g[0] for g in data["vault"]["gates"]))
