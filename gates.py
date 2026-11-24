"""Load a Yosys NAND/NOT netlist, simulate it gate by gate, and search it with a SAT solver."""
import json, sys
from pysat.solvers import Cadical153

class Netlist:
    def __init__(self, path, top="vault"):
        m = json.load(open(path))["modules"][top]
        self.ports = {n: (p["direction"], p["bits"]) for n, p in m["ports"].items()}
        self.gates = []                      # (kind, inputs, output)
        for c in m["cells"].values():
            t, pc = c["type"], c["connections"]
            if t == "$_NAND_": self.gates.append(("NAND", [pc["A"][0], pc["B"][0]], pc["Y"][0]))
            elif t == "$_NOT_": self.gates.append(("NOT", [pc["A"][0]], pc["Y"][0]))
            else: raise ValueError(f"non-NAND cell {t}")
        self._toposort()

    def _toposort(self):
        driver = {g[2]: g for g in self.gates}
        done, order = set(), []
        def visit(w, stack=()):
            if w in done or w not in driver: return
            g = driver[w]
            for i in g[1]: visit(i)
            done.add(w); order.append(g)
        sys.setrecursionlimit(100000)
        for g in self.gates: visit(g[2])
        self.gates = order

    def nand_count(self):   # NOT = NAND with both inputs tied together
        return len(self.gates)

    def simulate(self, inputs):
        """inputs: {port: int} -> {output port: int}"""
        v = {"0": 0, "1": 1}
        for n, (d, bits) in self.ports.items():
            if d == "input":
                for k, b in enumerate(bits): v[b] = (inputs[n] >> k) & 1
        for kind, ins, out in self.gates:
            v[out] = 1 - (v[ins[0]] & v[ins[-1]])
        return {n: sum(v[b] << k for k, b in enumerate(bits))
                for n, (d, bits) in self.ports.items() if d == "output"}

    def find(self, want):
        """SAT search: find inputs that make every output in `want` equal its value, or None."""
        ids = {}
        def var(b):
            if b not in ids: ids[b] = len(ids) + 1
            return ids[b]
        s = Cadical153()
        T = var("const1"); s.add_clause([T])
        lit = lambda b: T if b == "1" else (-T if b == "0" else var(b))
        for kind, ins, out in self.gates:          # Tseitin encoding of y = NAND(a, b)
            a, b, y = lit(ins[0]), lit(ins[-1]), lit(out)
            s.add_clause([y, a]); s.add_clause([y, b]); s.add_clause([-y, -a, -b])
        for n, val in want.items():
            s.add_clause([lit(self.ports[n][1][0]) if val else -lit(self.ports[n][1][0])])
        if not s.solve(): return None
        model = set(x for x in s.get_model() if x > 0)
        return {n: sum((lit(b) in model) << k for k, b in enumerate(bits))
                for n, (d, bits) in self.ports.items() if d == "input"}
