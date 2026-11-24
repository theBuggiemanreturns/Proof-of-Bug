"""NAND-only circuit builder.

Every signal is an integer id. 0 and 1 are the constants; every other id is a primary
input or a 2-input NAND gate. Building a gate first tries algebraic simplification and
structural hashing, so constant parts of a design fold away and identical sub-circuits
are shared. NOT x is NAND(x, x), so the gate count is exactly what TapeOut would burn.

Words are lists of signal ids, least significant bit first.
"""
from __future__ import annotations

FALSE, TRUE = 0, 1


class Circuit:
    def __init__(self):
        self.kind: list = [("const", 0), ("const", 1)]  # id -> ("const",v) | ("in",name) | ("nand",a,b)
        self._hash: dict = {}
        self.inputs: dict[str, list[int]] = {}
        self.outputs: dict[str, list[int]] = {}

    # ---------- primitives ----------
    def new_input(self, name: str, width: int = 1) -> list[int]:
        bits = []
        for i in range(width):
            self.kind.append(("in", f"{name}[{i}]"))
            bits.append(len(self.kind) - 1)
        self.inputs[name] = bits
        return bits

    def _inv_of(self, a: int):
        """If a == NOT x (i.e. NAND(x, x)), return x."""
        k = self.kind[a]
        if k[0] == "nand" and k[1] == k[2]:
            return k[1]
        return None

    def nand(self, a: int, b: int) -> int:
        if a == FALSE or b == FALSE:
            return TRUE
        if a == TRUE:
            return self.not_(b)
        if b == TRUE:
            return self.not_(a)
        if a == b:
            return self.not_(a)
        if self._inv_of(a) == b or self._inv_of(b) == a:
            return TRUE  # NAND(x, NOT x) = 1
        return self._gate(a, b)

    def _gate(self, a: int, b: int) -> int:
        key = (a, b) if a <= b else (b, a)
        g = self._hash.get(key)
        if g is None:
            self.kind.append(("nand", key[0], key[1]))
            g = len(self.kind) - 1
            self._hash[key] = g
        return g

    def not_(self, a: int) -> int:
        if a <= 1:
            return 1 - a
        x = self._inv_of(a)
        if x is not None:
            return x
        return self._gate(a, a)

    def and_(self, a, b):
        return self.not_(self.nand(a, b))

    def or_(self, a, b):
        return self.nand(self.not_(a), self.not_(b))

    def xor(self, a, b):
        if a == FALSE: return b
        if b == FALSE: return a
        if a == TRUE: return self.not_(b)
        if b == TRUE: return self.not_(a)
        if a == b: return FALSE
        t = self.nand(a, b)
        return self.nand(self.nand(a, t), self.nand(b, t))

    def mux(self, s, a, b):
        """s ? a : b"""
        if s == TRUE or a == b: return a
        if s == FALSE: return b
        if a == TRUE and b == FALSE: return s
        if a == FALSE and b == TRUE: return self.not_(s)
        return self.nand(self.nand(s, a), self.nand(self.not_(s), b))

    def any_(self, bits):
        acc = FALSE
        for b in bits:
            acc = self.or_(acc, b)
        return acc

    def all_(self, bits):
        acc = TRUE
        for b in bits:
            acc = self.and_(acc, b)
        return acc

    # ---------- words ----------
    @staticmethod
    def const_word(v: int, w: int) -> list[int]:
        return [(v >> i) & 1 for i in range(w)]

    def wnot(self, x): return [self.not_(a) for a in x]
    def wand(self, x, y): return [self.and_(a, b) for a, b in zip(x, y)]
    def wor(self, x, y): return [self.or_(a, b) for a, b in zip(x, y)]
    def wxor(self, x, y): return [self.xor(a, b) for a, b in zip(x, y)]
    def wmux(self, s, x, y): return [self.mux(s, a, b) for a, b in zip(x, y)]
    def iszero(self, x): return self.not_(self.any_(x))
    def eq(self, x, y): return self.iszero(self.wxor(x, y))

    def add(self, x, y, cin=FALSE):
        out, c = [], cin
        for a, b in zip(x, y):
            axb = self.xor(a, b)
            out.append(self.xor(axb, c))
            c = self.nand(self.nand(a, b), self.nand(c, axb))
        return out, c

    def sub(self, x, y):
        """x - y and the 'no borrow' flag (1 when x >= y unsigned)."""
        return self.add(x, self.wnot(y), TRUE)

    def lt(self, x, y):
        return self.not_(self.sub(x, y)[1])

    def slt(self, x, y):
        flip = lambda v: v[:-1] + [self.not_(v[-1])]
        return self.lt(flip(x), flip(y))

    def mul(self, x, y):
        w = len(x)
        acc = [FALSE] * w
        for i in range(w):
            partial = [FALSE] * i + [self.and_(a, y[i]) for a in x[: w - i]]
            acc, _ = self.add(acc, partial)
        return acc

    def divmod(self, x, y):
        """Unsigned restoring division. EVM semantics: x/0 = 0 and x%0 = 0."""
        w = len(x)
        r = [FALSE] * w
        q = [FALSE] * w
        yz = y + [FALSE]
        for i in range(w - 1, -1, -1):
            sh = [x[i]] + r  # (r << 1) | x_i, w+1 bits
            diff, no_borrow = self.add(sh, self.wnot(yz), TRUE)
            q[i] = no_borrow
            r = self.wmux(no_borrow, diff, sh)[:w]
        z = self.iszero(y)
        zero = [FALSE] * w
        return self.wmux(z, zero, q), self.wmux(z, zero, r)

    def _shift(self, x, amt, left, fill=FALSE):
        w = len(x)
        out = list(x)
        k = 0
        while (1 << k) < w:
            s = 1 << k
            if left:
                shifted = [fill] * s + out[: w - s]
            else:
                shifted = out[s:] + [fill] * s
            out = self.wmux(amt[k], shifted, out)
            k += 1
        # amount >= w gives all `fill`
        big = self.not_(self.lt(amt, self.const_word(w, len(amt))))
        return self.wmux(big, [fill] * w, out)

    def shl(self, x, amt): return self._shift(x, amt, True)
    def shr(self, x, amt): return self._shift(x, amt, False)
    def sar(self, x, amt): return self._shift(x, amt, False, fill=x[-1])

    # ---------- analysis ----------
    def gate_count(self) -> int:
        return sum(1 for k in self.kind if k[0] == "nand")

    def used_gates(self) -> list[int]:
        """Gates in the fan-in cone of the outputs (what would actually be taped out)."""
        seen, stack = set(), [b for bits in self.outputs.values() for b in bits]
        while stack:
            g = stack.pop()
            if g in seen or self.kind[g][0] != "nand":
                continue
            seen.add(g)
            stack.extend(self.kind[g][1:])
        return sorted(seen)

    def simulate(self, assign: dict[str, list[int]], lanes: int = 1) -> list[int]:
        """Bit-parallel simulation. assign[name][i] is an int whose bit L is the value
        of input bit i in lane L. Returns per-signal lane masks."""
        full = (1 << lanes) - 1
        val = [0] * len(self.kind)
        val[1] = full
        for name, bits in self.inputs.items():
            vs = assign.get(name)
            for i, b in enumerate(bits):
                val[b] = vs[i] if vs is not None else 0
        for g, k in enumerate(self.kind):
            if k[0] == "nand":
                val[g] = full ^ (val[k[1]] & val[k[2]])
        return val

    def eval_words(self, inputs: dict[str, int]) -> dict[str, int]:
        """Single-lane convenience: integer inputs -> integer outputs."""
        assign = {n: [(inputs.get(n, 0) >> i) & 1 for i in range(len(b))] for n, b in self.inputs.items()}
        val = self.simulate(assign)
        return {n: sum((val[b] & 1) << i for i, b in enumerate(bits)) for n, bits in self.outputs.items()}

    def cnf(self, require: dict[str, int]):
        """Clauses for 'these 1-bit outputs take these values' (Tseitin encoding of the NANDs)."""
        lit = lambda g: g + 1  # SAT variable for signal g
        cls = [[-lit(0)], [lit(1)]]
        for g in self.used_gates_for([self.outputs[n][0] for n in require]):
            _, a, b = self.kind[g]
            y, A, B = lit(g), lit(a), lit(b)
            cls += [[y, A], [y, B], [-y, -A, -B]]
        for n, v in require.items():
            b = self.outputs[n][0]
            cls.append([lit(b)] if v else [-lit(b)])
        return cls

    def _decode(self, model_true):
        return {n: sum(((b + 1) in model_true) << i for i, b in enumerate(bits)) for n, bits in self.inputs.items()}

    def solve(self, require: dict[str, int], timeout=None):
        """SAT: find an input assignment making each named 1-bit output equal the value given.
        Returns {input name: int}, None if impossible, or TIMEOUT if the budget ran out.
        With a timeout, a portfolio of solvers races in separate processes."""
        cls = self.cnf(require)
        if timeout is None:
            from pysat.solvers import Cadical153
            s = Cadical153(bootstrap_with=cls)
            if not s.solve():
                return None
            return self._decode({x for x in s.get_model() if x > 0})
        status, model = race(cls, timeout)
        if status == "sat":
            return self._decode(model)
        return None if status == "unsat" else TIMEOUT


    def used_gates_for(self, roots):
        seen, stack = set(), list(roots)
        while stack:
            g = stack.pop()
            if g in seen or self.kind[g][0] != "nand":
                continue
            seen.add(g)
            stack.extend(self.kind[g][1:])
        return sorted(seen)

    def to_json(self, outputs=None) -> dict:
        """Compact netlist: only gates feeding the outputs, renumbered in topological order."""
        outs = outputs or list(self.outputs)
        used = self.used_gates_for([b for n in outs for b in self.outputs[n]])
        ids = {0: 0, 1: 1}
        for name, bits in self.inputs.items():
            for b in bits:
                ids[b] = len(ids)
        gates = []
        for g in used:
            _, a, b = self.kind[g]
            ids[g] = len(ids)
            gates.append([ids[a], ids[b]])
        return {
            "inputs": {n: [ids[b] for b in bits] for n, bits in self.inputs.items()},
            "outputs": {n: [ids[b] for b in self.outputs[n]] for n in outs},
            "gates": gates,  # gate k drives signal id (2 + #input bits + k)
        }


TIMEOUT = "timeout"
PORTFOLIO = ("cadical153", "cadical195")


def _solve_worker(name, cls, q):
    from pysat.solvers import Solver
    s = Solver(name=name, bootstrap_with=cls)
    ok = s.solve()
    q.put((name, "sat" if ok else "unsat", {x for x in s.get_model() if x > 0} if ok else None))


def race(cls, timeout, solvers=PORTFOLIO):
    """Run several SAT solvers in parallel processes; first answer wins, all stop at the deadline."""
    import multiprocessing as mp
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    procs = [ctx.Process(target=_solve_worker, args=(n, cls, q), daemon=True) for n in solvers]
    for p in procs:
        p.start()
    try:
        name, status, model = q.get(timeout=timeout)
    except Exception:
        status, model = "timeout", None
    for p in procs:
        if p.is_alive():
            p.kill()
        p.join()
    return status, model
