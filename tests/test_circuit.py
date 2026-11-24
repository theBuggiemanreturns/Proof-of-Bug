"""Exhaustive check of every word operation against Python at a small width."""
import itertools, sys
sys.path.insert(0, ".")
from proofofbug.circuit import Circuit

W = 5
M = (1 << W) - 1
def sgn(v): return v - (1 << W) if v >> (W - 1) else v
ref = {
    "add": lambda a, b: (a + b) & M, "sub": lambda a, b: (a - b) & M, "mul": lambda a, b: (a * b) & M,
    "div": lambda a, b: a // b if b else 0, "mod": lambda a, b: a % b if b else 0,
    "lt": lambda a, b: int(a < b), "slt": lambda a, b: int(sgn(a) < sgn(b)), "eq": lambda a, b: int(a == b),
    "shl": lambda a, b: (b << a) & M if a < W else 0, "shr": lambda a, b: b >> a if a < W else 0,
    "sar": lambda a, b: (sgn(b) >> min(a, W)) & M, "and": lambda a, b: a & b, "xor": lambda a, b: a ^ b,
}
c = Circuit()
x, y = c.new_input("x", W), c.new_input("y", W)
c.outputs = {
    "add": c.add(x, y)[0], "sub": c.sub(x, y)[0], "mul": c.mul(x, y),
    "div": c.divmod(x, y)[0], "mod": c.divmod(x, y)[1],
    "lt": [c.lt(x, y)], "slt": [c.slt(x, y)], "eq": [c.eq(x, y)],
    "shl": c.shl(y, x), "shr": c.shr(y, x), "sar": c.sar(y, x), "and": c.wand(x, y), "xor": c.wxor(x, y),
}
pairs = list(itertools.product(range(1 << W), repeat=2))
lanes = len(pairs)
assign = {"x": [sum(((a >> i) & 1) << L for L, (a, b) in enumerate(pairs)) for i in range(W)],
          "y": [sum(((b >> i) & 1) << L for L, (a, b) in enumerate(pairs)) for i in range(W)]}
val = c.simulate(assign, lanes)
bad = 0
for op, bits in c.outputs.items():
    for L, (a, b) in enumerate(pairs):
        got = sum(((val[g] >> L) & 1) << i for i, g in enumerate(bits))
        if got != ref[op](a, b):
            bad += 1
            if bad < 10: print("MISMATCH", op, a, b, got, ref[op](a, b))
print(f"{len(c.outputs)} ops x {lanes} input pairs checked, {bad} mismatches; {c.gate_count()} gates total")
# constant folding sanity: adding constant 0 should create no gates
c2 = Circuit(); z = c2.new_input("z", 8); c2.add(z, Circuit.const_word(0, 8))
print("gates for z+0:", c2.gate_count())
sys.exit(1 if bad else 0)
