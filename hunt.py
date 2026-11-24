import sys, time
from gates import Netlist
for path in sys.argv[1:]:
    n = Netlist(path); t = time.time()
    cex = n.find({"bug": 1})
    print(f"{path}: {n.nand_count()} NAND-equivalent gates, solved in {time.time()-t:.2f}s")
    if cex is None: print("  PROVEN: no input sequence triggers the bug (within 8-bit, 3-tx model)")
    else:
        ops = ["deposit", "donate"]
        print("  BUG FOUND. Counterexample:")
        for i in range(3): print(f"    tx{i}: {ops[cex[f'op{i}']]}({cex[f'amt{i}']})")
        print("  circuit replay ->", n.simulate(cex))
