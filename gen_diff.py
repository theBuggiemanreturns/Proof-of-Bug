"""Build a Foundry test: random tx sequences, each with the circuit's verdict baked in.
Foundry then checks that the REAL Solidity contract agrees with the circuit on every case."""
import random, sys
from gates import Netlist
net = Netlist(sys.argv[1]); patched = sys.argv[2]; N = int(sys.argv[3])
random.seed(1)
def amt(): return random.choice([random.randint(0, 255), random.randint(0, 20), random.randint(0, 3)])
cases = []
for _ in range(N):
    c = {f"op{i}": random.randint(0, 1) for i in range(3)} | {f"amt{i}": amt() for i in range(3)}
    r = net.simulate(c); cases.append((c, r["bug"], r["valid"]))
rows = ",\n".join(
    f"        uint256({c['op0'] | c['op1']<<1 | c['op2']<<2 | c['amt0']<<8 | c['amt1']<<16 | c['amt2']<<24 | b<<32 | v<<33})"
    for c, b, v in cases)
print(f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../src/Vault.sol";
contract DiffTest_{"patched" if patched=="1" else "buggy"} {{
    function cases() internal pure returns (uint256[{N}] memory) {{ return [
{rows}
    ]; }}
    // Runs one sequence on the real contract. valid = every value stayed within 8 bits.
    function run(uint256 c) public returns (bool bug, bool valid) {{
        Vault v = new Vault({"true" if patched=="1" else "false"});
        valid = true;
        for (uint256 i = 0; i < 3; i++) {{
            uint256 op = (c >> i) & 1; uint256 a = (c >> (8 + 8 * i)) & 0xff;
            if (op == 0) {{
                if (v.totalSupply() != 0 && v.totalAssets() == 0) return (false, false); // div by zero
                try v.deposit(a) returns (uint256 s) {{ if (a > 0 && s == 0) bug = true; }}
                catch {{ continue; }} // patched vault reverted: tx had no effect
            }} else v.donate(a);
            if (v.totalAssets() > 255 || v.totalSupply() > 255) valid = false;
        }}
        bug = bug && valid;
    }}
    function test_circuit_matches_solidity() public {{
        uint256[{N}] memory cs = cases(); uint256 agree;
        for (uint256 k = 0; k < {N}; k++) {{
            (bool bug, bool valid) = run(cs[k]);
            bool cBug = (cs[k] >> 32) & 1 == 1; bool cValid = (cs[k] >> 33) & 1 == 1;
            require(valid == cValid, "MISMATCH valid");
            if (valid) require(bug == cBug, "MISMATCH bug");
            agree++;
        }}
        require(agree == {N});
    }}
}}""")
print(f"circuit flagged bug in {sum(b for _,b,_ in cases)}/{N} random cases, valid in {sum(v for *_,v in cases)}", file=sys.stderr)
