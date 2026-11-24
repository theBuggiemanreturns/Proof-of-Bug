# Proof of Bug: Proof of Bug
### Specification v0.2 (22 Nov 2026)

**Team:** you (product, OKB, on-chain ops) + Claude (all engineering, including Noir).
**Target:** X Layer TapeOut Accelerate. Submissions close **7 Dec 2026, 23:59 UTC** (15 days).
**Long-term target:** real protocols, up to Uniswap-sized contracts.

**Changes from v0.1:**
- AI no longer translates contracts. A **compiler** does it automatically (§3).
- TMR and the three-translator voting are removed. They aren't needed once translation is automatic.
- ZK is kept only as a stretch goal I build.

---

## 0. The idea in plain words

Proof of Bug **compiles** a smart contract into a TapeOut circuit automatically, like a calculator turning a formula into button presses. No human or AI rewrites it. A **solver** then checks every possible sequence of transactions for an attack. Every attack found is **replayed on the real contract** to prove it's real.

Results go on-chain on X Layer:
- a public **certificate** stating what was checked; or
- a **bug bounty** claimed through commit-reveal, with payouts shared with the people who crowdfunded the tape-out.

**AI's job is the part machines can't do alone:** deciding what counts as a bug (writing the rules), explaining the attacks it finds, and helping simplify very big contracts.

---

## 1. How the off-chain companies do it (and where we fit)

They all do the same thing at heart: **turn the contract into a logic formula and ask a solver whether a bad outcome is reachable.**

| Tool (who) | Starts from | How it turns code into logic | Solver |
|---|---|---|---|
| **hevm** (Ethereum Foundation / dapptools) | EVM bytecode | Symbolic execution: runs the code with unknown values, building formulas instead of numbers | z3 / cvc5 / Bitwuzla, bit-vector maths |
| **Halmos** (a16z) | EVM bytecode | Symbolic execution of Foundry tests | z3, bit-vectors |
| **Certora Prover** | EVM bytecode | Converts bytecode to its own simple language (TAC), plus rules written in its CVL spec language | SMT solvers |
| **Kontrol** (Runtime Verification) | EVM bytecode | KEVM, a complete mathematical definition of the EVM | K framework + SMT |
| **Mythril** (ConsenSys) | EVM bytecode | Symbolic execution, hunts known bug patterns | z3 |
| **solc SMTChecker** | Solidity source | Built into the compiler; uses whole numbers, not bits | CHC / SMT solvers |

**The key fact:** when an SMT solver handles bit-vector maths, it **"bit-blasts"**. It converts the formula into a circuit of AND and NOT gates (an And-Inverter Graph), then into SAT clauses. **So these tools already turn contracts into gate circuits.** They just do it hidden inside the solver and throw the circuit away.

**Proof of Bug's difference:** we make the circuit **visible and permanent**. It is NAND/LATCH, taped out on TapeOut, re-runnable by anyone with `eval`, and carries certificates and bounties.

---

## 2. Already proven (in this folder)

| Test | Result |
|---|---|
| Vault with the donation bug, as an 8-bit, 3-transaction circuit | ~2,420 NAND-equivalent gates |
| Solver on the buggy vault | **Bug found in 0.01 s**: `donate(120) → deposit(7) → deposit(16)` gives 0 shares |
| Solver on the patched vault | **Proven clean** within the model |
| Attack replayed on the real Solidity (Foundry) | Real loss confirmed; patch blocks it |
| Circuit vs real contract, 400 random sequences per version | 400/400 agree |
| Deliberately wrong circuit | Caught |

The PoC circuit was written by hand. v0.2 replaces that step with the compiler.

---

## 3. The pipeline

```
 Solidity ──solc──► Yul IR ──[Proof of Bug compiler]──► Verilog (W-bit words, k-tx unrolled)
                                                           │
                                         Yosys + ABC ──────┘──► NAND/LATCH netlist
                                                                      │
  AI rule writer ──► bug rules (Yul/Solidity-level predicates) ───────┤
                                                                      ▼
            CHECKS:  differential test │ bug search │ unbounded proof │ replay
                                                                      │
                                                                      ▼
                     X Layer: tape-out · certificate · bounty escrow · DeWEB dashboard
```

### 3.1 Why Yul
`solc --ir-optimized` gives Yul for any contract. It is small and structured: `let`, `if`, `switch`, `for`, functions, and simple built-ins (`add`, `mul`, `div`, `lt`, `iszero`, `sload`, `sstore`, `calldataload`, `revert`). From the vault's real Yul:
- each public function is a `case` on its selector, which becomes a multiplexer on `op`;
- storage variables are fixed slots (`sload(0)`, `sload(1)`), which become registers;
- `require` and panics are `revert`, which becomes "tx reverted, state unchanged";
- checked maths is explicit (`checked_add_uint256`, overflow panic `0x11`, division-by-zero panic `0x12`).

Working from Yul instead of raw bytecode means no stack or jump tables to untangle. Working from Yul instead of Solidity source means solc has already settled all of Solidity's tricky meaning (types, inheritance, modifiers, checked maths).

### 3.2 Compiler rules (Yul → circuit)

| Yul | Circuit |
|---|---|
| Arithmetic / bitwise / comparison built-ins | W-bit Verilog operators. `div`/`mod` use our textbook divider (Yosys's generic one synthesises too slowly) |
| `let`, assignment | Wires (SSA form) |
| `if`, `switch`, ternaries | Multiplexers; both branches computed, result selected |
| `for` with constant bounds | Unrolled; non-constant bounds are capped at a depth limit and flagged |
| Function calls | Inlined |
| `sload`/`sstore` constant slot | Registers, one copy per tx step |
| Mappings (`keccak256(key, slot)`) | Recognised from solc's helper pattern and mapped to a small fixed set of `U` keys (users) |
| `calldataload`, `caller`, `callvalue`, `timestamp` | Solver-chosen inputs |
| `revert`, panics | Revert flag: state rolls back. Panic `0x11` (overflow) at W bits is flagged as a **width artefact**, not a bug |
| `return`, memory for return values | Output wires (return value feeds the bug rules) |
| `call`/`staticcall` to external contracts | Phase 2: return data = solver inputs; optional reentrant callback step |
| Anything else (`create`, `delegatecall`, assembly tricks) | Rejected with the line number |

### 3.3 Shrinking (the "W-bit EVM")
We compile with **W-bit words instead of 256** (W = 8 by default). This is a consistent mini-EVM: same code, smaller numbers. Overflow checks trigger at 2^W instead of 2^256 and are flagged as width artefacts. Counterexamples use small numbers, so they **replay directly** on the real 256-bit contract. We rerun at W = 8, 12, 16 to catch bugs that need bigger numbers.

### 3.4 Transaction depth
The compiler unrolls `k` transactions. The solver picks each transaction's function, sender and arguments. Unbounded proof uses k-induction.

### 3.5 Bug rules and triage (two AI agents + standard library)
The compiler is the **only** translator. AI never votes on translation, because the real EVM is the answer key for that. AI is used only for the two judgement calls that have no answer key:

1. **Writing rules: two agents, union.**
   - **Standard library per contract type:**
     - ERC-20: supply equals the sum of balances; allowance only decreases.
     - Vault: deposit > 0 gives shares > 0; nobody redeems more than their share.
     - AMM: `x·y` never decreases.
     - Plus ownership and pause rules.
   - **Agent A and Agent B** (different model families, so their mistakes are independent) each write contract-specific rules without seeing the other's. Rules are Solidity-like expressions over storage before/after, return values and sender, for example `deposit.assets > 0 → deposit.ret > 0`.
   - **Every rule from every source is checked (union, no vote).** A rule only one agent thought of may be the one that catches the bug.
2. **Triage: two agents, must agree.** Replay proves that a rule really breaks on the real contract. It doesn't prove the rule was right. For each confirmed violation, both agents independently classify it:
   - both say "real bug" → **REPORTED**;
   - they disagree → **NEEDS HUMAN REVIEW**;
   - both say "intended behaviour" → rule dropped, with the reasoning logged.

AI also writes the plain-language explanation of each attack for the dashboard. Build order: one agent plus the library first (days 2–7), then the second agent once the pipeline works.

---

## 4. Checks

| Check | Question | How |
|---|---|---|
| **Differential** | Does the compiler's circuit behave like the real EVM? | Random + edge-case sequences in both (Foundry). This tests **the compiler**, once, across the whole benchmark, not each contract by hand |
| **Bug search** | Any attack within k transactions? | SAT solver (CaDiCaL), bounded model checking |
| **Unbounded proof** | Safe for any number of transactions? | k-induction |
| **Replay** | Is the bug real? | Counterexample run on the real contract in Foundry. **The final judge** |
| **Cross-check (Phase 3)** | Does our compiler agree with an independent tool? | Same query in Halmos/hevm; disagreement means a compiler bug |

A bug is **CONFIRMED** only if replay reproduces it. "Clean" certificates state exactly: rules, W, k (or ∞), and which checks passed.

---

## 5. On-chain (X Layer)

- **Tape-out:** netlist encoded in TapeOut's format (reusing Tape-OCCC's `curate.py encode`), deployed through the X Layer factory.
- **`CertificateRegistry.sol`:** contract code hash, circuit ID, rules hash, W, k/∞, checks passed.
- **`BugBountyEscrow.sol`:**
  1. **Fund:** the protocol deposits the bounty; backers crowdfund the tape-out.
  2. **Commit:** the hunter posts `hash(input, hunterAddress, salt)`. Copying it is useless.
  3. **Reveal:** after the commit is mined (plus a disclosure delay for live contracts).
  4. **Double proof:** circuit `eval` must say `bug = 1`, **and** the input replayed on a fresh deployment of the real contract must break the rule.
  5. **Payout split** (proposal): hunter 60%, rule writer / submitter 25%, backers 15% pro rata.
- **Crowdfunding note:** for the hackathon demo the first tape-out has to be paid directly (your OKB + NAND tokens), because the crowdfunding contract is part of what we're demoing. Keep demo circuits small (a few hundred to ~2,500 gates).

**Dashboard (DeWEB):** contract → Yul → circuit stats → rules → results → attack replay, step by step.

---

## 6. Backtesting

Each case is a **pair**: the buggy version must be caught and confirmed; the fixed version must be clean (no false alarm). One command (`make bench`) prints the scoreboard: found / confirmed / false alarm / missed, time, gates, depth, and differential agreement.

**"Training" now means:** improving the **compiler** (more Yul features) and the **AI rule writer** (better rules). Rule-writer prompts are tuned on training cases and scored on held-out cases.

### Level 1: single small contracts (hackathon)

| ID | Contract | Bug |
|---|---|---|
| B01 | Vault | Donation / zero-share deposit ✅ (hand-built; redo through the compiler) |
| B02 | Vault | Withdraw rounds in the user's favour |
| B03 | Token | `unchecked` underflow |
| B04 | Token | Anyone can mint (missing `onlyOwner`) |
| B05 | Token | `transferFrom` doesn't reduce the allowance |
| B06 | Pausable pool | Unpause while drained |
| B07 | AMM | Fee rounding lets `x·y` drop |
| B08 | Escrow | Withdraw twice |

### Level 2: multi-contract (hackathon, at least 2)

| ID | Setup | Bug |
|---|---|---|
| M01 | Vault + fee-on-transfer token | Vault credits more than it received |
| M02 | Bank + attacker contract | Reentrancy |
| M03 | Lending + oracle | Attacker-controlled price, borrow above the limit |

### Mutation testing
Automatic small edits (`<` → `<=`, a `require` deleted, `+1` removed) generate hundreds of variants. The real EVM decides which are buggy, and we measure the pipeline's hit rate.

---

## 7. Roadmap to big contracts

| Level | Target | Technique |
|---|---|---|
| 3 | 500+ line contracts | **Slicing:** one rule at a time, compiling only the code and storage it touches. Cross-check with Halmos/hevm |
| 4a | **Uniswap V2** core pair | Shrunk widths; rediscover known bugs from V2 forks as the backtest |
| 4b | **Uniswap V3** | Slice tick maths and liquidity accounting separately; fixed-point sqrt maths is the hard part |
| Stretch | Private proof of bug | I generate a Noir program from the netlist (bug input private, asserts `bug = 1`) and deploy its Solidity verifier on X Layer |

Honest expectation: V2 core is realistic after the hackathon. V3 needs slicing. "Any contract" is a research goal.

---

## 8. Timeline (15 days)

| Days | Dates | Work |
|---|---|---|
| 1 | 23 Nov | X Layer unknowns (§10), repo + `make bench` harness |
| 2–5 | 24–27 Nov | **Yul → Verilog compiler**; B01 through the compiler matches the hand-built result; B02–B08 |
| 6–7 | 28–29 Nov | Rule library + AI rule writer; k-induction; mutation testing |
| 8–9 | 30 Nov–1 Dec | Level 2: external calls in the compiler; M01, M02 (M03 if time) |
| 10–12 | 2–4 Dec | Tape-out on X Layer, `CertificateRegistry`, `BugBountyEscrow` |
| 13–14 | 5–6 Dec | DeWEB dashboard, demo video |
| 15 | 7 Dec | Buffer + submit |

Noir only if ahead of schedule by day 12.

---

## 9. Risks and limits

- **The compiler can have bugs.** It is tested by differential testing against the real EVM on every benchmark case, and every reported bug is confirmed by replay. Cross-checking with Halmos comes in Phase 3.
- **Rules decide what gets caught.** A missing rule means a missed bug. Certificates are scoped and never say "safe".
- **Easy bugs fall in milliseconds** to anyone with a solver, so protocols should check before publishing. Bounties matter most for hard cases.
- **Size and tape-out cost:** keep on-chain circuits small; most checking is off-chain.
- **Legal:** shared payouts may look like an investment product. Fine for the demo; get advice before real money.

---

## 10. Day-1 unknowns (needs your X Layer wallet)

1. TapeOut `eval` signature and the input/output encoding on X Layer.
2. `eval` gas per gate (measure ~100 and ~2,400 gates).
3. LATCH state semantics between calls.
4. NAND/LATCH token price, which sets the tape-out cost.
5. Tape-OCCC's `curate.py encode` works with our Yosys output.
6. Gas cost of deploying a fresh copy of the target inside the escrow (needed for the double proof).
