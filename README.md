# Proof of Bug

Solidity → Yul → NAND circuit (automatic compiler) → SAT bug search → replay on the real EVM.

## Quick start

    pip install -r requirements.txt          # python-sat, pycryptodome
    # needs Foundry (forge) on PATH, or FORGE=/path/to/forge
    make test                                # gate-level arithmetic vs Python, exhaustive
    make bench                               # Level 1 + 2 benchmark scoreboard (8-bit)
    make bench-deep                          # also search at 12 and 16 bits with time budgets

## Layout

| Path | What it does |
|---|---|
| `proofofbug/circuit.py` | NAND-only circuit builder: constant folding, gate sharing, W-bit arithmetic, bit-parallel simulation, SAT encoding |
| `proofofbug/yul.py` | Runs solc, extracts the optimized Yul AST, storage layout, ABI |
| `proofofbug/symexec.py` | **The compiler.** Executes Yul symbolically into gates: dispatcher, storage, mappings (keccak slots), packed storage (exact bit positions), memory, reverts, panics, loops, calls between contracts with revert rollback, an attacker contract that can call back (reentrancy) |
| `proofofbug/intproof.py` | **Integer maths engine.** Runs the same Yul as exact integers (Z3), proves rules by induction (all number sizes, any number of transactions), discovers simple invariants, checks invariant hints, holds the lemma library |
| `proofofbug/model.py` | k-transaction model over one or more contracts (solver picks contract, function, sender, arguments and the attacker's callback), rule language, bug search |
| `proofofbug/evm.py` | Runs sequences on the real contracts in Foundry: deploys them at the circuit's addresses, plants a programmable attacker contract, reads back storage |
| `proofofbug/check.py` | Differential test (circuit vs EVM) and replay of found attacks with exact 256-bit rule checks |
| `proofofbug/blind.py` | Blind-round harness: rule prompts, review, the four-engine search per case, verdicts, sealing |
| `proofofbug/trail.py`, `proofofbug/report.py` | Audit trail of every engine claim and the EVM's answer; step-by-step reports and the AI-review prompt |
| `proofofbug/bench.py`, `bench/level1.py`, `bench/level2.py` | Benchmark runner and cases |
| `src/bench/Level1.sol`, `src/bench/Level2.sol` | Benchmark contracts (each with a `fixed_` switch) |
| `survey/` | Coverage survey: common real contract code, what the engines can model and why not |
| `viz/` | Gate viewer |
| `poc/`-era files (`vault.v`, `gates.py`, `hunt.py`, ...) | The original hand-built proof of concept |

## Writing a rule

A rule returns 1 when a transaction breaks it:

    lambda tx: tx.called("deposit") & tx.ok & (tx.arg(0) > 0) & (tx.ret == 0)
    lambda tx: tx.ok & (tx.post_sum("deposits") != tx.post("held"))
    lambda tx: tx.ok & (tx.post("x").wide() * tx.post("y") < tx.pre("x").wide() * tx.pre("y"))

    lambda tx: tx.ok & (tx.post("totalDeposits") > tx.post("FeeToken.balanceOf", 0x99))   # another contract's storage

The same rule runs on the circuit (search) and on real EVM traces (confirmation).

## Three levels of answer

| Column | Meaning |
|---|---|
| verdict | bit-level search (k transactions, W-bit numbers): CAUGHT = attack found and confirmed on the real EVM; CLEAN = no attack exists in that model |
| notes `clean<=12` | the width ladder: no attack at 8 and 12 bits; `timeout@16` means the budget ran out there |
| all sizes | integer engine, by induction: PROVEN = holds for every number size and any number of transactions (for the modelled accounts); `not inductive` = the rule alone is not enough to prove it, a stronger invariant is needed (not a bug by itself); `unsupported` = the engine can't model something yet (attacker callbacks) |

A buggy version must never be PROVEN; the scoreboard counts that and it must be 0.

## Choosing bounds automatically (`--auto`), and never claiming what wasn't checked

Fixed bounds hide bugs (more users, longer sequences, bigger numbers, longer loops). With
`--auto` the bounds come from the contract:

- users: at least the largest number of address arguments of any function;
- number width: if the code compares inputs with constants wider than the model (e.g. a
  minimum lot of 2^62), the width is raised past them;
- loops: if a loop can run past the unroll limit, the limit is doubled (up to 64);
- depth: `--depths 3,5,8` searches longer transaction sequences when shorter ones are clean.

Coverage gaps that remain are reported, and the verdict becomes INCOMPLETE instead of
CLEAN/MISSED. The integer engine never assumes a loop stops (it raises "unsupported"),
treats storage it has not seen as unknown rather than 0, and rejects a proof whose own
assumptions rule out every successful call ("vacuous").

## Rules: the part that decides what counts as a bug

The solver finds anything that breaks a rule, and nothing that no rule covers, so rule
quality is the main lever. Four pieces:

**Safe rule language** (`proofofbug/rulelang.py`). Rules are short expressions, TRUE when a
transaction breaks them:

    ok and post_sum("credit") > post("totalPaid")
    called("deposit") and ok and post("totalAssets") != pre("totalAssets") + arg(0)
    called("withdraw") and reverted and arg(0) <= pre("shares", sender)

Parsed with a whitelist (no code can run, whoever wrote it). Arithmetic is exact (sums and
products never wrap); avoid subtraction, move terms to the other side instead.

**Rule families** (`proofofbug/families.py`): general laws with blanks. ledger, bounded_by,
account_bounded_by, nonzero_mint, fair_redemption, share_price_monotone, product_monotone,
authorized_change, authorized_increase, allowance_spent, breaker_hold, exact_effect,
exact_decrease, no_side_effect, must_succeed, exit_all, exit_amount, collateralized.
`bench/library.py` re-expresses every known bug in the benchmarks as a family rule.

**Mutation testing** (`python -m proofofbug.mutate bench.level1 --only B08`): many
deliberately broken copies of a correct contract (flipped comparisons, + for -, deleted
requires / updates, off-by-one constants, swapped statements). Rule strength = share of the
behaviour-changing copies the rules catch, each confirmed on the real EVM. Survivors are the
blind spots, listed line by line.

**Grouping** (`python -m proofofbug.grouping ...`): the solver proves when one rule covers
another (no sequence where B fires and A doesn't). Equal "what it catches" fingerprints are
duplicates; only one is kept.

**AI rule agent** (`python -m proofofbug.agent bench.level1 --only B01 --api`): Claude
(Opus 5.5, structured JSON output) reads the contract and the family catalog and proposes
family fills, custom rules and invariants. The machine then decides: compile (safe language)
-> names exist and the rule can fire -> must not fire on the intended contract (if it does
and the EVM confirms, it's reported as a finding) -> catches the known bug? -> mutants caught
-> duplicates pruned. `--proposals file.json` runs the same pipeline on proposals from a file
(the format the API returns); `--show-prompt` prints the prompt. API mode needs
ANTHROPIC_API_KEY (or an `ant auth login` profile).

## Invariant hints and lemmas

Induction proves "from any state where the invariants hold, any call keeps them". Some rules
need a stronger fact to rule out impossible starting states. Simple ones are discovered
automatically (a variable or mapping entry that never changes). Others are written as hints:

    invariants={"supply_is_sum": lambda tx: tx.post_sum("balanceOf") != tx.post("totalSupply")}
    invariants={"all_within_limit": lambda tx, u: tx.post("debt", u) * 2 > tx.post("collateral", u) * tx.post("OracleM03.fairPrice")}

A hint is used only if it holds in the real deployed state and is itself proven inductive;
if any hint fails, nothing that relied on it counts as proven.

Lemmas (`intproof.LEMMAS`) are maths facts each proven once by Z3 over unbounded integers
before use; `euclid-bound` is applied automatically to divisions when a proof times out.

## Model conventions

- Contracts live at 0x99 (primary), 0x98, 0x97 ...; users at 0x31, 0x32 ...
- Arithmetic is W-bit (default 8); bit positions, masks, shifts and comparisons are exact, so packed storage is modelled exactly.
- Mapping keys range over a key universe: the users, address 0 and the contracts.
- A case may make one user an attacker contract: whenever it is called it can make one call back into the caller, chosen by the solver (reentrancy).
- Width overflows, loop-unroll limits, keys outside the universe and call-depth limits mark a run "invalid" instead of producing false bugs.
- Dynamic arguments (`bytes`, `string`, `T[]` of anything, structs with dynamic members, nested) are laid out by
  `yul.calldata_words` with known offsets. A function with such arguments runs once per combination of argument
  lengths (arrays 0-3 elements, bytes 0/4/32/36/68 bytes, at most 64 combinations per function, the least common
  lengths dropped first and reported); `yul.length_variants` is the one source of those variants for every engine.
- A value that is one of a few known constants (where branches join: a length, a pointer, a return size) stays
  known: `symexec.Choice` in the bit-level engine, `intproof.z_options` in the Z3 engines. Memory, copy, hash,
  call and return instructions then run once per option under its condition.
- Memory touched past 16 MB is an out-of-gas revert, as on any chain.
- `block.timestamp` and `block.number` are clocks that may move forward between transactions; `block.chainid` is
  the chain every replay runs on (31337); `tx.origin` is the transaction's sender.
- Immutables come from the deployed code, including those a contract inherits.
- A dynamic storage array element (`keccak(p) + i`, also inside mappings and structs) ranges over the first 16
  slots of the array, as mapping keys range over the key universe; a path past them is flagged, not guessed.
- A function the engines cannot model yet is left out by name with its reason (`bench.isolate` finds it in the
  exact model the search uses, at the deepest depth, before any rule is judged); it is a reported coverage gap,
  never a silent one.

## Coverage on real code (`survey/`)

`python3 survey/survey.py --oz <openzeppelin-contracts 5.x checkout>` builds 14 contracts made of everyday
OpenZeppelin blocks (permit and votes tokens, flash mint, ERC-1363, multicall, ERC-4626, wrapper, staking with
SafeERC20/roles/pause, ERC-721, ERC-1155, a clone factory, a pool with a swap callback) with the engine's own
model at 1-3 transactions, and lists every function it cannot model and why (`survey/RESULTS.md`).

| | functions left out |
|---|---|
| before the big-contract work (`survey/RESULTS_before_fixes.md`) | 23 of 101 |
| now | 6 of 101 |

Fixed as classes, not instruction by instruction: inherited immutables, environment values, variable-size
data, impossible far-out memory, storage arrays (elements at `keccak(p) + i` over 16 offsets, and every slot a
value can occupy watched from the compiler's storage type tree). Still open: EIP-712 hashing at unaligned memory
offsets (and signatures need real keys anyway), `delegatecall`, `create`/`create2`.
On an 11-contract DeFi system the bit-level engine models all but 2 of 106 functions and the exact search all but
1. Each fix was checked against the real EVM (differential tests on the bytes-heavy survey contracts: 611
transactions, 0 mismatches) and by the full benchmark and training-set regression.

Planned (not built yet): every bound above and the machine limits become user settings, with auto-detection and
presets, printed in every report: see `PLANNED_SETTINGS.md`.

Size is the next wall for the bit-level engine: realistic balances (100 ether) need ~90-bit numbers, and an
11-contract system at that width is tens of millions of gates. The search then skips the bit-level stage (reported
as a coverage gap) and relies on the fuzzer, the exact 256-bit search and the prover.

## Original proof of concept

Smart contract -> logic circuit (NAND only) -> SAT solver finds the bug -> real contract confirms it.

| File | What it is |
|---|---|
| `Vault.sol`, `src/Vault.sol` | Vault with the donation / first-depositor bug (`patched=true` adds `require(shares > 0)`) |
| `vault.v` | Circuit model of the vault: 8-bit numbers, 3 transactions chosen by the solver |
| `stat_*.txt`, `netlist_*.json` | Yosys output: ~2,420 NAND-equivalent gates per version |
| `gates.py` | Gate-level simulator + SAT bug search (CaDiCaL via python-sat) |
| `hunt.py` | Runs the bug search and prints the counterexample or a proof of no bug |
| `gen_diff.py` | Generates a Foundry test with 400 random sequences, checking the circuit against the real contract |
| `test/Exploit.t.sol` | Replays the solver's attack against the real Solidity |

## Step-by-step reports (audit trail)

Every blind run records each claim an engine makes ("this sequence breaks these rules") together with
the real EVM's answer per transaction: whether it reverted, and every storage value that changed. A
claim the EVM does not reproduce is kept as "thrown out", with the evidence. This is record-keeping
only (`proofofbug/trail.py`); no engine reads it back.

    python -m proofofbug.report --round round2_posthoc            # ROUND/reports/<case>.md + INDEX.md
    python -m proofofbug.report --round round2_posthoc --only R05

Each report has nine sections: what was deployed; the rules (with the writer's reasons and the review);
how hard the machine looked (widths, depths, model check, limits, coverage gaps); every rule engine by
engine; each confirmed attack with the EVM's before/after values and the triage; each claim thrown out
and how it was disproved; the proofs and the facts they relied on; a coverage map (functions and
storage no rule names); and the raw run log.

`ROUND/reports/REVIEW_PROMPT.txt` is the task for an AI reviewer. It reads a report and the source and
lists what the engines were never asked: missed properties, findings that combine, triage calls that
look wrong, shallow coverage, and limits that could hide an attack. Every point must come with a new
rule, and that rule goes back through the machine. The reviewer proposes; the machine decides.

## Rebuild

    yosys -p "read_verilog vault.v; chparam -set PATCHED 0 vault; hierarchy -top vault; proc; flatten; opt; techmap; opt; abc -g NAND; opt_clean; stat; write_json netlist_0.json"
    python hunt.py netlist_0.json
    python gen_diff.py netlist_0.json 0 400 > test/DiffBuggy.t.sol
    forge test

Needs: yosys, python-sat, foundry.

## Results

- Buggy vault: bug found in 0.01s. The attack is donate(120) -> deposit(7) -> deposit(16), and the last depositor receives 0 shares.
- Patched vault: proven to have no bug within the 8-bit, 3-transaction model.
- The circuit agreed with the real Solidity on 400/400 random sequences for each version.
- A deliberately mismatched circuit made the differential test fail, so the test does catch mismatches.
