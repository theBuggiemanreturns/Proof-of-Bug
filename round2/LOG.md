# Round 2: what happened after the contracts arrived

Author: a fresh session (`Round 2 bug author`) that received the user's raw bug material, prepared
12 self-contained files, sealed its answer key (sha256 `54d7e092...609cab`) and sent only the files.
The operator never saw the raw material or the key. Hashes on receipt: `round2/RECEIVED.sha256`.
Engine state before receipt: FREEZE.txt v5.

## Receipt
- 2026-11-24 07:06-07:09 UTC: R01-R12 received byte-for-byte (`tools/relay.py files`, a new
  extraction mode for the author's `=== Rnn.sol ===` format).
- R09's DEPLOY note deploys `MockToken`, but the first R09.sol did not contain it (it would not
  compile). The operator asked the author to resend; the author sent the complete file and stated the
  answer-key hash is unchanged. Only the replacement is used (second line block of RECEIVED.sha256).

## Deployments (`round2/cases.py`)
Translated from the DEPLOY notes with round 1's policy plus the address mapping these notes need
(0x1111 -> U0, 0x2222 -> U1, 0x3333 -> U2; "may be a contract with a receive function" -> U1 is a
calling-back contract; "any other address may also call" -> one extra user). Written before any
rule existed; no rules in it.

## Engine changes forced by the contracts (Solidity/EVM modelling only; none is a rule)

| Change | Forced by | Before |
|---|---|---|
| dynamic array arguments (`uint256[] calldata`): the calldata gets head words, a length word and up to 3 element words, all chosen by the solver (offsets too); the contract's own ABI decoder checks them, as on chain. A load at an offset read from calldata selects among the calldata words; an unaligned load inside the calldata is excluded from searches (every attack is replayed on the EVM) and is an unconstrained value in proofs (sound). The bit model now gives each call its own calldata size and zero words past it, as the EVM does. Verdicts state the limit (arrays of at most 3 elements) and cannot be NO BUG FOUND without it | R07, R10 (`depositMulti(uint256[])`) | Unsupported ("calldataload at a non-constant offset") |
| loops carry the running path forward unmerged and join the exits once after the loop, so inside iteration n the counter is exactly n (a storage array indexed by it is an exact slot). Same semantics as before: each exit's state is selected under the condition that the loop stopped there | R07, R10 (`assets[i]` in a loop bounded by the array length) | the counter became "0 or 1 or ..." after the first merge: "sload at a computed slot" |
| fixed-size array parameters `T[n]` take n calldata words | (found while adding the above; no case uses it) | taken as one word (wrong) |

Rule-writer instructions got one factual line about the first change: `arg(i)` of an array parameter
is its raw calldata offset and the rule language cannot read array elements (the frozen rule-language
text is unchanged).

Regression after these changes: see the end of this file.

## Regression after the engine changes (before any round-2 hunt)
Full benchmark (level1, level2, real1, hidden; 44 variants) and training set (14 variants), same commands
as after FREEZE v5: 43/44 (same single known hole as before) and 14/14; 17/22 and 5/7 fixed versions
proven, identical to before; 0 buggy versions wrongly proven; 0 circuit-vs-EVM mismatches.

## Harness fix during the first hunt attempt (discarded)
The EVM runner wrote each contract's compiled creation code to `gg-out/code_<ContractName>.hex`.
With two hunts running in parallel and every case having a `MockToken`, the files raced (R01 crashed
reading an empty file) and a replay could read another case's compilation. The file is now named
per run (`code_<tag>_<name>.hex`). The first attempt was stopped and all of its output discarded;
every round-2 result comes from the restarted run.

## After the reveal: engine fixes (scored separately in round2_posthoc; the sealed verdicts stand)

One principle behind all of them: every engine models the same world (numbers, money, accounts),
and no engine's approximation may silently remove work from another.

| Fix | What was wrong | Now |
|---|---|---|
| approximate engines never remove work | a bit-level attack the EVM rejected marked the rule "unconfirmed" and took it out of the exact search and the prover; the verdict did not mention it (lost R05's real drain) | the rule stays open for the exact search and the prover; the verdict lists such rules and what covered them; a rule no engine covered makes the case INCOMPLETE |
| the circuit's two windows | the circuit is a W-bit EVM. Its numbers with the top bit set are the chain's numbers near 2^256 (negative ints, the max-uint sentinel, a decremented max approval). Signed inputs were replayed zero-extended (so its negative-fee attacks were not the attacks it meant), and the circuit-vs-EVM check compared raw bits | signed ABI inputs are sign-extended on replay; the check accepts either window; fuzzing also sends negative numbers for signed types |
| width from the deployed state | the width came only from constants in the code (R03 ran at 8 bits with 1e21 balances) | the width also covers every deployed amount (balances, reserves, supplies; addresses and hashes excluded) |
| every slot of a variable | only the first slot of a fixed-size array or multi-slot struct was copied from the deployed state (R07/R10: `assets[1]` read as 0, so every 2-element deposit failed in the exact engine) | all slots a variable occupies are tracked and copied |
| ETH in the exact engine and the prover | payable functions and ETH transfers were excluded (R02 INCOMPLETE) | balances, payable value (the caller must own it), value sent by calls, refunds on revert, `balance`/`selfbalance` and the rules' `ETH` reads, the same model as the bit engine. A call that pays the attacker contract: its callback is explored by the bit-level engine only, and this is reported |
| loop bounds from the solver | a loop with a symbolic bound counted as "may run past 64 steps" even when the code bounds it (`require(length == 2)`, R10) | each further iteration and the past-the-limit case are checked with the solver (exact engine and prover) and with SAT (bit engine, only paths still running); a limit is reported only if reachable |
| the deployer is in the address universe | sums over accounts left out what the deployer still held (R09 `ledger` failed trivially) | the deployer is a modelled account (not controlled by the solver); its balances count |
| a reverted call in the prover | a slot first read during a reverted call was reset to 0 in the post state | it keeps its starting value |

## Correction (2026-11-24, after FREEZE v6): the post-reveal regression was measured too early

The summary reported the regression after the post-reveal fixes as identical (43/44, 14/14). The
training-set run behind "14/14" (12:03 UTC) came before the last post-reveal change, *width from the
deployed state*. Re-run on the frozen v6 engine (bench.py hash as in FREEZE.txt v6): the full benchmark
is unchanged (43/44, 0 wrongly proven, 0 mismatches), but the training set is **13/14**. T03 (vesting keeps
paying after the period) is MISSED.

Why: the width now comes from the deployed state (largest amount 100, so 9 bits), and T03's attack
needs a timestamp of 513, past a 9-bit clock (511). Before the change the width was 16 and the bit-level
search found it. The bench runner uses only the bit-level search and the prover; the exact (256-bit)
search runs in blind rounds only. The deeper fault: "clean up to 8tx/9bit" does not say that later
times were never reached. A coverage statement must name the clock range too. To fix (not yet done):
the width must also cover the time the contract compares against, and the clock range must be reported
as a limit.
