# Blind test results

Three independent parties (see `BLIND_PROTOCOL.md`): a bug author (wrote 12 contracts and committed
to an answer key by hash), a rule writer (wrote the rules from the frozen agent prompt and later
triaged every counterexample), and the operator (ran the machine). Both sides committed before the
reveal and both commitments check out:

- author's `GROUND_TRUTH.md` sha256 `6283d550...630b4b` (committed 13:41 UTC, verified on reveal; copy in `blind/GROUND_TRUTH.md`)
- operator's `BLIND_VERDICTS.md` sha256 `9b6c807e...e08d609` (committed 19:11 UTC, verified by the author)

## Score (the blind result: nothing below this section changes it)

| Case | Truth | Verdict | Result |
|---|---|---|---|
| C01 | buggy: first-depositor inflation | BUGGY | caught |
| C02 | clean: Synthetix staking | INCOMPLETE | no claim |
| C03 | buggy: cross-function reentrancy | BUGGY | caught, exact mechanism |
| C04 | buggy: spot-AMM price used as oracle | INCOMPLETE | missed (did not fit / loop) |
| C05 | clean: EIP-712 vouchers | UNSUPPORTED | no claim |
| C06 | buggy: transfer skips the recipient's reward sync | BUGGY | caught, via a second real bug the author had not planted (self-transfer doubles shares) |
| C07 | buggy: cancel/modify double refund | BUGGY | caught, exact mechanism |
| C08 | buggy: constant-product check scaled 1000^2 vs 10_000 | INCOMPLETE | missed (160-bit circuit out of memory) |
| C09 | clean: virtual-share vault | INCOMPLETE | no claim |
| C10 | buggy: rewardDebt from the stale amount | INCOMPLETE | missed (timed out) |
| C11 | buggy: unchecked uint128 downcast | NO BUG FOUND (3 tx, 8 bits) | **missed** |
| C12 | clean: pull-payment auction | NO BUG FOUND | correct |

- Planted bugs caught: **4 of 8** (C01, C03, C06, C07), every one with an attack replayed on the real EVM.
- False alarms: **0**. All 4 clean contracts got no BUGGY verdict. 3 counterexamples came from the
  rule writer's own wrong rules, and the rule writer triaged them as `rule_wrong` itself.
- Extra: one real bug the author did not plant (C06 self-transfer inflation).
- The one verdict that was too optimistic: C11, NO BUG FOUND within 3 transactions / 8-bit numbers.
  The bug needs a rate near 2^127, which no 8-bit search can reach.

## Why the misses happened

| Case | What blocked it |
|---|---|
| C04 | 82-bit maths (pool of 10_000e18): the 3-transaction circuit (21M gates) ran out of memory; at 2 transactions all 28 rules timed out; the AMM's square-root loop is beyond the prover's 64-step limit |
| C08 | the constant-product check multiplies two 80-bit balances: 160-bit circuit, out of memory; same square-root loop for the prover |
| C10 | 82-bit maths: 21 of 25 rules timed out; the prover proved 19 rules for all sizes, the 6 others "not inductive" |
| C11 | searched at 8 bits; the bug needs 2^127. **The integer prover had the counterexample** (`create_deposit_exact` was "not inductive") but nothing turned it into an attack |

## After the reveal: what changed and what it would have caught (not part of the score)

1. **Prover counterexamples are now replayed on the EVM** (`proofofbug/cexreplay.py`). When a rule
   is "not inductive", the failing call Z3 found (exact 256-bit arguments) is run once from the real
   deployed state; if the rule breaks there, it is a confirmed finding. On C11 this turns the miss
   into a confirmed attack: `createStream(1, ~2^256, t, t+1)`, where the stored deposit wraps through
   `uint128(...)` while the stream pays the full rate (the author's planted bug). On C02, C09 and
   C10 every other counterexample was correctly *not* reproducible from the real state.
2. **Family templates now bracket their blanks.** The C02 replay also exposed a bug in our family
   library: `accrual_bounded` pasted `start = a - b` into `now - {start}` as `now - a - b`. The rule
   writer's C02 rule therefore fired on a correct contract. No blind verdict depended on it (it was a
   timeout and "not inductive", never a finding), and with the brackets the rule no longer fires.

With both fixes, the same run would have read: **5 of 8 planted bugs caught** (C11 added), still
0 false alarms. That is a statement about the improved engine, made after seeing the key; it is
listed here, not in the score.

## What the test says about the tool, in one paragraph

On logic bugs it is strong and precise: every bug it reported was real, each came with a concrete
attack that ran on the real EVM, and it found one the author missed. Its blind spot is size: bugs
that only exist with huge numbers (1e18 pools, 2^127 rates, 160-bit products) or long loops. There
the bit-level search either timed out or did not fit in memory. In every such case it said so
(INCOMPLETE) instead of calling the contract safe, except C11, where "no bug within 8 bits" was
true but not enough. The fix for that class is exact-integer reasoning turned into attacks, which
item 1 above starts.

## Post-hoc rerun with the new pipeline (after the reveal; does NOT change the score above)

Same 12 contracts, same deployments, same rule proposals, run through the improved pipeline
(fuzzing on the EVM, bit-level search, exact search at full 256-bit size, prover + counterexample
replay, size reporting, memory guard). Every new counterexample was triaged by the same independent
rule writer (`round1_posthoc/triage_3.json`: 6 real bugs, 2 of its own rules wrong).
Verdicts: `round1_posthoc/VERDICTS.md`.

| Case | Truth | Round 1 (sealed) | Post-hoc | Found by |
|---|---|---|---|---|
| C01 | buggy | BUGGY | BUGGY | bit-level |
| C02 | clean | INCOMPLETE | INCOMPLETE (all 34 rules clean under the exact search at 1-2 tx, 27 proven) | - |
| C03 | buggy | BUGGY | BUGGY | bit-level (ETH callback) |
| C04 | buggy | INCOMPLETE | INCOMPLETE | - (rules cannot express it, see below) |
| C05 | clean | UNSUPPORTED | UNSUPPORTED | - |
| C06 | buggy | BUGGY | BUGGY | bit-level and exact |
| C07 | buggy | BUGGY | BUGGY | bit-level |
| C08 | buggy | INCOMPLETE | **BUGGY** | exact search (bit-level would not fit in memory) |
| C09 | clean | INCOMPLETE | INCOMPLETE (only a rule-writer mistake fired) | - |
| C10 | buggy | INCOMPLETE | **BUGGY** | fuzzing |
| C11 | buggy | NO BUG FOUND | **BUGGY** | fuzzing (and exact search, tested separately) |
| C12 | clean | NO BUG FOUND | INCOMPLETE | - (ETH flows not modelled by the exact search; casts above the searched width reported) |

- Planted bugs caught: **7 of 8** (was 4). False alarms: **0** (was 0).
- The price of the stricter honesty: no safe contract gets a definitive NO BUG FOUND any more (C12
  dropped to INCOMPLETE because its ETH paths and 64/96-bit casts are now reported as not fully covered).
- C04 (spot-price oracle) stays missed for a reason no engine fixes: every rule the writer wrote checks
  health at the CURRENT pool price, and the bug is that the price can be pushed up for one transaction
  and come back after. That needs rules over several transactions ("a loan must still be covered after
  the price returns"), which the rule language does not have yet.
