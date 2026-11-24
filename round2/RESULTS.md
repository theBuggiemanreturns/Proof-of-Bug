# Round 2 results

Parties: bug author (fresh session; prepared the user's 9 real-world bugs + 3 clean contracts,
sealed ANSWERS.md), rule writer (fresh session), rule reviewer (fresh session), operator (this
session: ran the machine, wrote no rules). Commitments, both verified:

- author's ANSWERS.md sha256 `54d7e092...609cab` (sent 07:06 UTC with the contracts; key received
  after the verdicts, hash matches; copy in `round2/ANSWERS.md`)
- operator's VERDICTS.md sha256 `b4c4cd9f...bcb6fd3d` (sealed 08:49 UTC, sent before the key)

## Score

| Case | Truth | Sealed verdict | Result |
|---|---|---|---|
| R01 | buggy: release never lowers the lock's share counter, cancel pays twice | BUGGY | caught, exact mechanism |
| R02 | clean: ETH time lock | INCOMPLETE | no claim (2 counterexamples, both triaged `rule_wrong` by the writer) |
| R03 | buggy: withdraw(0) with zero liquidity pays the whole balance | BUGGY | caught, exact attack (1 tx) |
| R04 | buggy: unchecked underflow in delegate, overflow in transfer | BUGGY | caught, exact mechanism (both halves) |
| R05 | buggy: signed fee never checked; negative fee cancels the debit | BUGGY | caught the root cause (fee never checked against minFee); the attack shown is a below-minimum fee, not the full negative-fee drain |
| R06 | buggy: replaced rebalancer keeps its role | BUGGY | caught, exact attack (former operator U2 moves funds) |
| R07 | buggy: depositMulti accepts a 1-element array, holdings undercounted | BUGGY | caught, exact mechanism |
| R08 | buggy: importLegacy credits past rewards | BUGGY | caught, exact mechanism |
| R09 | buggy: sell tax burned from the pair and synced, k collapses | BUGGY | caught, exact mechanism |
| R10 | clean: fixed R07 | INCOMPLETE | no claim |
| R11 | buggy: deposits below 1e12 pull 0 tokens but mint LP | BUGGY | caught, exact mechanism |
| R12 | clean: fixed R08 | NO BUG FOUND | correct (23/25 rules proven for all sizes) |

- Planted bugs caught: **9 of 9**, each with an attack replayed on the real EVM.
- False alarms: **0**. The 3 clean contracts got no BUGGY verdict. Counterexamples from wrong rules
  (6, two of them on the clean R02) were all triaged `rule_wrong` by the rule writer itself.
- Clean contracts given a definitive verdict: 1 of 3 (R12). R02 and R10 stayed INCOMPLETE.
- Round 1, for comparison: 4 of 8 sealed (7 of 8 post-hoc with the later pipeline), 0 false alarms.

## Weak spots this round showed (to fix next; none changes the score above)

1. R02, clean, INCOMPLETE: the exact (full-size) search does not model ETH payments, and the
   bit-level search timed out on part of the rules. ETH in the exact engine is the gap.
2. R10, clean, INCOMPLETE: the engines did not derive that `require(amounts.length == 2)` bounds
   the loop, so it counted as possibly longer than 64 steps and no rule was proven.
3. R03 was searched at 8 bits by the bit-level engine: the width choice ignored the 1e21 balances
   the deployment set up. Fuzzing still found the bug.
4. Sums over accounts leave out accounts the deployment uses outside the model (R09: the deployer's
   7,000e18 tokens), so total-equals-sum rules fail trivially there.
5. The circuit keeps only the low bits of deployed values above its width (max approvals that this
   token decrements): differential mismatches in R03/R05/R08/R12.
6. R05, found after the reveal: the pipeline lost the full attack. At 39 bits the circuit read
   values near 2^39 as negative fees, so it produced attacks on three rules (`withdraw_debit_covers_quantity`,
   `withdraw_debit_split`, `backing_bound`). They did not reproduce on the 256-bit EVM. The runner
   then marked those rules "unconfirmed" and LEFT THEM OUT of the exact (256-bit) search and the
   prover. The exact search is the engine that sees real negative numbers, and it would have
   searched for exactly the planted drain, withdraw(q, -q). The verdict file did not mention the
   unconfirmed rules either (also R03, R04, R07, one rule each). An unconfirmed circuit attack means
   "the circuit is unreliable here". The rule should then stay open for the exact search and be
   reported, not be dropped silently. This is the most important fix from this round.

## Post-hoc rerun with the fixes (after the reveal; does NOT change the score above)

Same 12 contracts, deployments and reviewed rules, run through the engine with the post-reveal fixes
(`round2/LOG.md`, "After the reveal"). New counterexamples were triaged by the same rule writer
(`round2_posthoc/triage_2.json`: 3 real bugs). Verdicts: `round2_posthoc/VERDICTS.md`.

| Case | Truth | Sealed | Post-hoc | What changed |
|---|---|---|---|---|
| R01 | buggy | BUGGY | BUGGY | |
| R02 | clean | INCOMPLETE | **NO BUG FOUND WITHIN LIMITS** | the exact search now models ETH: every rule clean at 1-3 tx at full size; the attacker's callback during the ETH payment is searched by the bit-level engine (its width) |
| R03 | buggy | BUGGY | BUGGY | searched at 74 bits instead of 8 |
| R04 | buggy | BUGGY | BUGGY | |
| R05 | buggy | BUGGY (root cause only) | BUGGY, **the planted drain itself** | withdraw(2732304826, -1379951932) pays 1.38e9 more than it debits: three rules the sealed run had dropped are now broken and confirmed |
| R06 | buggy | BUGGY | BUGGY | |
| R07 | buggy | BUGGY | BUGGY | |
| R08 | buggy | BUGGY | BUGGY | |
| R09 | buggy | BUGGY | BUGGY | the trivial `ledger` failure is gone (the deployer's tokens are counted) |
| R10 | clean | INCOMPLETE | **NO BUG FOUND WITHIN LIMITS** | 11/15 rules proven for all sizes (was 0), exact search clean; limit: arrays of up to 3 elements |
| R11 | buggy | BUGGY | BUGGY | |
| R12 | clean | NO BUG FOUND | NO BUG FOUND | 0 circuit-vs-EVM mismatches (was 5) |

- Planted bugs caught: 9 of 9, now including R05's full attack.
- False alarms: 0. Clean contracts with a definitive verdict: 3 of 3 (was 1 of 3). Two of them are
  "within limits", and each verdict states its limit.
- Circuit vs EVM: 0 mismatches in all 12 cases (was 41 in four cases). No circuit attack was
  rejected by the EVM, so no rule was set aside.
- Regression after the fixes: 43/44 and 14/14, 17/22 and 5/7 proven, 0 wrongly proven, 0 mismatches
  (identical to before).
