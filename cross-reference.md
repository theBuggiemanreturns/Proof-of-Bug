# Vulnerability Cross-reference — Proof of Bug engine (rule families + benchmark)

**Cross-reference status:** CROSSREF_WITH_LIMITATIONS
**Reference date:** 2026-11-23

What is being cross-referenced here is not one protocol but the *engine*: its rule families
(`proofofbug/families.py`), its benchmark ledger (22 known bugs in `bench/`), and its modelling
coverage (`proofofbug/symexec.py`, `proofofbug/intproof.py`). Each of the 108 patterns asks
two questions: (1) can the engine even *see* this behaviour (modelling), and (2) is there a
general law (family) whose violation is this bug. Patterns found missing on either side were
turned into engine work or new families **before** the independent blind test set was
received (see section 5 and `BLIND_PROTOCOL.md`).

## 1. Input provenance

| Artifact | Path / hash / commit |
|---|---|
| protocol-map.md | n/a: the "protocol" is the engine; its map is README.md (layout) and SPEC.md |
| coverage.md | `bench/library.py` (22 bugs -> families), `gg-out/bench-library.json` (last full regression) |
| hypotheses.md | the 22 benchmark bugs (B01-B09, M01-M03, R01-R05, H00-H04) + training cases T01-T06 |
| tests.md | `bench/*.py`, Foundry replay of every counterexample, `tests/test_circuit.py` |
| findings directory | `gg-out/` (bench, mutation, agent reports) |
| source/evidence | `proofofbug/`, `src/`; family freeze hash in `FREEZE.txt` |

## 2. Category coverage

`applicable` = in scope for a single-chain EVM bug finder. "Model" says whether the engine can
represent the behaviour; "Law" names the family (new ones in **bold**).

| Category | Reference | Status | Map/route evidence | Checklist result / linked hypotheses |
|---|---|---|---|---|
| CAT-01 | 01-amm-pool-graduation-squatting.md | applicable | AMM pools (B07), first-mint (B01, R01) | AMM-03 -> nonzero_mint, share_price_monotone (B01, R01). AMM-01/04/05/06 need pool *creation* across contracts and CREATE2: Model no (no CREATE). AMM-02, RUG-08 slippage: Law **bounded_step** on price; a "user got at least min" rule is exact_effect. AMM-09 -> authorized_change. |
| CAT-02 | 02-oracle-price-feeds.md | applicable | M03 spot vs fair price | ORC-06/LIQ-05 -> collateralized at the fair price (M03). ORC-01 donation-moved rate -> **bounded_step** / share_price_monotone. ORC-03 future timestamp, ORC-05 uninitialised cache -> must_succeed, bounded_by; needed TIME (added). ORC-04 gas griefing: Model no (gas not modelled). |
| CAT-03 | 03-erc4626-vaults.md | applicable | B01, B02, R01, R03, M01 | VLT-01 -> nonzero_mint (B01, R01). VLT-05 -> fair_redemption, share_price_monotone (B02, R03). VLT-04/07 -> bounded_by (M01), **in_sync**. VLT-03 max*() vs real cap -> must_succeed, but needs a view call in rules: Law partial (gap G3). VLT-06 -> **monotone**, **accrual_bounded** (needed TIME). VLT-02 slippage parameter: design, not a rule. |
| CAT-04 | 04-reentrancy-cei.md | applicable | M02 attacker callback | REN-01/03/04 -> account_bounded_by, bounded_by (M02, T06). REN-02 unvalidated callback -> **no_third_party_loss**, bounded_by. Model: one solver-chosen callback per transaction; bit engine only (gap G4). |
| CAT-05 | 05-access-control-init.md | applicable | B04, B09, R02 Parity | ACC-01/02 -> authorized_change (R02). ACC-03 -> authorized_change, authorized_increase, **no_third_party_loss**, **no_loss_beyond_allowance** (T02). ACC-05 -> **rate_limited**, **bounded_step**, **frozen_when**. ACC-06 existence-vs-ownership -> **no_third_party_loss**. ACC-04 CREATE2 takeover: Model no. |
| CAT-06 | 06-signatures-replay.md | blocked | none in benchmark | SIG-01..04 need ecrecover: the engine reports Unsupported (precompile call) rather than guessing. SIG-02 nonce rule exists as **monotone**. Gap G1. |
| CAT-07 | 07-rounding-precision.md | applicable | B02, R03 | RND-01 -> share_price_monotone, fair_redemption (repetition found by multi-tx search, R03). RND-02/05 -> exact_effect, bounded_by. RND-04 stranded dust -> exit_all; with TIME **accrual_bounded**. RND-03 decimals: needs two tokens; Law = in_sync with a scale factor. |
| CAT-08 | 08-token-integration.md | applicable | M01 fee-on-transfer token | TOK-01 -> bounded_by (M01), **in_sync**. TOK-02 rebasing, TOK-03 blacklist: only if the token is in the model; an adversarial-token mode is gap G5. TOK-04/05 style. TOK-06 / ETH flows: ETH now modelled (X8, T07); the 2300-gas stipend is not (gas is not modelled). |
| CAT-09 | 09-dos-griefing.md | applicable | B08 exit_all | DOS-03 front-run to revert -> must_succeed, exit_all, exit_amount (multi-tx search finds the blocking tx). DOS-01/02/04/05 out-of-gas: Model no (gas is constant), loops beyond the unroll limit are reported INCOMPLETE, not clean. Gap G6. |
| CAT-10 | 10-cross-chain-bridging.md | not applicable | single-chain engine; no messaging layer | XCH-03's local half (two records of one value) -> **in_sync**. The rest needs a model of a second chain. |
| CAT-11 | 11-liquidations-collateral.md | applicable | M03 lending | LIQ-01/03 -> collateralized, bounded_by. LIQ-02 proceeds to wrong party -> exact_effect on the liquidator, **no_third_party_loss**. LIQ-04 refreshed timeout -> **never_when** / **rate_limited** (needed TIME). LIQ-05 -> collateralized at the fair price (M03). |
| CAT-12 | 12-governance-staking-rewards.md | applicable | R04, R05, H00-H04 reward accounting | GOV-01 -> bounded_by (R04), **accrual_bounded**, **monotone**. GOV-02 -> **frozen_when** (T05). GOV-03 double counting -> ledger. GOV-04 signature front-run: blocked with CAT-06. |
| CAT-13 | 13-centralization-trust.md | applicable | owner/guardian roles in B04, B09 | TRU-01/03/04 are trust properties, reported by stating them as rules (authorized_change with the admin allowed, **bounded_step**, **rate_limited**) and seeing which hold. TRU-02 renounce -> must_succeed for admin functions. |
| CAT-14 | 14-recurring-code-smells.md | not applicable | style/gas items | SMELL-01..08 are not behaviours a counterexample can show. SMELL-05 escalates to CAT-04 when a path exists, which the attacker search checks. |
| CAT-15 | 15-accounting-state-desync.md | applicable | B03, B08, M01, R04, R05 | ACD-01/02/03 -> **in_sync**, ledger (T04). ACD-04 balance-gated credit -> bounded_by with an accounted total, **no_third_party_loss**. Highest-value new family. |
| CAT-16 | 16-boundary-conditions-off-by-one.md | applicable | none before (no time) | BND-01/02 -> **never_when**, **frozen_when** with `now` (T01, T05); needed TIME. BND-03 loop index -> any value law; loops unrolled. BND-04 -> exit_amount (amount == balance), nonzero_mint for redeem. |
| CAT-17 | 17-incomplete-code-paths.md | applicable | sibling functions in every case | INC-01 is now in the agent prompt as a checklist; INC-02 -> **in_sync**; INC-03 -> **never_when** applied to every sibling (T01). |
| CAT-18 | 18-already-mitigated-signatures.md | applicable | positive controls in section 4 | used for section 4. |
| CAT-19 | 19-token-rugpull-signatures.md | applicable | B04 mint | RUG-01 -> authorized_increase, ledger. RUG-02 honeypot -> exit_amount / must_succeed on transfer. RUG-03 -> **bounded_step** on the fee or bounded_by(fee <= cap). RUG-04/07 -> authorized_change with admin = nobody. RUG-05 -> **frozen_when**. RUG-06 Solana: n/a. RUG-08 -> **bounded_step**. |
| CAT-20 | 20-emerging-2025-2026-patterns.md | applicable | none before | EMG-01 transient storage: Model added (tload/tstore, cleared per transaction, rolled back on revert; T06). EMG-02 7702, EMG-03 4337: blocked with CAT-06 (signatures). EMG-04 depeg -> collateralized at market price. |

## 3. Audit candidate cross-reference

The engine's 22 benchmark bugs and 6 training cases, matched to the corpus.

| Audit ID | Audit status | Root cause | Pattern ID(s) / no match | Strength | Common mechanism and material differences | Precedent/fix context | Disposition |
|---|---|---|---|---|---|---|---|
| B01, R01 | confirmed (caught, fixed clean) | donation makes deposit mint 0 shares | VLT-01, AMM-03 | strong | same first-depositor shape | virtual shares (MIT-05) | covered by nonzero_mint |
| B02, R03 | confirmed | redemption rounds for the user | VLT-05, RND-01 | strong | R03 needs repetition, as in RND-01 | round against the user | covered by fair_redemption, share_price_monotone |
| B03 | confirmed | unchecked underflow mints balance | NO_CLOSE_PRECEDENT | weak | nearest ACD (ledger desync) | checked math | covered by ledger |
| B04 | confirmed | anyone can mint | ACC-03, RUG-01 | strong | identical | access check | authorized_increase |
| B05 | confirmed | transferFrom never spends allowance | ACC-03 (sibling of TOK-04) | moderate | missing state update not missing check | spend allowance | allowance_spent |
| B06, B09 | confirmed | breaker reset while danger remains | ACC-05 (bypass of a safety gate) | weak | no timelock involved | gate the reset | breaker_hold |
| B07 | confirmed | AMM x*y shrinks | AMM family (pricing) | moderate | not a creation-time bug | k check | product_monotone |
| B08 | confirmed | withdraw blocked / books drift | DOS-03, ACD-02 | moderate | | | ledger, exit_all |
| M01 | confirmed | fee-on-transfer token over-booked | TOK-01, VLT-07, ACD-04 | strong | identical | measure balance delta | bounded_by |
| M02, T06 | confirmed | state written after callback | REN-01, REN-04, EMG-01 (T06) | strong | T06 uses a transient lock taken by one entry point only | CEI / guard every entry point (MIT-01) | account_bounded_by |
| M03 | confirmed | spot price used for borrowing | ORC-06, LIQ-05 | strong | | TWAP / fair price | collateralized |
| R02 | confirmed | unprotected init takes ownership | ACC-01, ACC-02 (Parity) | strong | identical precedent | disable initializers | authorized_change |
| R04 | confirmed | stale cached reward rate overpays | GOV-01 | strong | | settle before rate change | bounded_by |
| R05 | confirmed | accrual distributed twice | GOV-01, ACD-03 | moderate | | | bounded_by |
| H00-H04 | confirmed (blind ladder) | over-credit beyond what was paid | ACD-04, GOV-03 | moderate | difficulty from sequence length/width/loops, not the root cause | | bounded_by |
| T01 | training | sibling skips the time lock | INC-03, BND-02 | strong | | same check in every sibling | **never_when** |
| T02 | training | burnFrom ignores allowance | ACC-03 | strong | | | **no_loss_beyond_allowance** |
| T03 | training | vesting pays past the period | VLT-06, GOV-01, BND-04 | moderate | | cap elapsed time | bounded_by / **accrual_bounded** |
| T04 | training | fast-path skips held update | ACD-02 | strong | identical shape | | **in_sync** |
| T05 | training | vote changed after deadline | GOV-02 | strong | | freeze every path | **frozen_when** |
| T07 | training | ETH paid out before the balance is zeroed | REN-01, SMELL-05 escalated | strong | reentrancy through the ETH transfer itself | CEI | bounded_by with `ETH` |

## 4. Positive controls

| Audit hypothesis / invariant | High-stakes pattern | Exact defense | Source/deployed evidence | Result |
|---|---|---|---|---|
| fixed M02, fixed T06 | REN-01..04 (MIT-01) | every value-moving entry point takes the lock / updates first | `src/bench/Level2.sol` BankM02, `src/train/Train.sol` BankT06 (`fixed_`) | the attacker search finds no reentry; checked on EVM replay |
| fixed B01, R01 | VLT-01 (MIT-05) | zero-share deposits revert | `src/Vault.sol`, `src/real/R01*` | rule nonzero_mint holds, proven for all sizes |
| fixed R02 | ACC-01/02 (MIT-03) | init callable once, by the deployer | `src/real/R02*` | authorized_change proven for all sizes |
| engine | soundness of "proven" | every unmodelled feature now raises Unsupported (balance, chainid, number, ecrecover/ETH calls); time is a free variable in proofs | `proofofbug/intproof.py`, `proofofbug/symexec.py` | before this pass, time read as 0 in both engines: a time-dependent contract could be "proven" from a frozen clock |

## 5. Cross-reference-origin candidates and loopback

New engine features and families created from the corpus, each run on the training set.
The blind set (independent author) is the real test; results in `BLIND_RESULTS.md`.

| New hypothesis ID | Pattern/category source | Affected invariant/code | Returned audit evidence/test | Final status | Finding ID |
|---|---|---|---|---|---|
| X1 time | CAT-02, 03, 11, 12, 16 | block.timestamp was constant 0 | T01, T03, T05 + EVM replay with vm.warp | see training results | engine |
| X2 transient storage | EMG-01 | tload/tstore unsupported | T06 | see training results | engine |
| X8 ETH | REN-01 with ETH, TOK-06, CAT-11 payouts | msg.value was 0, ETH sends unsupported | T07: payable deposit + ETH reentrancy caught, EVM replay exact (408 txs, 0 mismatches) | fixed | engine |
| X9 early-return bug | ACD-02 fast paths | an internal function called after the caller's `return` could still revert | T04 fixed: 8 circuit/EVM mismatches before, 0 after | fixed | engine |
| X10 truncation | regression after the pass | solc writes `x * 2` as `shl(1, x)`; the bit above W was dropped by the next division without being marked as a width effect, so a too-small model looked like a real overflow revert | M03: 7 and 4 circuit/EVM mismatches before (pre-existing, also with the old code), 0 after | fixed | engine |
| X3 silent zeros | soundness | balance/chainid/number read as 0 | Unsupported -> INCOMPLETE | fixed | engine |
| X4 no_third_party_loss, no_loss_beyond_allowance | ACC-03, ACC-06, REN-02 | per-account rules (`u` = any user) | T02 | see training results | family |
| X5 in_sync | ACD-01..03, INC-02 | two records of one value | T04 | see training results | family |
| X6 frozen_when, never_when | GOV-02, INC-03, BND-01/02 | time and state gates on every sibling | T01, T05 | see training results | family |
| X7 bounded_step, monotone, rate_limited, accrual_bounded | ACC-05, RUG-03, SIG-02, GOV-01, VLT-06 | per-call limits, indices, time-based payouts | T03 | see training results | family |

## 6. Corpus gaps and no-close-precedent items

| Audit ID / behavior | Search terms/categories checked | Why no close precedent | KB follow-up |
|---|---|---|---|
| B03 unchecked underflow mint | rounding, accounting, boundary | the corpus has no "unchecked block" entry; closest is ACD (books drift) | suggest an "unchecked arithmetic" pattern |
| B06/B09 breaker reset | ACC-05, circuit breaker | corpus treats breakers only as an oracle defense (MIT-02) | suggest "safety switch reset while unsafe" |
| H03 bug only above 2^63 | boundary, rounding | width-dependent bugs (large values) are not a corpus pattern | engine-specific: width ladder |

## 7. Limitations and residual uncertainty

Each limitation below is either blocked in the engine (reported as Unsupported/INCOMPLETE, never as clean) or an unresolved modelling gap.

- G1 signatures (CAT-06, EMG-02/03, GOV-04): ecrecover is not modelled; such contracts are reported Unsupported.
- G2 ETH: now modelled in the bit engine (payable calls, balances, sends, reentrancy through ETH; T07). The integer prover takes any msg.value but refuses ETH balance reads and sends (Unsupported, never silently 0). Plain ETH transfers to receive() are not generated as transactions.
- G3 rules cannot call view functions (max*(), previews); expressible only through storage.
- G4 reentrancy: one callback per transaction, bit engine only; the integer prover refuses attacker cases.
- G5 adversarial tokens (rebasing, blacklisting, hooks) only when such a token is written into the case.
- G6 gas: not modelled, so out-of-gas DoS (DOS-01/02/04/05, ORC-04) cannot be shown; long loops give INCOMPLETE.
- No CREATE/CREATE2 (AMM-01/04, ACC-04), no cross-chain model (CAT-10).
- Matching a pattern to a family does not mean every instance is caught: a family must still be
  filled correctly for the contract, which is what the blind test measures.
