# Blind verdicts (committed before the answer key is revealed)

Rules: written by an independent rule-writer session from the frozen agent prompt (FREEZE.txt v3).
Every counterexample below was replayed on the real EVM (Foundry). The rule writer then triaged
each one as `real_bug` or `rule_wrong` (blind/triage_*.json). The operator did not judge them.
Generated 2026-11-23 19:11 UTC. Engine changes after receipt: BLIND_LOG.md.

Verdicts: BUGGY = at least one confirmed counterexample triaged as a real bug; NO BUG FOUND = no real
counterexample within the searched bounds (with how many rules are also proven for all sizes);
INCOMPLETE = part of the search timed out or did not fit; UNSUPPORTED = the engine cannot model it.

| Case | Verdict | Evidence |
|---|---|---|
| C01 | BUGGY | `deposit_nonzero`: deposit(20, 49) from 0x32 -> redeem(4, 153, 49) from 0x31 -> deposit(1, 49) from 0x32 (triage: After assets are pushed into the vault (redeem to receiver=vault), a 1-wei deposit is accepted and mints 0 shares, so the depositor silently loses funds; deposit lacks a shares>0 check.); rule-writer errors (triaged rule_wrong): transfer_exact; circuit vs EVM: 416 txs, 0 mismatches |
| C02 | INCOMPLETE | 34 rules; no real counterexample (searched 3tx/62bit); proven for all sizes: 27/34; search timed out on 21; circuit vs EVM: 425 txs, 0 mismatches |
| C03 | BUGGY | `ledger`: depositFor(49) from 0x32 sending 52 wei -> transfer(50, 49) from 0x31 -> withdrawAll() from 0x32 [attacker calls back transfer(49, 40)] (triage: withdrawAll sends ETH before zeroing the balance and transfer is not nonReentrant, so the callback moves the balance elsewhere and it is then counted twice, breaking sum(balanceOf)==totalDeposits.); `sum_backed`: depositFor(50) from 0x31 sending 1 wei [attacker calls back withdraw(4)] -> withdrawAll() from 0x32 [attacker calls back transfer(0, 1)] (triage: Same reentrancy in withdrawAll: balances transferred during the callback survive, leaving credited balances unbacked by ETH.); `exit_all`: deposit() from 0x32 sending 2 wei -> withdrawAll() from 0x32 [attacker calls back transfer(49, 2)] -> withdrawAll() from 0x31 [attacker calls back transfer(70, 0)] (triage: Because of the withdrawAll reentrancy, totalDeposits is lower than the credited balances, so an honest holder's withdrawAll underflows and their funds are stuck.); `exit_amount`: depositFor(50) from 0x31 sending 26 wei -> withdrawAll() from 0x32 [attacker calls back transfer(49, 4)] -> withdraw(1) from 0x31 (triage: Same desync: totalDeposits underflows and an honest holder cannot withdraw a balance they legitimately hold.); circuit vs EVM: 390 txs, 0 mismatches |
| C04 | INCOMPLETE | 28 rules; no real counterexample (searched nothing); proven for all sizes: 0/28; search timed out on 28; coverage: a loop can run past the unroll limit (64); circuit vs EVM: 263 txs, 0 mismatches |
| C05 | UNSUPPORTED | too many mapping key combinations |
| C06 | BUGGY | `exit_amount`: deposit(3) from 0x33 -> transfer(51, 3) from 0x33 -> redeem(6) from 0x33 (triage: _transfer caches fromBalance and toBalance before writing, so a self-transfer (from == to) doubles the sender's shares (3 -> 6) without changing totalSupply, and the redeem of the inflated balance then reverts; the root cause is shares minted from nothing, which also breaks the share ledger.); circuit vs EVM: 402 txs, 0 mismatches |
| C07 | BUGGY | `modify_auth`: place(94, 4611686018427387231) from 0x32 -> cancel(1) from 0x32 -> modify(1, 127, 4611686018427387903) from 0x32 (triage: modify works on a cancelled order whose amount was not zeroed, so the maker can extract base again (double refund / reopening a closed order).); `cancelled_no_refund_again`: place(1, 1) from 0x32 -> cancel(1) from 0x32 -> modify(1, 63, 4611686018427387903) from 0x32 (triage: Same missing active check in modify: a cancelled order can be modified and moves escrowed base again.); rule-writer errors (triaged rule_wrong): quote_never_held; circuit vs EVM: 291 txs, 0 mismatches |
| C08 | INCOMPLETE | 21 rules; no real counterexample (searched nothing); proven for all sizes: 0/21; coverage: bit-level search not run: the 160-bit circuit (7.5M+ gates) does not fit in this machine's memory (killed); integer prover only |
| C09 | INCOMPLETE | 27 rules; no real counterexample (searched 3tx/22bit); proven for all sizes: 23/27; search timed out on 10; rule-writer errors (triaged rule_wrong): deposit_works; circuit vs EVM: 306 txs, 0 mismatches |
| C10 | INCOMPLETE | 25 rules; no real counterexample (searched 3tx/82bit); proven for all sizes: 19/25; search timed out on 21; circuit vs EVM: 422 txs, 0 mismatches |
| C11 | NO BUG FOUND | 20 rules; no real counterexample (searched 3tx/8bit); proven for all sizes: 13/20; circuit vs EVM: 266 txs, 0 mismatches |
| C12 | NO BUG FOUND | 33 rules; no real counterexample (searched 3tx/24bit); proven for all sizes: 0/33; circuit vs EVM: 261 txs, 0 mismatches |
