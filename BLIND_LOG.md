# Blind test: what changed after the contracts arrived

Contracts received 2026-11-23T13:56Z (hashes in `blind/RECEIVED.sha256`; author's answer-key
commitment `6283d550...630b4b`). Families were frozen before that (FREEZE.txt v1/v2); nothing in
`proofofbug/families.py` changed afterwards (same hash in v3).

Every change below is to how the engine models Solidity/EVM or the deployment. None is a rule,
and none was made by looking for or at a bug: each was forced by a contract that could not be
compiled, deployed or modelled at all, and each applies to every contract equally.

## Engine features added (the contracts used things the 22-case benchmark never did)

| Change | Forced by | Before |
|---|---|---|
| `log0..log4` (events) are no-ops | every blind contract emits events | Unsupported |
| general `immutable` values, read from the deployed code; the EVM now deploys *our* compiled bytecode so model and chain run the same compilation | token/oracle addresses held as immutables (all but C03) | only the `fixed_` flag was supported |
| setup calls after deployment, deployment order, instance aliases (two copies of one token), deployer account, extra addresses | DEPLOY notes (mint, approve, add liquidity, notify reward...) | contracts could only be constructed |
| `mulmod` with the exact double-width product | C09 | Unsupported |
| struct fields in rules: `pre("orders", id, "amount")`; mappings keyed by ids get ids 1..8 in the address universe | C07, C10, C11, C12 keep state in id-keyed structs | an order with id 1 was "outside the model"; no rule could name a field (rule-language text changed: FREEZE v3) |
| precompile calls (`ecrecover`...) raise Unsupported | C05 | treated as a call to an empty account: a silent under-approximation (no signature could ever verify) |
| width rule: compare-with-deployer is an identity check; type-bound constants (2^k-1...) are overflow guards; arithmetic constants (1e18) count; probed at 2 transactions | first smoke runs gave 161-bit or wrongly 8-bit models | widths of 161 bits (22M gates) or 8 bits where 1e18 maths was meaningless |
| two constant free-memory-pointer values join to the larger one | every external call with return data (`if iszero(ok) {revert}` then `if ok {...}`) | "mstore at a computed address" |

## Soundness bug found and fixed (integer prover)

The prover's caches of upper bounds, bit masks and word-to-condition were keyed by Z3 term ids
without keeping the terms alive. Z3 reuses the id of a freed term for a new one, so a lookup could
return facts about a different expression. On C07 this made every function of the order book look
impossible to succeed, so a deliberately false rule ("order 1 never holds more than 3") was
reported PROVEN while the bit engine found the counterexample. Fixed by keeping each cached term
and checking it on lookup (`proofofbug/intproof.py`). The full 22-case regression was rerun with
the fix: every earlier proof still holds, so none of them depended on the bug.

## Rule-language implementation fixed to match its documentation (found in the first blind run)

The prompt says `called("fn")` is the contract under test and `called("Contract.fn")` another
contract. The implementation matched a bare name against EVERY contract, so on C01
`called("transfer")` also fired on the token's own `transfer` (a donation), and the rule writer's
"vault transfer never moves assets" rule broke on a token transfer. The engine now does what the
documentation says (bare name = A0) in all three engines and in the name check. The first C01
run (before the fix) was stopped and discarded; all blind verdicts come from runs after it.

## Rule evaluator: constants on the left of `-` and `//` (found on C10)

The documented language allows `+ - * //` freely, but the evaluator rejected `constant - value`
(e.g. `1000000e18 - post("TokenC10_FRM.balanceOf", A0)`) and did so at search time, which crashed
the whole case. Now supported in all three engines; and a rule that cannot be evaluated is rejected
and reported on its own, never crashing a case. C10 was rerun.

## Over-strict guard from the early-return fix (found on C12)

After the early-return fix, a helper called after a possible `leave` also guarded its local
variable/memory writes with "the caller is still alive", which turned helper return values (here the
computed input size of a token call) into symbolic choices: "call with a computed memory range" ->
UNSUPPORTED. Local writes need no such guard (the caller never reads them on paths where it has
left); reverts and storage writes keep it. C12 now builds and matches the EVM (101 txs, 0
mismatches); T04, the case the early-return fix was for, still matches (792 txs, 0 mismatches).

## Modelling policy for the blind deployments (`blind/cases.py`)

Written once, before the first case was translated, then extended twice when a note first needed it:
deployer = the test runner; amounts given in a note are used exactly, others are 100 base units per
user; users U0..U3 get the tokens and approve the maximum; [C06] an owner who "periodically" acts is
a model user (U2); [C08, C09] addresses the deployment itself uses are in the address universe;
[C03, C12] where the contract sends ETH/calls to msg.sender, user U1 is a contract that may call back.

## What the rule writer saw

Exactly the frozen agent prompt (families, rule language, checklist) plus, per case, the contract
sources and a deployment note (addresses, aliases, setup). The standard token, identical in 11
cases, was sent once instead of eleven times. The rule writer never saw the engine, the families'
code, the training contracts or any answer key.

## After the reveal: sealed verdict file accidentally regenerated, restored byte-exact

While making the runner reusable for later rounds, `python -m proofofbug.blind verdicts` rewrote
BLIND_VERDICTS.md with the new verdict wording. It was restored from the exact text sent to the
author (sha256 back to 9b6c807e...e08d609, matching blind/VERDICTS.sha256). The runner now refuses
to write a verdict file once its seal (VERDICTS.sha256) exists.
