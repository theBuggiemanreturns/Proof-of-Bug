# Blind test protocol (no grading our own homework)

Three separate parties, so whoever writes the rules never sees where the bugs are.

| Party | Who | Sees | Never sees |
|---|---|---|---|
| Bug author | a separate Claude session with no access to this repository | the public pattern corpus, its own ideas | our engine, rules, families, results |
| Rule writer | a second separate session | exactly the agent prompt: contract source + family catalog + rule language (`python -m proofofbug.agent ... --show-prompt`) | the answer key, the author's notes |
| Operator (this session) | runs the machine | contracts, rule proposals, results | the answer key until verdicts are committed |

Order of events
1. Families, rule language and agent prompt are frozen BEFORE any blind contract exists:
   `FREEZE.txt` holds their sha256. Any later change to them is listed in BLIND_RESULTS.md
   and the affected verdicts are scored separately ("post-freeze").
2. The author sends 12 contracts and a sha256 commitment of its answer key (with a salt).
3. The rule writer proposes rules per contract from the frozen prompt. The operator does not
   write or edit rules for blind contracts.
4. The machine validates proposals (compile, names, honest-usage... the agent pipeline) and hunts.
   Engine changes are allowed only to model Solidity/EVM features (never rules); each one is logged.
5. The operator commits its verdicts (sha256 of BLIND_VERDICTS.md) to the author, then asks for the key.
6. The author reveals the key; its hash must match the commitment. Scoring: buggy caught and
   confirmed on the EVM, clean contracts not flagged, and every "proven" checked against the key.
