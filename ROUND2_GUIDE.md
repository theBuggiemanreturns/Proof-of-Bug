# Round 2: how to bring the next bugs

Same protocol as round 1 (see BLIND_PROTOCOL.md): you are the bug author this time, a brand-new AI
session with no memory writes the rules, a second brand-new session reviews them, the machine hunts,
the rule writer triages every attack, I seal the verdicts, then you open your answer key.

## What to send me (per contract)

1. **One Solidity file**, everything inlined (no imports). For a real protocol, run
   `forge flatten src/Thing.sol > Thing.flat.sol`, or better: cut it down to the vulnerable contract
   plus small mock versions of what it talks to (a token, an oracle, a pool). Smaller files are
   tested more deeply.
2. **A DEPLOY note**, as a comment at the top of the file: constructor arguments, the order things are
   deployed in, and the setup (who gets minted what, what is approved, any admin calls), with real
   amounts if they matter. Name the contract under test.
3. **Nothing about the bug.** No comments like "// BUG", no names like `VulnerableVault`. Neutral names.

Mix in **2 to 4 contracts with no bug** (for example the fixed version of one of your bugs, or a clean
contract of the same kind) and do not tell me which. Without clean ones the test cannot show whether
the tool raises false alarms.

## Your answer key (keep it private until I send my sealed verdicts)

Write `ANSWERS.md`: first line a random salt (e.g. `openssl rand -hex 32`), then for each case:
buggy or clean, the root cause, the attack steps. Send me only its hash:

```bash
sha256sum ANSWERS.md
```

When I send you my verdict hash and verdicts, send me `ANSWERS.md`; I check it against your hash.

## What the tool can and cannot do today (so the test is informative, not a surprise)

- Handles: tokens, vaults, lending, AMMs, staking/rewards, auctions, order books, time locks, ETH
  payments, reentrancy through callbacks, several contracts talking to each other, large numbers
  (the exact search and the fuzzer work at full 256-bit size).
- Reports "unsupported" (never "safe"): signatures (`ecrecover`, EIP-712/permit), `delegatecall` and
  upgradeable proxies, contract creation (`new`, CREATE2), inline assembly that computes memory or
  storage locations, cross-chain messages.
- Bugs that need a long chain of transactions (more than ~4-8) or a multi-step price manipulation
  (borrow at a pumped price, then the price comes back) may come back INCOMPLETE: the rules today talk
  about one transaction at a time.

Including a few contracts in the "unsupported" list is fine: it tests that the tool says so honestly.
