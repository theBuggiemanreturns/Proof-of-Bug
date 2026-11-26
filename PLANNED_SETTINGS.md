# Planned: user-scalable settings (not built yet)

Status: agreed design, to be built after the current big-contract work. Nothing here changes how the engine
runs today.

## Why

How far the engines search depends on numbers that are fixed in the code today and were chosen for one
machine (15 GB, 4 cores). On a stronger machine the same engine could search wider and deeper; on a laptop it
should not run out of memory. Users know their hardware and their target, so they should be able to set these
numbers themselves.

## What becomes a setting

| Group | Setting | Today (where) |
|---|---|---|
| machine | memory the engine may use | none (the OS kills the process) |
| machine | largest bit-level circuit | `MAX_GATES = 6_000_000` (blind.py) |
| machine | parallel workers | 1 |
| machine | seconds per solver call | `--budget` (blind/bench) |
| search reach | transactions in a row | `--depths` |
| search reach | widest bit-level numbers | `--ladder`, auto width |
| model bounds | array element slots | `ARRAY_SPAN = 16` (symexec.py) |
| model bounds | dynamic array length | `ARRAY_MAX = 3` (yul.py) |
| model bounds | bytes/string lengths | `BYTES_LENGTHS = (0, 4, 32, 36, 68)` (yul.py) |
| model bounds | length combinations per function | `VARIANTS_MAX = 64` (yul.py) |
| model bounds | options a known-values value keeps | `CHOICE_MAX = 128` (symexec.py), `OPTIONS_MAX = 32` (intproof.py) |
| model bounds | memory treated as out of gas past | `MEMORY_LIMIT = 16 MB` (symexec.py, intproof.py) |
| model bounds | accounts in the key universe | users, contracts, deployer (model.py) |

## How users set them

1. One settings file per run (for example `bounds.toml` next to the case) or command-line flags.
2. Auto-detect by default: the engine reads the machine's memory and cores and picks values; a user sets only
   what they want to change.
3. Presets as starting points (`--profile laptop | default | server`), any setting overridable.

## Guardrails

- Every record and report prints the exact settings used. "No bug found" only means something next to the
  bounds it was found under, and two runs are only compared at the same settings.
- Before a run, the engine estimates memory from the settings and warns (with the estimate) instead of failing
  halfway.
- Floors: no setting can go below what the engines need to stay exact. Users can make a search smaller, never
  wrong.
- Blind rounds: the settings are sealed together with the rules before the run, so nobody tunes them after
  seeing results.

## Build order (when it is time)

1. Collect every constant above into one settings object; today's values become the defaults; the full
   regression must be identical.
2. Settings file, flags, auto-detect, the report line.
3. Memory estimates and warnings.

## What it does not solve

- Walls that are not about resources: functions the engines cannot model yet (unaligned EIP-712 hashing,
  `delegatecall`, `create`/`create2`, some deep encodings), and paths left out where a value is unknown only on
  paths that already failed (needs dead-path detection with the solver).
- The bit-level engine's cost grows about with the square of the number width, so even a large machine reaches
  a limit on systems with realistic balances (about 90-bit numbers); the exact 256-bit search, the prover and
  the fuzzer scale better there.
- Using many cores at once (running rules or engines in parallel) is a separate improvement, listed with this
  one but not part of it.
