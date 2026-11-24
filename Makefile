.PHONY: bench bench-deep bench-auto bench-library mutate agent test
PY ?= python
FORGE ?= forge
export FORGE

bench:            ## Level 1 + 2 benchmark: every bug caught, every fix clean, circuit vs real EVM
	$(PY) -m proofofbug.bench bench.level1 bench.level2 bench.real1 bench.hidden --auto

bench-deep:       ## also search at 12 and 16 bits, 120 s budget per solver call
	$(PY) -m proofofbug.bench bench.level1 bench.level2 bench.real1 --ladder 12,16 --budget 120

bench-auto:       ## all suites incl. the hidden ladder; bounds chosen from each contract, depths 3/5/8
	$(PY) -m proofofbug.bench bench.level1 bench.level2 bench.real1 bench.hidden --auto --depths 3,5,8 --budget 60

bench-library:    ## all suites using only the family rules from bench/library.py
	$(PY) -m proofofbug.bench bench.level1 bench.level2 bench.real1 bench.hidden --auto --depths 3,5,8 --rules library --budget 30

mutate:           ## rule strength of the library rules on every contract (mutation testing)
	$(PY) -m proofofbug.mutate bench.level1 bench.level2 bench.real1 bench.hidden --rules library --max 25

agent:            ## validate the agent's proposals for one case: make agent SUITE=bench.level1 CASE=B01
	$(PY) -m proofofbug.agent $(SUITE) --only $(CASE) --proposals proposals/$(CASE).json

test:             ## exhaustive check of the gate-level arithmetic
	$(PY) tests/test_circuit.py
