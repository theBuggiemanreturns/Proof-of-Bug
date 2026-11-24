"""Round 1 rerun AFTER the reveal with the improved pipeline (fuzzing, exact search, counterexample
replay, size reporting). Same contracts, deployments and rule proposals as blind/; results in
gg-out/round1_posthoc. Does not change the round-1 score (blind/VERDICTS.sha256)."""
import importlib.util, os
_spec = importlib.util.spec_from_file_location("blind_cases", os.path.join(os.path.dirname(__file__), "..", "blind", "cases.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
CASES = _mod.CASES
