"""Post-hoc rerun of round 2 (after the reveal): the same contracts, deployments and reviewed rule
proposals as round2/, run through the engine with the post-reveal fixes. Scored separately; the
sealed round-2 verdicts (round2/VERDICTS.md) are unchanged."""
import importlib.util, os
_spec = importlib.util.spec_from_file_location("round2_cases_src", os.path.join(os.path.dirname(__file__), "..", "round2", "cases.py"))
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
CASES = _m.CASES
