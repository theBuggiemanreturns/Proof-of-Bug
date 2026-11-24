"""CLI: score rule sets with mutation testing.

    python -m proofofbug.mutate bench.level1 --only B08 --rules library --max 30
"""
import argparse, importlib, json, os, sys
from .mutation import run_case, score
from .bench import library_rules


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("suites", nargs="+")
    ap.add_argument("--only", default=None)
    ap.add_argument("--rules", default="library", choices=["case", "library"])
    ap.add_argument("--max", type=int, default=30, help="mutants per contract (random sample)")
    ap.add_argument("--budget", type=float, default=20)
    a = ap.parse_args(argv)
    root = os.getcwd()
    cases = [c for s in a.suites for c in importlib.import_module(s).CASES]
    report = {}
    for case in cases:
        if a.only and case["id"] not in a.only.split(","):
            continue
        if case.get("attacker") is not None:
            print(f"{case['id']}: skipped (attacker cases not mutated yet)")
            continue
        if a.rules == "library":
            case = library_rules(case)
        print(f"{case['id']}: {case.get('title', '')}  rules: {', '.join(case['rules'])}")
        res, total = run_case(case, root, max_mutants=a.max, budget=a.budget)
        k, s, rate = score(res)
        eq = sum(r["status"] == "equivalent" for r in res)
        print(f"{case['id']}: {total} mutants possible, {len(res)} tested: killed {k}, survived {s}, "
              f"equivalent {eq}  -> rule strength {rate:.0%}" if rate is not None else f"{case['id']}: no scoreable mutants")
        report[case["id"]] = {"results": res, "killed": k, "survived": s, "equivalent": eq, "strength": rate}
    os.makedirs("gg-out", exist_ok=True)
    json.dump(report, open("gg-out/mutation-report.json", "w"), indent=1)


if __name__ == "__main__":
    sys.exit(main())
