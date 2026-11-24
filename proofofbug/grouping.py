"""Grouping rules by behaviour, not by how they look.

Two checks:
  covers(A, B)  the solver proves there is no transaction sequence (within the model's
                bounds) where B fires and A does not: everything B catches, A catches.
                Then B belongs under A (A is the more general law).
  fingerprint   the set of known bugs and mutants a rule catches (from benchmark and
                mutation reports); equal fingerprints mean duplicates in practice.

CLI:  python -m proofofbug.grouping bench.level1 bench.real1 ...
For every case it compares the case's original hand-written rules with the family rules
from the library, on the buggy and the fixed contract, and prints which covers which.
"""
from __future__ import annotations
import argparse, importlib, os, sys
from .circuit import TIMEOUT


def covers(m, a, b, timeout=30):
    """True if rule a covers rule b in model m, False if not (with a witness), None on timeout."""
    r = m.c.solve({f"rule:{b}": 1, f"rule:{a}": 0}, timeout=timeout)
    if r == TIMEOUT:
        return None, None
    if r is None:
        return True, None
    return False, m.decode(r)


def fires(m, a, timeout=30):
    r = m.c.solve({f"rule:{a}": 1}, timeout=timeout)
    return None if r == TIMEOUT else r is not None


def relation(m, a, b, timeout=30):
    fa, fb = fires(m, a, timeout), fires(m, b, timeout)
    if fa is False and fb is False:
        return "neither fires (nothing to compare)"
    ab, _ = covers(m, a, b, timeout)
    ba, _ = covers(m, b, a, timeout)
    if ab and ba:
        return "equivalent"
    if ab:
        return f"{a} covers {b}"
    if ba:
        return f"{b} covers {a}"
    if ab is None or ba is None:
        return "unknown (timeout)"
    return "overlap only"


def main(argv=None):
    from .bench import build, library_rules
    ap = argparse.ArgumentParser()
    ap.add_argument("suites", nargs="+")
    ap.add_argument("--only", default=None)
    a = ap.parse_args(argv)
    root = os.getcwd()
    for suite in a.suites:
        for case in importlib.import_module(suite).CASES:
            if a.only and case["id"] not in a.only.split(","):
                continue
            lib = library_rules(case)
            both = {f"orig:{n}": f for n, f in case["rules"].items()}
            both.update({f"lib:{n}": f for n, f in lib["rules"].items()})
            for fixed in (False, True):
                m, _, _ = build(dict(case, rules=both), fixed, root, 8, 3, case.get("users", 2))
                for o in [n for n in both if n.startswith("orig:")]:
                    for l in [n for n in both if n.startswith("lib:")]:
                        print(f"{case['id']} {'fixed' if fixed else 'buggy'}: {relation(m, l, o)}")


if __name__ == "__main__":
    sys.exit(main())
