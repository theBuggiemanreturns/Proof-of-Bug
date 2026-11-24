"""Coverage survey: which functions of common, real contract code can the engines model, and why not.

    python3 survey/survey.py --oz <path to openzeppelin-contracts> [--k 3] [--only SurveyVault,...]

Builds each corpus contract (survey/src, OpenZeppelin 5.x building blocks) with the engine's own model
builder at 1..k transactions and lists every function left out (bench.isolate) with its reason and the
depth at which the wall first shows. Writes survey/RESULTS.md. Nothing here is a benchmark: the corpus has
no planted bugs; it measures what the engines can see, not what they find.
"""
import argparse, collections, json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TOK, AST = "Tokens", "Assets"
MINT = ["{c}({A}).mint({U0}, 1000 ether);", "{c}({A}).mint({U1}, 1000 ether);"]


def case(name, file, args="''", deps=(), setup=()):
    return dict(name=name, file=file, args=args, deps=list(deps), setup=list(setup))


CORPUS = [
    case("SurveyToken", TOK, setup=MINT),
    case("SurveyPermitToken", TOK, setup=MINT),
    case("SurveyVotesToken", TOK, setup=MINT),
    case("SurveyFlashToken", TOK, setup=MINT),
    case("SurveyCallToken", TOK, setup=MINT),
    case("SurveyMulticallToken", TOK, setup=MINT),
    case("SurveyOwnable2Step", TOK),
    case("SurveyVault", AST, "abi.encode({A1})", ["SurveyAsset"],
         ["SurveyAsset({A1}).mint({U0}, 1000 ether);", "SurveyAsset({A1}).mint({U1}, 1000 ether);",
          "vm.prank({U0}); SurveyAsset({A1}).approve({A0}, type(uint256).max);",
          "vm.prank({U1}); SurveyAsset({A1}).approve({A0}, type(uint256).max);"]),
    case("SurveyWrapper", AST, "abi.encode({A1})", ["SurveyAsset"],
         ["SurveyAsset({A1}).mint({U0}, 1000 ether);",
          "vm.prank({U0}); SurveyAsset({A1}).approve({A0}, type(uint256).max);"]),
    case("SurveyStaking", AST, "abi.encode({A1})", ["SurveyAsset"],
         ["SurveyAsset({A1}).mint({U0}, 1000 ether);",
          "vm.prank({U0}); SurveyAsset({A1}).approve({A0}, type(uint256).max);"]),
    case("SurveyNFT", AST),
    case("SurveyMulti", AST),
    case("SurveyCloneFactory", AST, "abi.encode({A1})", ["SurveyAsset"]),
    case("SurveyCallbackPool", AST, "abi.encode({A1}, {A2})", ["SurveyAsset", "SurveyAsset"],
         ["SurveyAsset({A1}).mint({A0}, 100 ether);", "SurveyAsset({A2}).mint({A0}, 100 ether);",
          "SurveyCallbackPool({A0}).sync();", "SurveyAsset({A1}).mint({U0}, 100 ether);"]),
]


def flatten(oz, out):
    """forge flatten each corpus file against the given OpenZeppelin checkout (nothing is copied in)."""
    proj = os.path.join(out, "proj")
    os.makedirs(proj, exist_ok=True)
    open(os.path.join(proj, "foundry.toml"), "w").write(
        f'[profile.default]\nsrc = "{HERE}/src"\nlibs = []\n'
        f'remappings = ["@openzeppelin/contracts/={os.path.abspath(oz)}/contracts/"]\n')
    for f in (TOK, AST):
        dst = os.path.join(out, f"{f}_flat.sol")
        subprocess.run(["forge", "flatten", "--root", proj, os.path.join(HERE, "src", f"{f}.sol"), "-o", dst],
                       check=True, capture_output=True)
    return {f: os.path.relpath(os.path.join(out, f"{f}_flat.sol"), ROOT) for f in (TOK, AST)}


def run(oz, kmax, only):
    from proofofbug import bench
    from proofofbug.symexec import Unsupported
    out = os.path.join(ROOT, "gg-out", "survey")
    flat = flatten(oz, out)
    rows, results = [], {}
    for c in CORPUS:
        if only and c["name"] not in only:
            continue
        contracts = [dict(name=c["name"], file=flat[c["file"]], args=c["args"])] + \
                    [dict(name=d, file=flat[AST], args="''") for d in c["deps"]]
        cs = dict(id=f"survey_{c['name']}", contracts=contracts, users=3, rules={},
                  setup=[s.format(c=c["name"], A="{A0}", **{k: "{" + k + "}" for k in ("A0", "A1", "A2", "U0", "U1")})
                         for s in c["setup"]])
        first, n_funcs, err, t0 = {}, 0, None, time.time()
        bench._ISOLATED.pop(f"{cs['id']}_fix", None)
        for k in range(1, kmax + 1):
            try:
                m, _, _ = bench.build(cs, True, ROOT, 16, k, 3)
            except Unsupported as e:
                err = f"whole model at {k} tx: {e}"
                break
            except Exception as e:  # a harness problem, reported, never hidden
                err = f"{type(e).__name__}: {str(e)[:300]}"
                break
            for f, why in m.excluded.items():
                first.setdefault(f, (k, why))
            n_funcs = len(m.funcs) + len(m.excluded)
        mine = {f: v for f, v in first.items() if f.startswith(c["name"] + ".")}
        results[c["name"]] = dict(functions=n_funcs, left_out={f: list(v) for f, v in first.items()}, error=err,
                                  seconds=round(time.time() - t0, 1))
        print(f"{c['name']}: {n_funcs} functions, {len(mine)} of its own left out"
              + (f", ERROR {err}" if err else ""), flush=True)
        for f, (k, why) in sorted(first.items()):
            print(f"    [{k} tx] {f}: {why}", flush=True)
    json.dump(results, open(os.path.join(out, "results.json"), "w"), indent=1)
    if not only:  # RESULTS.md describes the whole corpus
        write_md(results, kmax)


def write_md(results, kmax):
    reasons = collections.Counter()
    for r in results.values():
        for f, (k, why) in r["left_out"].items():
            reasons["immutable has no value" if why.startswith("immutable") else why] += 1
    L = ["# Coverage survey", "",
         f"Common OpenZeppelin 5.x building blocks (survey/src), built with the engine's own model at 1..{kmax} "
         "transactions. A function \"left out\" cannot be modelled yet and is not searched. Generated by "
         "`survey/survey.py`.", "",
         "| Contract | Functions | Left out (own + deps) | Error |", "|---|---|---|---|"]
    for n, r in results.items():
        L.append(f"| {n} | {r['functions']} | {len(r['left_out'])} | {r['error'] or ''} |")
    L += ["", "## Every function left out", "", "| Function | First seen at | Why |", "|---|---|---|"]
    for n, r in results.items():
        for f, (k, why) in sorted(r["left_out"].items()):
            L.append(f"| `{f}` | {k} tx | {why} |")
    L += ["", "## Reasons, counted", "", "| Reason | Functions |", "|---|---|"]
    L += [f"| {why} | {n} |" for why, n in reasons.most_common()]
    open(os.path.join(HERE, "RESULTS.md"), "w").write("\n".join(L) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--oz", required=True, help="path to an openzeppelin-contracts checkout (5.x)")
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    run(a.oz, a.k, set(filter(None, a.only.split(","))))
