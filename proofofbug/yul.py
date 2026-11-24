"""Compile Solidity with solc and extract what the circuit compiler needs:
the optimized Yul AST of the deployed code, storage layout, ABI and selectors."""
from __future__ import annotations
import json, os, re, subprocess, glob

SOLC_GLOB = os.path.expanduser("~/.local/share/svm/*/solc-*")


def find_solc(version: str | None = None) -> str:
    found = sorted(glob.glob(SOLC_GLOB))
    if version:
        found = [f for f in found if f.endswith(version)]
    if not found:
        raise RuntimeError("solc not found; run `forge build` once so Foundry installs it")
    return found[-1]


class Contract:
    def __init__(self, name, yul_ast, storage, abi, selectors):
        self.name = name
        self.code = yul_ast  # deployed object's code block (YulBlock)
        self.storage = storage  # label -> slot (int)
        self.abi = abi
        self.selectors = selectors  # signature -> selector int
        self.payable = {f"{i['name']}({','.join(x['type'] for x in i['inputs'])})" for i in abi
                        if i.get("type") == "function" and i.get("stateMutability") == "payable"}
        self.has_receive = any(i.get("type") in ("receive", "fallback") and i.get("stateMutability") == "payable"
                               for i in abi)

    def field(self, var, nkeys, name):
        """Struct member `name` of var after nkeys mapping levels: (extra slot, byte offset, bytes)."""
        t = self.storage_types[var]
        for _ in range(nkeys):
            t = self.types[t]["value"]
        members = self.types.get(t, {}).get("members") or []
        m = next((x for x in members if x["label"] == name), None)
        if m is None:
            raise KeyError(f"{var} has no field {name}" if members else f"{var} is not a struct")
        return int(m["slot"]), int(m["offset"]), int(self.types[m["type"]]["numberOfBytes"])

    def value_slots(self, var):
        """How many slots one entry of var occupies (a struct can take several)."""
        t = self.storage_types[var]
        while self.types.get(t, {}).get("encoding") == "mapping":
            t = self.types[t]["value"]
        return max(1, int(self.types.get(t, {}).get("numberOfBytes", 32)) // 32)

    def uint_keyed(self):
        """Is some mapping keyed by an integer (an id) rather than an address?"""
        for var in self.storage:
            t = self.storage_types[var]
            while self.types.get(t, {}).get("encoding") == "mapping":
                if self.types[t]["key"].startswith(("t_uint", "t_int")):
                    return True
                t = self.types[t]["value"]
        return False

    def mapping_depth(self, var):
        """0 for a plain variable, 1 for mapping(k => v), 2 for mapping(k => mapping(k2 => v))."""
        t, d = self.storage_types[var], 0
        while self.types.get(t, {}).get("encoding") == "mapping":
            t = self.types[t]["value"]
            d += 1
        return d

    def functions(self, include_view=False):
        """External functions the solver may call: [(name, signature, selector, n_args)]."""
        out = []
        for item in self.abi:
            if item.get("type") != "function":
                continue
            if not include_view and item.get("stateMutability") in ("view", "pure"):
                continue
            sig = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"
            out.append((item["name"], sig, self.selectors[sig], calldata_words([i["type"] for i in item["inputs"]])))
        return sorted(out, key=lambda f: f[1])


ARRAY_MAX = 3  # a dynamic array argument holds at most this many elements (a search and proof limit, reported)
_STATIC = re.compile(r"^(u?int\d*|address|bool|bytes([1-9]|[12]\d|3[012]))$")


def calldata_words(types):
    """The calldata words (after the selector) of a call with these ABI parameter types, as word types.
    Static values take one word each; a fixed array T[n] takes n words; a dynamic array T[] of a static
    T takes a head word "offset:<canonical offset>" and, after all heads, a tail: "length:<ARRAY_MAX>"
    then ARRAY_MAX words of T. The solver chooses every word (offsets and lengths too); the contract's
    own ABI decoder checks them, as on the chain. Other dynamic types (bytes, string, nested arrays,
    structs) are kept as one word and the engines raise Unsupported when the code reads them."""
    heads, tails = [], []
    for t in types:
        m = re.fullmatch(r"(.+)\[(\d*)\]", t)
        if m and _STATIC.match(m.group(1)) and m.group(2):
            heads += [m.group(1)] * int(m.group(2))
        elif m and _STATIC.match(m.group(1)):
            heads.append(("offset", len(tails)))
            tails += ["length:%d" % ARRAY_MAX] + [m.group(1)] * ARRAY_MAX
        else:
            heads.append(t)
    nh = len(heads)
    return [f"offset:{32 * (nh + h[1])}" if isinstance(h, tuple) else h for h in heads] + tails


def compile_contract(path: str, name: str, root: str = ".") -> Contract:
    std = {
        "language": "Solidity",
        "sources": {path: {"urls": [path]}},
        "settings": {
            "optimizer": {"enabled": True},
            "outputSelection": {"*": {"*": ["irOptimizedAst", "storageLayout", "abi", "evm.methodIdentifiers",
                                             "evm.bytecode.object", "evm.deployedBytecode.immutableReferences"],
                                       "": ["ast"]}},
        },
    }
    p = subprocess.run([find_solc(), "--standard-json", "--allow-paths", "."], input=json.dumps(std),
                       capture_output=True, text=True, cwd=root, check=True)
    out = json.loads(p.stdout)
    errs = [e for e in out.get("errors", []) if e["severity"] == "error"]
    if errs:
        raise RuntimeError("\n".join(e["formattedMessage"] for e in errs))
    c = out["contracts"][path][name]
    ast = c["irOptimizedAst"]
    deployed = next(o for o in ast["subObjects"] if o.get("name", "").endswith("_deployed"))
    storage = {s["label"]: int(s["slot"]) for s in c["storageLayout"]["storage"]}
    stypes = {s["label"]: s["type"] for s in c["storageLayout"]["storage"]}
    types = c["storageLayout"]["types"] or {}
    sels = {k: int(v, 16) for k, v in c["evm"]["methodIdentifiers"].items()}
    immut = {}
    def walk(n):
        if isinstance(n, dict):
            if n.get("nodeType") == "VariableDeclaration" and n.get("mutability") == "immutable":
                immut[n["name"]] = str(n["id"])
            for v in n.values(): walk(v)
        elif isinstance(n, list):
            for v in n: walk(v)
    for node in out["sources"][path]["ast"]["nodes"]:
        if node.get("nodeType") == "ContractDefinition" and node.get("name") == name:
            walk(node)
    k = Contract(name, deployed["code"]["block"], storage, c["abi"], sels)
    k.immutable_ids = immut  # variable name -> id used by loadimmutable
    k.bytecode = c["evm"]["bytecode"]["object"]  # creation code of exactly this compilation
    k.immutable_refs = {i: (r[0]["start"], r[0]["length"])
                        for i, r in c["evm"]["deployedBytecode"].get("immutableReferences", {}).items() if r}
    k.storage_types = stypes
    k.types = types
    k.storage_offset = {s["label"]: int(s["offset"]) for s in c["storageLayout"]["storage"]}
    k.storage_bytes = {s["label"]: int(types.get(s["type"], {}).get("numberOfBytes", 32))
                       for s in c["storageLayout"]["storage"]}
    return k
