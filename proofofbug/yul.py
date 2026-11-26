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
        self.excluded = {}  # signature -> why the engines cannot model it (reported, never silent)
        self.only = None  # a probe of one function: the only signature callable
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

    def type_slots(self, t, base, keys, span, depth=0, mdepth=0):
        """Every slot a value of storage type t at `base` can occupy, walking the compiler's type tree: a struct's
        members at their offsets, a fixed array's slots, a mapping's entry for every key, a dynamic array's (or
        long bytes') length slot and its first `span` data slots at keccak(base). Under two levels of mappings
        only a value's own slots are listed (as before arrays were walked): expanding arrays and inner mappings
        there too costs keys^2 x (span + keys) slots per variable (47,594 for one registry contract), and every
        replayed transaction snapshots every listed slot."""
        from .symexec import mapping_slot, keccak_int
        info = self.types.get(t, {})
        enc = info.get("encoding", "inplace")
        if depth > 6:
            return {base}
        if mdepth >= 2:
            n = max(1, int(info.get("numberOfBytes", 32)) // 32) if enc == "inplace" else 1
            return {base + j for j in range(n)}
        if enc == "mapping":
            out = set()
            for k in keys:
                out |= self.type_slots(info["value"], mapping_slot(k, base), keys, span, depth + 1, mdepth + 1)
            return out
        if enc in ("dynamic_array", "bytes"):
            data = keccak_int(base.to_bytes(32, "big"))
            out = {base} | {(data + j) % (1 << 256) for j in range(span)}
            elem = info.get("base")
            if enc == "dynamic_array" and elem and self.types.get(elem, {}).get("encoding", "inplace") != "inplace":
                esize = max(1, int(self.types[elem].get("numberOfBytes", 32)) // 32)
                for j in range(0, span, esize):  # elements that are themselves arrays/bytes
                    out |= self.type_slots(elem, (data + j) % (1 << 256), keys, span, depth + 1, mdepth)
            return out
        if info.get("members"):
            out = set()
            for mem in info["members"]:
                out |= self.type_slots(mem["type"], base + int(mem["slot"]), keys, span, depth + 1, mdepth)
            return out
        n = max(1, int(info.get("numberOfBytes", 32)) // 32)
        return {base + j for j in range(n)}

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
            types = [abi_type(i) for i in item["inputs"]]
            sig = f"{item['name']}({','.join(types)})"
            if sig in self.excluded or (self.only is not None and sig not in self.only):
                continue  # left out of the model (see bench.isolate), or a single-function probe
            out.append((item["name"], sig, self.selectors[sig], calldata_words(types)))
        return sorted(out, key=lambda f: f[1])


def abi_type(param):
    """The canonical ABI type of a parameter, as in the selector: a struct is its components in
    brackets, e.g. (address,uint256)[] (the ABI JSON says only "tuple[]")."""
    t = param["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(abi_type(c) for c in param["components"]) + ")" + t[len("tuple"):]
    return t


def _split_top(inner):
    """Split a tuple's component list at its top-level commas."""
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch == "," and depth == 0:
            out.append(cur); cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    return out + [cur] if cur else out


def _static_words(t):
    """The words of a static type (a value, a fixed array of values, a struct of static members),
    or None if the type is dynamic."""
    if _STATIC.match(t):
        return [t]
    m = re.fullmatch(r"(.+)\[(\d+)\]", t)
    if m:
        w = _static_words(m.group(1))
        return None if w is None else w * int(m.group(2))
    if t.startswith("(") and t.endswith(")"):
        out = []
        for c in _split_top(t[1:-1]):
            w = _static_words(c)
            if w is None:
                return None
            out += w
        return out
    return None


ARRAY_MAX = 3  # a dynamic array argument holds at most this many elements (a search and proof limit, reported)
_STATIC = re.compile(r"^(u?int\d*|address|bool|bytes([1-9]|[12]\d|3[012]))$")


# A bytes/string argument is one of these lengths (a search and proof limit, reported like ARRAY_MAX):
# empty, a bare selector, one word, a selector and one word, a selector and two words.
BYTES_LENGTHS = (0, 4, 32, 36, 68)


def _dynamic_tail(t):
    """The tail words of a dynamic type, offsets relative to the start of that tail's own block."""
    if t in ("bytes", "string"):
        return [f"blength:{','.join(map(str, BYTES_LENGTHS))}"] + ["raw"] * ((max(BYTES_LENGTHS) + 31) // 32)
    m = re.fullmatch(r"(.+)\[(\d*)\]", t)
    if m and not m.group(2):  # T[]: a length, then ARRAY_MAX elements laid out like a tuple of them
        return [f"length:{ARRAY_MAX}"] + _block([m.group(1)] * ARRAY_MAX)
    if m:  # T[k] with a dynamic T
        return _block([m.group(1)] * int(m.group(2)))
    if t.startswith("(") and t.endswith(")"):
        return _block(_split_top(t[1:-1]))
    raise ValueError(f"not a dynamic ABI type: {t}")


def _block(types):
    """One ABI encoding block (a call's arguments, a struct, an array's elements): static members inline,
    each dynamic member a head word "offset:<bytes from the block start>" and its tail after all heads.
    Every tail has a fixed place (its longest form), so every offset is a known number; a shorter value
    leaves unused words, which the ABI allows and every decoder accepts."""
    heads, tails = [], []
    for ty in types:
        sw = _static_words(ty)
        if sw is not None:
            heads += sw
        else:
            heads.append(("offset", len(tails)))
            tails += _dynamic_tail(ty)
    nh = len(heads)
    return [f"offset:{32 * (nh + h[1])}" if isinstance(h, tuple) else h for h in heads] + tails


VARIANTS_MAX = 64  # most length combinations one function is run with (fewer lengths beyond: reported)
# which lengths to give up first when a function has too many combinations (most common kept)
_KEEP_ORDER = {"length": (1, 0, 2, 3), "blength": (36, 0, 4, 68, 32)}


def length_variants(types, max_variants=VARIANTS_MAX):
    """The calldata variants every engine runs a function with: one word-type list per combination of its
    argument lengths, in which every offset and every length is a known number ("const:N"); raw bytes stay
    "raw". Returns (variants, slots, note): slots are the positions of the lengths; note says which lengths
    were given up to stay within max_variants (None if none). None if no argument is dynamic."""
    import itertools
    types = [str(t) for t in types]
    if not any(t.startswith(("offset:", "length:", "blength:")) for t in types):
        return None
    slots = []
    for j, t in enumerate(types):
        if t.startswith("length:"):
            slots.append((j, "length", list(range(int(t[7:]) + 1))))
        elif t.startswith("blength:"):
            slots.append((j, "blength", [int(x) for x in t[8:].split(",")]))
    n, note = 1, None
    for _, _, vs in slots:
        n *= len(vs)
    while n > max_variants:  # give up the least common length of the slot with the most
        j, kind, vs = max(slots, key=lambda s: len(s[2]))
        order = [v for v in _KEEP_ORDER[kind] if v in vs] + [v for v in vs if v not in _KEEP_ORDER[kind]]
        vs.remove(order[-1])
        n = n // (len(vs) + 1) * len(vs)
        note = "argument lengths limited to " + "; ".join(f"word {j}: {sorted(v)}" for j, _, v in slots)
    base = [f"const:{t[7:]}" if t.startswith("offset:") else t for t in types]
    out = []
    for pick in itertools.product(*[vs for _, _, vs in slots]):
        vt = list(base)
        for (j, _, _), v in zip(slots, pick):
            vt[j] = f"const:{v}"
        out.append(vt)
    return out, [j for j, _, _ in slots], note


def calldata_words(types):
    """The calldata words (after the selector) of a call with these ABI parameter types, as word types.
    Static values take one word each; fixed arrays and structs of static members are inline. Every dynamic
    argument (T[], bytes, string, structs with dynamic members, nested to any depth) is laid out with
    known offsets ("offset:N", always N), a length chosen from a few values ("length:N" = 0..N elements,
    "blength:a,b,..." = one of those byte lengths) and the content words ("raw" for bytes: a word whose low
    W bits and top 4 bytes the solver chooses)."""
    return _block(types)


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
    # immutables of the contract AND of every contract it inherits from (ERC4626's asset, EIP712's domain,
    # solmate ERC20's chain id...): a parent's immutable lives in this contract's code too
    immut = {}
    defs = {}
    for src in out["sources"].values():
        for node in src["ast"]["nodes"]:
            if node.get("nodeType") == "ContractDefinition":
                defs[node["id"]] = node
    def walk(n, owner):
        if isinstance(n, dict):
            if n.get("nodeType") == "VariableDeclaration" and n.get("mutability") == "immutable":
                key = n["name"] if n["name"] not in immut else f"{owner}.{n['name']}"  # same name in two parents
                immut[key] = str(n["id"])
            for v in n.values(): walk(v, owner)
        elif isinstance(n, list):
            for v in n: walk(v, owner)
    me = next((d for d in defs.values() if d.get("name") == name and
               any(d is x for x in out["sources"][path]["ast"]["nodes"])), None)
    for cid in (me or {}).get("linearizedBaseContracts", []):
        if cid in defs:
            walk(defs[cid], defs[cid]["name"])
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
