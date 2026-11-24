"""Read what another Claude session sent this session (contracts, rule proposals, triage, reveals),
byte-for-byte, from this session's transcript.

    python3 -I tools/relay.py contracts <transcript.jsonl> <from-session-id> <out dir>
    python3 -I tools/relay.py json      <transcript.jsonl> <from-session-id> <out dir>   # {"C01": {...}} -> C01.json
    python3 -I tools/relay.py triage    <transcript.jsonl> <from-session-id> <out file>
"""
import hashlib, html, json, os, re, sys


def bodies(log, sid):
    tag = f'<cross-session-message from-session="{sid}">'
    out = []
    def walk(o):
        if isinstance(o, str):
            if tag in o:
                for part in o.split(tag)[1:]:
                    b = part.split("</cross-session-message>", 1)[0]
                    b = "\n".join(l[4:] if l.startswith("    ") else l for l in b.split("\n"))
                    out.append(html.unescape(b))
        elif isinstance(o, dict):
            for v in o.values(): walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
    for line in open(log):
        if sid not in line:
            continue
        try:
            walk(json.loads(line))
        except Exception:
            pass
    seen, uniq = set(), []
    for b in out:
        if b not in seen:
            seen.add(b); uniq.append(b)
    return uniq


def json_objects(text):
    i = text.find("{")
    while i != -1:
        try:
            obj, end = json.JSONDecoder().raw_decode(text[i:])
            yield obj
            i = text.find("{", i + end)
        except json.JSONDecodeError:
            i = text.find("{", i + 1)


def main():
    mode, log, sid, out = sys.argv[1:5]
    if mode == "contracts":
        os.makedirs(out, exist_ok=True)
        for b in bodies(log, sid):
            for name, code in re.findall(r"### (\w+\.sol)\s*\n```solidity\n(.*?)\n```", b, re.S):
                open(os.path.join(out, name), "w").write(code + "\n")
                print(name, hashlib.sha256((code + "\n").encode()).hexdigest()[:16])
    elif mode == "files":  # "=== R01.sol ===" blocks; a file ends at the next block or the body's end
        os.makedirs(out, exist_ok=True)
        for b in bodies(log, sid):
            parts = re.split(r"^=== (\w+\.sol) ===[ \t]*$\n", b, flags=re.M)
            for name, code in zip(parts[1::2], parts[2::2]):
                code = re.sub(r"\n*(DONE)?\s*$", "", code) + "\n"
                open(os.path.join(out, name), "w").write(code)
                print(name, hashlib.sha256(code.encode()).hexdigest()[:16])
    elif mode == "json":
        os.makedirs(out, exist_ok=True)
        for b in bodies(log, sid):
            for obj in json_objects(b):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if re.fullmatch(r"[A-Z][A-Z0-9_]*\d+|[A-Z][A-Z0-9]*(_[A-Z0-9]+)+", k) and isinstance(v, dict):
                            json.dump(v, open(os.path.join(out, f"{k}.json"), "w"), indent=1)
                            print(k, len(v.get("rules", [])), "rules")
    elif mode == "triage":
        items = []
        for b in bodies(log, sid):
            for obj in json_objects(b):
                if isinstance(obj, dict) and "triage" in obj:
                    items += obj["triage"]
        json.dump({"triage": items}, open(out, "w"), indent=1)
        print(len(items), "triage entries")


if __name__ == "__main__":
    main()
