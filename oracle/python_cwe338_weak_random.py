"""python-cwe338 -- cryptographically weak PRNG, decided on the IMPORT BINDING (not the call name).

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff the call on the given line resolves, through the
module's import bindings, to a non-cryptographic generator of the stdlib `random` module. Calls on a
`random.SystemRandom()` instance are SAFE, as are `secrets.*` and `os.urandom`.

Binding-based, so `from random import randint as ri; ri(1, 6)` resolves; and a module's OWN
`def random(...)` shadows the library name and is NOT flagged. stdlib `ast` only; no code is executed.
NO-VIRUS: the Bandit rule was re-implemented from its description; Bandit is not installed or run.
"""
import ast

CWE = "CWE-338"
_WEAK = {"random." + f for f in ("random", "randint", "choice", "choices", "randrange", "uniform",
                                 "shuffle", "sample", "getrandbits", "randbytes", "betavariate",
                                 "gauss", "normalvariate", "triangular")}
# --- import-kotes feloldas (zafire #19219: a dontes a KOTESRE alljon, ne a nevre) ---

def _dotted(node):
    """a.b.c -> "a.b.c"; barmi mas -> None"""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _resolve(dotted, binds):
    head, _, rest = dotted.partition(".")
    if head in binds:
        return binds[head] + ("." + rest if rest else "")
    return dotted


def _bindings(tree):
    """lokalis nev -> teljes (pontozott) eredet: importok + egyszeru referencia-atadas."""
    binds = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                binds[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            for a in n.names:
                binds[a.asname or a.name] = (mod + "." + a.name) if mod else a.name
    for n in ast.walk(tree):          # f = hashlib.md5  ->  f kotese hashlib.md5
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            d = _dotted(n.value)
            if d:
                binds[n.targets[0].id] = _resolve(d, binds)
    return binds


def _local_defs(tree):
    """a modul altal MAGA definialt nevek -- ezek arnyekoljak az azonos nevu konyvtari hivast."""
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
    return out


def _origin(call, binds, local):
    """A hivott dolog KOTES szerinti teljes neve. None = nem eldontheto. '<local>.' = sajat definicio."""
    f = call.func
    if isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr" \
            and len(f.args) == 2 and isinstance(f.args[1], ast.Constant) \
            and isinstance(f.args[1].value, str):
        base = _dotted(f.args[0])
        return _resolve(base + "." + f.args[1].value, binds) if base else None
    d = _dotted(f)
    if d is None:
        return None
    head = d.split(".")[0]
    if head in local and head not in binds:
        return "<local>." + d
    return _resolve(d, binds)


def _const_strs(tree):
    """modul-szintu `NEV = "literal"` / `NEV = b"literal"` konstansok (konstans-propagacio)."""
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) \
                and isinstance(n.value.value, (str, bytes)):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = n.value.value
    return out


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    binds, local = _bindings(tree), _local_defs(tree)
    # SystemRandom peldanyok nevei -> biztonsagosak
    safe_inst = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
            o = _origin(n.value, binds, local)
            if o and o.endswith("SystemRandom"):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        safe_inst.add(t.id)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or getattr(node, "lineno", None) != line:
            continue
        d = _dotted(node.func)
        if d and d.split(".")[0] in safe_inst:
            continue
        origin = _origin(node, binds, local)
        if not origin or origin.startswith("<local>."):
            continue
        if origin in _WEAK:
            return "FLAG"
    return "SAFE"
