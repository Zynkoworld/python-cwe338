"""python-cwe338 -- cryptographically weak PRNG (Bandit B311-ekvivalens, SAJAT ast-implementacio).

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff a megadott soron a `random` modul nem-kriptografikus
generatorat hivjak (random/randint/choice/randrange/uniform/shuffle/sample/getrandbits a `random`
modulbol). SAFE, ha a `secrets` v. `os.urandom` v. `random.SystemRandom` van hasznalva.
stdlib `ast` only. NO-VIRUS: a Bandit szabalya ujraimplementalva, a Bandit NINCS telepitve/futtatva.
"""
import ast

CWE = "CWE-338"
_WEAK_FUNCS = {"random", "randint", "choice", "randrange", "uniform", "shuffle", "sample",
               "getrandbits", "randbytes"}


def _root_name(node):
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    # a SystemRandom peldanyok nevei (biztonsagos) -- ezeket kizarjuk
    safe_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            if isinstance(f, ast.Attribute) and f.attr == "SystemRandom":
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        safe_names.add(t.id)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == line:
            f = node.func
            fname = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
            if fname not in _WEAK_FUNCS:
                continue
            root = _root_name(f) if isinstance(f, ast.Attribute) else None
            if root in safe_names:          # sysrand.randint(...) -> biztonsagos
                return "SAFE"
            if root in (None, "random"):    # random.randint(...) v. bare randint(...)
                return "FLAG"
    return "SAFE"
