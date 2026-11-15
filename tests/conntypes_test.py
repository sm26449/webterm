"""Tipurile de conexiune trăiesc într-un singur loc (`gateway/app/conntypes.py`).

De ce: până la 3.6.35 grupările („ssh sau ssh-jump", „tipurile jump", „orice în afară de agent")
erau tupluri literale repetate de ~70 de ori, iar regula „NULL = agent" era copiată ca
`row["connection_type"] or "agent"`. Bypass-urile de retarget din review-ul lotului SSH (3.6.34)
stăteau în matricea asta: o ramură uita un tip. Testul ţine matricea într-un singur loc:

  1. în gateway/app, în afară de conntypes.py: nicio colecţie literală cu 2+ nume de tip,
     niciun SQL cu o listă de tipuri, nicio regulă `… or "agent"` pe connection_type;
  2. lista din frontend (`lib/conntypes.ts`) = cea din backend, în aceeaşi ordine;
  3. comportamentul helperilor (NULL = agent, strict pe rânduri fără coloană, porturi).
"""
import ast
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP = ROOT / "gateway" / "app"
sys.path.insert(0, str(ROOT / "gateway"))

from app import conntypes  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


NAMES = set(conntypes.ALL)
# `connection_type='agent'`, `connection_type IN ('ssh',…)`, `coalesce(connection_type,'agent')`
SQL_RULE = re.compile(r"connection_type\s*(?:!?=|<>|\bIN\b)\s*\(?\s*'|coalesce\(\s*connection_type",
                      re.IGNORECASE)


def _mentions_ctype(node) -> bool:
    return "connection_type" in ast.dump(node)


def violations(path: pathlib.Path) -> list:
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    # docstring-urile pot vorbi despre tipuri; doar codul nu are voie să le enumere
    docs = {id(n.value) for n in ast.walk(tree)
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            vals = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if len(vals) >= 2 and len(vals) == len(node.elts) and set(vals) <= NAMES:
                out.append("%s:%d: listă literală de tipuri %r" % (path.name, node.lineno, vals))
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            last = node.values[-1]
            if (isinstance(last, ast.Constant) and last.value == conntypes.AGENT
                    and any(_mentions_ctype(v) for v in node.values[:-1])):
                out.append("%s:%d: `… or \"agent\"` pe connection_type (foloseşte conntypes.of)"
                           % (path.name, node.lineno))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
            if SQL_RULE.search(node.value):
                out.append("%s:%d: tip de conexiune scris în SQL (foloseşte conntypes.SQL_IS_AGENT"
                           " / SQL_NETWORK / un parametru)" % (path.name, node.lineno))
    return out


def main():
    files = [p for p in sorted(APP.glob("*.py")) if p.name != "conntypes.py"]
    bad = [v for p in files for v in violations(p)]
    check("nicio listă de tipuri de conexiune în afara conntypes.py", not bad, "\n      " + "\n      ".join(bad))

    # testul chiar prinde ce interzice (nu e o glumă)
    probe = pathlib.Path(tempfile.mkdtemp()) / "probe.py"
    try:
        probe.write_text('X = ("ssh", "ssh-jump")\ny = r["connection_type"] or "agent"\n'
                         'q = "WHERE connection_type=\'agent\'"\n'
                         'p = "WHERE COALESCE(connection_type,\'agent\')!=\'agent\'"\n'
                         'def f():\n    "connection_type=\'agent\' în docstring e ok"\n', encoding="utf-8")
        check("detectorul prinde tuplu, `or \"agent\"` şi SQL (nu docstring-uri)", len(violations(probe)) == 4,
              str(violations(probe)))
    finally:
        probe.unlink(missing_ok=True)

    ts = (ROOT / "frontend" / "src" / "lib" / "conntypes.ts").read_text(encoding="utf-8")
    m = re.search(r"export const CONN_TYPES = \[([^\]]*)\]", ts)
    fe = tuple(re.findall(r"'([^']+)'", m.group(1))) if m else ()
    check("frontend CONN_TYPES = backend conntypes.ALL", fe == conntypes.ALL, "%r vs %r" % (fe, conntypes.ALL))

    c = conntypes
    check("NULL / gol = agent", c.of(None) == c.of("") == c.of({"connection_type": None}) == c.AGENT)
    try:
        c.of({"id": 1})
        strict = False
    except KeyError:
        strict = True
    check("un rând fără coloana connection_type NU e ghicit ca agent (KeyError)", strict)
    check("familiile partiţionează tipurile: agent + SSH + telnet",
          sorted((c.AGENT,) + c.SSH_FAMILY + c.TELNET_FAMILY) == sorted(c.ALL)
          and set(c.NETWORK) == set(c.ALL) - {c.AGENT})
    check("jump ⊂ reţea", set(c.JUMP) <= set(c.NETWORK))
    check("porturi implicite", [c.default_port(t) for t in c.ALL] == [22, 22, 22, 23, 23])
    check("ţinta unui host agent se compară ca SSH", c.target_proto(c.AGENT) == c.SSH
          and c.target_proto(c.TELNET_JUMP) == c.TELNET)

    print(f"\n{ok}/{total} passed")
    raise SystemExit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
