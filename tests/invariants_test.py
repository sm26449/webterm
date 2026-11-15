"""docs/design/INVARIANTS.md şi codul rămân legate.

Pagina listează regulile de business pe care contributorii (oameni şi agenţi) le-au greşit, cu
locul din cod care le aplică. Fără verificare, o redenumire o face să mintă exact acolo unde
contează. Testul cere:
  1. fiecare regulă `INV-NN` din pagină are cel puţin o ancoră în cod (`INV-NN (docs/design/
     INVARIANTS.md): …`), iar fiecare ancoră din cod numeşte o regulă care există;
  2. identificatorii din „Enforced in" (funcţii, clase, constante) există în cod;
  3. testele din „Tests" există (tests/<nume>_test.py sau frontend/src/lib/<nume>).
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "design" / "INVARIANTS.md"

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def code_files():
    for base, pats in ((ROOT / "gateway" / "app", ("*.py",)), (ROOT / "frontend" / "src", ("**/*.ts", "**/*.tsx")),
                       (ROOT / "agent", ("*.py",))):
        for pat in pats:
            yield from base.glob(pat)


def main():
    doc = DOC.read_text(encoding="utf-8")
    sections = re.split(r"(?m)^## (INV-\d\d):", doc)
    rules = {sections[i]: sections[i + 1] for i in range(1, len(sections) - 1, 2)}
    check("pagina are reguli (testul nu e gol)", len(rules) >= 10, str(sorted(rules)))
    table = set(re.findall(r"\[(INV-\d\d)\]\(#inv-\d\d\)", doc))
    check("tabelul de sus = secţiunile", table == set(rules), "%s vs %s" % (sorted(table), sorted(rules)))

    src = {p: p.read_text(encoding="utf-8", errors="ignore") for p in code_files()}
    anchors = {}
    for p, s in src.items():
        for m in re.finditer(r"(INV-\d\d) \(docs/design/INVARIANTS\.md\)", s):
            anchors.setdefault(m.group(1), []).append(p.name)
    missing = sorted(set(rules) - set(anchors))
    check("fiecare regulă are o ancoră în cod", not missing, str(missing))
    unknown = sorted(set(anchors) - set(rules))
    check("fiecare ancoră din cod numeşte o regulă din pagină", not unknown, str(unknown))

    blob = "\n".join(src.values())
    gone = []
    for rid, body in rules.items():
        m = re.search(r"\*\*Enforced in\*\*:(.*?)(?:\*\*Tests\*\*|\Z)", body, re.S)
        for ident in re.findall(r"`([A-Za-z_][\w.]*)`", m.group(1) if m else ""):
            last = ident.split(".")[-1]
            if last.endswith(("py", "ts")) or ident.startswith("[") or len(last) < 4:
                continue                              # nume de fişier / tag, nu identificator
            if not re.search(r"\b%s\b" % re.escape(last), blob):
                gone.append("%s: %s" % (rid, ident))
    check("identificatorii din „Enforced in” există în cod", not gone, str(gone))

    no_test = []
    for rid, body in rules.items():
        m = re.search(r"\*\*Tests\*\*:(.*?)(?:\n\n|\Z)", body, re.S)
        for name in re.findall(r"`([\w.]+)`", m.group(1) if m else ""):
            if name.endswith(".ts"):
                hit = list((ROOT / "frontend" / "src").glob("**/" + name))
            else:
                hit = [ROOT / "tests" / (name + "_test.py")] if (ROOT / "tests" / (name + "_test.py")).exists() else []
            if not hit:
                no_test.append("%s: %s" % (rid, name))
    check("testele citate există", not no_test, str(no_test))

    print(f"\n{ok}/{total} passed")
    raise SystemExit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
