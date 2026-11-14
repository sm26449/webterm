#!/usr/bin/env python3
"""Bump gateway dependencies and regenerate the hashed lock — one command.

    PY=.venv/bin/python; $PY scripts/relock-reqs.py fastapi==0.162.4 cryptography==50.0.3
    $PY scripts/relock-reqs.py            # no arguments: just re-lock what requirements.txt says

De ce există: imaginea instalează din `gateway/requirements.lock` (--require-hashes), dar
Dependabot ştie să schimbe doar `gateway/requirements.txt`. Fiecare PR „pip" al lui e deci roşu
la `check-reqs-lock.py` — corect, dar reparaţia era o reţetă ţinută minte (ce pip-compile, cu ce
Python, din ce director). A regenera lock-ul AUTOMAT pe PR ar cere un token cu drept de scriere
într-un job care rezolvă şi descarcă pachete noi — exact pasul expus la un pachet compromis — aşa
că rămâne un pas făcut de om, dar unul singur.

Ce face, în ordine:
  1. refuză dacă interpretorul nu e versiunea de Python din Dockerfile (rezolvarea depinde de ea);
  2. aplică `nume==versiune` din argumente în requirements.txt (pinul trebuie să existe deja —
     o dependenţă NOUĂ se adaugă de mână, deliberat);
  3. rulează pip-compile --generate-hashes, exact comanda din antetul lock-ului;
  4. verifică sincronizarea cu check-reqs-lock.py;
  5. spune ce s-a schimbat — şi, separat, ce pachete NOI au intrat în imagine (tranzitive): alea
     sunt cod nou într-un produs de securitate şi merită citite înainte de commit.

Nu instalează nimic şi nu atinge venv-ul. La orice eşec, cele două fişiere rămân cum erau.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GW = ROOT / "gateway"
TXT = GW / "requirements.txt"
LOCK = GW / "requirements.lock"
DOCKERFILE = ROOT / "Dockerfile"

PIN_ARG = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)$")


def norm(name: str) -> str:
    """PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def die(msg: str, code: int = 2) -> "None":
    print(f"relock-reqs: {msg}", file=sys.stderr)
    sys.exit(code)


def image_python() -> "tuple[int, int] | None":
    """(major, minor) din ultimul `FROM python:X.Y…` al Dockerfile-ului (etapa finală)."""
    found = None
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*FROM\s+python:(\d+)\.(\d+)", line)
        if m:
            found = (int(m.group(1)), int(m.group(2)))
    return found


def lock_pins(text: str) -> "dict[str, str]":
    """{nume_normalizat: versiune} — pin-urile de la început de linie din lock."""
    pins = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s\\;]+)", line)
        if m:
            pins[norm(m.group(1))] = m.group(2)
    return pins


def apply_bumps(text: str, bumps: "dict[str, tuple[str, str]]") -> "tuple[str, list[str]]":
    """Înlocuieşte versiunea pinului fiecărui pachet cerut. Extras, markeri şi comentarii rămân.
    Întoarce (text nou, schimbări lizibile). Un pachet fără pin în fişier e eroare, nu adăugare."""
    lines = text.splitlines(keepends=True)
    done = []
    for key, (shown, version) in bumps.items():
        hits = []
        for i, line in enumerate(lines):
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)((?:\[[^\]]*\])?)==([^\s;#]+)(.*)$", line, re.S)
            if m and norm(m.group(1)) == key:
                hits.append((i, m))
        if not hits:
            die(f"{shown} has no `==` pin in gateway/requirements.txt — a NEW dependency is added by hand, on purpose")
        if len(hits) > 1:
            die(f"{shown} is pinned {len(hits)} times in gateway/requirements.txt — fix that first")
        i, m = hits[0]
        if m.group(3) != version:
            done.append(f"{m.group(1)} {m.group(3)} → {version}")
            lines[i] = f"{m.group(1)}{m.group(2)}=={version}{m.group(4)}"
    return "".join(lines), done


def main(argv: "list[str]") -> int:
    if any(a in ("-h", "--help") for a in argv):
        print(__doc__)
        return 0
    bumps = {}
    for a in argv:
        m = PIN_ARG.match(a)
        if not m:
            die(f"'{a}' is not name==version")
        bumps[norm(m.group(1))] = (m.group(1), m.group(2))

    want = image_python()
    have = sys.version_info[:2]
    if want and have != want:
        die(f"this is Python {have[0]}.{have[1]}, the image runs {want[0]}.{want[1]} — the lock must be resolved "
            f"with the image's Python (run with a {want[0]}.{want[1]} interpreter, e.g. .venv/bin/python)")
    if subprocess.run([sys.executable, "-m", "piptools", "compile", "--version"], capture_output=True).returncode != 0:
        die(f"pip-tools is not installed for {sys.executable} — `{sys.executable} -m pip install pip-tools`")

    txt_before = TXT.read_text(encoding="utf-8")
    lock_before = LOCK.read_text(encoding="utf-8")
    txt_after, changed = apply_bumps(txt_before, bumps)

    try:
        TXT.write_text(txt_after, encoding="utf-8")
        # exact comanda din antetul lock-ului, rulată din gateway/ ca antetul să rămână identic
        r = subprocess.run(
            [sys.executable, "-m", "piptools", "compile", "--quiet", "--generate-hashes",
             "--output-file=requirements.lock", "requirements.txt"],
            cwd=GW, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("pip-compile failed:\n" + (r.stderr or r.stdout).strip())
        chk = subprocess.run([sys.executable, str(ROOT / "scripts" / "check-reqs-lock.py")],
                             capture_output=True, text=True)
        if chk.returncode != 0:
            raise RuntimeError("requirements.txt and the new lock disagree:\n" + (chk.stderr or chk.stdout).strip())
    except (RuntimeError, OSError) as e:
        TXT.write_text(txt_before, encoding="utf-8")
        LOCK.write_text(lock_before, encoding="utf-8")
        die(f"{e}\nNothing was changed.", 1)

    old, new = lock_pins(lock_before), lock_pins(LOCK.read_text(encoding="utf-8"))
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    moved = sorted(k for k in set(old) & set(new) if old[k] != new[k])

    for c in changed:
        print(f"requirements.txt: {c}")
    if not (added or removed or moved):
        print("requirements.lock: already in sync, nothing to change")
        return 0
    print("requirements.lock:")
    for k in moved:
        print(f"  {k} {old[k]} → {new[k]}")
    for k in removed:
        print(f"  - {k} {old[k]} (no longer needed)")
    if added:
        print("\nNEW packages in the image — read what they are before committing:")
        for k in added:
            print(f"  + {k} {new[k]}")
    print("\nNext: install the lock into your venv and run the gate —")
    print(f"  {sys.executable} -m pip install --require-hashes -r gateway/requirements.lock")
    print(f"  PY={sys.executable} scripts/ci-local.sh all")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
