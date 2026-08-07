#!/usr/bin/env python3
"""Gardă de CI: requirements.txt și requirements.lock trebuie să fie sincrone.

Imaginea instalează din `requirements.lock` (--require-hashes), dar CI testează pe
`requirements.txt`. Dacă Dependabot (sau cineva) bumpează `.txt` fără să regenereze
`.lock`, testele trec pe versiuni pe care imaginea NU le livrează — drift silențios,
tocmai la pachetele critice (cryptography/asyncssh/webauthn). Scriptul pică dacă vreun
pin `name==versiune` din `.txt` lipsește ori diferă ca versiune în `.lock`.

Regenerare lock: pip-compile --generate-hashes --output-file=requirements.lock requirements.txt
"""
import re
import sys
from pathlib import Path

REQ_DIR = Path(__file__).resolve().parent.parent / "gateway"
TXT = REQ_DIR / "requirements.txt"
LOCK = REQ_DIR / "requirements.lock"


def norm(name: str) -> str:
    """Normalizare PEP 503 a numelui de pachet (extras eliminate în apelant)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_txt(text: str) -> dict:
    """{nume_normalizat: versiune} din requirements.txt (ignoră extras/markers/comentarii)."""
    pins = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?==([^\s;]+)", line)
        if m:
            pins[norm(m.group(1))] = m.group(2)
    return pins


def parse_lock(text: str) -> dict:
    """{nume_normalizat: versiune} din requirements.lock (pin-urile de la începutul liniei)."""
    pins = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?==([^\s\\]+)", line)
        if m:
            pins[norm(m.group(1))] = m.group(2)
    return pins


def main() -> int:
    txt = parse_txt(TXT.read_text(encoding="utf-8"))
    lock = parse_lock(LOCK.read_text(encoding="utf-8"))
    problems = []
    for name, ver in sorted(txt.items()):
        if name not in lock:
            problems.append(f"  {name}=={ver}  →  MISSING from requirements.lock")
        elif lock[name] != ver:
            problems.append(f"  {name}: .txt={ver}  vs  .lock={lock[name]}  (different versions)")
    if problems:
        print("DRIFT requirements.txt ↔ requirements.lock:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print("\nRegenerate the lock:\n  pip-compile --generate-hashes "
              "--output-file=gateway/requirements.lock gateway/requirements.txt", file=sys.stderr)
        return 1
    print(f"OK: {len(txt)} pins from requirements.txt found identical in requirements.lock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
