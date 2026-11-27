#!/usr/bin/env bash
# Publică site-ul pe VM-ul site-urilor. Cloudflare şi browserele ţin /assets/ 7 zile, iar tokenul
# nostru n-are drept de purge: fiecare referinţă la un fişier din assets/ primeşte deci ?v=<hash
# conţinut> într-o copie temporară. Un fişier schimbat (CSS, o captură, video-ul) are alt URL, unul
# neschimbat rămâne în cache. Apoi tar peste ssh şi `docker compose up -d --build --wait`.
#   site/deploy/deploy.sh [ssh-host]      # implicit: evershell-web (vezi ~/.ssh/config)
set -euo pipefail
HOST="${1:-evershell-web}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp -a "$SRC/." "$TMP/"
python3 - "$TMP" <<'PY'
import hashlib, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
ver = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()[:10]
       for p in (root / "assets").rglob("*") if p.is_file()}
pat = re.compile(r'((?:\.\./|/)?)(assets/[^"?\s]+)(?=")')
for html in root.rglob("*.html"):
    s = html.read_text()
    out = pat.sub(lambda m: m.group(0) + ("?v=" + ver[m.group(2)] if m.group(2) in ver else ""), s)
    missing = sorted({m.group(2) for m in pat.finditer(s)} - ver.keys())
    if missing: sys.exit(f"{html.relative_to(root)}: referinţe lipsă: {missing}")
    html.write_text(out)
print(f"versioned {len(ver)} assets")
PY
tar -C "$TMP" -czf - . | ssh "$HOST" 'tar -C /home/website/sites/evershell -xzf - && cd /home/website/sites/evershell/deploy && docker compose up -d --build --wait 2>&1 | tail -1'
echo deployed
