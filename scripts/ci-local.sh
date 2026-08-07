#!/usr/bin/env bash
# Rulează LOCAL exact pașii jobului `build` din .github/workflows/docker-publish.yml.
# Motivul: o rulare pe GitHub durează ~30 min; asta ne spune același lucru în câteva minute.
#
# Diferențe față de CI, toate impuse de mediu (nu de scop):
#   - niciuna la porturi: TREBUIE 8000/8001 ca în CI. `127.0.0.1` e context securizat,
#     un hostname pe HTTP simplu nu — iar fără contextul securizat `navigator.clipboard`
#     e undefined şi testele de copiere crapă. Tot 127.0.0.1:8000 e şi ce vede curl-ul
#     de integrare shell din INTERIORUL containerului, deci maparea trebuie 1:1.
#   - scripturile .mjs rulează în containerul Playwright, pe aceeași rețea docker, cu
#     node_modules montat, fiindcă hostul n-are node/npm. Montarea e la /node_modules
#     și scriptul rulează din /: un simlink /work/node_modules -> /nm nu merge, fiindcă
#     Node rezolvă dependențele relativ la calea REALĂ (căuta /nm/node_modules/playwright-core).
# Restul — imagine, variabile, ordine, praguri — sunt identice cu CI.
set -uo pipefail

REPO=${REPO:-$(cd "$(dirname "$0")/.." && pwd)}
NM=${PW_MODULES:-$REPO/frontend/node_modules}
PW=mcr.microsoft.com/playwright:v1.61.1-noble
IMG=${IMG:-webterm-verify:local}
P1=8000; P2=8001
C1=wtci-smoke; C2=wtci-fwd
NET=wtci-net
# URL-ul public trebuie să fie valid ŞI din browser, ŞI din interiorul containerului:
# butonul „Enable shell integration" rulează un curl către el ÎN container. Cu o mapare
# 8010→8000 pe host, acel curl bate în gol şi pică exact testele OSC 133.
BASE1="http://127.0.0.1:$P1"
OUT=${OUT:-/tmp/wt-ci-shots}
ONLY="${*:-all}"   # unul sau mai mulţi paşi: `ci-local.sh e2e a11y`
# paşi: unit sig lint build smoke e2e a11y fs fwd mobile — sau `all`

pass=0; fail=0; skipped=""
say()  { printf '\n\033[1;36m── %s ──\033[0m\n' "$*"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$*"; pass=$((pass+1)); }
no()   { printf '\033[31m  ✗ %s\033[0m\n' "$*"; fail=$((fail+1)); }

cleanup() { docker rm -f $C1 $C2 >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT

want() { case " $ONLY " in *" all "*|*" $1 "*) return 0 ;; *) return 1 ;; esac; }

# Preflight: cele două cauze care produc mesaje greşit interpretate. Portul ocupat se
# manifesta ca „nu a devenit healthy" după 90s; `cryptography` lipsă ca „✗ agent signature",
# care se citeşte drept „semnătura e stricată", nu „îţi lipseşte un pachet".
if want sig || want smoke || want e2e || want a11y || want fs || want fwd || want mobile; then
  python3 -c 'import cryptography' 2>/dev/null || {
    echo "python3 nu are pachetul 'cryptography' — pip install cryptography" >&2; exit 2; }
fi
for prt in $P1 $P2; do
  case " $ONLY " in *" all "*|*" smoke "*|*" e2e "*|*" a11y "*|*" fs "*|*" fwd "*|*" mobile "*)
    if ss -ltn 2>/dev/null | grep -q ":$prt "; then
      echo "portul $prt e ocupat — runner-ul are nevoie de $P1 şi $P2 (vezi nota de sus)" >&2
      exit 2
    fi ;;
  esac
done

# ── pasul 1: semnătura agentului (identic cu poarta blocantă din CI) ─────────
if want sig; then
say "agent signature"
python3 - "$REPO" <<'EOF' && ok "agent signature" || no "agent signature"
import base64, os, re, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
os.chdir(sys.argv[1])
src = open("agent/ptyd.py", "rb").read()
m = re.search(rb'UPDATE_PUBKEY = bytes\.fromhex\(\s*["\']([0-9a-f]+)["\']', src)
if not m: raise SystemExit("UPDATE_PUBKEY not found")
embedded = m.group(1).decode()
signer = open("agent/ptyd.py.signer").read().strip() if os.path.exists("agent/ptyd.py.signer") else embedded
sig = base64.b64decode(open("agent/ptyd.py.sig").read().strip())
Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(sig, src)
if signer != embedded: print("KEY ROLLOVER")
EOF
fi

# ── lint frontend (eslint) ──────────────────────────────────────────────────
if want lint; then
say "eslint (frontend)"
docker run --rm -v "$REPO/frontend:/w" -w /w node:20-alpine \
  sh -c 'npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 && npx eslint .' \
  && ok "eslint" || no "eslint"
fi

# ── porţile din jobul `unit-tests` ──────────────────────────────────────────
# Lipseau cu totul, deşi scriptul se prezenta drept „lanţul complet de CI": un contribuitor
# putea fi verde local şi să cadă în CI la şase porţi diferite.
if want unit; then
say "unit-tests gates"
V=$(grep -m1 '^GATEWAY_VERSION' "$REPO/gateway/app/config.py" | cut -d'"' -f2)
grep -q "version-v$V-blue" "$REPO/README.md" && ok "badge ↔ GATEWAY_VERSION ($V)" || no "badge (aşteptat v$V)"
python3 "$REPO/scripts/check-reqs-lock.py" >/dev/null && ok "requirements.txt ↔ .lock" || no "requirements drift"
(cd "$REPO" && ruff check --select F gateway/app agent/ptyd.py >/dev/null 2>&1) \
  && ok "ruff --select F" || no "ruff --select F"
docker run --rm -v "$REPO:/repo" \
  zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f \
  detect --source /repo --config /repo/.gitleaks.toml --no-banner >/dev/null 2>&1 \
  && ok "gitleaks (istoric)" || no "gitleaks"
(cd "$REPO" && bash scripts/run-tests.sh ci >/dev/null 2>&1) \
  && ok "suita Python" || no "suita Python"
fi

# ── pasul 2: build imagine ──────────────────────────────────────────────────
if want build; then
say "docker build"
docker build -q -t "$IMG" "$REPO" >/dev/null 2>&1 && ok "docker build" || { no "docker build"; exit 1; }
fi

# ── containerul de smoke ────────────────────────────────────────────────────
boot() {
  local name=$1 port=$2 url=$3
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker network create "$NET" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network "$NET" -p "$port:8000" \
    -e WEBTERM_SETUP_TOKEN=ci-e2e-token -e WEBTERM_PUBLIC_URL="$url" \
    -e WEBTERM_AGENT_INSECURE=1 "$IMG" >/dev/null
  local st=starting
  for _ in $(seq 1 45); do
    st=$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null)
    [ "$st" = healthy ] && return 0
    sleep 2
  done
  echo "  $name nu a devenit healthy (status: $st)"; docker logs "$name" | tail -20; return 1
}

# node în containerul Playwright, cu node_modules montat și rețea host.
# Verificarea era la începutul scriptului, deci `ci-local.sh lint` sau `sig` — paşi care
# n-au nevoie de browser — se opreau cerând un `npm ci` de 146 MB. O mutăm aici, unde
# lipsa chiar contează.
pwrun() {
  [ -d "$NM/playwright" ] || {
    echo "  playwright lipseşte în $NM — rulează 'npm ci' în frontend/, sau PW_MODULES=<cale>" >&2
    return 2
  }
  local script=$1; shift
  docker run --rm --network host \
    -v "$REPO:/repo:ro" -v "$NM:/node_modules:ro" -v "$OUT:/out" \
    -w / "$@" "$PW" \
    sh -c "cp /repo/$script /$(basename "$script") && node /$(basename "$script") \${SCRIPT_ARGS}"
}

if want smoke || want e2e || want a11y || want fs || want mobile; then
  say "pornesc containerul de smoke pe :$P1"
  boot $C1 $P1 "$BASE1" && ok "smoke container healthy" || { no "smoke container"; exit 1; }
fi

# ── smoke-boot ──────────────────────────────────────────────────────────────
if want smoke; then
say "smoke-boot"
pwrun scripts/smoke-boot.mjs -e SCRIPT_ARGS="$BASE1" \
  && ok "smoke-boot" || no "smoke-boot"
fi

# ── E2E (cere tmux în container, ca în CI) ──────────────────────────────────
if want e2e; then
say "E2E sessions"
docker exec -u root $C1 sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends tmux' >/dev/null 2>&1
docker exec $C1 sh -c 'command -v tmux' >/dev/null || { no "tmux în container"; }
# Scriptul E2E porneşte agentul cu `docker exec`, dar containerul Playwright n-are CLI-ul
# docker. Calea prevăzută pentru asta e AGENT_TOKEN_FILE: scriptul scrie tokenul pe disc
# şi aşteaptă un host online, iar noi pornim agentul din afară.
rm -f "$OUT/agent-token"; mkdir -p "$OUT"
( for _ in $(seq 1 120); do
    if [ -s "$OUT/agent-token" ]; then
      TOK=$(cat "$OUT/agent-token")
      CFG="{\"url\":\"ws://127.0.0.1:8000/agent/ws\",\"token\":\"$TOK\",\"insecure\":true}"
      docker exec $C1 sh -c "mkdir -p /root/.webterm && printf '%s' '$CFG' > /root/.webterm/agent.json"
      docker exec -d -e HOME=/root $C1 python3 /srv/webterm/agent/ptyd.py run
      break
    fi
    sleep 1
  done ) &
WATCHER=$!
pwrun scripts/e2e-session.mjs -e SCRIPT_ARGS="$BASE1 $C1" -e E2E_SETUP_TOKEN=ci-e2e-token \
  -e AGENT_TOKEN_FILE=/out/agent-token \
  && ok "E2E sessions" || no "E2E sessions"
kill $WATCHER 2>/dev/null
fi

# ── accesibilitate ──────────────────────────────────────────────────────────
# În CI pasul ăsta rulează DUPĂ E2E, pe acelaşi container: E2E a creat contul ŞI un host,
# iar `ui_review.mjs` are nevoie de amândouă (aşteaptă butonul „New session", care apare
# doar dacă există un host). Deci a11y NU e de sine stătător: rulează-l ca `e2e a11y`.
# Contul îl creăm şi aici, ca pasul să meargă şi dacă E2E a fost sărit.
if want a11y; then
say "accessibility (axe-core)"
curl -fsS -X POST "$BASE1/api/setup" -H 'Content-Type: application/json' \
  -d '{"email":"e2e@example.com","password":"parola-e2e-123456","setup_token":"ci-e2e-token"}' \
  >/dev/null 2>&1 && echo "  (cont creat pentru a11y)" || echo "  (contul exista deja)"
pwrun tests/ui_review.mjs -e SCRIPT_ARGS="" -e BASE="$BASE1" -e A11Y_MAX_SERIOUS=0 \
  -e A11Y_EMAIL=e2e@example.com -e A11Y_PASSWORD=parola-e2e-123456 \
  && ok "accessibility" || no "accessibility"
fi

# ── FS API ──────────────────────────────────────────────────────────────────
if want fs; then
say "FS API"
E2E_SETUP_TOKEN=ci-e2e-token bash "$REPO/scripts/fs-test.sh" "http://127.0.0.1:$P1" $C1 \
  && ok "FS API" || no "FS API"
fi

# ── port forwarding (container separat, ca în CI) ───────────────────────────
if want fwd; then
say "port forwarding"
boot $C2 $P2 "http://wt.test" && ok "fwd container healthy" || no "fwd container"
bash "$REPO/scripts/fwd-test.sh" "http://127.0.0.1:$P2" $C2 wt.test \
  && ok "port forwarding" || no "port forwarding"
fi

# ── audit mobil ─────────────────────────────────────────────────────────────
if want mobile; then
say "mobile audit"
mkdir -p "$OUT"
pwrun scripts/mobile-audit.mjs -e SCRIPT_ARGS="$BASE1 /out" \
  && ok "mobile audit" || no "mobile audit"
fi

printf '\n\033[1m%d trecute, %d eșuate\033[0m\n' "$pass" "$fail"
exit $((fail > 0 ? 1 : 0))
