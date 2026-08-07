#!/usr/bin/env bash
# Test cap-coadă pentru operațiile de fișiere (agent REAL), la nivel de API —
# acoperă ce e2e-ul UI nu atinge: rename, conflict de mtime, preview view-only,
# salvare atomică, guard fișiere speciale, delete recursiv, păstrarea permisiunilor.
#
# Rulează în CI DUPĂ e2e, pe același container (refolosește contul + host-ul cu
# agent online), sau izolat pe un container proaspăt (face setup singur).
#
#   scripts/fs-test.sh [base_url] [container]
set -u
B="${1:-http://127.0.0.1:8000}"
CT="${2:-smoke}"
EMAIL="e2e@example.com"; PASSWORD="parola-e2e-123456"; SETUP_TOKEN="${E2E_SETUP_TOKEN:-ci-e2e-token}"
J="$(mktemp)"
pass=0; fail=0
ok()  { echo "  PASS $1"; pass=$((pass+1)); }
no()  { echo "  FAIL $1  --  $2"; fail=$((fail+1)); }
enc() { python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$1"; }
j()   { curl -s -b "$J" "$@"; }

# --- login (container deja setat de e2e) sau setup complet (container proaspăt) ---
login_code=$(curl -s -c "$J" -o /dev/null -w '%{http_code}' -X POST "$B/api/login" \
  -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
if [ "$login_code" != "200" ]; then
  curl -s -c "$J" -X POST "$B/api/setup" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"setup_token\":\"$SETUP_TOKEN\"}" >/dev/null
  HOST_JSON=$(curl -s -b "$J" -X POST "$B/api/hosts" -H 'Content-Type: application/json' \
    -d '{"name":"fs","note":"","connection_type":"agent","require_2fa":false}')
  ENROLL=$(echo "$HOST_JSON" | grep -oE 'install/[A-Za-z0-9_-]+\.sh' | head -1 | sed 's|install/||;s|\.sh||')
  TOKEN=$(curl -s "$B/install/$ENROLL.sh" | grep -oE '^TOKEN="[^"]+"' | sed 's/TOKEN="//;s/"//')
  CFG="{\"url\":\"ws://127.0.0.1:8000/agent/ws\",\"token\":\"$TOKEN\",\"insecure\":true}"
  docker exec "$CT" sh -c "mkdir -p /root/.webterm && printf '%s' '$CFG' > /root/.webterm/agent.json"
  docker exec -d -e HOME=/root "$CT" python3 /srv/webterm/agent/ptyd.py run
fi

# așteaptă un host cu agent online, ia id-ul
HOST_ID=""
for i in $(seq 1 30); do
  HOST_ID=$(curl -s -b "$J" "$B/api/hosts" | python3 -c \
    "import sys,json;hs=json.load(sys.stdin);print(next((h['id'] for h in hs if h.get('online')),''))" 2>/dev/null)
  [ -n "$HOST_ID" ] && break; sleep 1
done
[ -n "$HOST_ID" ] && ok "host with an online agent (host_id=$HOST_ID)" || { no "bootstrap" "no host online"; exit 1; }
FS="$B/api/hosts/$HOST_ID/fs"

# --- mkdir ---
R=$(j -X POST "$FS/mkdir" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest"}')
echo "$R" | grep -q '"ok":true' && ok "mkdir creates the directory" || no "mkdir" "$R"
R=$(j -o /dev/null -w '%{http_code}' -X POST "$FS/mkdir" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest"}')
[ "$R" = "400" ] && ok "mkdir pe director existent → 400" || no "mkdir dublu" "cod $R"

R=$(j "$FS?path=~")
echo "$R" | grep -q 'wtfstest' && ok "list shows the new directory" || no "list dir" "$R"

# mkdir parents (upload de folder), idempotent
R=$(j -X POST "$FS/mkdir" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest/a/b/c","parents":true}')
echo "$R" | grep -q '"ok":true' && ok "mkdir parents creates the chain" || no "mkdir parents" "$R"
R=$(j -X POST "$FS/mkdir" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest/a/b/c","parents":true}')
echo "$R" | grep -q '"ok":true' && ok "mkdir parents e idempotent" || no "mkdir parents idempotent" "$R"

# --- upload + download ---
printf 'continut-original-v1' > /tmp/wtfile.txt
R=$(j -X POST "$FS/upload?path=$(enc '~/wtfstest/f.txt')" --data-binary @/tmp/wtfile.txt)
echo "$R" | grep -q '"ok":true' && ok "upload a file" || no "upload" "$R"
R=$(j "$FS/download?path=$(enc '~/wtfstest/f.txt')")
[ "$R" = "continut-original-v1" ] && ok "download returns the exact content" || no "download" "got: $R"

# --- salvare atomică (upload peste) + fără temp orfan ---
printf 'continut-nou-v2-mai-lung' > /tmp/wtfile2.txt
j -X POST "$FS/upload?path=$(enc '~/wtfstest/f.txt')" --data-binary @/tmp/wtfile2.txt >/dev/null
R=$(j "$FS/download?path=$(enc '~/wtfstest/f.txt')")
[ "$R" = "continut-nou-v2-mai-lung" ] && ok "atomic save overwrites completely" || no "atomic save" "got: $R"
R=$(j "$FS?path=~/wtfstest")
echo "$R" | grep -q 'wtpart' && no "temp cleaned up" "a .wtpart was left behind" || ok "the .wtpart temp file is cleaned up after commit"

# --- permisiunile se PĂSTREAZĂ la salvare (regresie de securitate: cheie SSH) ---
docker exec "$CT" sh -c 'printf cheie > /root/wtfstest/key && chmod 600 /root/wtfstest/key'
printf 'cheie-editata' > /tmp/key2
j -X POST "$FS/upload?path=$(enc '~/wtfstest/key')" --data-binary @/tmp/key2 >/dev/null
MODE=$(docker exec "$CT" sh -c 'stat -c %a /root/wtfstest/key' 2>/dev/null | tr -d '[:space:]')
[ "$MODE" = "600" ] && ok "saving preserves permissions (600 stays 600)" || no "perms preserve" "mode=$MODE"

# --- rename (+ anti-clobber) ---
R=$(j -X POST "$FS/rename" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest/f.txt","to":"~/wtfstest/renamed.txt"}')
echo "$R" | grep -q '"ok":true' && ok "rename a file" || no "rename" "$R"
R=$(j "$FS?path=~/wtfstest")
echo "$R" | grep -q 'renamed.txt' && ok "list confirms the rename" || no "rename verify" "$R"
printf 'x' > /tmp/x.txt
j -X POST "$FS/upload?path=$(enc '~/wtfstest/other.txt')" --data-binary @/tmp/x.txt >/dev/null
R=$(j -o /dev/null -w '%{http_code}' -X POST "$FS/rename" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest/other.txt","to":"~/wtfstest/renamed.txt"}')
[ "$R" = "400" ] && ok "rename over an existing file → 400 (no clobber)" || no "rename clobber" "cod $R"

# --- preview mic (editabil) / mare (view-only) ---
printf 'preview-mic' > /tmp/pv.txt
j -X POST "$FS/upload?path=$(enc '~/wtfstest/pv.txt')" --data-binary @/tmp/pv.txt >/dev/null
R=$(j "$FS/preview?path=$(enc '~/wtfstest/pv.txt')")
echo "$R" | grep -q '"editable":true' && echo "$R" | grep -q 'preview-mic' && ok "small preview: editable + content" || no "small preview" "$R"
MT=$(echo "$R" | grep -oE '"mtime":[0-9]+' | grep -oE '[0-9]+')
docker exec "$CT" sh -c 'head -c 1500000 /dev/zero | tr "\0" "x" > /root/wtfstest/big.txt'
R=$(j "$FS/preview?path=$(enc '~/wtfstest/big.txt')")
echo "$R" | grep -q '"editable":false' && echo "$R" | grep -q '"truncated":true' && ok "preview mare: view-only + truncat" || no "preview mare" "$R"

# --- conflict de mtime → 409, apoi force overwrite ---
sleep 1.1
docker exec "$CT" sh -c 'printf "schimbat-din-afara" > /root/wtfstest/pv.txt'
printf 'salvare-cu-mtime-vechi' > /tmp/pv2.txt
R=$(j -o /dev/null -w '%{http_code}' -X POST "$FS/upload?path=$(enc '~/wtfstest/pv.txt')&if_mtime=$MT" --data-binary @/tmp/pv2.txt)
[ "$R" = "409" ] && ok "save with a stale mtime → 409 (conflict)" || no "conflict" "cod $R (mtime=$MT)"
R=$(j -X POST "$FS/upload?path=$(enc '~/wtfstest/pv.txt')" --data-binary @/tmp/pv2.txt)
echo "$R" | grep -q '"ok":true' && ok "overwrite anyway (no if_mtime) succeeds" || no "force overwrite" "$R"

# --- guard fișiere speciale ---
R=$(j -o /dev/null -w '%{http_code}' "$FS/download?path=$(enc '/dev/zero')")
[ "$R" = "400" ] && ok "download of /dev/zero refused (special-file guard)" || no "special guard" "cod $R"

# --- delete fișier / dir (recursiv) ---
R=$(j -X POST "$FS/delete" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest/renamed.txt"}')
echo "$R" | grep -q '"ok":true' && ok "delete a file" || no "delete file" "$R"
R=$(j "$FS?path=~/wtfstest"); echo "$R" | grep -q 'renamed.txt' && no "delete verify" "it still shows up" || ok "list confirms the file was deleted"
R=$(j -o /dev/null -w '%{http_code}' -X POST "$FS/delete" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest"}')
[ "$R" = "400" ] && ok "delete a non-empty dir without recursive → 400" || no "delete nonempty" "cod $R"
R=$(j -X POST "$FS/delete" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest","recursive":true}')
echo "$R" | grep -q '"ok":true' && ok "delete recursiv al directorului" || no "delete recursive" "$R"
R=$(j "$FS?path=~"); echo "$R" | grep -q 'wtfstest' && no "dir deleted verify" "it still shows up" || ok "list confirms the directory was deleted"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
