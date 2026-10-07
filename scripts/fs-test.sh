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
# Cererile care poartă cookie-ul din jar trebuie să trimită şi Origin: `csrf_guard`
# cere asta credenţialelor ambientale, exact ca un browser.
j()   { curl -s -b "$J" -H "Origin: $B" "$@"; }

# --- login (container deja setat de e2e) sau setup complet (container proaspăt) ---
login_code=$(curl -s -c "$J" -o /dev/null -w '%{http_code}' -X POST "$B/api/login" \
  -H 'Content-Type: application/json' -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
if [ "$login_code" != "200" ]; then
  curl -s -c "$J" -X POST "$B/api/setup" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"setup_token\":\"$SETUP_TOKEN\"}" >/dev/null
  HOST_JSON=$(curl -s -b "$J" -H "Origin: $B" -X POST "$B/api/hosts" -H 'Content-Type: application/json' \
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

# --- upload resumabil pe chunk-uri (resume din offset + guard anti-corupere) ---
UPID=deadbeefcafe0001
printf 'PART-ONE-' > /tmp/wtc1; printf 'part-two-END' > /tmp/wtc2
L1=$(wc -c < /tmp/wtc1 | tr -d ' ')
UP="$FS/upload?path=$(enc '~/wtfstest/big.bin')&upload_id=$UPID"
R=$(j -X POST "$UP&offset=0" --data-binary @/tmp/wtc1)
echo "$R" | grep -q "\"offset\":$L1" && ok "resumable: first chunk landed" || no "resumable chunk1" "$R"
# /status = punctul de resume (sursa de adevăr: statul pe host)
R=$(j "$FS/upload/status?path=$(enc '~/wtfstest/big.bin')&upload_id=$UPID")
echo "$R" | grep -q "\"offset\":$L1" && ok "resumable: status returns the resume offset" || no "resumable status" "$R"
# offset greşit → 409, temp-ul NU e corupt (guard)
R=$(j -o /dev/null -w '%{http_code}' -X POST "$UP&offset=999" --data-binary @/tmp/wtc2)
[ "$R" = "409" ] && ok "resumable: wrong offset refused (409)" || no "resumable offset guard" "cod $R"
# al doilea chunk la offset-ul corect = reluare
R=$(j -X POST "$UP&offset=$L1" --data-binary @/tmp/wtc2)
echo "$R" | grep -q '"offset":' && ok "resumable: second chunk appended" || no "resumable chunk2" "$R"
# commit cu CRC-32 corect → integritate OK, rename atomic
CRC=$(python3 -c "import zlib;print(zlib.crc32(b'PART-ONE-part-two-END'))")
R=$(j -X POST "$FS/upload/commit?path=$(enc '~/wtfstest/big.bin')&upload_id=$UPID&crc32=$CRC")
echo "$R" | grep -q '"ok":true' && ok "resumable: commit with matching CRC succeeds" || no "resumable commit crc" "$R"
R=$(j "$FS/download?path=$(enc '~/wtfstest/big.bin')")
[ "$R" = "PART-ONE-part-two-END" ] && ok "resumable: content = chunk1+chunk2, in order" || no "resumable content" "got: $R"

# CRC greşit → integritate eşuează, fişierul corupt NU ajunge la ţintă (temp şters)
UPID2=cafe00011234abcd
UP2="$FS/upload?path=$(enc '~/wtfstest/bad.bin')&upload_id=$UPID2"
j -X POST "$UP2&offset=0" --data-binary @/tmp/wtc1 >/dev/null
R=$(j -o /dev/null -w '%{http_code}' -X POST "$FS/upload/commit?path=$(enc '~/wtfstest/bad.bin')&upload_id=$UPID2&crc32=1")
[ "$R" = "400" ] && ok "resumable: wrong CRC rejected at commit" || no "resumable crc reject" "cod $R"
R=$(j -o /dev/null -w '%{http_code}' "$FS/download?path=$(enc '~/wtfstest/bad.bin')")
[ "$R" != "200" ] && ok "resumable: corrupt file never reached the target" || no "resumable crc leak" "file exists"
R=$(j "$FS?path=~/wtfstest")
echo "$R" | grep -q 'wtpart' && no "temp cleaned up" "a .wtpart was left behind" || ok "the .wtpart temp file is cleaned up after commit"

# --- upload_id e validat STRICT la graniţă (anti path-trick + anti log-injection) ---
# upload_id intră în `<path>.wtpart.<upload_id>` şi (brut) în logul gateway-ului. Tiparul e
# `[0-9a-f]{16,64}`; orice altceva → 400 files.badUpload, fără scriere, fără temp orfan.
for BAD in '../../../tmp/pwned' '..%2f..%2fx' 'ABCDEF0123456789' 'deadbeef' 'z123456789abcdef' 'deadbeefcafe0001%0ainjected'; do
  R=$(j -o /dev/null -w '%{http_code}' -X POST "$FS/upload?path=$(enc '~/wtfstest/trav.bin')&upload_id=$BAD&offset=0" --data-binary @/tmp/wtc1)
  [ "$R" = "400" ] && ok "bad upload_id rejected (400): $BAD" || no "bad upload_id $BAD" "cod $R"
done
# traversal n-a aterizat NICĂIERI (nici în /tmp, nici în parintele lui wtfstest)
docker exec "$CT" sh -c 'ls /tmp/pwned.wtpart.* /root/tmp/pwned.wtpart.* 2>/dev/null' | grep -q . \
  && no "upload_id traversal contained" "a temp escaped the target dir" \
  || ok "rejected upload_id wrote no file outside the target"

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

# --- arhivă: director → tar.gz făcut pe host (op `run`, agent NEatins), streamat, temp şters ---
docker exec "$CT" sh -c 'mkdir -p "/root/wtfstest/arc dir/sub" && printf unu > "/root/wtfstest/arc dir/a.txt" && printf doi > "/root/wtfstest/arc dir/sub/b.txt"'
j -o /tmp/arc.tgz "$FS/archive?path=$(enc '~/wtfstest/arc dir')"
if tar -tzf /tmp/arc.tgz 2>/dev/null | grep -q 'arc dir/sub/b.txt'; then
  ok "archive: folder (cu spaţiu în nume) descărcat ca tgz, cu conţinut"
else no "archive contents" "$(tar -tzf /tmp/arc.tgz 2>&1 | head -2)"; fi
R=$(docker exec "$CT" sh -c 'ls /root/wtfstest/.wtarch.* 2>/dev/null | wc -l')
[ "$R" = "0" ] && ok "archive: temp-ul de pe host şters după streaming" || no "archive temp" "$R rămase"
R=$(j -o /dev/null -w '%{http_code}' "$FS/archive?path=$(enc '/')")
[ "$R" = "400" ] && ok "archive pe / refuzat" || no "archive root guard" "cod $R"

# --- copiere host → host pe server (3.5.5): AL DOILEA agent în acelaşi container ---
# Agentul are lock de instanţă unică per HOME (~/.webterm/ptyd.lock) şi socket tmux per UID, deci
# un al doilea agent rulează curat ca ALT user (alt HOME, alt lock, alt /tmp/tmux-UID). Fiecare e
# un host separat în WebTerm → copierea A → B trece prin gateway exact ca între două maşini.
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$1" 2>/dev/null; }
docker exec "$CT" sh -c 'id wtcopy >/dev/null 2>&1 || useradd -m -s /bin/sh wtcopy' >/dev/null 2>&1
H2_JSON=$(j -X POST "$B/api/hosts" -H 'Content-Type: application/json' \
  -d '{"name":"fs-copy-b","note":"","connection_type":"agent","require_2fa":false}')
H2=$(echo "$H2_JSON" | jget 'd["id"]')
ENR2=$(echo "$H2_JSON" | grep -oE 'install/[A-Za-z0-9_-]+\.sh' | head -1 | sed 's|install/||;s|\.sh||')
TOK2=$(curl -s "$B/install/$ENR2.sh" | grep -oE '^TOKEN="[^"]+"' | sed 's/TOKEN="//;s/"//')
CFG2="{\"url\":\"ws://127.0.0.1:8000/agent/ws\",\"token\":\"$TOK2\",\"insecure\":true}"
docker exec -u wtcopy -e HOME=/home/wtcopy "$CT" sh -c "mkdir -p /home/wtcopy/.webterm /home/wtcopy/in && printf '%s' '$CFG2' > /home/wtcopy/.webterm/agent.json"
docker exec -d -u wtcopy -e HOME=/home/wtcopy "$CT" sh -c 'exec python3 /srv/webterm/agent/ptyd.py run >>/tmp/wt-agent2.log 2>&1'
ON2=""
for i in $(seq 1 30); do
  ON2=$(j "$B/api/hosts" | python3 -c "import sys,json;print(next((1 for h in json.load(sys.stdin) if h['id']==$H2 and h.get('online')),''))" 2>/dev/null)
  [ -n "$ON2" ] && break; sleep 1
done
[ -n "$ON2" ] && ok "copy: a second agent (user wtcopy, own HOME) is online as host $H2" \
  || no "copy: second agent" "not online: $(docker exec "$CT" tail -n 3 /tmp/wt-agent2.log 2>/dev/null)"

# fişiere de test pe A: unul mic + unul de 3 MiB aleator (mai multe blocuri de 1 MiB, nealiniat)
docker exec "$CT" sh -c 'printf "copy-me-v1" > /root/wtfstest/cp-a.txt && head -c 3146001 /dev/urandom > /root/wtfstest/cp-big.bin'
copy_wait() {   # $1 = corpul JSON → tipăreşte starea finală (JSON) a job-ului
  local jid st r
  jid=$(j -X POST "$B/api/fs/copy" -H 'Content-Type: application/json' -d "$1" | jget 'd["job_id"]')
  [ -z "$jid" ] && { echo '{}'; return; }
  for _ in $(seq 1 120); do
    r=$(j "$B/api/fs/copy/$jid?files=1")
    st=$(echo "$r" | jget 'd["state"]')
    [ "$st" != "running" ] && { echo "$r"; return; }
    sleep 0.5
  done
  echo "$r"
}
R=$(copy_wait "{\"src_host\":$HOST_ID,\"paths\":[\"~/wtfstest/cp-a.txt\",\"~/wtfstest/cp-big.bin\"],\"dst_host\":$H2,\"dst_dir\":\"~/in\",\"on_conflict\":\"skip\"}")
[ "$(echo "$R" | jget 'd["state"]')" = "done" ] && [ "$(echo "$R" | jget 'd["files_done"]')" = "2" ] \
  && ok "copy A → B: job done, 2/2 files" || no "copy A → B" "$R"
S1=$(docker exec "$CT" sha256sum /root/wtfstest/cp-big.bin | cut -d' ' -f1)
S2=$(docker exec "$CT" sha256sum /home/wtcopy/in/cp-big.bin 2>/dev/null | cut -d' ' -f1)
[ -n "$S1" ] && [ "$S1" = "$S2" ] && ok "copy A → B: 3 MiB file arrives byte-identical (sha256)" || no "copy content" "$S1 vs $S2"
R=$(docker exec "$CT" cat /home/wtcopy/in/cp-a.txt 2>/dev/null)
[ "$R" = "copy-me-v1" ] && ok "copy A → B: small file content identical" || no "copy small" "got: $R"
R=$(docker exec "$CT" stat -c %U /home/wtcopy/in/cp-big.bin 2>/dev/null)
[ "$R" = "wtcopy" ] && ok "copy A → B: owned by the destination agent's user" || no "copy owner" "$R"
R=$(docker exec "$CT" sh -c 'ls -a /home/wtcopy/in | grep -c wtpart')
[ "$R" = "0" ] && ok "copy A → B: no .wtpart temp left on the destination" || no "copy temp" "$R left"
R=$(copy_wait "{\"src_host\":$HOST_ID,\"paths\":[\"~/wtfstest/cp-a.txt\"],\"dst_host\":$H2,\"dst_dir\":\"~/in\",\"on_conflict\":\"rename\"}")
docker exec "$CT" test -f "/home/wtcopy/in/cp-a (1).txt" && ok "copy on_conflict=rename → 'cp-a (1).txt'" || no "copy rename" "$R"
R=$(copy_wait "{\"src_host\":$HOST_ID,\"paths\":[\"/dev/zero\",\"~/wtfstest/arc dir\"],\"dst_host\":$H2,\"dst_dir\":\"~/in\",\"on_conflict\":\"skip\"}")
echo "$R" | grep -q '"code":"files.notRegular"' && ok "copy: special file (/dev/zero) refused per file" || no "copy special" "$R"
echo "$R" | grep -q '"code":"copy.folder"' && ok "copy: folder refused per file (next agent update)" || no "copy folder" "$R"
j -X POST "$FS/mkdir" -H 'Content-Type: application/json' -d '{"path":"~/wtfstest/cpdst"}' >/dev/null
R=$(copy_wait "{\"src_host\":$HOST_ID,\"paths\":[\"~/wtfstest/cp-a.txt\"],\"dst_host\":$HOST_ID,\"dst_dir\":\"~/wtfstest/cpdst\",\"on_conflict\":\"skip\"}")
R2=$(docker exec "$CT" cat /root/wtfstest/cpdst/cp-a.txt 2>/dev/null)
[ "$R2" = "copy-me-v1" ] && ok "copy on the same host (src == dst, other folder)" || no "copy same host" "$R"
R=$(j -o /dev/null -w '%{http_code}' -X POST "$B/api/fs/copy" -H 'Content-Type: application/json' \
  -d "{\"src_host\":$HOST_ID,\"paths\":[\"/root/../etc/shadow\"],\"dst_host\":$H2,\"dst_dir\":\"~/in\"}")
[ "$R" = "400" ] && ok "copy: '..' in a source path refused (400)" || no "copy traversal" "cod $R"
# curăţenie: al doilea agent oprit, hostul lui şters (paşii următori — mobile/a11y — văd doar hostul e2e)
docker exec -u wtcopy -e HOME=/home/wtcopy "$CT" python3 /srv/webterm/agent/ptyd.py stop >/dev/null 2>&1 || true
j -X DELETE "$B/api/hosts/$H2" >/dev/null
docker exec "$CT" rm -rf /home/wtcopy/in >/dev/null 2>&1

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
