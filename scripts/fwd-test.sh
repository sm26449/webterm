#!/usr/bin/env bash
# Test cap-coadă port forwarding: handshake de auth (redirect→token→cookie→proxy),
# proxy HTTP prin tunel pe subdomeniu, + teste de securitate (token legat de slug,
# fără cookie → redirect, forward oprit → 404, anti-SSRF prin ținta stocată).
set -u
B="${1:-http://127.0.0.1:8000}"   # url gateway (host)
CT="${2:-smoke}"                  # nume container
D="${3:-wt.test}"                 # _FWD_DOMAIN (== hostname din WEBTERM_PUBLIC_URL)
pass=0; fail=0
ok(){ echo "  PASS $1"; pass=$((pass+1)); }
no(){ echo "  FAIL $1  --  $2"; fail=$((fail+1)); }
# curl cu Host override; $1=host $2..=restul
ch(){ local h="$1"; shift; curl -s -H "Host: $h" "$@"; }

# --- bootstrap cont + host + agent + serviciu țintă ---
SC=$(curl -s -D - -o /dev/null -X POST "$B/api/setup" -H 'Content-Type: application/json' \
  -d '{"email":"e2e@example.com","password":"parola-e2e-123456","setup_token":"ci-e2e-token"}' \
  | grep -i '^set-cookie:' | sed -E 's/set-cookie: ([^;]+).*/\1/i' | tr -d '\r')
[ -n "$SC" ] && ok "setup + session cookie ($(echo $SC|cut -d= -f1))" || { no "setup" "no cookie"; exit 1; }
# Cererile care poartă cookie trebuie să trimită şi Origin: `csrf_guard` cere asta
# credenţialelor ambientale, exact ca un browser.
sess(){ curl -s -H "Cookie: $SC" -H "Origin: $B" "$@"; }

HJSON=$(sess -X POST "$B/api/hosts" -H 'Content-Type: application/json' -d '{"name":"fwd","connection_type":"agent","note":"","require_2fa":false}')
ENROLL=$(echo "$HJSON" | grep -oE 'install/[A-Za-z0-9_-]+\.sh' | head -1 | sed 's|install/||;s|\.sh||')
TOKEN=$(curl -s "$B/install/$ENROLL.sh" | grep -oE '^TOKEN="[^"]+"' | sed 's/TOKEN="//;s/"//')
docker exec "$CT" sh -c "mkdir -p /root/.webterm && printf '%s' '{\"url\":\"ws://127.0.0.1:8000/agent/ws\",\"token\":\"$TOKEN\",\"insecure\":true}' > /root/.webterm/agent.json"
docker exec -d -e HOME=/root "$CT" python3 /srv/webterm/agent/ptyd.py run
HID=""
for i in $(seq 1 30); do HID=$(sess "$B/api/hosts" | python3 -c "import sys,json;hs=json.load(sys.stdin);print(next((h['id'] for h in hs if h.get('online')),''))" 2>/dev/null); [ -n "$HID" ] && break; sleep 1; done
[ -n "$HID" ] && ok "agent online (host_id=$HID)" || { no "agent" "offline"; exit 1; }

docker exec -d "$CT" python3 -c "
import http.server,socketserver,threading,time
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        if 'slow' in s.path: time.sleep(3)   # simulează long-poll (răspuns întârziat)
        s.send_response(200); s.send_header('Content-Type','text/plain'); s.end_headers()
        s.wfile.write(b'GRAFANA_OK-'+s.path.encode())
    def log_message(s,*a): pass
srv=socketserver.ThreadingTCPServer(('127.0.0.1',9999),H); srv.daemon_threads=True; srv.serve_forever()
"
sleep 1

# --- creează forward ---
FJSON=$(sess -X POST "$B/api/hosts/$HID/forwards" -H 'Content-Type: application/json' \
  -d '{"label":"grafana","target_host":"127.0.0.1","target_port":9999,"scheme":"http","enabled":true}')
FID=$(echo "$FJSON" | grep -oE '"id":[0-9]+' | head -1 | grep -oE '[0-9]+')
SLUG=$(echo "$FJSON" | grep -oE '"slug":"[^"]+"' | sed 's/"slug":"//;s/"//')
[ "$SLUG" = "grafana" ] && ok "forward creat (slug=$SLUG, id=$FID)" || no "create" "$FJSON"

# --- probă pe forward-id (ținta stocată, anti-SSRF) ---
R=$(sess "$B/api/forwards/$FID/probe")
echo "$R" | grep -q '"reachable":true' && ok "probe: target reachable (via the stored target)" || no "probe" "$R"

# === HANDSHAKE ===
# 1. subdomeniu fără cookie → 302 la /__wtfwd/auth
LOC=$(ch "$SLUG.$D" -D - -o /dev/null "$B/dashboards" | grep -i '^location:' | tr -d '\r' | sed 's/location: //i')
echo "$LOC" | grep -q "/__wtfwd/auth?slug=$SLUG" && ok "1. no cookie → redirect to the handshake" || no "handshake-1" "$LOC"

# 2. /__wtfwd/auth pe domeniul principal, cu sesiune → 302 cu token
LOC2=$(curl -s -H "Cookie: $SC" -H "Host: $D" -D - -o /dev/null "$B/__wtfwd/auth?slug=$SLUG&next=/dashboards" | grep -i '^location:' | tr -d '\r' | sed 's/location: //i')
echo "$LOC2" | grep -qE "$SLUG\.$D/__wtfwd/set\?t=[0-9]+\." && ok "2. auth (valid session) → signed token" || no "handshake-2" "$LOC2"
TK=$(echo "$LOC2" | sed -E 's/.*[?&]t=([^&]+).*/\1/')

# 3. /__wtfwd/set pe subdomeniu → 302 + Set-Cookie
SETRESP=$(ch "$SLUG.$D" -D - -o /dev/null "$B/__wtfwd/set?t=$TK&next=/dashboards")
FC=$(echo "$SETRESP" | grep -i '^set-cookie:' | sed -E 's/set-cookie: ([^;]+).*/\1/i' | tr -d '\r')
echo "$SETRESP" | grep -qE '^HTTP/[^ ]+ 302' && [ -n "$FC" ] && ok "3. set-cookie pe subdomeniu ($(echo $FC|cut -d= -f1))" || no "handshake-3" "$SETRESP"

# 4. subdomeniu CU cookie → proxy la țintă
BODY=$(ch "$SLUG.$D" -H "Cookie: $FC" "$B/pagina")
echo "$BODY" | grep -q 'GRAFANA_OK-/pagina' && ok "4. with cookie → proxied through the tunnel (body + path)" || no "handshake-4" "$BODY"
# răspunsul de forward NU trebuie să poarte CSP-ul WebTerm (ar rupe UI-ul echipamentului)
HDRS=$(ch "$SLUG.$D" -D - -o /dev/null -H "Cookie: $FC" "$B/x")
echo "$HDRS" | grep -qi 'content-security-policy' && no "fwd-csp" "the forward carries WebTerm CSP" || ok "5. the forward is served WITHOUT WebTerm CSP (different origin)"
# invers: domeniul principal (app-ul WebTerm) PĂSTREAZĂ CSP-ul (nu am slăbit securitatea)
MAINHDRS=$(ch "$D" -D - -o /dev/null "$B/")
echo "$MAINHDRS" | grep -qi 'content-security-policy' && ok "5b. the main app keeps its CSP" || no "main-csp" "the main app was left without CSP"
# long-poll: țintă care întârzie răspunsul (~3s) → proxy-ul îl livrează, nu 502
SLOW=$(ch "$SLUG.$D" -m 20 -H "Cookie: $FC" "$B/slow-poll")
echo "$SLOW" | grep -q 'GRAFANA_OK-/slow-poll' && ok "6. delayed response (long-poll) → delivered, not timed out" || no "fwd-slow" "$SLOW"

# === SECURITATE ===
# token legat de slug: token(grafana) pe alt subdomeniu → 403
CODE=$(ch "altul.$D" -o /dev/null -w '%{http_code}' "$B/__wtfwd/set?t=$TK&next=/")
[ "$CODE" = "403" ] && ok "SEC: token(grafana) refuzat pe alt subdomeniu (403)" || no "sec-slug" "cod $CODE"

# fără cookie → redirect, NU proxy (nu expune ținta)
CODE=$(ch "$SLUG.$D" -o /dev/null -w '%{http_code}' "$B/secret")
[ "$CODE" = "302" ] && ok "SEC: no cookie → redirect, not proxy" || no "sec-nocookie" "cod $CODE"

# cookie invalid (semnătură stricată) → redirect
CODE=$(ch "$SLUG.$D" -H "Cookie: wt_fwd=9999999999.deadbeef" -o /dev/null -w '%{http_code}' "$B/x")
[ "$CODE" = "302" ] && ok "SEC: cookie with an invalid signature → redirect" || no "sec-badsig" "cod $CODE"

# forward oprit → 404 (chiar cu cookie valid)
sess -X PATCH "$B/api/forwards/$FID" -H 'Content-Type: application/json' -d '{"enabled":false}' >/dev/null
CODE=$(ch "$SLUG.$D" -H "Cookie: $FC" -o /dev/null -w '%{http_code}' "$B/x")
[ "$CODE" = "404" ] && ok "SEC: disabled forward → 404 (not proxied)" || no "sec-disabled" "cod $CODE"

# === WEBSOCKET prin tunel ===
# server echo WS țintă pe 127.0.0.1:9998 + rezolvare subdomeniu în container
docker exec "$CT" sh -c "grep -q wsecho.$D /etc/hosts || echo '127.0.0.1 wsecho.$D' >> /etc/hosts"
docker exec -d "$CT" python3 -c "
import asyncio, websockets
async def echo(ws):
    async for m in ws: await ws.send('echo:'+m)
async def main():
    async with websockets.serve(echo, '127.0.0.1', 9998): await asyncio.Future()
asyncio.run(main())
"
sleep 1
WFJSON=$(sess -X POST "$B/api/hosts/$HID/forwards" -H 'Content-Type: application/json' \
  -d '{"label":"wsecho","target_host":"127.0.0.1","target_port":9998,"scheme":"http","enabled":true}')
# token de forward pentru wsecho (prin handshake)
WLOC=$(curl -s -H "Cookie: $SC" -H "Host: $D" -D - -o /dev/null "$B/__wtfwd/auth?slug=wsecho&next=/" | grep -i '^location:' | tr -d '\r')
WTK=$(echo "$WLOC" | sed -E 's/.*[?&]t=([^&]+).*/\1/')
# client WS prin subdomeniu (rezolvat la 127.0.0.1), cu cookie + Origin corect
WSOUT=$(docker exec "$CT" python3 -c "
import asyncio, websockets, sys
async def main():
    async with websockets.connect('ws://wsecho.$D:8000/live',
            additional_headers={'Cookie':'wt_fwd=$WTK','Origin':'http://wsecho.$D'}) as ws:
        await ws.send('hello-ws')
        print(await asyncio.wait_for(ws.recv(), timeout=10))
asyncio.run(main())
" 2>&1 | tail -1)
echo "$WSOUT" | grep -q 'echo:hello-ws' && ok "WebSocket through the tunnel: message → echo (round-trip)" || no "websocket" "$WSOUT"
# SEC anti-CSWSH: Origin ostil (alt site) → handshake respins, chiar cu cookie valid
WSBAD=$(docker exec "$CT" python3 -c "
import asyncio, websockets
async def main():
    try:
        async with websockets.connect('ws://wsecho.$D:8000/live',
                additional_headers={'Cookie':'wt_fwd=$WTK','Origin':'http://evil.example'}) as ws:
            await ws.send('x'); print('CONNECTED')
    except Exception as e:
        print('REJECTED')
asyncio.run(main())
" 2>&1 | tail -1)
echo "$WSBAD" | grep -q 'REJECTED' && ok "SEC: WebSocket with a hostile Origin → rejected (anti-CSWSH)" || no "cswsh" "$WSBAD"

# === TARGET HTTPS (TLS pe ultimul hop, gateway → țintă) ===
# server https self-signed pe 127.0.0.1:9443; gateway-ul ridică TLS peste tunel
openssl req -x509 -newkey rsa:2048 -keyout /tmp/fwdk.pem -out /tmp/fwdc.pem \
  -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1
docker exec -i "$CT" sh -c 'cat > /tmp/fwdk.pem' < /tmp/fwdk.pem
docker exec -i "$CT" sh -c 'cat > /tmp/fwdc.pem' < /tmp/fwdc.pem
docker exec -d "$CT" python3 -c "
import http.server, ssl, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        s.send_response(200); s.send_header('Content-Type','text/plain'); s.end_headers()
        s.wfile.write(b'HTTPS_OK-'+s.path.encode())
    def log_message(s,*a): pass
httpd=socketserver.TCPServer(('127.0.0.1',9443),H)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('/tmp/fwdc.pem','/tmp/fwdk.pem')
httpd.socket=ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
"
sleep 1
sess -X POST "$B/api/hosts/$HID/forwards" -H 'Content-Type: application/json' \
  -d '{"label":"secure","target_host":"127.0.0.1","target_port":9443,"scheme":"https","enabled":true}' >/dev/null
HSLOC=$(curl -s -H "Cookie: $SC" -H "Host: $D" -D - -o /dev/null "$B/__wtfwd/auth?slug=secure&next=/" | grep -i '^location:' | tr -d '\r')
HSTK=$(echo "$HSLOC" | sed -E 's/.*[?&]t=([^&]+).*/\1/')
HSBODY=$(ch "secure.$D" -H "Cookie: wt_fwd=$HSTK" "$B/pag")
echo "$HSBODY" | grep -q 'HTTPS_OK-/pag' && ok "target https: TLS pe ultimul hop → proxy (corp+path)" || no "https-target" "$HSBODY"

# === DOMENIU DE FORWARD CONFIGURABIL (Settings) ===
# schimbă domeniul → URL-urile forward-urilor și rutarea pe Host îl reflectă
sess -X POST "$B/api/settings/forward" -H 'Content-Type: application/json' -d "{\"domain\":\"apps.$D\"}" >/dev/null
NEWJSON=$(sess -X POST "$B/api/hosts/$HID/forwards" -H 'Content-Type: application/json' \
  -d '{"label":"cfgdom","target_host":"127.0.0.1","target_port":9999,"scheme":"http","enabled":true}')
NEWSLUG=$(echo "$NEWJSON" | grep -oE '"slug":"[^"]+"' | sed 's/"slug":"//;s/"//')
echo "$NEWJSON" | grep -q "\"url\":\"http://$NEWSLUG.apps.$D\"" && ok "custom domain: the URL reflects apps.$D" || no "cfg-url" "$NEWJSON"
LOC=$(ch "$NEWSLUG.apps.$D" -D - -o /dev/null "$B/x" | grep -i '^location:' | tr -d '\r')
echo "$LOC" | grep -q "/__wtfwd/auth?slug=$NEWSLUG" && ok "custom domain: routing on apps.$D → handshake" || no "cfg-route" "$LOC"
# vechiul subdomeniu nu mai e tratat ca forward (nu mai face handshake); la nivel de
# app primește SPA-ul (200), în prod Traefik nici nu l-ar ruta (alt domeniu)
LOCO=$(ch "grafana.$D" -D - -o /dev/null "$B/x" | grep -i '^location:' | tr -d '\r')
echo "$LOCO" | grep -q "__wtfwd/auth" && no "cfg-old" "it still does the handshake: $LOCO" || ok "custom domain: the old subdomain is no longer a forward (fără handshake)"
# validare: domeniu invalid → 400
CODE=$(sess -X POST "$B/api/settings/forward" -H 'Content-Type: application/json' -d '{"domain":"nu valid/x"}' -o /dev/null -w '%{http_code}')
[ "$CODE" = "400" ] && ok "domeniu custom: input invalid → 400" || no "cfg-valid" "cod $CODE"
# reset la domeniul implicit
sess -X POST "$B/api/settings/forward" -H 'Content-Type: application/json' -d "{\"domain\":\"$D\"}" >/dev/null

# === FORWARD PE HOST SSH (canal direct-tcpip prin conexiunea asyncssh) ===
# sshd real în container; hostul SSH țintește serverul de pe 127.0.0.1:9999.
docker exec "$CT" sh -c 'command -v sshd >/dev/null 2>&1 || (apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq openssh-server >/dev/null 2>&1)'
docker exec "$CT" sh -c '
  mkdir -p /run/sshd; ssh-keygen -A >/dev/null 2>&1
  id wtssh >/dev/null 2>&1 || useradd -m -s /bin/bash wtssh
  echo "wtssh:sshpass123" | chpasswd
  grep -q "^Port 2222" /etc/ssh/sshd_config || echo "Port 2222" >> /etc/ssh/sshd_config
  sed -i "s/#*PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config
  pkill sshd 2>/dev/null; /usr/sbin/sshd' >/dev/null 2>&1
sleep 2
# host SSH cu credențială STOCATĂ + fără 2FA → forward-ul poate auto-conecta
SSHID=$(sess -X POST "$B/api/hosts" -H 'Content-Type: application/json' \
  -d '{"name":"ssh-fwd","connection_type":"ssh","hostname":"127.0.0.1","ssh_port":2222,"ssh_username":"wtssh","auth_method":"password","credential":"sshpass123","credential_policy":"stored","require_2fa":false}' \
  | grep -oE '"id":[0-9]+' | head -1 | grep -oE '[0-9]+')
SFJSON=$(sess -X POST "$B/api/hosts/$SSHID/forwards" -H 'Content-Type: application/json' \
  -d '{"label":"sshsvc","target_host":"127.0.0.1","target_port":9999,"scheme":"http","enabled":true}')
SFSLUG=$(echo "$SFJSON" | grep -oE '"slug":"[^"]+"' | sed 's/"slug":"//;s/"//')
SFID=$(echo "$SFJSON" | grep -oE '"id":[0-9]+' | head -1 | grep -oE '[0-9]+')
# probă: fără sesiune deschisă, auto-dial SSH → open_connection → 9999
sess "$B/api/forwards/$SFID/probe" | grep -q '"reachable":true' && ok "SSH host: probe via auto-dial (no session)" || no "ssh-probe" "$(sess "$B/api/forwards/$SFID/probe")"
# acces prin subdomeniu → proxy prin canalul SSH
SFTK=$(curl -s -H "Cookie: $SC" -H "Host: $D" -D - -o /dev/null "$B/__wtfwd/auth?slug=$SFSLUG&next=/" | grep -i '^location:' | tr -d '\r' | sed -E 's/.*[?&]t=([^&]+).*/\1/')
SFBODY=$(ch "$SFSLUG.$D" -H "Cookie: wt_fwd=$SFTK" "$B/ssh-path")
echo "$SFBODY" | grep -q 'SSH_SVC_OK-/ssh-path\|GRAFANA_OK-/ssh-path' && ok "SSH host: proxied over the SSH channel (body+path)" || no "ssh-forward" "$SFBODY"
# Gardul de 2FA pe forward-uri, pe ambele planuri. Fixture-ul se montează cu 2FA STINSĂ şi se
# aprinde după: activarea nu cere step-up (doar dezactivarea o cere), iar din curl nu putem face
# ceremonia passkey — cu WebAuthn disponibil, parola contului NU mai e acceptată ca fallback.
SSH2=$(sess -X POST "$B/api/hosts" -H 'Content-Type: application/json' \
  -d '{"name":"ssh-2fa","connection_type":"ssh","hostname":"127.0.0.1","ssh_port":2222,"ssh_username":"wtssh","auth_method":"password","credential":"sshpass123","credential_policy":"stored","require_2fa":false}' \
  | grep -oE '"id":[0-9]+' | head -1 | grep -oE '[0-9]+')
SF2JSON=$(sess -X POST "$B/api/hosts/$SSH2/forwards" -H 'Content-Type: application/json' \
  -d '{"label":"ssh2fa","target_host":"127.0.0.1","target_port":9999,"scheme":"http","enabled":true}')
SF2=$(echo "$SF2JSON" | grep -oE '"id":[0-9]+' | head -1 | grep -oE '[0-9]+')
SF2SLUG=$(echo "$SF2JSON" | grep -oE '"slug":"[^"]+"' | sed 's/"slug":"//;s/"//')
sess -o /dev/null -X POST "$B/api/hosts/$SSH2/require-2fa" -H 'Content-Type: application/json' -d '{"enabled":true}'
# configurare: nu mai poţi re-ţinti tunelul cu un simplu cookie
CODE=$(sess -o /dev/null -w '%{http_code}' -X PATCH "$B/api/forwards/$SF2" \
  -H 'Content-Type: application/json' -d '{"target_port":22}')
[ "$CODE" = "403" ] && ok "SEC: re-targeting a forward on a 2FA host → 403" || no "fwd-2fa-patch" "cod $CODE"
# recunoaştere: proba spune dacă un port e deschis în reţeaua host-ului — tot oracol
CODE=$(sess -o /dev/null -w '%{http_code}' "$B/api/forwards/$SF2/probe")
[ "$CODE" = "403" ] && ok "SEC: probing a 2FA host without step-up → 403" || no "ssh-2fa-gate" "cod $CODE"
# ACCES: un tunel deja creat nu se deschide pe cookie — omul e trimis să deblocheze
LOC=$(curl -s -H "Cookie: $SC" -H "Host: $D" -D - -o /dev/null "$B/__wtfwd/auth?slug=$SF2SLUG&next=/" | grep -i '^location:' | tr -d '\r')
case "$LOC" in
  *stepup=forward*) ok "SEC: forward access on a 2FA host requires step-up (no token)" ;;
  *) no "fwd-2fa-access" "$LOC" ;;
esac

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
