#!/usr/bin/env python3
"""ptyd - WebTerm host agent.

Single-file, Python 3.6+ stdlib-only daemon that keeps pty sessions alive on
this host and bridges them to the WebTerm gateway over an outbound WebSocket
connection authenticated with a per-host token.

Usage:
  ptyd.py start            daemonize (default)
  ptyd.py run              run in foreground
  ptyd.py stop             stop the running daemon
  ptyd.py status           print daemon status
  ptyd.py info             print paths, commands and upload location

Config: ~/.webterm/agent.json  {"url": "wss://gw/agent/ws", "token": "..."}
"""

import base64
import binascii
import errno
import fcntl
import glob
import hashlib
import hmac
import json
import os
import pty
import pwd
import queue
import select
import selectors
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import termios
import threading
import time

AGENT_VERSION = 40
PROTO = 1

RUN_MAX_TIMEOUT = 300           # plafon timeout pentru op-ul `run` (consola de flotă)
RUN_OUTPUT_CAP = 256 * 1024     # plafon stdout/stderr per rulare non-interactivă
RUN_CAPTURE_HARD = 8 * 1024 * 1024   # G3: plafon DUR de captură în RAM/flux (înainte de
                                     # trunchierea la RUN_OUTPUT_CAP) — peste atât omorâm
                                     # procesul, ca `yes`/`cat /dev/zero` prin flotă să nu
                                     # umple memoria agentului
MAX_RUNS = 16                        # rulări `run` concurente per agent — fără cap, sute de cereri
                                     # simultane pornesc sute de thread-uri + procese → epuizare PID/FD
WS_MSG_MAX = 32 * 1024 * 1024   # G4: plafon pe mesajul WS REASAMBLAT total (fragmente)
LOG_MAX = 4 * 1024 * 1024       # G7: rotăm ptyd.log peste atât (trunchiere în _tick)
AGENT_HUNG_AFTER = 120.0        # G1: agent care nu şi-a atins fişierul de liveness atâtea
                                # secunde e considerat BLOCAT → watchdog-ul îl omoară + reporneşte

FS_CHUNK = 256 * 1024            # bytes per file-read reply
FS_MAX_LIST = 2000              # entries returned by fs_list

MAX_SESSIONS = 32
CONNECT_STUCK_SECS = 120      # o conectare mai lungă de-atât e blocată: o reluăm
RING_LIMIT = 2 * 1024 * 1024          # scrollback bytes kept per session
OUTBOX_LIMIT = 4 * 1024 * 1024        # drop connection if gateway stalls
# Backlog-uri de intrare mărginite (anti-OOM la producător rapid + consumator lent):
# input pentru un pty blocat, respectiv octeți de scris către o țintă de forward lentă.
PENDING_INPUT_MAX = 1 * 1024 * 1024   # input în așteptare per sesiune (paste-storm în app blocată)
FWD_WBUF_MAX = 8 * 1024 * 1024        # octeți în așteptare către ținta unui forward
READ_CHUNK = 65536
HEARTBEAT_INTERVAL = 30.0
HB_ACK_TIMEOUT = 75.0           # fără ack la heartbeat atâta timp → conexiunea nu mai ajunge la
                               # gateway (half-open); forţăm reconnect (detecţie mai rapidă/fiabilă
                               # decât TCP keepalive, care unele NAT-uri îl blochează)
EXITED_TTL = 24 * 3600
BACKOFF_MIN, BACKOFF_MAX = 1.0, 60.0
# Cât trebuie să reziste o conexiune ca s-o considerăm sănătoasă şi să repunem backoff-ul la
# minim. Peste HEARTBEAT_INTERVAL, ca o legătură tăiată înainte de primul heartbeat să NU
# treacă drept stabilă.
STABLE_CONNECTION = 120.0
SID_LEN = 32

FRAME_CTRL = b"J"
FRAME_DATA = b"D"
FRAME_FWD = b"F"                       # port-forward: FRAME_FWD + stream_id(32) + bytes
                                       # (reutilizat și pentru consolele SERIALE — tot
                                       #  un stream de octeți brut, keyed pe stream_id)

MAX_FORWARDS = 64                     # conexiuni de forward concurente per agent
MAX_SERIALS = 16                      # console seriale concurente per agent
FWD_CONNECT_TIMEOUT = 10.0            # connect() non-blocant: dacă ținta nu răspunde
                                      # (IP:port filtrat / SYN black-hole) în atâtea
                                      # secunde, abandonăm — altfel socketul rămâne
                                      # `connecting` la infinit, ținând un slot + un fd

WEBTERM_DIR = os.path.join(os.path.expanduser("~"), ".webterm")
CONFIG_PATH = os.path.join(WEBTERM_DIR, "agent.json")
LOCK_PATH = os.path.join(WEBTERM_DIR, "ptyd.lock")
LOG_PATH = os.path.join(WEBTERM_DIR, "ptyd.log")
ALIVE_PATH = os.path.join(WEBTERM_DIR, "alive")   # G1: mtime atins la fiecare tick;
                                                  # stale = event-loop blocat
SELF_PATH = os.path.abspath(__file__)


def _instance_id():
    """Stable per-machine id so the gateway can fence a host token to one box.
    Prefer /etc/machine-id (systemd regenerates it per cloned VM), fall back to
    a random id persisted in ~/.webterm. Hashed so the raw machine-id never
    leaves the host. WEBTERM_INSTANCE_ID overrides (containers that share a
    machine-id, or tests)."""
    env = os.environ.get("WEBTERM_INSTANCE_ID")
    if env:
        return hashlib.sha256(("webterm-instance:" + env).encode()).hexdigest()[:32]
    raw = ""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p) as f:
                raw = f.read().strip()
            if raw:
                break
        except OSError:
            pass
    if not raw:
        path = os.path.join(WEBTERM_DIR, "instance")
        try:
            with open(path) as f:
                raw = f.read().strip()
        except OSError:
            raw = ""
        if not raw:
            raw = binascii.hexlify(os.urandom(16)).decode()
            try:
                os.makedirs(WEBTERM_DIR, mode=0o700, exist_ok=True)
                with open(path, "w") as f:
                    f.write(raw)
                os.chmod(path, 0o600)
            except OSError:
                pass
    return hashlib.sha256(("webterm-instance:" + raw).encode()).hexdigest()[:32]


INSTANCE_ID = _instance_id()

# ── Agent-update signature verification (Ed25519, RFC 8032, pure stdlib) ──────
# Updates pushed by the gateway MUST carry a signature from the key this agent was
# installed with. Public key only on this side.
#
# What the signature actually buys, stated honestly. This comment used to claim "the gateway
# never holds the private key, so a compromised gateway cannot install code on every host".
# That stopped being true when per-deployment keys were introduced: a gateway now generates
# its own key at first boot and holds it, unencrypted by default, so that agents can be
# updated without a human present. So:
#   * a network MITM cannot install code — it has no key;
#   * a compromised PUBLIC SOURCE cannot install code on your fleet — your agents trust your
#     gateway's key, not the project's;
#   * a compromised GATEWAY *can*. It is the trust anchor for its own fleet, by design. The
#     mitigations are the key passphrase (auto-update then pauses until unlocked) and treating
#     the data volume as key material.
# The premise mattered: it was the stated justification for the whole mechanism, and it
# survived unchanged through the architecture change that invalidated it.
UPDATE_PUBKEY = bytes.fromhex(
    "c25a523e97ac82bb5b473f159f90483add239e25850d86a973fb9640789e9e00")

_ed_p = 2 ** 255 - 19
_ed_l = 2 ** 252 + 27742317777372353535851937790883648493
_ed_d = (-121665 * pow(121666, _ed_p - 2, _ed_p)) % _ed_p
_ed_ii = pow(2, (_ed_p - 1) // 4, _ed_p)


def _ed_inv(x):
    return pow(x, _ed_p - 2, _ed_p)


def _ed_xrecover(y):
    xx = (y * y - 1) * _ed_inv(_ed_d * y * y + 1)
    x = pow(xx, (_ed_p + 3) // 8, _ed_p)
    if (x * x - xx) % _ed_p != 0:
        x = (x * _ed_ii) % _ed_p
    if x % 2 != 0:
        x = _ed_p - x
    return x


_ed_By = (4 * _ed_inv(5)) % _ed_p
_ed_B = [_ed_xrecover(_ed_By) % _ed_p, _ed_By % _ed_p, 1,
         (_ed_xrecover(_ed_By) * _ed_By) % _ed_p]


def _ed_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = ((y1 - x1) * (y2 - x2)) % _ed_p
    B = ((y1 + x1) * (y2 + x2)) % _ed_p
    C = (t1 * 2 * _ed_d * t2) % _ed_p
    D = (z1 * 2 * z2) % _ed_p
    E, F, G, H = B - A, D - C, D + C, B + A
    return [(E * F) % _ed_p, (G * H) % _ed_p, (F * G) % _ed_p, (E * H) % _ed_p]


def _ed_mul(P, e):
    Q = [0, 1, 1, 0]
    while e > 0:
        if e & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        e >>= 1
    return Q


def _ed_decodepoint(s):
    n = int.from_bytes(s, "little")
    y = n & ((1 << 255) - 1)
    x = _ed_xrecover(y)
    if (x & 1) != (n >> 255):
        x = _ed_p - x
    return [x, y, 1, (x * y) % _ed_p]


def _ed_affine(P):
    zi = _ed_inv(P[2])
    return ((P[0] * zi) % _ed_p, (P[1] * zi) % _ed_p)


def _ed_isoncurve(P):
    # ecuația edwards25519: -x² + y² = 1 + d·x²·y² (mod p). P e afin ([x, y, 1, x·y]).
    x, y = P[0], P[1]
    xx, yy = (x * x) % _ed_p, (y * y) % _ed_p
    return (-xx + yy - 1 - _ed_d * xx * yy) % _ed_p == 0


def _new_agent_starts(content):
    """Sursa nouă chiar PORNEŞTE pe host-ul ăsta? Verificat prin execuţie, nu prin citire.

    Se scria direct peste agent, care făcea execv şi murea dacă noul cod era stricat — iar
    supravegherea (systemd Restart=always / watchdog cron la fiecare minut) repornea la infinit
    acelaşi fişier mort, pe TOATĂ flota deodată, fiindcă update-ul se împinge la toţi. Nu era
    nicio cale de întoarcere: codul care ar fi trebuit să repare e chiar cel care nu porneşte.
    Recuperarea cerea SSH pe fiecare maşină — exact situaţia pentru care există produsul ăsta.

    Semnătura garantează CINE a trimis codul, nu că el funcţionează. Îl rulăm cu `selftest`
    într-un subproces, cât timp agentul vechi e încă în viaţă: aşa prindem şi sintaxa, şi
    erorile de import, şi incompatibilităţile cu interpretorul de pe host-ul ĂSTA (agentul
    promite Python 3.6+, dar CI-ul rulează pe 3.12)."""
    try:
        compile(content, SELF_PATH, "exec")
    except (SyntaxError, ValueError) as e:
        log("update refused: the new source does not compile (%s)" % e)
        return False
    probe = SELF_PATH + ".probe"
    try:
        with open(probe, "wb") as f:
            f.write(content)
        os.chmod(probe, 0o700)
        r = subprocess.run([sys.executable, probe, "selftest"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if r.returncode != 0:
            log("update refused: the new source does not start (rc=%s) %s"
                % (r.returncode, (r.stderr or b"")[-300:].decode("utf-8", "replace")))
            return False
        return True
    except Exception as e:                  # noqa: BLE001 — orice eşec = refuz, nu înlocuire
        log("update refused: could not verify the new source (%s)" % e)
        return False
    finally:
        try:
            os.remove(probe)
        except OSError:
            pass


def ed25519_verify(pubkey, sig, msg):
    try:
        if len(sig) != 64 or len(pubkey) != 32:
            return False
        R = _ed_decodepoint(sig[:32])
        A = _ed_decodepoint(pubkey)
        # L6: ambele puncte trebuie să fie PE curbă (ca implementarea de referință RFC 8032,
        # care ridică pe `not isoncurve`). Un punct decodat în afara curbei ar pica oricum la
        # comparația finală; verificarea explicită aliniază strict cu referința (hardening).
        if not (_ed_isoncurve(R) and _ed_isoncurve(A)):
            return False
        S = int.from_bytes(sig[32:], "little")
        if S >= _ed_l:                 # S canonic (RFC 8032 §5.1.7): respinge S ne-redus
            return False               # (anti-malleabilitate); nu e vector de forjare, dar strict
        h = int.from_bytes(hashlib.sha512(sig[:32] + pubkey + msg).digest(),
                           "little") % _ed_l
        return _ed_affine(_ed_mul(_ed_B, S)) == _ed_affine(_ed_add(R, _ed_mul(A, h)))
    except Exception:
        return False


def _content_version(src):
    """Extrage AGENT_VERSION din sursa unui update (pt. anti-rollback). None dacă
    lipsește (nu blocăm atunci — semnătura rămâne gardul principal)."""
    for line in src.split(b"\n")[:200]:
        s = line.strip()
        if not s.startswith(b"AGENT_VERSION"):
            continue
        rest = s[len(b"AGENT_VERSION"):].lstrip()
        if not rest.startswith(b"="):    # ancorat: EXACT `AGENT_VERSION =`, nu AGENT_VERSION_OLD etc.
            continue
        try:
            return int(rest[1:].strip())
        except (ValueError, IndexError):
            return None
    return None


# tmux integration: sessions live inside a dedicated tmux server (-L webterm)
# so they survive agent crashes/upgrades; the agent re-adopts them by name.
TMUX_BIN = shutil.which("tmux")
TMUX_SOCKET = "webterm"
TMUX_CONF = os.path.join(WEBTERM_DIR, "tmux.conf")
TMUX_SESSION_PREFIX = "wt-"
TMUX_SWEEP_INTERVAL = 120.0    # igienă periodică: reapează sesiuni tmux orfane (fără
                               # backing în agent) — vezi _sweep_orphan_tmux
TMUX_SERVER_KILL_COOLDOWN = 30.0   # nu re-vâna serverul înțepenit mai des de-atât
# Reataşarea la o sesiune tmux al cărei client a murit. Cazul sănătos (client omorât,
# detach manual) se rezolvă din prima încercare; când NU se rezolvă, agentul ≤31 renunţa
# după 3 încercări în 2s şi OMORA sesiunea tmux — adică o ceartă tranzitorie între clienţi
# (două agenţi pe acelaşi socket, `attach -D` reciproc) costa utilizatorul tot ce avea
# deschis acolo. S-a întâmplat: 2026-08-05, două sesiuni live distruse în aceeaşi secundă.
# Acum: câteva încercări rapide, apoi rărim la infinit. Cât timp sesiunea tmux EXISTĂ, ea
# rămâne neatinsă — preferăm o sesiune la care nu ne putem lipi acum unei sesiuni distruse
# definitiv; utilizatorul se poate ataşa şi manual (`tmux -L webterm attach`).
TMUX_REATTACH_FAST = 3             # încercări imediate înainte de a rări
TMUX_REATTACH_BACKOFF = (2.0, 5.0, 15.0, 30.0)   # apoi; ultima valoare se repetă la infinit
TMUX_CLIENT_HEALTHY = 10.0         # un client care a trăit atât = reataşare reuşită (resetăm)
# mouse on: rotita deruleaza istoricul tmux (50k linii) prin copy-mode, chiar
# si pentru output in rafala pe care tmux il redeseneaza in loc sa-l deruleze.
# set-clipboard + Ms: selectia cu mouse-ul din tmux ajunge in clipboardul
# browserului prin OSC 52 (xterm.js clipboard addon). prefix None + status off
# tin tmux invizibil; bindingurile default de mouse raman (sunt exact ce vrem).
TMUX_EXTRA_OPTIONS = [
    ("history-limit", "50000"),
    ("escape-time", "0"),
    ("destroy-unattached", "off"),
    ("detach-on-destroy", "on"),
    ("status", "off"),
    ("mouse", "on"),
    ("set-clipboard", "on"),
    # focus-events: retransmite CSI I/O (focus in/out de la xterm.js) catre
    # aplicatiile din pane care au cerut modul 1004 (Claude Code, vim autoread)
    ("focus-events", "on"),
    # nota: tmux emite ]52;;<b64> (destinatie goala) la copy-selection;
    # frontend-ul are un handler OSC52 propriu care accepta orice destinatie
    ("terminal-overrides", ",*:Ms=\\E]52;%p1%s;%p2%s\\007"),
]
TMUX_CONF_CONTENT = (
    'set -g default-terminal "xterm-256color"\n'
    "set -g prefix None\n"
    + "".join("set -g %s '%s'\n" % (k, v) for k, v in TMUX_EXTRA_OPTIONS)
)


def tmux_apply_conf():
    """Apply config to an already-running tmux server (config files are only
    read at server start, e.g. before an agent upgrade shipped new settings)."""
    try:
        r = tmux_cmd("list-sessions")
        if r.returncode != 0:
            return                      # no server running; conf applies at start
        for key, value in TMUX_EXTRA_OPTIONS:
            tmux_cmd("set-option", "-g", key, value)
    except (OSError, subprocess.TimeoutExpired):
        pass


def tmux_cmd(*args, **kw):
    # G2: timeout scurt — tmux_cmd rulează pe event-loop-ul single-threaded, deci cât
    # stă blocat nu servește I/O pentru celelalte sesiuni. Comenzile normale sunt <100ms;
    # 5s acoperă orice caz sănătos și mărginește stall-ul la un wedge (oricum prevenit acum).
    timeout = kw.get("timeout", 5)
    return subprocess.run(
        [TMUX_BIN, "-L", TMUX_SOCKET, "-f", TMUX_CONF] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)


def tmux_session_state(sid):
    """„alive" | „gone" | „unknown".

    Distincţia contează: `has-session` întoarce eşec ŞI când sesiunea chiar nu există, ŞI
    când serverul n-a răspuns (timeout, socket refuzat, server înţepenit). Confundându-le,
    o sesiune VIE e declarată moartă la prima sughiţătură de tmux — adică exact felul în
    care se pierd sesiuni. „unknown" înseamnă „nu ştiu", nu „a murit"."""
    try:
        r = tmux_cmd("has-session", "-t", "=" + TMUX_SESSION_PREFIX + sid)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if r.returncode == 0:
        return "alive"
    err = (r.stderr or b"").lower()
    # răspunsuri CLARE de la tmux: server viu fără sesiunea asta / niciun server pornit
    if b"can't find session" in err or b"no server running" in err:
        return "gone"
    return "unknown"        # „server exited unexpectedly", „lost server", erori de socket


def tmux_has_session(sid):
    return tmux_session_state(sid) == "alive"


def tmux_server_wedged():
    """True dacă serverul tmux e VIU dar nu răspunde clienţilor: o comandă de control
    întoarce „server exited unexpectedly" / „lost server" (serverul acceptă socketul şi-l
    închide imediat — see SESSION-LIFECYCLE). DIFERIT de „no server running" (normal,
    niciun server pornit). Semnalul după care recuperăm serverul în loc să declarăm
    o sesiune moartă pe nedrept."""
    try:
        r = tmux_cmd("list-sessions")
    except (OSError, subprocess.TimeoutExpired):
        return False
    if r.returncode == 0:
        return False
    err = (r.stderr or b"").lower()
    return b"exited unexpectedly" in err or b"lost server" in err


def tmux_cmdline_matches(parts, socket):
    """True dacă un cmdline (listă de octeți split pe NUL din /proc/<pid>/cmdline)
    e un proces `tmux -L <socket>` — server sau client pe socketul nostru. Pur, ca
    să fie testabil: e criteriul după care _kill_tmux_procs decide ce SIGKILL-uiește,
    deci NU trebuie să prindă alte tmux-uri (alt socket) sau procese non-tmux."""
    if not parts or not parts[0] or b"tmux" not in os.path.basename(parts[0]):
        return False
    try:
        i = parts.index(b"-L")
    except ValueError:
        return False
    return i + 1 < len(parts) and parts[i + 1] == socket.encode()


# ---------------------------------------------------------------------------
# System metrics (load / cpu / mem / disk), reported with each heartbeat
# ---------------------------------------------------------------------------

class Metrics:
    def __init__(self):
        self._prev_cpu = None

    def _cpu_percent(self):
        """CPU busy % since the previous heartbeat (from /proc/stat)."""
        try:
            with open("/proc/stat") as f:
                fields = [int(x) for x in f.readline().split()[1:]]
        except (OSError, ValueError, IndexError):
            return None
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
        total = sum(fields)
        prev, self._prev_cpu = self._prev_cpu, (total, idle)
        if not prev or total <= prev[0]:
            return None
        dt, di = total - prev[0], idle - prev[1]
        return round(100.0 * (dt - di) / dt, 1) if dt > 0 else None

    def sample(self):
        m = {}
        try:
            m["load1"], m["load5"], m["load15"] = (round(x, 2) for x in os.getloadavg())
        except OSError:
            pass
        cpu = self._cpu_percent()
        if cpu is not None:
            m["cpu_pct"] = cpu
        try:
            info = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    key, _, rest = line.partition(":")
                    info[key] = int(rest.split()[0]) * 1024
            m["mem_total"] = info["MemTotal"]
            m["mem_used"] = info["MemTotal"] - info.get(
                "MemAvailable", info.get("MemFree", 0))
        except (OSError, KeyError, ValueError, IndexError):
            pass
        # `/` NU e de ajuns. Agentul îşi ţine logul, configul şi fişierul de liveness în
        # `~/.webterm`, iar pe orice layout obişnuit (`/home` pe alt LV, `$HOME` pe tmpfs
        # într-un container) acela e alt filesystem. Măsurat: cu `$HOME` 100% plin, gateway-ul
        # raporta liniştit 74% şi nicio alertă — exact cazul în care alerta ar fi trebuit să
        # sune. Raportăm filesystemul cel mai PLIN dintre cele două: întrebarea operatorului e
        # „mi se umple ceva de care depinde agentul?", nu „cât mai e pe rootfs".
        best = None
        seen = set()
        for path in ("/", WEBTERM_DIR):
            try:
                st = os.statvfs(path)
            except OSError:
                continue
            # `f_blocks > 0` nu garantează `total > 0`: dimensiunea blocului intră şi ea în
            # produs, iar un `f_frsize` zero (filesystem exotic, mount degradat, FUSE care
            # raportează prost) dădea ZeroDivisionError chiar în împărţirea de mai jos —
            # dintr-o funcţie chemată la fiecare heartbeat, negardat. Metrica lipsă e o
            # neplăcere; agentul căzut e o pană.
            total = st.f_blocks * st.f_frsize
            if total <= 0 or (st.f_fsid, st.f_blocks) in seen:
                continue
            seen.add((st.f_fsid, st.f_blocks))
            used = (st.f_blocks - st.f_bavail) * st.f_frsize
            if best is None or used / total > best[1] / best[0]:
                best = (total, used)
        if best:
            m["disk_total"], m["disk_used"] = best
        return m


def log(msg):
    """Jurnalizare best-effort. Un `write` pe stderr POATE eşua — disc plin (ENOSPC), pipe
    închis, cotă depăşită — iar excepţia se propaga din orice loc de unde s-a chemat `log`,
    adică din bucla de evenimente, din reconciliere, din update. Agentul murea din cauza
    jurnalului, exact în situaţia despre care jurnalul încerca să te anunţe. Nu jurnalizăm
    eşecul jurnalizării: n-am avea unde."""
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        sys.stderr.write("[%s] %s\n" % (ts, msg))
        sys.stderr.flush()
    except Exception:      # noqa: BLE001 — logul nu are voie să doboare agentul
        pass


# ---------------------------------------------------------------------------
# Minimal RFC6455 client-side WebSocket
# ---------------------------------------------------------------------------

class WSError(Exception):
    pass


class WSClient:
    """Blocking WebSocket client. recv() runs in a reader thread, send() is
    serialized by the writer thread; close() may be called from any thread."""

    def __init__(self, url, token, insecure=False, cert_pin=None):
        self.url = url
        self.token = token
        self.insecure = insecure
        # cert pinning: amprenta SHA-256 a certificatului DER al gateway-ului (hex), fixată
        # la înrolare. Dacă e setată, se verifică la fiecare conectare — ÎNAINTE de a trimite
        # tokenul —, apărând de un gateway fals (DNS hijack / MITM) chiar în modul insecure.
        self.cert_pin = (cert_pin or "").lower() or None
        self.peer_pin = None            # amprenta observată acum (pt. TOFU la prima conectare)
        self.sock = None
        self._recv_buf = b""
        self._send_lock = threading.Lock()

    def connect(self, timeout=15):
        scheme, rest = self.url.split("://", 1)
        if scheme not in ("ws", "wss"):
            raise WSError("bad url scheme: %s" % scheme)
        hostpart, _, path = rest.partition("/")
        path = "/" + path
        host, _, port_s = hostpart.partition(":")
        port = int(port_s) if port_s else (443 if scheme == "wss" else 80)

        raw = socket.create_connection((host, port), timeout=timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if scheme == "wss":
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=host)
            # Cert pinning ÎNAINTE de a trimite tokenul (vezi _check_cert_pin): un gateway
            # fals (DNS hijack / MITM) nu primește niciodată tokenul și nu poate comanda agentul.
            self._check_cert_pin(self.sock.getpeercert(binary_form=True))
        else:
            self.sock = raw

        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Authorization: Bearer %s\r\n"
            "X-Webterm-Instance: %s\r\n"
            "\r\n" % (path, hostpart, key, self.token, INSTANCE_ID)
        )
        self.sock.sendall(req.encode())

        # Termen-limită TOTAL pe citirea răspunsului de handshake: fără el, un gateway ostil
        # (DNS hijack) putea PICURA octeți (1 la fiecare ~timeout s) și ține conectarea deschisă
        # la nesfârșit. Acum handshake-ul întreg trebuie să încapă în `timeout` secunde.
        deadline = time.monotonic() + timeout
        resp = b""
        while b"\r\n\r\n" not in resp:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WSError("handshake timeout")
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                raise WSError("handshake timeout")
            if not chunk:
                raise WSError("connection closed during handshake")
            resp += chunk
            if len(resp) > 65536:
                raise WSError("oversized handshake response")
        head, _, self._recv_buf = resp.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 101 " not in status_line + " ":
            raise WSError("handshake rejected: %s" % status_line)
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        if accept.encode() not in head:
            raise WSError("bad Sec-WebSocket-Accept")
        self.sock.settimeout(None)
        # Detectează un gateway care dispare fără FIN/RST (cădere de rețea, VPS oprit
        # brusc): fără keepalive, recv() ar bloca ~15 min (timeout TCP default al
        # kernelului) → agentul se crede conectat, nu reîncearcă, sesiunile par moarte
        # pentru user. Cu keepalive, socketul moare în ~idle+intvl*cnt s → recv ridică
        # eroare → reader postează __disconnect__ → reconectare pe backoff.
        _set_keepalive(self.sock)

    def _check_cert_pin(self, der):
        """Cert pinning: amprenta SHA-256 a certificatului DER al gateway-ului trebuie să
        corespundă pin-ului fixat la înrolare. Apără de gateway fals (DNS hijack / MITM)
        CHIAR în modul insecure (unde validarea TLS e oprită). Model known_hosts: TOFU la
        prima conectare (peer_pin expus pentru salvare), enforce după. Fără pin → no-op
        (deployment-urile cu CA public se bazează pe validarea TLS standard, care oricum
        respinge un cert nevalid — pin-ul ar rupe reînnoirea, deci nu-l cerem acolo)."""
        self.peer_pin = hashlib.sha256(der or b"").hexdigest()
        if self.cert_pin and not hmac.compare_digest(self.peer_pin, self.cert_pin):
            raise WSError("cert pin mismatch — unexpected gateway (DNS hijack / MITM?)")

    def _read_exact(self, n):
        while len(self._recv_buf) < n:
            chunk = self.sock.recv(READ_CHUNK)
            if not chunk:
                raise WSError("connection closed")
            self._recv_buf += chunk
        out, self._recv_buf = self._recv_buf[:n], self._recv_buf[n:]
        return out

    @staticmethod
    def _mask(data, mask):
        n = len(data)
        full = mask * (n // 4 + 1)
        return (int.from_bytes(data, "little") ^ int.from_bytes(full[:n], "little")).to_bytes(n, "little")

    def send_message(self, payload, opcode=0x2):
        header = bytearray([0x80 | opcode])
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        with self._send_lock:
            self.sock.sendall(bytes(header) + self._mask(payload, mask))

    def recv_message(self):
        """Returns (opcode, payload) of the next complete message."""
        payload = b""
        first_opcode = None
        while True:
            b1, b2 = self._read_exact(2)
            fin = b1 & 0x80
            opcode = b1 & 0x0F
            masked = b2 & 0x80
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read_exact(8))[0]
            if length > 16 * 1024 * 1024:
                raise WSError("oversized frame")
            mask = self._read_exact(4) if masked else None
            data = self._read_exact(length)
            if mask:
                data = self._mask(data, mask)
            if opcode == 0x9:                      # ping
                try:
                    self.send_message(data, opcode=0xA)
                except OSError:
                    pass
                continue
            if opcode == 0xA:                      # pong
                continue
            if opcode == 0x8:                      # close
                raise WSError("close frame received")
            if opcode in (0x1, 0x2):
                first_opcode = opcode
            payload += data
            # G4: frame-ul e ≤16MB, dar un peer ostil/buggy poate trimite fragmente
            # (fin=0) la infinit → mesajul reasamblat ar creşte nemărginit (OOM). Plafon.
            if len(payload) > WS_MSG_MAX:
                raise WSError("oversized reassembled message")
            if fin:
                return first_opcode, payload

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Session: one pty
# ---------------------------------------------------------------------------

class Session:
    def __init__(self, sid, rows, cols, term, cmd=None, backend="pty", tz=None):
        self.sid = sid
        self.rows = rows
        self.cols = cols
        self.term = term or "xterm-256color"
        self.cmd = cmd
        self.backend = backend        # "tmux" or "pty"
        self.tz = tz                  # TZ pentru shell (ex. "Europe/Bucharest")
        self.created = time.time()
        self.last_output = self.created
        self.exited_at = None
        self.alive = True
        self.exit_status = None
        self.exit_signal = None
        self.attached = False
        self.kill_requested = False
        self.respawns = 0
        self.last_respawn = 0.0
        self.client_started = 0.0     # când a pornit clientul tmux curent (vezi TMUX_CLIENT_HEALTHY)
        self.retry_at = 0.0           # >0 = fără client ataşat, reîncercăm la momentul ăsta
        self.pending_input = b""
        self.ring = []                # list of (offset, bytes)
        self.ring_bytes = 0
        self.stream_offset = 0
        self.spawn_client()

    def spawn_client(self):
        """Start the pty child: either `tmux new-session -A` (survives agent
        death, re-adopted by name) or a direct login shell as fallback."""
        pid, master = pty.fork()
        if pid == 0:                  # child
            try:
                shell = pwd.getpwuid(os.getuid()).pw_shell or "/bin/sh"
            except KeyError:
                shell = "/bin/sh"
            env = dict(os.environ)
            env["TERM"] = self.term
            env["COLORTERM"] = "truecolor"
            env["WEBTERM_SESSION"] = self.sid
            if self.tz:               # sincronizează ora cu fusul ales, fără a atinge serverul
                env["TZ"] = self.tz
            for k in list(env):
                if k.startswith("SSH_") and k != "SSH_AUTH_SOCK":
                    env.pop(k)
            os.chdir(os.path.expanduser("~"))
            try:
                if self.backend == "tmux":
                    # -D: la re-atașare, detașează orice alt client de pe aceeași
                    # sesiune. Fără el, un client rămas orfan (agent repornit,
                    # client vechi care n-a murit) stă atașat în paralel: tmux
                    # strânge pane-ul la cel mai mic client ȘI redesenează pentru
                    # amândoi → linii duplicate/artefacte, mai ales la TUI-uri
                    # care se redesenează des. Un singur client per sesiune.
                    argv = [TMUX_BIN, "-L", TMUX_SOCKET, "-f", TMUX_CONF,
                            "new-session", "-A", "-D", "-s", TMUX_SESSION_PREFIX + self.sid]
                    if self.cmd:
                        argv += [shell, "-lc", self.cmd]
                    os.execve(TMUX_BIN, argv, env)
                elif self.cmd:
                    os.execve(shell, [shell, "-lc", self.cmd], env)
                else:
                    os.execve(shell, ["-" + os.path.basename(shell)], env)
            except OSError:
                os._exit(127)
        self.pid = pid
        self.master = master
        self.client_started = time.time()
        self.retry_at = 0.0
        os.set_blocking(master, False)
        # CLOEXEC pe master: la re-exec-ul agentului (update), fd-ul master TREBUIE să
        # se închidă, altfel clientul tmux vechi își ține PTY-ul deschis și NU moare
        # (deşi `-D` îl detaşează) → clienţi acumulaţi peste re-exec-uri → epuizare de
        # fd pe serverul tmux → „server exited unexpectedly". Noul agent re-adoptă
        # sesiunile cu clienţi proaspeţi, deci masterele vechi nu trebuie moştenite.
        os.set_inheritable(master, False)
        self.set_winsize(self.rows, self.cols)

    def set_winsize(self, rows, cols):
        # clamp to the unsigned-short range TIOCSWINSZ accepts; an out-of-range
        # value (e.g. a bogus resize frame) would make struct.pack raise
        # struct.error — not an OSError — and take down the whole agent loop
        rows = max(1, min(65535, int(rows)))
        cols = max(1, min(65535, int(cols)))
        self.rows, self.cols = rows, cols
        if self.master is None:
            return          # între clienţi (reataşare cu backoff): mărimea se aplică la spawn
        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            os.kill(self.pid, signal.SIGWINCH)
        except OSError:
            pass

    @property
    def buffer_base(self):
        return self.ring[0][0] if self.ring else self.stream_offset

    def append_output(self, data):
        self.ring.append((self.stream_offset, data))
        self.stream_offset += len(data)
        self.ring_bytes += len(data)
        self.last_output = time.time()
        while self.ring_bytes > RING_LIMIT and len(self.ring) > 1:
            _, old = self.ring.pop(0)
            self.ring_bytes -= len(old)

    def replay_chunks(self, from_offset):
        """Yield output bytes from max(from_offset, buffer_base) onward."""
        start = self.buffer_base if from_offset is None else max(from_offset, self.buffer_base)
        for off, chunk in self.ring:
            end = off + len(chunk)
            if end <= start:
                continue
            yield chunk[start - off:] if off < start else chunk
        return

    def meta(self):
        return {
            "sid": self.sid, "pid": self.pid, "alive": self.alive,
            "rows": self.rows, "cols": self.cols, "backend": self.backend,
            "created": self.created, "last_output": self.last_output,
            "exit_status": self.exit_status, "exit_signal": self.exit_signal,
            "stream_offset": self.stream_offset, "buffer_base": self.buffer_base,
            "attached": self.attached,
        }


# ---------------------------------------------------------------------------
# Agent main loop
# ---------------------------------------------------------------------------

def _set_keepalive(sock, idle=60, intvl=15, cnt=4):
    """TCP keepalive pe un socket de forward: un peer care dispare fără FIN (device
    care face idle-disconnect half-open, NAT care uită starea) e detectat în ~idle +
    intvl*cnt secunde (≈120s) → recv întoarce EOF/eroare → tunelul se închide, iar
    gateway-ul marchează sesiunea telnet 'lost' în loc s-o lase fantomă 'live'.
    Opțiunile per-socket sunt Linux; le aplicăm best-effort (guard hasattr)."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, intvl)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, cnt)
    except OSError:
        pass


def _sd_notify(state):
    """systemd sd_notify (stdlib, fără libsystemd): trimite un mesaj de stare pe
    $NOTIFY_SOCKET. No-op dacă socketul lipsește (cron/manual/systemd fără WatchdogSec).
    Cu `WatchdogSec` în unit, systemd setează NOTIFY_SOCKET + WATCHDOG_USEC; agentul
    trimite `WATCHDOG=1` la fiecare tick → dacă event-loop-ul se blochează (nu mai
    ticăie), systemd îl omoară + repornește. Complementar watchdog-ului cron (G1)."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr.startswith("@"):                 # namespace abstract Linux
        addr = "\0" + addr[1:]
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            s.sendto(state.encode() if isinstance(state, str) else state, addr)
        finally:
            s.close()
    except OSError:
        pass


class Forward:
    """Un tunel TCP către un serviciu local pe host (port forwarding). Socket
    non-blocant multiplexat în bucla de `selectors`, exact ca un PTY. Există doar
    cât timp curge trafic real (un tab de browser deschis); nu se ține deschis
    pentru forward-urile doar declarate."""
    __slots__ = ("stream_id", "sock", "connecting", "wbuf", "opened_at")

    def __init__(self, stream_id, sock):
        self.stream_id = stream_id
        self.sock = sock
        self.connecting = True        # connect() non-blocant încă în curs
        self.wbuf = b""               # octeți de scris către țintă, în așteptare
        self.opened_at = time.time()  # pt. abandonarea connect-urilor blocate (vezi _tick)


class Serial:
    """O consolă serială (RS232/RS485/USB) deschisă pe host: un fd `/dev/tty*`
    configurat cu termios, multiplexat în `selectors` exact ca un PTY. Bridge de
    octeți bruți către gateway prin FRAME_FWD (același transport ca forward-urile)."""
    __slots__ = ("stream_id", "fd", "wbuf", "opened_at")

    def __init__(self, stream_id, fd):
        self.stream_id = stream_id
        self.fd = fd
        self.wbuf = b""
        self.opened_at = time.time()


_TIOCGSERIAL = 0x541E

# linux/serial.h PORT_* → nume prietenos (doar tipurile uzuale de UART real)
_UART_TYPES = {1: "8250", 2: "16450", 3: "16550", 4: "16550A", 5: "Cirrus",
               6: "16650", 7: "16650V2", 8: "16750", 9: "Startech",
               10: "16C950", 11: "16654", 12: "16850", 13: "RSA"}


def _serial_uart_type(dev):
    """Tipul UART din TIOCGSERIAL.type. 0 = fantomă serial8250 (fără hardware); None la eroare."""
    try:
        fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        buf = bytearray(72)
        fcntl.ioctl(fd, _TIOCGSERIAL, buf)
        return struct.unpack("i", bytes(buf[:4]))[0]
    except OSError:
        return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _sys_read(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _serial_meta(name):
    """Metadate bogate pentru un port serial, din /sys (stdlib, fără pyudev): driver +,
    dacă e USB, VID:PID / producător / produs / serial — urcând din interfaţa tty până la
    nodul USB care poartă `idVendor` (interfaţa are `:1.0`, device-ul e părintele)."""
    m = {"driver": "", "vid": "", "pid": "", "vendor": "", "product": "", "serial": ""}
    base = "/sys/class/tty/%s" % name
    try:
        m["driver"] = os.path.basename(os.readlink(base + "/device/driver"))
    except OSError:
        pass
    d = os.path.realpath(base + "/device")
    for _ in range(6):
        if os.path.exists(os.path.join(d, "idVendor")):
            m["vid"] = _sys_read(os.path.join(d, "idVendor"))
            m["pid"] = _sys_read(os.path.join(d, "idProduct"))
            m["vendor"] = _sys_read(os.path.join(d, "manufacturer"))
            m["product"] = _sys_read(os.path.join(d, "product"))
            m["serial"] = _sys_read(os.path.join(d, "serial"))
            break
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return m


def _serial_busy_map():
    """{/dev/tty*: 'comm[pid]'} — porturi ţinute deschise de vreun proces (scan /proc/*/fd).
    Include şi sesiunile seriale WebTerm în curs (util: „e deja folosit de X")."""
    busy = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return busy
    for pid in pids:
        fddir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fddir)
        except OSError:
            continue                                   # proces dispărut / fără drept
        for fd in fds:
            try:
                tgt = os.readlink(os.path.join(fddir, fd))
            except OSError:
                continue
            if tgt.startswith("/dev/tty") and tgt not in busy:
                busy[tgt] = "%s[%s]" % (_sys_read("/proc/%s/comm" % pid) or "?", pid)
    return busy


def serial_ports():
    """Enumeră porturile seriale reale (ttyUSB/ttyACM/ttyAMA + ttyS* cu hardware) cu
    metadate bogate: nume stabile (by-id), cale fizică USB (by-path), VID:PID, serial USB,
    producător/produs, driver, tip UART şi dacă portul e ţinut deschis de un proces."""
    def _links(pat):
        m = {}
        for link in sorted(glob.glob(pat)):
            try:
                m[os.path.realpath(link)] = link
            except OSError:
                pass
        return m
    byid = _links("/dev/serial/by-id/*")
    bypath = _links("/dev/serial/by-path/*")
    busy = _serial_busy_map()
    out = {}
    try:
        names = sorted(os.listdir("/sys/class/tty"))
    except OSError:
        names = []
    for name in names:
        if not os.path.exists("/sys/class/tty/%s/device" % name):
            continue                                   # port fantomă
        dev = "/dev/" + name
        if not os.path.exists(dev):
            continue
        uart = None
        if name.startswith(("ttyUSB", "ttyACM", "ttyAMA")) or dev in byid:
            pass                                       # USB/embedded/by-id: real
        elif name.startswith("ttyS"):
            t = _serial_uart_type(dev)
            if not t:                                  # 0/None = fantomă serial8250
                continue
            uart = _UART_TYPES.get(t, "tip %d" % t)
        else:
            continue
        meta = _serial_meta(name)
        label = (meta["product"]
                 or (os.path.basename(byid[dev]) if dev in byid else "")
                 or (("UART %s" % uart) if uart else name))
        out[dev] = {
            "device": dev,
            "by_id": byid.get(dev),
            "by_path": bypath.get(dev),
            "vid": meta["vid"], "pid": meta["pid"],
            "vendor": meta["vendor"], "product": meta["product"],
            "serial": meta["serial"], "driver": meta["driver"],
            "uart": uart,
            "busy": busy.get(dev, ""),
            "desc": label,                             # etichetă prietenoasă (back-compat)
        }
    return sorted(out.values(), key=lambda p: p["device"])


def _configure_serial(fd, baud, bits, parity, stop, flow):
    """Configurează termios pentru o consolă serială (raw mode + baud/paritate/...)."""
    baud_const = getattr(termios, "B%d" % int(baud), None)
    if baud_const is None:
        raise ValueError("baud nesuportat: %s" % baud)
    a = termios.tcgetattr(fd)          # [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
    a[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP
             | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
    a[1] &= ~termios.OPOST
    a[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
    a[2] &= ~(termios.CSIZE | termios.PARENB | termios.PARODD | termios.CSTOPB | termios.CRTSCTS)
    a[2] |= termios.CLOCAL | termios.CREAD             # ignoră liniile de modem, activează RX
    a[2] |= {5: termios.CS5, 6: termios.CS6, 7: termios.CS7, 8: termios.CS8}.get(int(bits), termios.CS8)
    if parity == "even":
        a[2] |= termios.PARENB
    elif parity == "odd":
        a[2] |= termios.PARENB | termios.PARODD
    if int(stop) == 2:
        a[2] |= termios.CSTOPB
    if flow == "rtscts":
        a[2] |= termios.CRTSCTS
    elif flow == "xonxoff":
        a[0] |= termios.IXON | termios.IXOFF
    a[4] = baud_const
    a[5] = baud_const
    termios.tcsetattr(fd, termios.TCSANOW, a)


class Agent:
    def __init__(self, config):
        self.config = config
        self.sessions = {}            # sid -> Session
        self.forwards = {}            # stream_id -> Forward (port forwarding)
        self.serials = {}             # stream_id -> Serial (console seriale)
        self._run_sem = threading.Semaphore(MAX_RUNS)   # cap pe rulările `run` concurente
        # epoch identifies this agent process' stream-offset space: after an
        # agent restart offsets reset, so the gateway must not reuse old ones
        self.epoch = binascii.hexlify(os.urandom(8)).decode()
        self.backend = "tmux" if TMUX_BIN else "pty"
        if self.backend == "tmux":
            with open(TMUX_CONF, "w") as f:
                f.write(TMUX_CONF_CONTENT)
            tmux_apply_conf()
        self.sel = selectors.DefaultSelector()
        self.ws = None
        self.outbox = queue.Queue()
        self.outbox_bytes = 0
        self.outbox_lock = threading.Lock()
        self.inbox = queue.Queue()
        self.wake_r, self.wake_w = os.pipe()
        os.set_blocking(self.wake_r, False)
        self.sel.register(self.wake_r, selectors.EVENT_READ, ("wake", None))
        self.connected = False
        self.backoff = BACKOFF_MIN
        self.next_connect = 0.0
        self.next_heartbeat = 0.0
        # Health de link (Faza 3 observabilitate): heartbeat-ack + RTT + flapping.
        self._hb_seq = 0              # secvenţă de heartbeat (pt. ack + RTT)
        self._hb_sent_at = {}         # seq -> timp trimitere (pt. RTT; curăţat la ack)
        self._last_hb_ack = 0.0       # ultimul ack primit; dacă lipseşte >HB_ACK_TIMEOUT → half-open
        self._last_rtt = None         # RTT ms din ultimul dus-întors de heartbeat
        self._reconnect_count = 0     # de câte ori a RECONECTAT procesul (semnal de flapping)
        self._ever_connected = False
        self._connected_since = 0.0
        self.stop_requested = False
        self.pending_update = False
        self.reader_thread = None
        self.writer_thread = None
        self.reaped = {}              # pid -> waitpid status (from the sweep)
        self._pending_reap = set()    # pid-uri de sesiune ieșite din pty dar încă neieșite → reaper în sweep
        self.metrics = Metrics()
        self._last_alive = 0.0        # G1: throttling pt. fişierul de liveness
        self._last_logcheck = 0.0     # G7: throttling pt. verificarea mărimii logului
        # watchdog systemd: pingăm WATCHDOG=1 la ~jumătate din WatchdogSec (interval
        # sigur, permite un tick ratat). 0 = fără watchdog systemd (cron/manual).
        self._wd_interval = 0.0
        try:
            usec = int(os.environ.get("WATCHDOG_USEC", "0"))
            if usec > 0:
                self._wd_interval = max(1.0, usec / 1e6 / 2.0)
        except ValueError:
            pass
        self._last_wd = 0.0
        # igienă tmux (evită husk-uri care consumă resurse invizibil): prima trecere
        # e amânată ca să ruleze DUPĂ adopția de la pornire (nu înaintea ei)
        self._next_tmux_sweep = time.time() + TMUX_SWEEP_INTERVAL
        self._last_server_kill = 0.0  # cooldown pt. omorârea serverului tmux înțepenit
        # deconectare cerută din afara loop-ului (ex. overflow de outbox semnalat de un
        # thread worker) — loop-ul o execută pe thread-ul propriu (vezi run)
        self._disconnect_requested = False
        self._connecting = False       # o conectare e în curs pe un thread worker (vezi _start_connect)
        self._connect_started = 0.0    # când a pornit (pt. plasa anti-blocare din buclă)

    # -- outbound ----------------------------------------------------------

    def _wake(self):
        try:
            os.write(self.wake_w, b"x")
        except OSError:
            pass

    def send_frame(self, payload):
        if not self.connected:
            return
        with self.outbox_lock:
            self.outbox_bytes += len(payload)
            over = self.outbox_bytes > OUTBOX_LIMIT
        if over:
            # gateway blocat: outbox-ul a crescut peste plafon. NU face _disconnect() AICI —
            # send_frame poate rula pe un thread worker (_run_command/_rmtree → send_ctrl), iar
            # _disconnect mută selector-ul (unregister) în timp ce loop-ul principal e în
            # sel.select() → „dict changed size during iteration" / corupere → crash de loop.
            # Semnalizează loop-ul, care se deconectează pe thread-ul propriu.
            log("outbox overflow (%d bytes), dropping connection" % self.outbox_bytes)
            self._disconnect_requested = True
            self._wake()
            return
        self.outbox.put(payload)

    def send_ctrl(self, obj):
        self.send_frame(FRAME_CTRL + json.dumps(obj).encode())

    def send_data(self, sid, data):
        self.send_frame(FRAME_DATA + sid.encode() + data)

    def _persist_cert_pin(self, pin):
        """Fixează amprenta certificatului gateway-ului în agent.json (TOFU, mod insecure).
        Scriere atomică (temp + rename), permisiuni 0600."""
        try:
            with open(CONFIG_PATH) as f:
                data = json.load(f)
            data["cert_pin"] = pin
            tmp = CONFIG_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, CONFIG_PATH)
            log("cert pin fixat (TOFU, mod insecure): %s…" % pin[:16])
        except (OSError, ValueError) as e:
            log("could not pin the certificate in %s: %s" % (CONFIG_PATH, e))

    # -- connection lifecycle ----------------------------------------------

    def _start_connect(self):
        """Pornește o conectare pe un THREAD worker (non-blocant). Connect-ul TCP+TLS+handshake
        ar bloca event-loop-ul ~15s (sau la nesfârșit dacă un gateway ostil picură handshake-ul),
        oprind citirea PTY-urilor/forward-urilor și heartbeat-urile. Loop-ul continuă să servească
        selectorul cât timp thread-ul face handshake-ul; rezultatul revine prin inbox
        (__connected__ / __connect_failed__). Cel mult o conectare în curs (gardat de _connecting)."""
        self._connecting = True
        self._connect_started = time.time()
        cfg = self.config
        ws = WSClient(cfg["url"], cfg["token"], insecure=cfg.get("insecure", False),
                      cert_pin=cfg.get("cert_pin"))
        threading.Thread(target=self._connect_worker, args=(ws,), daemon=True).start()

    def _connect_worker(self, ws):
        # rulează pe thread separat: verifică cert_pin (dacă e setat) înainte de a trimite tokenul;
        # WSClient impune un termen-limită TOTAL pe handshake (anti drip-feed).
        #
        # Se prindeau DOAR (WSError, OSError, ssl.SSLError). Orice altceva scăpa din thread fără
        # să pună nimic în inbox, deci `_connecting` rămânea True pentru totdeauna, iar loop-ul
        # nu mai încerca niciodată o reconectare (gardul din buclă e chiar `_connecting`).
        # Agentul rămânea offline definitiv — cu AMBELE watchdog-uri verzi, fiindcă `_tick`
        # continuă să atingă fişierul de viaţă. Nu e ipotetic: pe Python 3.6 `ssl.CertificateError`
        # e subclasă de ValueError, deci o simplă schimbare de certificat era de ajuns.
        queued = False
        try:
            ws.connect()
            self.inbox.put(("__connected__", ws))
            queued = True
        except Exception as e:          # noqa: BLE001 — orice eroare TREBUIE raportată loop-ului
            try:
                self.inbox.put(("__connect_failed__", "%s: %s" % (type(e).__name__, e)))
                queued = True
            except Exception:           # noqa: BLE001
                pass
        finally:
            if not queued:              # nici măcar raportarea n-a mers → deblochează oricum
                try:
                    self.inbox.put(("__connect_failed__", "internal error while connecting"))
                except Exception:       # noqa: BLE001
                    pass
            self._wake()

    def _on_connect_failed(self, err):
        self._connecting = False
        self._connected_since = 0.0
        self.next_connect = time.time() + self.backoff
        self.backoff = min(self.backoff * 2, BACKOFF_MAX)
        log("connect failed: %s" % err)

    def _on_connected(self, ws):
        """Rulează pe thread-ul loop-ului: cablează o conexiune reușită (reader/writer/hello)."""
        self._connecting = False
        if self.connected or self.stop_requested:   # rezultat învechit (deja conectați / la oprire)
            try:
                ws.close()
            except OSError:
                pass
            return
        cfg = self.config
        # TOFU (mod insecure, fără pin încă): fixează amprenta certificatului la prima conectare
        if cfg.get("insecure") and not cfg.get("cert_pin") and ws.peer_pin:
            cfg["cert_pin"] = ws.peer_pin
            self._persist_cert_pin(ws.peer_pin)
        self.ws = ws
        self.connected = True
        # health de link: resetăm secvenţa/ack la fiecare conexiune nouă
        now0 = time.time()
        self._connected_since = now0
        self._last_hb_ack = now0
        self._hb_seq = 0
        self._hb_sent_at.clear()
        if self._ever_connected:
            self._reconnect_count += 1     # numărăm RE-conectările (nu prima)
        self._ever_connected = True
        # COADĂ PER-CONEXIUNE: writer-ul citește coada pe care i-o dăm ca argument, nu
        # `self.outbox`. Astfel un writer vechi (dintr-o conexiune anterioară, încă blocat în
        # `get()`) nu mai poate FURA frame-ul `hello` al conexiunii noi — el drenează exclusiv
        # coada lui veche (unde `_disconnect` a pus otrava None) și iese. Fără asta, ambii writeri
        # concurau pe aceeași coadă și hello putea ajunge pe socketul mort.
        with self.outbox_lock:
            self.outbox = queue.Queue()
            self.outbox_bytes = 0
        outbox = self.outbox
        self.reader_thread = threading.Thread(target=self._reader, args=(ws,), daemon=True)
        self.writer_thread = threading.Thread(target=self._writer, args=(ws, outbox), daemon=True)
        self.reader_thread.start()
        self.writer_thread.start()
        self.send_ctrl({
            "event": "hello", "agent_version": AGENT_VERSION, "proto": PROTO,
            "epoch": self.epoch, "backend": self.backend,
            "hostname": socket.gethostname(), "user": pwd.getpwuid(os.getuid()).pw_name,
            "pid": os.getpid(), "metrics": self.metrics.sample(),
            "reconnects": self._reconnect_count, "uptime": 0,
            "sessions": [s.meta() for s in self.sessions.values()],
        })
        self.next_heartbeat = time.time() + HEARTBEAT_INTERVAL
        log("connected to %s" % cfg["url"])

    def _disconnect(self):
        if not self.connected:
            return
        self.connected = False
        for s in self.sessions.values():
            s.attached = False
        # forward-urile + consolele seriale aparțin conexiunii cu gateway-ul → cad toate
        for stream in list(self.forwards):
            self._fwd_teardown(stream, notify=False)
        for stream in list(self.serials):
            self._serial_teardown(stream, notify=False)
        ws, self.ws = self.ws, None
        if ws:
            ws.close()
        self.outbox.put(None)         # unblock writer
        # Backoff-ul se resetează după o conexiune care a REZISTAT, nu după una care doar s-a
        # deschis. Se reseta la fiecare `_on_connected`, deci un middlebox care taie legăturile
        # inactive sub intervalul de heartbeat producea churn perpetuu la 1 secundă: măsurat cu
        # un proxy care taie la 12s — reconectare la fiecare ~30s, la infinit, iar hostul rămâne
        # `online`, deci nimeni nu vede nimic. Acum backoff-ul creşte până la BACKOFF_MAX cât
        # timp conexiunile mor repede, şi coboară abia când una chiar ţine.
        if self._connected_since and time.time() - self._connected_since >= STABLE_CONNECTION:
            self.backoff = BACKOFF_MIN
        self._connected_since = 0.0
        self.next_connect = time.time() + self.backoff
        self.backoff = min(self.backoff * 2, BACKOFF_MAX)
        log("disconnected; retry in %.0fs" % (self.next_connect - time.time()))

    def _reader(self, ws):
        try:
            while True:
                opcode, payload = ws.recv_message()
                self.inbox.put(payload)
                self._wake()
        except (WSError, OSError) as e:
            self.inbox.put(("__disconnect__", str(e), ws))
            self._wake()

    def _writer(self, ws, outbox):
        # `outbox` e coada ACESTEI conexiuni (vezi _on_connected). Un writer vechi rămâne pe
        # coada lui → nu atinge frame-urile conexiunii curente.
        while True:
            item = outbox.get()
            if item is None:
                return
            try:
                ws.send_message(item)
            except (WSError, OSError) as e:
                self.inbox.put(("__disconnect__", "send: %s" % e, ws))
                self._wake()
                return
            with self.outbox_lock:
                # ajustăm contorul de backpressure DOAR dacă suntem încă writer-ul activ
                # (altfel un writer vechi ar corupe contorul conexiunii noi)
                if outbox is self.outbox:
                    self.outbox_bytes -= len(item)

    # -- control ops from gateway -------------------------------------------

    def _run_command(self, rid, cmd, cmd_timeout):
        """Rulează comanda în shell-ul de login al userului (PATH/aliasuri ca la
        tastare), capturează stdout/stderr + exit code, trimite reply-ul cu id-ul
        cererii. Rulează într-un thread; send_ctrl e thread-safe (outbox). Niciun
        privilegiu nou: agentul rulează oricum comenzi ca tine în PTY — aici doar le
        capturează.

        G3: citim INCREMENTAL cu `select`, ţinând în RAM DOAR cât trimitem
        (RUN_OUTPUT_CAP/flux). Dacă totalul depăşeşte RUN_CAPTURE_HARD (comandă
        guralivă — `yes`, `cat /dev/zero`), omorâm procesul. Fără asta,
        subprocess.run(PIPE) materializa TOT output-ul în memorie → OOM."""
        start = time.time()
        shell = os.environ.get("SHELL") or "/bin/bash"
        try:
            p = subprocess.Popen(
                [shell, "-lc", cmd], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True)      # grup propriu → omorâm tot arborele la runaway
        except Exception as e:
            self.send_ctrl({"ok": False, "id": rid, "code": "run_error", "msg": str(e)})
            return
        ofd, efd = p.stdout.fileno(), p.stderr.fileno()
        bufs = {ofd: bytearray(), efd: bytearray()}
        total = 0
        open_fds = {ofd, efd}
        deadline = start + cmd_timeout
        timed_out = capped = False
        try:
            while open_fds:
                remaining = deadline - time.time()
                if remaining <= 0:
                    timed_out = True
                    break
                r, _, _ = select.select(list(open_fds), [], [], min(remaining, 1.0))
                for fd in r:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        chunk = b""
                    if not chunk:                    # EOF pe fluxul ăsta
                        open_fds.discard(fd)
                        continue
                    total += len(chunk)
                    buf = bufs[fd]
                    if len(buf) < RUN_OUTPUT_CAP:     # ţinem doar cât trimitem
                        buf += chunk[:RUN_OUTPUT_CAP - len(buf)]
                    if total > RUN_CAPTURE_HARD:      # runaway → oprim procesul
                        capped = True
                        break
                if capped:
                    break
        finally:
            if p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except OSError:
                    try:
                        p.kill()
                    except OSError:
                        pass
            try:
                p.wait(timeout=2)
            except Exception:                        # noqa: BLE001
                pass
            for f in (p.stdout, p.stderr):
                try:
                    f.close()
                except Exception:                    # noqa: BLE001
                    pass
        err = bytes(bufs[efd])
        if capped:
            err = (err[:RUN_OUTPUT_CAP] +
                   ("\n[webterm: output peste %d MB — proces oprit]"
                    % (RUN_CAPTURE_HARD // (1024 * 1024))).encode("utf-8"))
        self.send_ctrl({
            "ok": True, "id": rid,
            "exit_code": None if (timed_out or capped) else p.returncode,
            "timed_out": timed_out,
            "stdout": bytes(bufs[ofd])[:RUN_OUTPUT_CAP].decode("utf-8", "replace"),
            "stderr": err[:RUN_OUTPUT_CAP + 64].decode("utf-8", "replace"),
            "duration": round(time.time() - start, 3)})

    def _run_command_guarded(self, rid, cmd, cmd_timeout):
        """Rulează comanda şi ELIBERĂ MEREU slotul din `_run_sem` (chiar la return-ul timpuriu
        de la Popen eşuat sau o excepţie neaşteptată) — altfel slotul s-ar scurge şi capul de
        rulări concurente s-ar epuiza permanent."""
        try:
            self._run_command(rid, cmd, cmd_timeout)
        finally:
            self._run_sem.release()

    def handle_ctrl(self, msg):
        op = msg.get("op")
        rid = msg.get("id")

        if msg.get("type") == "hb_ack":     # ack de heartbeat (health de link + RTT dus-întors)
            self._last_hb_ack = time.time()
            sent = self._hb_sent_at.pop(msg.get("seq", 0), None)
            if sent is not None:
                self._last_rtt = round((time.time() - sent) * 1000)
            return

        def ok(**kw):
            r = {"ok": True, "id": rid}
            r.update(kw)
            self.send_ctrl(r)

        def err(code, text=""):
            self.send_ctrl({"ok": False, "id": rid, "code": code, "msg": text})

        try:
            if op == "create":
                sid = msg.get("sid")
                # protocolul feliază sid pe exact SID_LEN octeți pe sârmă (FRAME_DATA/FWD);
                # un sid malformat ar rula input-ul/output-ul pe granițe greșite. Adopt-ul
                # tmux valida deja lungimea (vezi mai jos) — calea `create` nu o făcea.
                if not isinstance(sid, str) or len(sid) != SID_LEN:
                    return err("bad_sid")
                if sid in self.sessions:
                    return err("exists")
                if len(self.sessions) >= MAX_SESSIONS:
                    return err("limit")
                s = Session(sid, int(msg.get("rows", 24)), int(msg.get("cols", 80)),
                            msg.get("term", "xterm-256color"), msg.get("cmd"),
                            backend=self.backend, tz=msg.get("tz"))
                self.sessions[sid] = s
                self.sel.register(s.master, selectors.EVENT_READ, ("pty", sid))
                ok(pid=s.pid, stream_offset=0, backend=s.backend)

            elif op == "attach":
                s = self.sessions.get(msg["sid"])
                if not s:
                    return err("no_session")
                from_offset = msg.get("from_offset")
                truncated = from_offset is not None and from_offset < s.buffer_base
                replay_start = s.buffer_base if from_offset is None else max(from_offset, s.buffer_base)
                s.attached = True
                ok(replay_start=replay_start, stream_offset=s.stream_offset,
                   truncated=truncated, alive=s.alive, rows=s.rows, cols=s.cols)
                for chunk in s.replay_chunks(from_offset):
                    self.send_data(s.sid, chunk)
                self.send_ctrl({"event": "replay_end", "sid": s.sid, "offset": s.stream_offset})

            elif op == "detach":
                s = self.sessions.get(msg["sid"])
                if s:
                    s.attached = False
                ok()

            elif op == "resize":
                s = self.sessions.get(msg["sid"])
                if not s:
                    return err("no_session")
                s.set_winsize(int(msg["rows"]), int(msg["cols"]))
                ok()

            elif op == "kill":
                s = self.sessions.get(msg["sid"])
                if not s:
                    return err("no_session")
                s.kill_requested = True
                if s.alive:
                    if s.backend == "tmux":
                        try:
                            tmux_cmd("kill-session", "-t",
                                     "=" + TMUX_SESSION_PREFIX + s.sid)
                        except (OSError, subprocess.TimeoutExpired):
                            pass
                    try:
                        if s.pid:      # None cât suntem între clienţi; kill-session e de-ajuns
                            os.kill(s.pid, int(msg.get("sig", signal.SIGHUP)))
                    except OSError:
                        pass
                ok()

            elif op == "reap":
                s = self.sessions.get(msg["sid"])
                if not s:
                    return err("no_session")
                if s.alive:
                    return err("alive")
                self._drop_session(s)
                ok()

            elif op == "list":
                ok(sessions=[s.meta() for s in self.sessions.values()],
                   agent_version=AGENT_VERSION, proto=PROTO)

            elif op == "run":
                # rulare non-interactivă a unei comenzi (consola de flotă): captură
                # stdout/stderr + exit code. Într-un thread ca să NU blocheze bucla
                # de selector (sesiuni + heartbeat trebuie să meargă mai departe).
                cmd = msg.get("cmd") or ""
                if not cmd:
                    return err("bad_request", "empty command")
                cmd_timeout = min(max(int(msg.get("cmd_timeout", 60)), 1), RUN_MAX_TIMEOUT)
                # cap pe rulări concurente: reject NON-blocant (nu blocăm un thread în plus),
                # ca sute de cereri simultane să nu pornească sute de procese/thread-uri.
                if not self._run_sem.acquire(blocking=False):
                    return err("run_limit", "too many concurrent runs on this host (max %d)" % MAX_RUNS)
                threading.Thread(target=self._run_command_guarded,
                                 args=(rid, cmd, cmd_timeout), daemon=True).start()
                # NU răspundem aici — worker-ul trimite reply-ul cu același id

            elif op == "fs_list":
                path = os.path.expanduser(msg.get("path") or "~")
                path = os.path.abspath(path)
                try:
                    entries = []
                    with os.scandir(path) as it:
                        for e in it:
                            try:
                                st = e.stat(follow_symlinks=False)
                                entries.append({
                                    "name": e.name,
                                    "dir": e.is_dir(follow_symlinks=False),
                                    "link": e.is_symlink(),
                                    "size": st.st_size,
                                    "mtime": int(st.st_mtime),
                                    "mode": st.st_mode & 0o777,
                                })
                            except OSError:
                                continue
                            if len(entries) >= FS_MAX_LIST:
                                break
                    entries.sort(key=lambda x: (not x["dir"], x["name"].lower()))
                    parent = os.path.dirname(path.rstrip("/")) or "/"
                    ok(path=path, parent=parent, entries=entries,
                       truncated=len(entries) >= FS_MAX_LIST)
                except OSError as e:
                    err("fs_error", "%s: %s" % (path, e.strerror or e))

            elif op == "fs_read":
                path = os.path.abspath(os.path.expanduser(msg["path"]))
                offset = int(msg.get("offset", 0))
                try:
                    st = os.stat(path)
                    # doar fișiere obișnuite: un FIFO/dispozitiv (/dev/zero) ar
                    # stream-ui la infinit, un socket/director n-are conținut de citit
                    if not stat.S_ISREG(st.st_mode):
                        err("fs_error", "not a regular file (directory/device/socket)")
                    else:
                        with open(path, "rb") as f:
                            f.seek(offset)
                            chunk = f.read(FS_CHUNK)
                        ok(path=path, offset=offset, size=st.st_size,
                           mtime=int(st.st_mtime),
                           eof=offset + len(chunk) >= st.st_size,
                           data_b64=base64.b64encode(chunk).decode())
                except OSError as e:
                    err("fs_error", "%s: %s" % (path, e.strerror or e))

            elif op == "fs_write":
                path = os.path.abspath(os.path.expanduser(msg["path"]))
                data = base64.b64decode(msg["data_b64"])
                off = int(msg.get("offset", 0))
                # O_NOFOLLOW: nu scriem prin symlink (upload-ul aterizează exact
                # unde arată calea, nu unde duce un link pre-creat). Numele temp e
                # oricum aleator acum, dar e apărare în adâncime.
                try:
                    if off == 0:
                        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
                    else:
                        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
                    with os.fdopen(fd, "ab") as f:
                        f.write(data)
                    ok(path=path, written=len(data))
                except OSError as e:
                    err("fs_error", "%s: %s" % (path, e.strerror or e))

            elif op == "fs_mkdir":
                path = os.path.abspath(os.path.expanduser(msg["path"]))
                parents = bool(msg.get("parents"))   # upload de folder: idempotent
                try:
                    if parents:
                        os.makedirs(path, 0o755, exist_ok=True)
                    else:
                        os.mkdir(path, 0o755)
                    ok(path=path)
                except OSError as e:
                    err("fs_error", "%s: %s" % (path, e.strerror or e))

            elif op == "fs_rename":
                src = os.path.abspath(os.path.expanduser(msg["path"]))
                dst = os.path.abspath(os.path.expanduser(msg["to"]))
                overwrite = bool(msg.get("overwrite"))
                if_mtime = msg.get("if_mtime")   # None = fără verificare conflict
                try:
                    if not overwrite and os.path.lexists(dst):
                        err("fs_error", "the destination already exists")
                    elif (if_mtime is not None and os.path.lexists(dst)
                          and int(os.stat(dst).st_mtime) != int(if_mtime)):
                        # fișierul s-a schimbat între citire și salvare → nu-l
                        # suprascriem orbește (editare concurentă / din terminal)
                        err("conflict", "the file changed in the meantime")
                    else:
                        # commit upload = os.replace peste temp: fișierul final
                        # moștenește permisiunile TEMP-ului (0644), nu ale țintei.
                        # Păstrăm modul original — altfel o cheie SSH 0600 devine
                        # world-readable la salvare (și SSH o refuză).
                        keep_mode = None
                        if overwrite:
                            try:
                                keep_mode = stat.S_IMODE(os.stat(dst).st_mode)
                            except OSError:
                                keep_mode = None
                        # os.replace = atomic overwrite (commit upload);
                        # os.rename pe o destinație inexistentă = mutare/redenumire
                        os.replace(src, dst) if overwrite else os.rename(src, dst)
                        if keep_mode is not None:
                            try:
                                os.chmod(dst, keep_mode)
                            except OSError:
                                pass
                        ok(path=dst)
                except OSError as e:
                    err("fs_error", "%s: %s" % (src, e.strerror or e))

            elif op == "fs_delete":
                path = os.path.abspath(os.path.expanduser(msg["path"]))
                recursive = bool(msg.get("recursive"))
                if recursive and os.path.isdir(path) and not os.path.islink(path):
                    # G6: rmtree pe un arbore mare ar bloca event-loop-ul secunde → pe
                    # thread, cu reply asincron (send_ctrl e thread-safe prin outbox).
                    def _rmtree(p=path, _rid=rid):
                        try:
                            shutil.rmtree(p)
                            self.send_ctrl({"ok": True, "id": _rid, "path": p})
                        except OSError as e:
                            self.send_ctrl({"ok": False, "id": _rid, "code": "fs_error",
                                            "msg": "%s: %s" % (p, e.strerror or e)})
                    threading.Thread(target=_rmtree, daemon=True).start()
                    # nu răspundem aici — thread-ul trimite reply-ul
                else:
                    try:
                        if os.path.islink(path):
                            os.unlink(path)           # nu urmări symlink-ul
                        elif os.path.isdir(path):
                            os.rmdir(path)
                        else:
                            os.remove(path)
                        ok(path=path)
                    except OSError as e:
                        err("fs_error", "%s: %s" % (path, e.strerror or e))

            elif op == "session_cwd":
                # directorul curent al shell-ului sesiunii, FĂRĂ shell integration:
                # tmux știe pane_current_path; altfel citim /proc/<pid>/cwd. Așa
                # panoul de fișiere se deschide unde ești, nu în ~.
                sid = msg.get("sid")
                s = self.sessions.get(sid)
                cwd = None
                if s and s.backend == "tmux":
                    try:
                        # ținta ca SESIUNE (`name:`), NU `=name`: pe tmux 3.4
                        # `display-message -t =name -p …` întoarce GOL (contextul
                        # e pane-target, iar exact-match `=name` nu rezolvă pane-ul
                        # activ), deci cwd cădea pe /proc/<pid> = HOME. `name:`
                        # rezolvă fereastra/pane-ul activ al sesiunii → cwd corect.
                        r = tmux_cmd("display-message", "-t",
                                     TMUX_SESSION_PREFIX + sid + ":",
                                     "-p", "#{pane_current_path}", timeout=5)
                        if r.returncode == 0:
                            cwd = r.stdout.decode("utf-8", "replace").strip() or None
                    except (OSError, subprocess.TimeoutExpired):
                        cwd = None
                if not cwd and s and s.pid:
                    try:
                        cwd = os.readlink("/proc/%d/cwd" % s.pid)
                    except OSError:
                        cwd = None
                ok(cwd=cwd or os.path.expanduser("~"))

            elif op == "fwd_open":
                # deschide un tunel TCP către un serviciu local pe host (port
                # forwarding). connect() non-blocant; finalizarea se detectează pe
                # EVENT_WRITE în bucla principală. stream = id-ul canalului (de la gateway).
                stream = msg.get("stream")
                host = msg.get("host") or "127.0.0.1"
                port = int(msg.get("port") or 0)
                if not stream or stream in self.forwards:
                    return err("exists")
                if len(self.forwards) >= MAX_FORWARDS:
                    return err("limit")
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    _set_keepalive(sock)   # detectează peer mort half-open (ex. Cisco
                                           # exec-timeout fără FIN) în ~120s → EOF → sesiune
                                           # telnet marcată 'lost', nu fantomă 'live'
                    e = sock.connect_ex((host, port))
                    if e not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK):
                        sock.close()
                        return err("connect", os.strerror(e))
                except OSError as ex:
                    return err("connect", str(ex))
                fwd = Forward(stream, sock)
                self.forwards[stream] = fwd
                # EVENT_WRITE: aflăm când s-a finalizat connect-ul non-blocant
                self.sel.register(sock, selectors.EVENT_WRITE, ("fwd", stream))
                ok()

            elif op == "fwd_close":
                # reutilizat și pt. serial: ForwardStream.close() trimite fwd_close
                self._fwd_teardown(msg.get("stream"), notify=False)
                self._serial_teardown(msg.get("stream"), notify=False)
                ok()

            elif op == "serial_list":
                # discovery: porturile seriale reale de pe host (fără fantomele ttyS)
                try:
                    ok(ports=serial_ports())
                except OSError as e:
                    err("serial_error", str(e))

            elif op == "get_log":
                # tail-ul logului agentului (ptyd.log) pentru panoul de Diagnostic — debug fără SSH.
                try:
                    with open(LOG_PATH, "rb") as f:
                        f.seek(0, 2)
                        sz = f.tell()
                        f.seek(max(0, sz - 16384))     # ultimii 16 KiB
                        data = f.read()
                    ok(log=data.decode("utf-8", "replace"), size=sz)
                except OSError as e:
                    err("log_error", str(e))

            elif op == "serial_open":
                stream = msg.get("stream")
                device = msg.get("device") or ""
                if not stream or stream in self.forwards or stream in self.serials:
                    return err("exists")
                if len(self.serials) >= MAX_SERIALS:
                    return err("limit")
                # anti-traversal: doar dispozitive din /dev, fără NUL
                if not device.startswith("/dev/") or "\x00" in device:
                    return err("bad_device", "dispozitiv invalid")
                try:
                    fd = os.open(device, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
                except OSError as e:
                    return err("open", os.strerror(e.errno) if e.errno else str(e))
                try:
                    if not os.isatty(fd):
                        os.close(fd)
                        return err("not_serial", "not a serial device (tty)")
                    _configure_serial(fd, msg.get("baud", 115200), msg.get("bits", 8),
                                      msg.get("parity", "none"), msg.get("stop", 1),
                                      msg.get("flow", "none"))
                except (OSError, ValueError) as e:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    return err("configure", str(e))
                self.serials[stream] = Serial(stream, fd)
                self.sel.register(fd, selectors.EVENT_READ, ("serial", stream))
                ok()

            elif op == "serial_close":
                self._serial_teardown(msg.get("stream"), notify=False)
                ok()

            elif op == "update":
                content = base64.b64decode(msg["content_b64"])
                sig = base64.b64decode(msg.get("sig_b64", "") or "")
                # refuse unsigned / tampered updates — the whole point is that a
                # rogue gateway or MITM can't install code on the host
                if not ed25519_verify(UPDATE_PUBKEY, sig, content):
                    err("update_unsigned", "update signature invalid — refused")
                elif _content_version(content) is not None and _content_version(content) < AGENT_VERSION:
                    # anti-rollback: refuză o versiune mai veche, chiar valid-semnată.
                    # Un gateway compromis (exact adversarul pe care semnătura îl
                    # blochează) ar putea re-trimite o versiune veche ca să reintroducă
                    # o vulnerabilitate reparată ulterior (downgrade-replay).
                    err("update_downgrade",
                        "versiune %d < %d — refuzat (anti-rollback)"
                        % (_content_version(content), AGENT_VERSION))
                elif not _new_agent_starts(content):
                    # Un `ptyd.py` care nu se compilează se scria peste agent, care făcea execv
                    # şi murea — iar supravegherea (systemd Restart=always / watchdog cron la
                    # fiecare minut) repornea la infinit acelaşi fişier stricat. Pe TOATĂ flota
                    # deodată, fiindcă update-ul se împinge la toţi. Recuperarea cerea SSH pe
                    # fiecare maşină: exact situaţia pentru care există produsul ăsta.
                    # Semnătura garantează CINE a trimis codul, nu că el chiar porneşte.
                    err("update_badcode", "the new source does not compile — refused")
                else:
                    new_path = SELF_PATH + ".new"
                    with open(new_path, "wb") as f:
                        f.write(content)
                    os.chmod(new_path, 0o700)
                    # copie de rezervă ÎNAINTE de înlocuire: `compile()` prinde erorile de
                    # sintaxă, dar nu şi o excepţie la import (o constantă calculată greşit,
                    # un modul lipsă pe host-ul ăsta). `.prev` e plasa pentru aia.
                    try:
                        shutil.copy2(SELF_PATH, SELF_PATH + ".prev")
                    except OSError as e:
                        log("could not save the agent backup copy: %s" % e)
                    os.rename(new_path, SELF_PATH)
                    live = any(s.alive for s in self.sessions.values())
                    # force: restart imediat; sesiunile tmux supravietuiesc si sunt
                    # re-adoptate de noul proces (cele pty-fallback se pierd)
                    if live and not msg.get("force"):
                        self.pending_update = True
                        ok(deferred=True)
                    else:
                        ok(deferred=False)
                        self._reexec()

            elif op == "shutdown":
                mode = msg.get("mode", "idle")
                live = any(s.alive for s in self.sessions.values())
                if mode == "force" or not live:
                    ok()
                    self.stop_requested = True
                else:
                    err("busy")

            elif op == "uninstall":
                # dezinstalare completă de pe host: scoate supravegherea (systemd/cron) +
                # serverul tmux + fișierele din ~/.webterm/, apoi IES DEFINITIV (nu repornesc,
                # fiindcă supravegherea a fost scoasă). Ack-ul se trimite SINCRON, ca să ajungă
                # la gateway înainte de închiderea socketului.
                warnings = self._uninstall_agent()
                try:
                    frame = FRAME_CTRL + json.dumps(
                        {"ok": True, "id": rid, "warnings": warnings}).encode()
                    if self.ws:
                        self.ws.send_message(frame)   # thread-safe prin _send_lock
                except Exception:                     # noqa: BLE001
                    pass
                log("uninstall: agent scos de pe host (%d avertismente), ies definitiv"
                    % len(warnings))
                time.sleep(0.3)          # lasă TCP să golească ack-ul înainte de exit
                os._exit(0)

            else:
                err("bad_op", str(op))
        except (KeyError, ValueError, TypeError) as e:
            err("bad_request", str(e))
        except Exception as e:                       # noqa: BLE001
            # G5: NICIUN mesaj nu trebuie să crape agentul (ex. OSError la pty.fork în
            # `create`, sau un tip de excepţie neprevăzut) → altfel s-ar propaga în bucla
            # principală şi ar opri procesul (crash-loop dacă gateway-ul repetă mesajul).
            log("handle_ctrl op=%s failed: %r" % (op, e))
            try:
                err("internal", str(e))
            except Exception:                        # noqa: BLE001
                pass

    def _drop_session(self, s):
        if s.master is not None:
            try:
                self.sel.unregister(s.master)
            except (KeyError, ValueError):
                pass
            try:
                os.close(s.master)
            except OSError:
                pass
            s.master = None
        # Eliberează explicit scrollback-ul. `sessions.pop` scotea ultima referinţă la obiect,
        # dar ring-ul rămânea o listă de sute de obiecte `bytes` până când ajungea gc-ul la ea,
        # iar alocatorul glibc nu dă înapoi arenele fragmentate de la sine. Măsurat pe agent:
        # ~22 MB reţinuţi după FIECARE episod de output masiv, pentru un ring de 2 MiB, pe
        # sesiuni care nu mai există — 25 MB → 143 MB după opt episoade, fără platou.
        # `malloc_trim` e best-effort şi doar pe glibc; restul e curăţenie care oricum trebuia.
        s.ring = []
        s.ring_bytes = 0
        self.sessions.pop(s.sid, None)
        try:
            import ctypes
            ctypes.CDLL("libc.so.6").malloc_trim(0)
        except Exception:            # noqa: BLE001 — musl, non-Linux, orice: nu e o eroare
            pass

    def _reexec(self):
        log("re-executing new agent version")
        # lasă răspunsul (ok) să ajungă la gateway înainte de a închide conexiunea
        deadline = time.time() + 1.0
        while not self.outbox.empty() and time.time() < deadline:
            time.sleep(0.02)
        self.ws and self.ws.close()
        os.execv(sys.executable, [sys.executable, SELF_PATH, "run" if FOREGROUND else "start", "--reexec"])

    # -- pty I/O -------------------------------------------------------------

    def handle_pty(self, sid):
        s = self.sessions.get(sid)
        if not s:
            return
        try:
            data = os.read(s.master, READ_CHUNK)
        except OSError as e:
            data = b"" if e.errno == errno.EIO else None
            if data is None:
                return
        if data:
            s.append_output(data)
            if s.attached and self.connected:
                self.send_data(sid, data)
        else:
            self._session_exited(s)

    def _session_exited(self, s):
        try:
            self.sel.unregister(s.master)
        except (KeyError, ValueError):
            pass
        try:
            os.close(s.master)
        except OSError:
            pass
        s.master = None
        try:
            status = self.reaped.pop(s.pid, None)
            if status is None:
                # WNOHANG, NU waitpid(pid, 0) blocant: pe EOF de pty normal copilul a ieșit deja
                # și WNOHANG îl reapează imediat; dar un copil care închide pty-ul FĂRĂ să iasă
                # (rar) ar bloca loop-ul — și toate sesiunile — la infinit. Dacă n-a ieșit încă,
                # îl predăm sweep-ului (_pending_reap) ca să nu lăsăm un zombie.
                pid_done, status = os.waitpid(s.pid, os.WNOHANG)
                if pid_done == 0:
                    self._pending_reap.add(s.pid)
                    status = 0
        except OSError:
            status = 0

        # tmux client died but the tmux session still lives (e.g. manual
        # detach, agent hiccup): reattach instead of declaring the session dead
        if s.backend == "tmux" and not s.kill_requested:
            state = tmux_session_state(s.sid)
            if state == "unknown":
                # tmux nu ne-a răspuns → NU ştim dacă sesiunea trăieşte, deci nu o îngropăm.
                # Dacă serverul e înţepenit, îl recuperăm; oricum reîncercăm mai târziu, iar
                # atunci `has-session` va da un răspuns clar.
                if tmux_server_wedged():
                    log("session %s: the tmux server is wedged — recovering (kill + fresh)" % s.sid)
                    self._kill_wedged_tmux_server()
                now = time.time()
                s.respawns += 1
                s.last_respawn = now
                idx = min(max(s.respawns - TMUX_REATTACH_FAST, 1),
                          len(TMUX_REATTACH_BACKOFF)) - 1
                s.retry_at = now + TMUX_REATTACH_BACKOFF[idx]
                s.pid = None
                log("session %s: tmux is not responding — retrying in %.0fs (nothing is destroyed)"
                    % (s.sid, TMUX_REATTACH_BACKOFF[idx]))
                return
            if state == "alive":
                now = time.time()
                # un client care a trăit destul înseamnă că reataşarea reuşise: repornim
                # numărătoarea, ca un incident de acum să nu moştenească backoff-ul de ieri
                lived = now - s.client_started
                s.respawns = 1 if lived >= TMUX_CLIENT_HEALTHY else s.respawns + 1
                s.last_respawn = now
                if s.respawns <= TMUX_REATTACH_FAST:
                    log("session %s: tmux client died, reattaching" % s.sid)
                    s.spawn_client()
                    self.sel.register(s.master, selectors.EVENT_READ, ("pty", s.sid))
                    return
                # Reataşări rapide eşuate la rând. NU distrugem nimic: sesiunea tmux există,
                # deci procesele utilizatorului rulează în ea — doar noi nu ne putem lipi
                # acum (ceartă de clienţi, server ocupat). Rărim şi reîncercăm din _tick;
                # sesiunea rămâne `alive`, fără client (master/pid None până reuşim).
                idx = min(s.respawns - TMUX_REATTACH_FAST, len(TMUX_REATTACH_BACKOFF)) - 1
                delay = TMUX_REATTACH_BACKOFF[idx]
                s.retry_at = now + delay
                s.pid = None          # pid-ul a fost reapat; refolosit de alt proces = pericol
                log("session %s: reattach failed (attempt %d) — retrying in %.0fs, "
                    "the tmux session stays intact" % (s.sid, s.respawns, delay))
                return
            # state == "gone": tmux a răspuns clar (server viu fără sesiunea asta, sau
            # niciun server pornit) → sesiunea chiar s-a dus, cade la 'exit'. Cazul
            # „server înţepenit" e tratat mai sus, la „unknown".

        self._declare_exited(s, status)

    def _declare_exited(self, s, status=0):
        """Marchează sesiunea moartă şi anunţă gateway-ul. Separat de `_session_exited`
        fiindcă şi calea de reataşare (`_retry_reattach`) ajunge aici, când sesiunea tmux
        chiar a dispărut între timp."""
        s.alive = False
        s.retry_at = 0.0
        s.exited_at = time.time()
        try:
            if os.WIFEXITED(status):
                s.exit_status = os.WEXITSTATUS(status)
            elif os.WIFSIGNALED(status):
                s.exit_signal = os.WTERMSIG(status)
        except (TypeError, ValueError):
            pass
        log("session %s exited status=%s signal=%s" % (s.sid, s.exit_status, s.exit_signal))
        if self.connected:
            self.send_ctrl({"event": "exit", "sid": s.sid, "status": s.exit_status,
                            "signal": s.exit_signal, "stream_offset": s.stream_offset})
        if self.pending_update and not any(x.alive for x in self.sessions.values()):
            self._reexec()

    def _retry_reattach(self, now):
        """Sesiunile rămase fără client (vezi backoff-ul din `_session_exited`) îşi
        reîncearcă ataşarea aici, rar şi la infinit. Cât timp sesiunea tmux există, NU o
        atingem: e mai bine să nu ne putem lipi o vreme decât să pierdem ce e în ea."""
        for s in list(self.sessions.values()):
            if not s.alive or s.master is not None or not s.retry_at or now < s.retry_at:
                continue
            state = tmux_session_state(s.sid)
            if state == "gone":
                # a dispărut între timp (kill din altă parte / server oprit) → chiar a murit
                self._declare_exited(s)
                continue
            if state == "unknown":
                # tmux nu răspunde: reîncercăm, nu îngropăm. Un server înţepenit se recuperează.
                if tmux_server_wedged():
                    self._kill_wedged_tmux_server()
                idx = min(max(s.respawns - TMUX_REATTACH_FAST, 1),
                          len(TMUX_REATTACH_BACKOFF)) - 1
                s.retry_at = now + TMUX_REATTACH_BACKOFF[idx]
                continue
            try:
                s.spawn_client()
            except OSError as e:
                idx = min(s.respawns - TMUX_REATTACH_FAST, len(TMUX_REATTACH_BACKOFF)) - 1
                s.retry_at = now + TMUX_REATTACH_BACKOFF[idx]
                log("session %s: spawn failed (%s) — retrying later" % (s.sid, e))
                continue
            self.sel.register(s.master, selectors.EVENT_READ, ("pty", s.sid))
            log("session %s: reattached after %d attempts" % (s.sid, s.respawns))
            self._flush_input(s)          # ce a tastat utilizatorul cât eram fără client

    def write_input(self, sid, data):
        s = self.sessions.get(sid)
        if not s or not s.alive:
            return
        # pty blocat + flux mare de input (paste-storm într-o app care nu citește) ar
        # umfla pending_input nemărginit → OOM. Peste plafon, aruncăm intrarea nouă;
        # ce e deja în coadă se scurge când pty-ul acceptă din nou.
        if len(s.pending_input) + len(data) > PENDING_INPUT_MAX:
            log("session %s: input backlog over %d KB — input dropped"
                % (sid, PENDING_INPUT_MAX // 1024))
            return
        s.pending_input += data
        self._flush_input(s)

    def _flush_input(self, s):
        if s.master is None:
            return          # fără client ataşat: input-ul aşteaptă în pending_input
        while s.pending_input:
            try:
                n = os.write(s.master, s.pending_input[:READ_CHUNK])
                s.pending_input = s.pending_input[n:]
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                s.pending_input = b""
                return
        events = selectors.EVENT_READ | (selectors.EVENT_WRITE if s.pending_input else 0)
        try:
            self.sel.modify(s.master, events, ("pty", s.sid))
        except (KeyError, ValueError):
            pass

    # -- port forwarding -------------------------------------------------------

    def _fwd_teardown(self, stream, notify=True):
        """Închide un tunel de forward. notify=True → anunță gateway-ul (socketul
        s-a închis din partea țintei: EOF/eroare); notify=False → gateway-ul a cerut."""
        fwd = self.forwards.pop(stream, None)
        if not fwd:
            return
        try:
            self.sel.unregister(fwd.sock)
        except (KeyError, ValueError):
            pass
        try:
            fwd.sock.close()
        except OSError:
            pass
        if notify:
            self.send_ctrl({"event": "fwd_close", "stream": stream})

    def fwd_write(self, stream, data):
        """Octeți de la gateway → către țintă (buffer + flush non-blocant)."""
        fwd = self.forwards.get(stream)
        if not fwd:
            return
        # țintă lentă + upload rapid → wbuf ar crește nemărginit (OOM). Fără flow
        # control în protocol, backpressure-ul e închiderea tunelului peste plafon.
        if len(fwd.wbuf) + len(data) > FWD_WBUF_MAX:
            log("forward %s: write backlog over %d KB — tunnel closed"
                % (stream, FWD_WBUF_MAX // 1024))
            self._fwd_teardown(stream, notify=True)
            return
        fwd.wbuf += data
        self._fwd_flush(fwd)

    def _fwd_flush(self, fwd):
        if fwd.connecting:
            return                      # așteptăm finalizarea connect (EVENT_WRITE)
        while fwd.wbuf:
            try:
                n = fwd.sock.send(fwd.wbuf)
                fwd.wbuf = fwd.wbuf[n:]
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                self._fwd_teardown(fwd.stream_id, notify=True)
                return
        events = selectors.EVENT_READ | (selectors.EVENT_WRITE if fwd.wbuf else 0)
        try:
            self.sel.modify(fwd.sock, events, ("fwd", fwd.stream_id))
        except (KeyError, ValueError):
            pass

    # -- serial (console seriale) ----------------------------------------------

    def _serial_teardown(self, stream, notify=True):
        """Închide o consolă serială. notify=True → device-ul a dispărut/eroare (anunță
        gateway-ul cu ACELAȘI event `fwd_close`, fiindcă reutilizează ForwardStream)."""
        ser = self.serials.pop(stream, None)
        if not ser:
            return
        try:
            self.sel.unregister(ser.fd)
        except (KeyError, ValueError):
            pass
        try:
            os.close(ser.fd)
        except OSError:
            pass
        if notify:
            self.send_ctrl({"event": "fwd_close", "stream": stream})

    def serial_write(self, stream, data):
        """Octeți de la gateway → către portul serial (buffer + flush non-blocant)."""
        ser = self.serials.get(stream)
        if not ser:
            return
        if len(ser.wbuf) + len(data) > FWD_WBUF_MAX:
            log("serial %s: write backlog over %d KB — closed" % (stream, FWD_WBUF_MAX // 1024))
            self._serial_teardown(stream, notify=True)
            return
        ser.wbuf += data
        self._serial_flush(ser)

    def _serial_flush(self, ser):
        while ser.wbuf:
            try:
                n = os.write(ser.fd, ser.wbuf)
                ser.wbuf = ser.wbuf[n:]
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                self._serial_teardown(ser.stream_id, notify=True)
                return
        events = selectors.EVENT_READ | (selectors.EVENT_WRITE if ser.wbuf else 0)
        try:
            self.sel.modify(ser.fd, events, ("serial", ser.stream_id))
        except (KeyError, ValueError):
            pass

    # -- housekeeping ----------------------------------------------------------

    def _touch_alive(self):
        """G1: scrie un timestamp în ALIVE_PATH — dovada că event-loop-ul se învârte.
        Watchdog-ul (`ptyd.py start`) compară mtime-ul: stale = agent BLOCAT → kill+restart."""
        now = time.time()
        if now - self._last_alive < 5:
            return
        self._last_alive = now
        try:
            with open(ALIVE_PATH, "w") as f:
                f.write("%d" % int(now))
        except OSError:
            pass

    def _rotate_log(self):
        """G7: trunchiază ptyd.log la runtime dacă depăşeşte LOG_MAX (nu doar la pornire)."""
        now = time.time()
        if now - self._last_logcheck < 60:
            return
        self._last_logcheck = now
        try:
            if os.path.getsize(LOG_PATH) > LOG_MAX:
                with open(LOG_PATH, "r+") as f:
                    f.truncate(0)
                log("(log rotated — it had exceeded %d MB)" % (LOG_MAX // (1024 * 1024)))
        except OSError:
            pass

    def _tick(self, now):
        self._touch_alive()          # G1: dovada că event-loop-ul se învârte (watchdog cron)
        if self._wd_interval and now - self._last_wd >= self._wd_interval:
            self._last_wd = now
            _sd_notify("WATCHDOG=1")  # systemd: event-loop viu; blocare → kill+restart
        self._rotate_log()           # G7: trunchiază ptyd.log dacă a crescut prea mult
        # detecţie half-open agent→gateway: dacă heartbeat-urile nu mai primesc ack, conexiunea
        # e moartă deşi socketul pare viu (scrierile intră în buffer TCP fără eroare) → reconnect.
        if self.connected and now - self._last_hb_ack > HB_ACK_TIMEOUT:
            log("no heartbeat ack for %.0fs — connection stale, reconnecting"
                % (now - self._last_hb_ack))
            self._disconnect_requested = True
        if self.connected and now >= self.next_heartbeat:
            self._hb_seq += 1
            self._hb_sent_at[self._hb_seq] = now
            if len(self._hb_sent_at) > 8:          # nu ţinem un istoric mare de seq-uri neack-uite
                self._hb_sent_at.pop(min(self._hb_sent_at), None)
            self.send_ctrl({"event": "heartbeat", "agent_version": AGENT_VERSION,
                            "proto": PROTO, "epoch": self.epoch, "backend": self.backend,
                            "hb_seq": self._hb_seq, "uptime": round(now - self._connected_since),
                            "reconnects": self._reconnect_count, "rtt_ms": self._last_rtt,
                            "metrics": self.metrics.sample(),
                            "sessions": [s.meta() for s in self.sessions.values()]})
            self.next_heartbeat = now + HEARTBEAT_INTERVAL
        # Reapează DOAR pid-urile de sesiune. Un waitpid(-1) global fura copilul lui
        # subprocess.run din op-ul `run` (rulează pe un thread worker) → subprocess
        # primea ECHILD, iar CPython raporta silent exit code 0 (comenzi eșuate
        # apăreau ca reușite pe consola de flotă). Sesiunile au oricum un fallback
        # de waitpid în _session_exited.
        for s in list(self.sessions.values()):
            if not s.alive or not s.pid or s.pid in self.reaped:
                continue                      # pid None = sesiune fără client (reataşare)
            try:
                pid, status = os.waitpid(s.pid, os.WNOHANG)
                if pid:
                    self.reaped[pid] = status
            except OSError:
                pass
        # pid-uri predate din _session_exited (pty EOF fără exit): le reapem non-blocant aici,
        # ca să nu lăsăm zombie (sesiunea lor e deja `not alive`, deci bucla de mai sus le sare)
        for pid in list(self._pending_reap):
            try:
                done, _ = os.waitpid(pid, os.WNOHANG)
                if done:
                    self._pending_reap.discard(pid)
            except OSError:
                self._pending_reap.discard(pid)   # deja reaper / dispărut
        for s in list(self.sessions.values()):
            if not s.alive and s.exited_at and now - s.exited_at > EXITED_TTL:
                self._drop_session(s)
        # abandonează forward-urile al căror connect() non-blocant nu s-a finalizat
        # în FWD_CONNECT_TIMEOUT (țintă filtrată / SYN black-hole) — altfel ar ține
        # un slot din MAX_FORWARDS + un fd la infinit.
        for fwd in list(self.forwards.values()):
            if fwd.connecting and now - fwd.opened_at > FWD_CONNECT_TIMEOUT:
                log("forward %s: connect timed out after %.0fs — abandoned"
                    % (fwd.stream_id, FWD_CONNECT_TIMEOUT))
                self._fwd_teardown(fwd.stream_id, notify=True)
        # reataşare rărită pentru sesiunile rămase fără client (vezi _retry_reattach)
        self._retry_reattach(now)
        # igienă (A): reapează periodic sesiunile tmux orfane (fără backing viu în
        # agent) — drift din adopții eșuate, creări întrerupte etc.
        if self.backend == "tmux" and now >= self._next_tmux_sweep:
            self._next_tmux_sweep = now + TMUX_SWEEP_INTERVAL
            self._sweep_orphan_tmux()

    # -- main loop ---------------------------------------------------------------

    # -- igienă tmux (evită husk-uri care consumă resurse) -----------------------

    def _reap_tmux_session(self, sid):
        """Omoară sesiunea tmux rămasă în urma unei sesiuni pe care nu o mai putem
        reataşa. Dacă până şi kill-session eşuează, serverul tmux e înţepenit
        (accept-then-close) → un server înţepenit doboară TOATE sesiunile lui, deci
        îl dobor de tot (case B). tmux porneşte un server nou curat la prima sesiune."""
        try:
            r = tmux_cmd("kill-session", "-t", "=" + TMUX_SESSION_PREFIX + sid)
            if r.returncode == 0:
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
        self._kill_wedged_tmux_server()

    def _kill_wedged_tmux_server(self):
        """Serverul tmux (-L webterm) nu mai serveşte clienţi (înţepenit). Îl dobor
        cu SIGKILL împreună cu clienţii orfani, ca panourile moarte să nu rămână vii.
        Cooldown ca reap-urile în lanţ (fiecare sesiune moartă) să nu-l tot vâneze."""
        now = time.time()
        if now - self._last_server_kill < TMUX_SERVER_KILL_COOLDOWN:
            return
        self._last_server_kill = now
        killed = self._kill_tmux_procs()
        if killed:
            log("tmux server -L %s wedged — %d processes killed (server + orphaned clients)"
                % (TMUX_SOCKET, killed))

    def _kill_tmux_procs(self):
        """SIGKILL toate procesele `tmux -L <socket>` (server + clienţi), scanând
        /proc (fără dependenţă de lsof). Nu se atinge de sine."""
        me = os.getpid()
        killed = 0
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return 0
        for pid in pids:
            try:
                with open("/proc/%s/cmdline" % pid, "rb") as f:
                    parts = f.read().split(b"\0")
            except OSError:
                continue
            if not tmux_cmdline_matches(parts, TMUX_SOCKET):
                continue
            p = int(pid)
            if p == me:
                continue
            try:
                os.kill(p, signal.SIGKILL)
                killed += 1
            except OSError:
                pass
        return killed

    def _uninstall_agent(self):
        """Scoate agentul de pe host: supraveghere (systemd --user / cron) + serverul tmux +
        fișierele din ~/.webterm/. Best-effort; întoarce lista pașilor care au eșuat (avertismente).
        Apelat din op-ul `uninstall`, urmat de os._exit — nu mai repornim (supravegherea e scoasă)."""
        warn = []
        home = os.path.expanduser("~")
        # 1) systemd --user: dezactivează + șterge unit-ul
        try:
            subprocess.run(["systemctl", "--user", "disable", "--now", "webterm-agent.service"],
                           timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            warn.append("systemctl disable")
        unit = os.path.join(home, ".config/systemd/user/webterm-agent.service")
        try:
            if os.path.exists(unit):
                os.remove(unit)
        except OSError:
            warn.append("unit systemd")
        # 2) cron: scoate DOAR liniile noastre (@reboot + watchdog)
        try:
            # Codul de ieşire CONTEAZĂ. `crontab -l` poate eşua şi când omul ARE un crontab:
            # `/etc/cron.deny`, spool ilizibil momentan, un wrapper care scrie pe stderr. Vechea
            # variantă lua atunci `cur=""` → `kept=[]` → `body=""` → `crontab -r`, adică ştergea
            # TOT crontab-ul utilizatorului ca să scoată două rânduri de-ale noastre. Dacă nu
            # putem citi, nu scriem: mai bine rămân două linii moarte decât să pierdem ce n-am
            # pus noi acolo.
            r = subprocess.run(["crontab", "-l"], timeout=10,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                kept = [ln for ln in r.stdout.decode().splitlines()
                        if "webterm/ptyd.py" not in ln and "webterm-watchdog" not in ln]
                body = ("\n".join(kept) + "\n") if any(k.strip() for k in kept) else ""
                subprocess.run(["crontab", "-"] if body else ["crontab", "-r"],
                               input=body.encode() if body else None,
                               timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                warn.append("cron (nu am putut citi crontab-ul; liniile WebTerm au rămas)")
        except (OSError, subprocess.SubprocessError):
            pass                                   # crontab poate lipsi — nu e o eroare
        # 3) serverul tmux (decomisionare — doar sesiunile noastre `-L webterm`)
        try:
            self._kill_tmux_procs()
        except Exception:                          # noqa: BLE001
            warn.append("tmux")
        # 4) fișierele din ~/.webterm/ (ptyd.py, agent.json cu tokenul, lock, log, cert_pin, …)
        try:
            shutil.rmtree(WEBTERM_DIR, ignore_errors=True)
        except Exception:                          # noqa: BLE001
            warn.append("~/.webterm files")
        return warn

    def _sweep_orphan_tmux(self):
        """Reapează sesiunile tmux cu prefixul nostru care NU mai au o sesiune urmărită în
        agent — husk-uri lăsate în urmă (adopţie eşuată, creări întrerupte). E SINGURUL loc
        care omoară sesiuni tmux din igienă: o sesiune urmărită nu se atinge, oricât de greu
        ne-am reataşa la ea (vezi _retry_reattach). Rulează DUPĂ adopţie (prima trecere e
        amânată), altfel ar şterge exact sesiunile pe care tocmai urmează să le adoptăm."""
        try:
            r = tmux_cmd("list-sessions", "-F", "#{session_name}")
        except (OSError, subprocess.TimeoutExpired):
            return
        if r.returncode != 0:
            return                      # server absent/înţepenit → nu e treaba sweep-ului
        for name in r.stdout.decode(errors="replace").split():
            if not name.startswith(TMUX_SESSION_PREFIX):
                continue
            sid = name[len(TMUX_SESSION_PREFIX):]
            if len(sid) != SID_LEN or sid in self.sessions:
                continue                # urmărită (chiar dacă moartă, o drop-uie _tick)
            # prin _reap_tmux_session, nu kill-session direct: dacă până şi kill-ul eşuează,
            # serverul e înţepenit şi trebuie recuperat (altfel sweep-ul eşua tăcut la infinit)
            log("hygiene: orphaned tmux session %s — reaping it (no backing in the agent)" % sid)
            self._reap_tmux_session(sid)

    def _adopt_tmux_sessions(self):
        """After an agent restart, re-adopt live tmux sessions by name."""
        if self.backend != "tmux":
            return
        try:
            r = tmux_cmd("list-sessions", "-F", "#{session_name}")
        except (OSError, subprocess.TimeoutExpired):
            return
        if r.returncode != 0:
            return
        for name in r.stdout.decode(errors="replace").split():
            if not name.startswith(TMUX_SESSION_PREFIX):
                continue
            sid = name[len(TMUX_SESSION_PREFIX):]
            if len(sid) != SID_LEN or sid in self.sessions:
                continue
            try:
                s = Session(sid, 24, 80, "xterm-256color", backend="tmux")
            except OSError as e:
                log("adopt %s failed: %s" % (sid, e))
                continue
            self.sessions[sid] = s
            self.sel.register(s.master, selectors.EVENT_READ, ("pty", sid))
            log("adopted tmux session %s" % sid)

    def _request_stop(self, *_):
        self.stop_requested = True
        self._wake()          # întrerupe select() ca oprirea să fie imediată

    def run(self):
        signal.signal(signal.SIGTERM, self._request_stop)
        signal.signal(signal.SIGINT, self._request_stop)
        _sd_notify("READY=1")         # systemd (Type=notify): pornire confirmată; no-op altfel
        self._adopt_tmux_sessions()
        while not self.stop_requested:
            now = time.time()
            # deconectare cerută din afara loop-ului (overflow de outbox pe un worker) —
            # o executăm AICI, pe thread-ul loop-ului, ca să nu mutăm selector-ul din alt thread
            if self._disconnect_requested:
                self._disconnect_requested = False
                self._disconnect()
            # pornim conectarea pe un thread worker (non-blocant); rezultatul vine prin inbox.
            # cel mult una în curs (gardat de _connecting) → nu batem gateway-ul în paralel.
            # Plasă de siguranţă pentru cazul în care thread-ul de conectare nu mai raportează
            # NICIODATĂ (a murit înainte de `finally`, sau atârnă într-un apel care nu respectă
            # termenul-limită). Fără ea, `_connecting` rămâne True şi agentul nu mai încearcă
            # nimic — tăcut, cu watchdog-urile verzi. Un handshake are termen total mult sub asta.
            if self._connecting and now - self._connect_started > CONNECT_STUCK_SECS:
                log("connection stuck for %.0fs — restarting it" % (now - self._connect_started))
                self._connecting = False
            if not self.connected and not self._connecting and now >= self.next_connect:
                self._start_connect()
            timeout = max(0.05, min(
                (self.next_heartbeat - now) if self.connected
                else (5.0 if self._connecting else (self.next_connect - now)),
                5.0))
            for key, events in self.sel.select(timeout):
                kind, sid = key.data
                if kind == "wake":
                    try:
                        while os.read(self.wake_r, 4096):
                            pass
                    except (BlockingIOError, InterruptedError):
                        pass
                    self._drain_inbox()
                elif kind == "pty":
                    if events & selectors.EVENT_WRITE:
                        s = self.sessions.get(sid)
                        if s:
                            self._flush_input(s)
                    if events & selectors.EVENT_READ:
                        self.handle_pty(sid)
                elif kind == "fwd":
                    fwd = self.forwards.get(sid)
                    if not fwd:
                        continue
                    if events & selectors.EVENT_WRITE:
                        if fwd.connecting:
                            e = fwd.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                            if e != 0:                 # connect a eșuat
                                self._fwd_teardown(sid, notify=True)
                                continue
                            fwd.connecting = False     # conectat → trecem pe READ
                        self._fwd_flush(fwd)
                    if events & selectors.EVENT_READ and sid in self.forwards:
                        try:
                            data = fwd.sock.recv(READ_CHUNK)
                        except (BlockingIOError, InterruptedError):
                            data = None
                        except OSError:
                            self._fwd_teardown(sid, notify=True)
                            continue
                        if data == b"":                # EOF de la țintă
                            self._fwd_teardown(sid, notify=True)
                        elif data:
                            self.send_frame(FRAME_FWD + sid.encode() + data)
                elif kind == "serial":
                    ser = self.serials.get(sid)
                    if not ser:
                        continue
                    if events & selectors.EVENT_WRITE:
                        self._serial_flush(ser)
                    if events & selectors.EVENT_READ and sid in self.serials:
                        try:
                            data = os.read(ser.fd, READ_CHUNK)
                        except (BlockingIOError, InterruptedError):
                            data = None
                        except OSError:                # device deconectat (USB scos)
                            self._serial_teardown(sid, notify=True)
                            continue
                        if data == b"":                # EOF (rar pe serial)
                            self._serial_teardown(sid, notify=True)
                        elif data:
                            self.send_frame(FRAME_FWD + sid.encode() + data)
            self._tick(time.time())
        log("agent stopping")
        for s in self.sessions.values():
            if s.alive and s.pid:
                try:
                    os.kill(s.pid, signal.SIGHUP)
                except OSError:
                    pass
        if self.ws:
            self.ws.close()

    def _drain_inbox(self):
        while True:
            try:
                item = self.inbox.get_nowait()
            except queue.Empty:
                return
            if isinstance(item, tuple):
                tag = item[0]
                if tag == "__connected__":       # conectare reușită pe thread-ul worker
                    self._on_connected(item[1])
                    continue
                if tag == "__connect_failed__":  # conectarea a eșuat/timeout pe worker
                    self._on_connect_failed(item[1])
                    continue
                if tag == "__disconnect__":
                    if item[2] is self.ws:       # ignore markers from a stale connection
                        log("connection lost: %s" % item[1])
                        self._disconnect()
                    continue
            if not item:
                continue
            ftype, body = item[:1], item[1:]
            if ftype == FRAME_CTRL:
                try:
                    self.handle_ctrl(json.loads(body.decode()))
                except (ValueError, UnicodeDecodeError) as e:
                    log("bad ctrl frame: %s" % e)
            elif ftype == FRAME_DATA:
                sid = body[:SID_LEN].decode(errors="replace")
                self.write_input(sid, body[SID_LEN:])
            elif ftype == FRAME_FWD:
                stream = body[:SID_LEN].decode(errors="replace")
                if stream in self.serials:          # FRAME_FWD e reutilizat pt. serial
                    self.serial_write(stream, body[SID_LEN:])
                else:
                    self.fwd_write(stream, body[SID_LEN:])


# ---------------------------------------------------------------------------
# Daemon plumbing
# ---------------------------------------------------------------------------

def ensure_dir():
    os.makedirs(WEBTERM_DIR, mode=0o700, exist_ok=True)
    os.chmod(WEBTERM_DIR, 0o700)


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        sys.stderr.write("cannot read %s: %s\n" % (CONFIG_PATH, e))
        sys.exit(2)
    if "url" not in cfg or "token" not in cfg:
        sys.stderr.write("config must contain url and token\n")
        sys.exit(2)
    return cfg


def acquire_lock():
    fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
    return fd                          # keep open for daemon lifetime


def read_daemon_pid():
    try:
        with open(LOCK_PATH) as f:
            pid = int(f.read().strip() or "0")
    except (OSError, ValueError):
        return None
    if not pid:
        return None
    # if we can flock it, no daemon holds it
    try:
        fd = os.open(LOCK_PATH, os.O_RDWR)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    except OSError:
        return pid
    finally:
        os.close(fd)


def agent_hung():
    """G1: True dacă agentul care rulează pare BLOCAT — nu şi-a atins fişierul de
    liveness (ALIVE_PATH) de peste AGENT_HUNG_AFTER. Fişier lipsă → False (agent proaspăt
    care încă nu l-a scris, sau versiune veche pre-v20) ca să nu omorâm un agent sănătos."""
    try:
        return time.time() - os.path.getmtime(ALIVE_PATH) > AGENT_HUNG_AFTER
    except OSError:
        return False


def detach_daemon():
    """Complete daemonization. The first fork happens in main() so the
    original process can wait and confirm the daemon actually came up."""
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    os.chdir("/")
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    logfd = os.open(LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        if os.fstat(logfd).st_size > 1024 * 1024:
            os.ftruncate(logfd, 0)
    except OSError:
        pass
    os.dup2(logfd, 1)
    os.dup2(logfd, 2)
    os.close(logfd)


FOREGROUND = False


def _detect_supervision():
    """Best-effort guess of how the agent is kept alive on this host."""
    unit = os.path.expanduser("~/.config/systemd/user/webterm-agent.service")
    if os.path.exists(unit):
        return "systemd --user (webterm-agent.service, Restart=always)"
    try:
        cron = subprocess.run(["crontab", "-l"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=5).stdout.decode()
        if "webterm-watchdog" in cron:
            return "cron (@reboot + a watchdog every minute)"
        if "webterm/ptyd.py" in cron:
            return "cron (@reboot)"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "none detected — manual start"


def print_info():
    pid = read_daemon_pid()
    try:
        home = os.path.expanduser("~")
        shell = pwd.getpwuid(os.getuid()).pw_shell or "/bin/sh"
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        home, shell, user = os.path.expanduser("~"), "/bin/sh", "?"
    url = "?"
    try:
        with open(CONFIG_PATH) as f:
            url = json.load(f).get("url", "?")
    except (OSError, ValueError):
        pass
    restart = ("systemctl --user restart webterm-agent"
               if "systemd" in _detect_supervision()
               else "python3 %s start" % SELF_PATH)
    print("""\
WebTerm agent (ptyd) v%d
────────────────────────────────────────────────────────
State:            %s
User / shell:     %s  (%s)
Connects to:      %s

Paths:
  Agent:          %s
  Config:         %s
  Log:            %s
  Base directory: %s

Supervision:      %s

Commands:
  status          python3 %s status
  start           python3 %s start
  stop            python3 %s stop
  restart         %s
  info            python3 %s info

File transfer:
  Files uploaded from the interface are saved into the directory you have
  open in the Files panel (default: %s). Navigate or type the path you want
  before uploading — nothing leaves this user account (%s) or its
  permissions.
────────────────────────────────────────────────────────""" % (
        AGENT_VERSION,
        ("running (pid %d)" % pid) if pid else "stopped",
        user, shell, url,
        SELF_PATH, CONFIG_PATH, LOG_PATH, WEBTERM_DIR,
        _detect_supervision(),
        SELF_PATH, SELF_PATH, SELF_PATH, restart, SELF_PATH,
        home, user))


def main():
    global FOREGROUND
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    cmd = args[0] if args else "start"
    ensure_dir()

    if cmd == "selftest":
        # Rulat de agentul VECHI pe fişierul NOU, înainte de a se suprascrie: dacă ajungem
        # aici, modulul s-a importat integral (constante, regexuri, clase) pe interpretorul
        # ACESTUI host. `compile()` nu poate spune asta — o eroare de import ar fi ucis
        # agentul după înlocuire, iar supravegherea ar fi repornit la infinit acelaşi fişier
        # mort. După înlocuire e prea târziu: codul nou nu porneşte, deci nu se poate repara.
        print("selftest ok v%d" % AGENT_VERSION)
        sys.exit(0)

    if cmd == "status":
        pid = read_daemon_pid()
        print("running (pid %d)" % pid if pid else "not running")
        sys.exit(0 if pid else 1)

    if cmd in ("info", "help"):
        print_info()
        sys.exit(0)

    if cmd == "stop":
        pid = read_daemon_pid()
        if not pid:
            print("not running")
            sys.exit(0)
        os.kill(pid, signal.SIGTERM)
        # oprire elegantă: până la 15s (agentul poate închide conexiuni/sesiuni)
        for _ in range(150):
            if read_daemon_pid() is None:
                print("stopped")
                sys.exit(0)
            time.sleep(0.1)
        # a durat prea mult — forțăm, fără să te punem să faci kill manual
        print("did not stop within 15s, forcing (SIGKILL)…")
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        for _ in range(50):
            if read_daemon_pid() is None:
                print("stopped (forced)")
                sys.exit(0)
            time.sleep(0.1)
        print("could not stop process %d" % pid)
        sys.exit(1)

    if cmd not in ("run", "start"):
        sys.stderr.write(__doc__)
        sys.exit(2)

    FOREGROUND = cmd == "run"
    cfg = load_config()

    if cmd == "start":
        existing = read_daemon_pid()
        if existing and agent_hung():
            # G1: agentul e viu (ţine lock-ul) dar BLOCAT (liveness stale) → watchdog-ul
            # verifica doar lock-ul, deci un agent hung rămânea offline la infinit. Îl
            # omorâm; sesiunile tmux supravieţuiesc şi sunt re-adoptate de instanţa nouă.
            log("watchdog: agent %d pare blocat (liveness stale) — kill + restart" % existing)
            try:
                os.kill(existing, signal.SIGKILL)
            except OSError:
                pass
            for _ in range(50):            # aşteaptă eliberarea lock-ului (≤5s)
                if read_daemon_pid() is None:
                    break
                time.sleep(0.1)
            existing = read_daemon_pid()
        if existing:
            print("already running (pid %d)" % existing)
            sys.exit(0)
        # forkează daemonul, iar procesul original confirmă că a pornit
        if os.fork() > 0:
            for _ in range(60):          # așteaptă până la 6s să apară în lock
                dp = read_daemon_pid()
                if dp:
                    print("started (pid %d)" % dp)
                    sys.stdout.flush()   # os._exit nu golește buffer-ul
                    os._exit(0)
                time.sleep(0.1)
            sys.stderr.write("started, but no confirmation within 6s; see %s\n" % LOG_PATH)
            sys.stderr.flush()
            os._exit(1)
        detach_daemon()               # copilul devine daemon

    lock_fd = acquire_lock()
    if lock_fd is None:
        log("another instance holds the lock; exiting")
        sys.exit(0)

    log("ptyd v%d starting (pid %d)" % (AGENT_VERSION, os.getpid()))
    Agent(cfg).run()


if __name__ == "__main__":
    main()
