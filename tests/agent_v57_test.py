"""Agent v57 — pornirea la boot: raportare structurată + comutare din UI; curăţenie de protocol.

De ce: agentul root de pe hostul de producţie n-avea NICIO supraveghere (pornit de mână, orfan
după un reexec). Merge până la primul reboot, după care hostul rămâne OFFLINE în WebTerm până
intră cineva prin SSH. v57 raportează în diagnostic `supervision` = {mode, linger, boot, …}, iar
op-ul `autostart` {enable} instalează / scoate mecanismul (systemd --user sau cron, ca
instalatorul) fără să atingă agentul care rulează.

Acoperă:
  1. parsarea (crontab, systemctl is-enabled, linger) → {mode, linger, boot, scope, watchdog};
  2. `autostart` enable/disable cu subprocess MOCKUIT: unit-ul scris (KillMode/WatchdogSec),
     unit existent nerescris, `enable`/`disable` FĂRĂ `--now`, cron citit-verificat-filtrat
     (liniile străine rămân; crontab ilizibil = neatins), hint de linger;
  3. op-ul prin handle_ctrl (validare, worker, lock, reply cu starea nouă);
  4. op-urile moarte (`list`, `detach`, `serial_close`) au dispărut; `shutdown`/`fs_write` rămân;
  5. tmux: `new-session -e WEBTERM_SESSION=<sid>` doar pe tmux ≥ 3.1;
  6. gateway: `supervision_summary` (listă albă), coloana, `_host_json`, endpoint-ul
     `POST /api/hosts/{id}/autostart` (step-up, gate pe v57, stocare imediată).

Hermetic: HOME sandboxat ÎNAINTE de import, niciun systemctl/crontab/loginctl real (toate
trec prin `_sup_run`, mockuit), agent construit cu `object.__new__` ca agent_v54..v56_test.
"""
import asyncio
import json
import os
import queue
import sys
import tempfile
import time

os.environ["HOME"] = tempfile.mkdtemp(prefix="v57-home-")
os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp(prefix="v57-data-")
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

os.makedirs(ptyd.WEBTERM_DIR, exist_ok=True)
ok_n = 0
total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % (detail,)))


# ───────────────────────── host fals: systemctl / crontab / loginctl ─────────────────────────
class FakeHost:
    """Starea unui host văzută prin `_sup_run`. Fiecare apel e jurnalizat în `calls`."""

    def __init__(self):
        self.calls = []
        self.user_bus = True          # `systemctl --user` ajunge la managerul de user
        self.user_enabled = False
        self.user_state = None        # override pt. ieşirea lui is-enabled (ex. "enabled-runtime")
        self.system_enabled = False
        self.crontab = None           # None = „no crontab for u"; str = conţinut
        self.crontab_unreadable = False
        self.crontab_missing = False  # binarul lipseşte
        self.linger_on_loginctl = False
        self.enable_fails = False

    def link(self):
        return ptyd._user_unit_link()

    def run(self, argv, input_bytes=None):
        self.calls.append(list(argv))
        a = list(argv)
        if a[0] == "systemctl":
            user = "--user" in a
            rest = [x for x in a[1:] if x != "--user"]
            if user and not self.user_bus:
                return (1, "", "Failed to connect to bus: No medium found")
            if rest[0] == "is-enabled":
                if user:
                    st = self.user_state or ("enabled" if self.user_enabled else "disabled")
                else:
                    st = "enabled" if self.system_enabled else "disabled"
                return (0 if st == "enabled" else 1, st + "\n", "")
            if rest[0] == "show-environment":
                return (0, "HOME=/x\n", "")
            if rest[0] == "daemon-reload":
                return (0, "", "")
            if rest[0] == "enable":
                if self.enable_fails:
                    return (1, "", "Failed to enable unit")
                self.user_enabled = True
                os.makedirs(os.path.dirname(self.link()), exist_ok=True)
                if not os.path.lexists(self.link()):
                    os.symlink(ptyd._user_unit_path(), self.link())
                return (0, "", "")
            if rest[0] == "disable":
                if user:
                    self.user_enabled = False
                    if os.path.lexists(self.link()):
                        os.remove(self.link())
                else:
                    self.system_enabled = False
                return (0, "", "")
            return (1, "", "unknown")
        if a[0] == "crontab":
            if self.crontab_missing:
                return None
            if a[1] == "-l":
                if self.crontab_unreadable:
                    return (1, "", "crontab: permission denied")
                if self.crontab is None:
                    return (1, "", "no crontab for tester")
                return (0, self.crontab, "")
            if a[1] == "-":
                self.crontab = input_bytes.decode()
                return (0, "", "")
            if a[1] == "-r":
                self.crontab = None
                return (0, "", "")
        if a[0] == "loginctl":
            if self.linger_on_loginctl:
                open(os.path.join(ptyd._LINGER_DIR, "tester"), "w").close()
                return (0, "", "")
            return (1, "", "Access denied")
        return None


LINGER = tempfile.mkdtemp(prefix="v57-linger-")
_orig = {"run": ptyd._sup_run, "user": ptyd._sup_user, "linger": ptyd._LINGER_DIR,
         "which": ptyd.shutil.which, "getuid": ptyd.os.getuid}


def fresh(uid=1000, systemctl=True):
    """Host curat: fără unit, fără link, fără linger, fără crontab."""
    h = FakeHost()
    ptyd._sup_run = h.run
    ptyd._sup_user = lambda: "tester"
    ptyd._LINGER_DIR = LINGER
    real_which = _orig["which"]
    def which(n):
        if n == "systemctl" and not systemctl:
            return None
        return ("/usr/bin/" + n) if n in ("systemctl", "crontab", "loginctl") else real_which(n)
    ptyd.shutil.which = which
    ptyd.os.getuid = lambda: uid
    for p in (ptyd._user_unit_path(), ptyd._user_unit_link(), os.path.join(LINGER, "tester")):
        if os.path.lexists(p):
            os.remove(p)
    return h


def restore():
    ptyd._sup_run = _orig["run"]
    ptyd._sup_user = _orig["user"]
    ptyd._LINGER_DIR = _orig["linger"]
    ptyd.shutil.which = _orig["which"]
    ptyd.os.getuid = _orig["getuid"]


def linger_on():
    open(os.path.join(LINGER, "tester"), "w").close()


FOREIGN = "0 3 * * * /usr/local/bin/backup.sh\n# un comentariu al omului\n"
OURS = ("@reboot /usr/bin/python3 /home/t/.webterm/ptyd.py start # webterm\n"
        "* * * * * /usr/bin/python3 /home/t/.webterm/ptyd.py start # webterm-watchdog\n")

# ───────────────────────── versiune ─────────────────────────
# v58 a crescut versiunea; gate-ul pe 57 (autostart/history) rămâne valabil pentru orice ≥ 57
check("AGENT_VERSION >= 57", ptyd.AGENT_VERSION >= 57, ptyd.AGENT_VERSION)

# ═════════════════════════ 1. parsare ═════════════════════════
check("_cron_scan: @reboot + watchdog", ptyd._cron_scan(OURS.splitlines()) == (True, True))
check("_cron_scan: liniile comentate NU contează",
      ptyd._cron_scan(["# @reboot python3 ~/.webterm/ptyd.py start # webterm"]) == (False, False))
check("_cron_scan: liniile străine NU contează", ptyd._cron_scan(FOREIGN.splitlines()) == (False, False))
check("_cron_scan: doar watchdog", ptyd._cron_scan(OURS.splitlines()[1:]) == (False, True))

try:
    h = fresh()
    check("nimic → mode none, boot false",
          ptyd._diag_supervision() == {"mode": "none", "linger": False, "boot": False},
          ptyd._diag_supervision())

    h = fresh(); h.crontab = FOREIGN + OURS
    check("cron @reboot + watchdog → mode cron, boot, watchdog",
          ptyd._diag_supervision() == {"mode": "cron", "linger": False, "boot": True, "watchdog": True},
          ptyd._diag_supervision())

    h = fresh(); h.crontab = OURS.splitlines()[1] + "\n"
    check("cron doar watchdog → boot false (revine doar dacă moare, nu după reboot)",
          ptyd._diag_supervision() == {"mode": "cron", "linger": False, "boot": False, "watchdog": True},
          ptyd._diag_supervision())

    h = fresh(); h.user_enabled = True
    check("systemd --user fără linger → boot false",
          ptyd._diag_supervision() == {"mode": "systemd", "linger": False, "boot": False, "scope": "user"},
          ptyd._diag_supervision())
    linger_on()
    check("systemd --user cu linger → boot true",
          ptyd._diag_supervision() == {"mode": "systemd", "linger": True, "boot": True, "scope": "user"},
          ptyd._diag_supervision())

    h = fresh(); h.user_enabled = True; h.user_state = "enabled-runtime"
    check("enabled-runtime (/run, dispare la reboot) NU contează ca enabled",
          ptyd._diag_supervision()["mode"] == "none", ptyd._diag_supervision())

    # fără bus de user (sub cron / orfan): citim symlink-ul lăsat de `enable`
    h = fresh(); h.user_bus = False
    check("fără bus, fără link → none", ptyd._diag_supervision()["mode"] == "none")
    os.makedirs(os.path.dirname(ptyd._user_unit_link()), exist_ok=True)
    os.symlink(ptyd._user_unit_path(), ptyd._user_unit_link())
    check("fără bus, cu link default.target.wants → systemd user",
          ptyd._diag_supervision().get("scope") == "user", ptyd._diag_supervision())

    # root cu unit de SISTEM
    h = fresh(uid=0)
    sysunit = os.path.join("/etc/systemd/system", ptyd._UNIT_NAME)
    if not os.path.exists(sysunit):
        _exists = ptyd.os.path.exists
        ptyd.os.path.exists = lambda p: True if p == sysunit else _exists(p)
        try:
            h.system_enabled = True
            st = ptyd._diag_supervision()
            check("root + unit de sistem enabled → systemd/system, boot (fără linger)",
                  st == {"mode": "systemd", "linger": False, "boot": True, "scope": "system"}, st)
            h2 = fresh(uid=1000); h2.system_enabled = True
            check("non-root NU întreabă de unit-ul de sistem",
                  not any(c[:2] == ["systemctl", "is-enabled"] for c in h2.calls)
                  and ptyd._diag_supervision()["mode"] == "none")
        finally:
            ptyd.os.path.exists = _exists
    else:                                       # pragma: no cover — CI nu are unit-ul
        print("  SKIP unit de sistem real prezent pe maşina de test")

    h = fresh(); h.crontab_unreadable = True
    check("crontab ilizibil → nu inventăm cron", ptyd._diag_supervision()["mode"] == "none")
    h = fresh(); h.crontab_missing = True
    check("crontab lipsă → none, fără excepţie", ptyd._diag_supervision()["mode"] == "none")

    # mărginit: fiecare subproces prin _sup_run cu SUPERVISION_TIMEOUT (verificăm codul real)
    check("_sup_run e mărginit în timp", ptyd.SUPERVISION_TIMEOUT <= 10)
    h = fresh(); ptyd._diag_supervision()
    check("≤3 subprocese per raportare (user is-enabled + crontab)", len(h.calls) <= 3, h.calls)

    # în diagnostic
    h = fresh(); h.crontab = OURS
    snap = ptyd.collect_diagnostics()
    check("collect_diagnostics conţine `supervision`",
          snap.get("supervision", {}).get("mode") == "cron", snap.get("supervision"))

    # ═════════════════════════ 2. autostart enable / disable ═════════════════════════
    h = fresh(); h.crontab = FOREIGN + OURS
    res = ptyd.autostart_set(True)
    unit_txt = open(ptyd._user_unit_path()).read() if os.path.exists(ptyd._user_unit_path()) else ""
    check("enable (systemd): unit scris", "[Service]" in unit_txt, unit_txt[:80])
    check("enable: ExecStart = python-ul curent + ACEST ptyd.py + run",
          ("ExecStart=%s %s run" % (ptyd._python_bin(), ptyd.SELF_PATH)) in unit_txt)
    check("enable: KillMode=process + WatchdogSec=45 + Restart=always (sincron cu instalatorul)",
          all(x in unit_txt for x in ("KillMode=process", "WatchdogSec=45", "Restart=always",
                                      "WantedBy=default.target")))
    enables = [c for c in h.calls if c[:3] == ["systemctl", "--user", "enable"]]
    check("enable: `systemctl --user enable` FĂRĂ --now", enables and all("--now" not in c for c in enables),
          enables)
    check("enable: liniile noastre de cron scoase, cele străine păstrate",
          h.crontab == FOREIGN, repr(h.crontab))
    check("enable fără linger → hint cu loginctl enable-linger + boot false, dar NU eroare",
          res["error"] == "" and "enable-linger tester" in res["hint"]
          and res["supervision"]["boot"] is False and res["supervision"]["mode"] == "systemd", res)
    check("enable a încercat linger fără prompt",
          ["loginctl", "--no-ask-password", "enable-linger", "tester"] in h.calls)

    h = fresh(); h.linger_on_loginctl = True
    res = ptyd.autostart_set(True)
    check("enable + loginctl reuşeşte → boot true, fără hint",
          res["error"] == "" and res["hint"] == "" and res["supervision"]["boot"] is True, res)

    # unit EXISTENT (ex. hardened) nu se rescrie
    h = fresh()
    os.makedirs(os.path.dirname(ptyd._user_unit_path()), exist_ok=True)
    with open(ptyd._user_unit_path(), "w") as f:
        f.write("[Service]\nExecStart=x\nNoNewPrivileges=true\n")
    linger_on()
    ptyd.autostart_set(True)
    check("unit existent (hardening opt-in) NU e rescris",
          "NoNewPrivileges=true" in open(ptyd._user_unit_path()).read())

    # fără systemd --user → cron, ca instalatorul
    h = fresh(systemctl=False); h.crontab = FOREIGN
    res = ptyd.autostart_set(True)
    lines = (h.crontab or "").splitlines()
    check("enable fără systemd → cron @reboot + watchdog adăugate",
          res["error"] == "" and res["supervision"] == {"mode": "cron", "linger": False, "boot": True,
                                                        "watchdog": True}, res)
    check("cron: liniile străine păstrate, în ordine, înaintea alor noastre",
          lines[:2] == FOREIGN.splitlines() and len(lines) == 4, lines)
    check("cron: aceleaşi linii ca instalatorul (# webterm / # webterm-watchdog)",
          lines[2:] == ptyd._cron_lines(ptyd._python_bin(), ptyd.SELF_PATH), lines[2:])
    ptyd.autostart_set(True)
    check("enable de două ori = idempotent (nu dublează liniile)",
          len((h.crontab or "").splitlines()) == 4, h.crontab)

    h = fresh(systemctl=False)                   # „no crontab for tester" = crontab gol
    res = ptyd.autostart_set(True)
    check("enable pe crontab inexistent → creat", res["error"] == "" and res["supervision"]["boot"], res)

    h = fresh(systemctl=False); h.crontab = FOREIGN; h.crontab_unreadable = True
    res = ptyd.autostart_set(True)
    check("enable pe crontab ilizibil → eroare, crontab NEATINS",
          res["error"] and not any(c[:2] == ["crontab", "-"] for c in h.calls), res)

    h = fresh(systemctl=False); h.crontab_missing = True
    res = ptyd.autostart_set(True)
    check("enable fără systemd şi fără crontab → eroare clară", "neither" in res["error"], res)

    h = fresh(); h.enable_fails = True; h.crontab = FOREIGN
    res = ptyd.autostart_set(True)
    check("systemctl enable refuzat → fallback pe cron (ca instalatorul)",
          res["supervision"]["mode"] == "cron" and res["error"] == "", res)

    # disable
    h = fresh(); h.crontab = FOREIGN + OURS
    linger_on()
    ptyd.autostart_set(True)
    h.crontab = FOREIGN + OURS                  # cineva a pus şi cron pe lângă
    res = ptyd.autostart_set(False)
    disables = [c for c in h.calls if "disable" in c]
    check("disable: `systemctl --user disable` FĂRĂ --now (nu omoară agentul care răspunde)",
          disables and all("--now" not in c for c in disables), disables)
    check("disable: liniile noastre scoase, cele străine păstrate", h.crontab == FOREIGN, repr(h.crontab))
    check("disable → mode none, boot false, fără eroare",
          res["error"] == "" and res["supervision"]["mode"] == "none" and not res["supervision"]["boot"], res)

    h = fresh(); h.crontab = OURS
    res = ptyd.autostart_set(False)
    check("disable cu DOAR liniile noastre → `crontab -r` (nu un crontab gol scris)",
          ["crontab", "-r"] in h.calls and h.crontab is None, h.calls)

    h = fresh(); h.crontab = FOREIGN + OURS; h.crontab_unreadable = True
    res = ptyd.autostart_set(False)
    check("disable pe crontab ilizibil → avertisment, crontab NEATINS",
          "cron" in res["error"] and not any(c[:2] in (["crontab", "-"], ["crontab", "-r"]) for c in h.calls),
          res)

    h = fresh(); h.user_bus = False
    os.makedirs(os.path.dirname(ptyd._user_unit_link()), exist_ok=True)
    os.symlink(ptyd._user_unit_path(), ptyd._user_unit_link())
    res = ptyd.autostart_set(False)
    check("disable fără bus de user → symlink-ul scos direct",
          not os.path.lexists(ptyd._user_unit_link()) and res["error"] == "", res)

    h = fresh(); h.crontab = None
    res = ptyd.autostart_set(False)
    check("disable fără nimic de scos → ok, nicio scriere",
          res["error"] == "" and not any(c[0] == "crontab" and c[1] != "-l" for c in h.calls), h.calls)

    # dezinstalarea foloseşte acelaşi filtru sigur
    h = fresh(); h.crontab = FOREIGN + OURS
    check("_cron_remove_webterm (comun cu uninstall) păstrează liniile străine",
          ptyd._cron_remove_webterm() is None and h.crontab == FOREIGN, repr(h.crontab))

    # ═════════════════════════ 3. op-ul prin handle_ctrl ═════════════════════════
    def fake_agent():
        ag = object.__new__(ptyd.Agent)
        ag.replies = []
        ag.send_ctrl = ag.replies.append
        ag._hb_sent_at = {}
        ag.inbox = queue.Queue()
        return ag

    def wait_reply(ag, n=1, timeout=5.0):
        end = time.time() + timeout
        while len(ag.replies) < n and time.time() < end:
            time.sleep(0.01)
        return list(ag.replies)

    def settle():
        """Reply-ul pleacă din worker chiar înainte de `finally` → aşteptăm eliberarea lock-ului."""
        if ptyd._AUTOSTART_LOCK.acquire(timeout=5):
            ptyd._AUTOSTART_LOCK.release()

    h = fresh(systemctl=False); h.crontab = FOREIGN
    ag = fake_agent()
    ptyd.Agent.handle_ctrl(ag, {"op": "autostart", "id": 1, "enable": "yes"})
    check("enable ne-bool → bad_request (nu „truthy”)",
          ag.replies and ag.replies[0].get("code") == "bad_request", ag.replies)

    ag = fake_agent()
    ptyd.Agent.handle_ctrl(ag, {"op": "autostart", "id": 2, "enable": True})
    r = wait_reply(ag)
    check("autostart enable → reply ok cu starea NOUĂ",
          r and r[0].get("ok") is True and r[0].get("id") == 2
          and r[0].get("supervision", {}).get("mode") == "cron", r)
    # reply-ul pleacă din worker chiar înainte de `finally` → aşteptăm eliberarea, mărginit
    check("lock-ul e eliberat după reply", ptyd._AUTOSTART_LOCK.acquire(timeout=5))
    ptyd._AUTOSTART_LOCK.release()

    ag = fake_agent()
    ptyd._AUTOSTART_LOCK.acquire()
    try:
        ptyd.Agent.handle_ctrl(ag, {"op": "autostart", "id": 3, "enable": False})
    finally:
        ptyd._AUTOSTART_LOCK.release()
    check("o comutare deja în zbor → busy", ag.replies and ag.replies[0].get("code") == "busy", ag.replies)

    h = fresh(systemctl=False); h.crontab_unreadable = True
    ag = fake_agent()
    ptyd.Agent.handle_ctrl(ag, {"op": "autostart", "id": 4, "enable": True})
    r = wait_reply(ag)
    settle()
    check("eşec → ok:false, code autostart_failed, cu starea curentă ataşată",
          r and r[0].get("ok") is False and r[0].get("code") == "autostart_failed"
          and "supervision" in r[0], r)

    _boom = ptyd.autostart_set
    ptyd.autostart_set = lambda e: 1 / 0
    try:
        ag = fake_agent()
        ptyd.Agent.handle_ctrl(ag, {"op": "autostart", "id": 5, "enable": True})
        r = wait_reply(ag)
    finally:
        ptyd.autostart_set = _boom
    check("excepţie în worker → reply de eroare, lock eliberat",
          r and r[0].get("code") == "autostart_failed" and ptyd._AUTOSTART_LOCK.acquire(timeout=5), r)
    ptyd._AUTOSTART_LOCK.release()
finally:
    restore()

# ═════════════════════════ 4. op-uri moarte scoase ═════════════════════════
for dead in ("list", "detach", "serial_close"):
    ag = object.__new__(ptyd.Agent)
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag.sessions = {}
    ptyd.Agent.handle_ctrl(ag, {"op": dead, "id": 9, "sid": "x" * 32, "stream": "y" * 32})
    check("op mort `%s` → bad_op" % dead, ag.replies and ag.replies[0].get("code") == "bad_op", ag.replies)
src = open(ptyd.SELF_PATH, encoding="utf-8").read()
check("`shutdown` rămâne (păstrat intenţionat)", 'op == "shutdown"' in src)
check("`fs_write` rămâne (fallback pt. agenţi mai vechi / gateway mai vechi)", 'op == "fs_write"' in src)

# ═════════════════════════ 5. tmux: WEBTERM_SESSION per sesiune ═════════════════════════
class Exec(Exception):
    pass


def spawn_argv(has_env, tz=None):
    """argv-ul cu care copilul pty ar face execve (fork + execve mockuite)."""
    s = object.__new__(ptyd.Session)
    s.sid, s.term, s.tz, s.cmd, s.backend, s.rows, s.cols = "a" * 32, "xterm", tz, None, "tmux", 24, 80
    saved = (ptyd.pty.fork, ptyd.os.execve, ptyd._TMUX_HAS_NEW_SESSION_ENV, ptyd.TMUX_BIN, os.getcwd())
    got = {}

    def fake_exec(path, argv, env):
        got["argv"], got["env"] = argv, env
        raise Exec()

    ptyd.pty.fork = lambda: (0, -1)
    ptyd.os.execve = fake_exec
    ptyd._TMUX_HAS_NEW_SESSION_ENV = has_env
    ptyd.TMUX_BIN = "/usr/bin/tmux"
    try:
        s.spawn_client()
    except Exec:
        pass
    finally:
        ptyd.pty.fork, ptyd.os.execve, ptyd._TMUX_HAS_NEW_SESSION_ENV, ptyd.TMUX_BIN = saved[:4]
        os.chdir(saved[4])
    return got.get("argv") or [], got.get("env") or {}


argv, env = spawn_argv(True, tz="Europe/Bucharest")
check("tmux ≥3.1: new-session primeşte -e WEBTERM_SESSION=<sid>",
      "WEBTERM_SESSION=" + "a" * 32 in argv and argv[argv.index("WEBTERM_SESSION=" + "a" * 32) - 1] == "-e",
      argv)
check("tmux ≥3.1: şi -e TZ=<fus>", "TZ=Europe/Bucharest" in argv, argv)
check("-e stă ÎNAINTE de -s <nume> (argumentele lui new-session)",
      argv.index("-s") > argv.index("WEBTERM_SESSION=" + "a" * 32) and argv[-1] == ptyd.TMUX_SESSION_PREFIX + "a" * 32,
      argv)
check("env-ul clientului păstrează WEBTERM_SESSION (sesiunea care porneşte serverul)",
      env.get("WEBTERM_SESSION") == "a" * 32)
argv, _ = spawn_argv(False)
check("tmux vechi / versiune necunoscută: fără -e (new-session ar eşua)", "-e" not in argv, argv)
check("pragul -e e 3.1, iar o versiune necunoscută NU e tratată ca modernă",
      "_TMUX_HAS_NEW_SESSION_ENV = _TMUX_VER is not None and _TMUX_VER >= (3, 1)" in src)

# ═════════════════════════ 6. gateway ═════════════════════════
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))
import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402
from app.main import app  # noqa: E402

ss = core.supervision_summary
check("supervision_summary: formă validă → listă albă",
      ss({"supervision": {"mode": "cron", "linger": False, "boot": True, "watchdog": True, "x": "y" * 99}})
      == {"mode": "cron", "linger": False, "boot": True, "watchdog": True})
check("supervision_summary: mod necunoscut → None", ss({"supervision": {"mode": "rc.local", "linger": False, "boot": True}}) is None)
check("supervision_summary: boot ne-bool → None", ss({"supervision": {"mode": "none", "linger": False, "boot": 1}}) is None)
check("supervision_summary: lipsă / non-dict → None", ss({}) is None and ss([1]) is None and ss({"supervision": "x"}) is None)
check("supervision_summary: scope doar user/system",
      "scope" not in ss({"supervision": {"mode": "systemd", "linger": True, "boot": True, "scope": "evil"}}))

PW = "parolabuna1"
_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}


class FakeConn(core.AgentConnection):
    def __init__(self, host_id, version, reply=None, gone=False):
        self.host_id = host_id
        self.agent_version = version
        self.metrics = None
        self.link = {}
        self.forwards = {}
        self.diagnostics = None
        self._diag_refused_at = 0.0
        self.reply = reply
        self.gone = gone
        self.sent = []

    async def request(self, op, timeout=20.0, **fields):
        self.sent.append(dict(fields, op=op))
        if self.gone:
            raise core.AgentGone()
        return self.reply

    async def disconnect(self):
        pass


async def gateway():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
            await c.post("/api/setup", json={"email": "a@b.co", "password": PW, "setup_token": "test-setup"})
            hid = (await c.post("/api/hosts", json={"name": "boot"})).json()["id"]
            cols = [r["name"] for r in await db.fetchall("PRAGMA table_info(hosts)")]
            check("migraţia hosts.supervision_summary e aplicată", "supervision_summary" in cols)

            # diagnostic → coloană → _host_json
            fa = FakeConn(hid, 57)
            await fa._store_diagnostics({"collected_at": time.time(),
                                         "supervision": {"mode": "none", "linger": False, "boot": False}})
            row = await db.fetchone("SELECT * FROM hosts WHERE id=?", hid)
            check("_store_diagnostics scrie supervision_summary",
                  json.loads(row["supervision_summary"]) == {"mode": "none", "linger": False, "boot": False},
                  row["supervision_summary"])
            h = next(x for x in (await c.get("/api/hosts")).json() if x["id"] == hid)
            check("GET /api/hosts expune `supervision`", h.get("supervision", {}).get("boot") is False, h.get("supervision"))
            await fa._store_diagnostics({"collected_at": time.time(), "system": {}})
            h = next(x for x in (await c.get("/api/hosts")).json() if x["id"] == hid)
            check("agent < 57 (fără `supervision`) → null (necunoscut, nu „nu”)", h.get("supervision") is None)
            await db.execute("UPDATE hosts SET supervision_summary='{x' WHERE id=?", hid)
            h = next(x for x in (await c.get("/api/hosts")).json() if x["id"] == hid)
            check("coloană coruptă → null, nu 500", h.get("supervision") is None)

            url = "/api/hosts/%d/autostart" % hid
            r = await c.post(url, json={"enable": True})
            check("offline → 409 host.offline", r.status_code == 409
                  and r.headers.get("X-WebTerm-Error") == "host.offline", r.text)

            core.sources[hid] = FakeConn(hid, 56)
            r = await c.post(url, json={"enable": True})
            check("agent v56 → 409 host.autostartAgentOld (cu need/have)",
                  r.status_code == 409 and r.headers.get("X-WebTerm-Error") == "host.autostartAgentOld"
                  and core.sources[hid].sent == [], r.text)

            new_state = {"mode": "cron", "linger": False, "boot": True, "watchdog": True}
            conn = FakeConn(hid, 57, reply={"ok": True, "supervision": new_state, "hint": ""})
            core.sources[hid] = conn
            r = await c.post(url, json={"enable": True})
            check("v57 → 200 + starea nouă", r.status_code == 200 and r.json()["supervision"] == new_state, r.text)
            check("gateway-ul a trimis op-ul autostart cu enable=true",
                  conn.sent == [{"enable": True, "op": "autostart"}], conn.sent)
            row = await db.fetchone("SELECT supervision_summary FROM hosts WHERE id=?", hid)
            check("starea stocată IMEDIAT (nu la diagnosticul orar)",
                  json.loads(row["supervision_summary"]) == new_state, row["supervision_summary"])

            r = await c.post(url, json={"enable": "da"})
            check("enable ne-bool → 422", r.status_code == 422, r.status_code)

            conn.reply = {"ok": False, "code": "autostart_failed", "msg": "could not read the crontab",
                          "supervision": {"mode": "none", "linger": False, "boot": False}}
            r = await c.post(url, json={"enable": True})
            check("eşec pe agent → 400 host.autostartFailed, starea curentă tot stocată",
                  r.status_code == 400 and r.headers.get("X-WebTerm-Error") == "host.autostartFailed", r.text)
            row = await db.fetchone("SELECT supervision_summary FROM hosts WHERE id=?", hid)
            check("…şi starea raportată la eşec ajunge în DB", json.loads(row["supervision_summary"])["boot"] is False)

            core.sources[hid] = FakeConn(hid, 57, gone=True)
            r = await c.post(url, json={"enable": False})
            check("agentul nu răspunde → 504 host.noAnswer", r.status_code == 504
                  and r.headers.get("X-WebTerm-Error") == "host.noAnswer", r.text)

            # H1: step-up ÎNAINTE de orice contact cu agentul
            await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", hid)
            conn = FakeConn(hid, 57, reply={"ok": True, "supervision": new_state})
            core.sources[hid] = conn
            r = await c.post(url, json={"enable": False})
            check("host cu 2FA, fără step-up → 403, agentul NEcontactat",
                  r.status_code == 403 and conn.sent == [], (r.status_code, conn.sent))
            await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", hid)

            sid = (await c.post("/api/hosts", json={"name": "ssh", "connection_type": "ssh",
                                                    "hostname": "10.0.0.9", "ssh_username": "u"})).json().get("id")
            if sid:
                r = await c.post("/api/hosts/%d/autostart" % sid, json={"enable": True})
                check("host SSH direct → 400 host.autostartNotAgent",
                      r.headers.get("X-WebTerm-Error") == "host.autostartNotAgent", r.text)
                h = next(x for x in (await c.get("/api/hosts")).json() if x["id"] == sid)
                check("host ne-agent: supervision null", h.get("supervision") is None)
            core.sources.pop(hid, None)
    finally:
        await db.close()


asyncio.run(gateway())

# ═════════════════════════ 7. agent: op-ul `history` (capture-pane) ═════════════════════════
import base64  # noqa: E402
import subprocess  # noqa: E402
import uuid  # noqa: E402
import zlib  # noqa: E402

HSID = "h" * 32
argv = ptyd.history_capture_argv(HSID, 3000)
check("history: argv = capture-pane -p -e -J, ţinta `wt-<sid>:` (ca session_cwd), -S -N -E -1",
      argv == ["capture-pane", "-p", "-e", "-J", "-t", ptyd.TMUX_SESSION_PREFIX + HSID + ":",
               "-S", "-3000", "-E", "-1"], argv)
# v58: probe-ul are şi pane_id + window_zoomed_flag (agent_v58_test acoperă pane-urile multiple)
check("history: probe parsat", ptyd.parse_history_probe(b"1981 1 %0 0\n") == (1981, 1, "%0", False))
check("history: probe ciudat → None",
      ptyd.parse_history_probe(b"") is None and ptyd.parse_history_probe(b"x 1") is None
      and ptyd.parse_history_probe(b"1 2 3") is None)
d, t = ptyd.cap_history_bytes(b"aa\nbb\ncc\n", 100)
check("cap: sub plafon → neschimbat", d == b"aa\nbb\ncc\n" and t is False)
d, t = ptyd.cap_history_bytes(b"aaaa\nbbbb\ncccc\n", 7)
check("cap: peste plafon → SFÂRŞITUL, tăiat la început de rând", d == b"cccc\n" and t is True, d)


class FakeTmux:
    def __init__(self, probe=b"1981 1 %0 0\n", data=b"L1\nL2\n", rc=0, timeout_on=None):
        self.calls = []
        self.probe, self.data, self.rc, self.timeout_on = probe, data, rc, timeout_on

    def __call__(self, *args, **kw):
        self.calls.append(list(args))
        if self.timeout_on and args[0] == self.timeout_on:
            raise subprocess.TimeoutExpired(args, kw.get("timeout"))
        if args[0] == "display-message":
            return subprocess.CompletedProcess(args, self.rc, self.probe, b"no such session")
        return subprocess.CompletedProcess(args, self.rc, self.data, b"")


def with_tmux(fake, fn):
    saved = ptyd.tmux_cmd
    ptyd.tmux_cmd = fake
    try:
        return fn()
    finally:
        ptyd.tmux_cmd = saved


ft = FakeTmux()
res = with_tmux(ft, lambda: ptyd.tmux_history(HSID, 3000))
check("tmux_history: -S plafonat la history_size (1981 < 3000)",
      ft.calls[1] == ptyd.history_capture_argv(HSID, 1981, "%0"), ft.calls)
check("tmux_history: probe pe ţinta `wt-<sid>:` cu history_size + window_panes",
      ft.calls[0][:4] == ["display-message", "-p", "-t", ptyd.TMUX_SESSION_PREFIX + HSID + ":"]
      and "#{history_size}" in ft.calls[0][4] and "#{window_panes}" in ft.calls[0][4], ft.calls[0])
check("tmux_history: z = zlib+base64 al capturii, n/lines corecte",
      zlib.decompress(base64.b64decode(res["z"])) == b"L1\nL2\n" and res["n"] == 6 and res["lines"] == 2, res)
ft = FakeTmux(probe=b"0 1 %0 0")
res = with_tmux(ft, lambda: ptyd.tmux_history(HSID, 3000))
check("tmux_history: fără istoric → NU rulează capture-pane (ar dubla primul rând vizibil)",
      len(ft.calls) == 1 and res["n"] == 0, (ft.calls, res))
res = with_tmux(FakeTmux(probe=b"500 2 %0 0"), lambda: ptyd.tmux_history(HSID, 3000))
check("tmux_history: pane-uri multiple → multi_pane (gateway-ul rămâne pe transcript)",
      res.get("error") == "multi_pane", res)
res = with_tmux(FakeTmux(rc=1), lambda: ptyd.tmux_history(HSID, 3000))
check("tmux_history: tmux eşuează → capture_failed", res.get("error") == "capture_failed", res)
res = with_tmux(FakeTmux(timeout_on="capture-pane"), lambda: ptyd.tmux_history(HSID, 3000))
check("tmux_history: timeout → capture_failed (nu excepţie)", res.get("error") == "capture_failed", res)
big = b"".join(b"%s\n" % os.urandom(60).hex().encode() for _ in range(60000))   # ~7 MiB, greu compresibil
res = with_tmux(FakeTmux(data=big), lambda: ptyd.tmux_history(HSID, 50000))
raw = zlib.decompress(base64.b64decode(res["z"]))
check("tmux_history: răspunsul mare încape sub HISTORY_MAX_REPLY (OUTBOX_LIMIT e 4 MiB!)",
      len(res["z"]) <= ptyd.HISTORY_MAX_REPLY < ptyd.OUTBOX_LIMIT and res["truncated"] is True, len(res["z"]))
check("tmux_history: trunchierea păstrează rândurile RECENTE, întregi",
      raw and big.endswith(raw) and big[len(big) - len(raw) - 1:len(big) - len(raw)] == b"\n")


class HSess:
    def __init__(self, backend):
        self.backend = backend


def hist_agent(backend="tmux"):
    ag = object.__new__(ptyd.Agent)
    ag.replies = []
    ag.send_ctrl = ag.replies.append
    ag._hb_sent_at = {}
    ag.sessions = {HSID: HSess(backend)}
    return ag


ag = hist_agent()
ptyd.Agent.handle_ctrl(ag, {"op": "history", "id": 1, "sid": "z" * 32, "lines": 10})
check("op history: sesiune necunoscută → no_session", ag.replies and ag.replies[0].get("code") == "no_session", ag.replies)
ag = hist_agent("pty")
ptyd.Agent.handle_ctrl(ag, {"op": "history", "id": 2, "sid": HSID, "lines": 10})
check("op history: backend pty → ok:false not_tmux", ag.replies and ag.replies[0].get("ok") is False
      and ag.replies[0].get("code") == "not_tmux", ag.replies)
for bad in ("10", 0, -5, True, None, 1.5):
    ag = hist_agent()
    ptyd.Agent.handle_ctrl(ag, {"op": "history", "id": 3, "sid": HSID, "lines": bad})
    check("op history: lines=%r → bad_request" % (bad,), ag.replies and ag.replies[0].get("code") == "bad_request", ag.replies)
ag = hist_agent()
ft = FakeTmux(data=b"\x1b[31mred\x1b[0m\nplain\n")
saved_cmd = ptyd.tmux_cmd
ptyd.tmux_cmd = ft
try:
    ptyd.Agent.handle_ctrl(ag, {"op": "history", "id": 4, "sid": HSID, "lines": 3000})
    end = time.time() + 5
    while not ag.replies and time.time() < end:
        time.sleep(0.01)
finally:
    ptyd.tmux_cmd = saved_cmd
r = ag.replies[0] if ag.replies else {}
check("op history: worker răspunde cu acelaşi id, ok, captura intactă",
      r.get("ok") is True and r.get("id") == 4
      and zlib.decompress(base64.b64decode(r["z"])) == b"\x1b[31mred\x1b[0m\nplain\n", r)
ok_sem = all(ptyd._HISTORY_SEM.acquire(timeout=5) for _ in range(2))
check("op history: semaforul e eliberat după reply", ok_sem)
ag = hist_agent()
ptyd.Agent.handle_ctrl(ag, {"op": "history", "id": 5, "sid": HSID, "lines": 10})
check("op history: capturi în zbor la plafon → busy", ag.replies and ag.replies[0].get("code") == "busy", ag.replies)
ptyd._HISTORY_SEM.release()
ptyd._HISTORY_SEM.release()

# ═════════════════════════ 8. gateway: îmbinare, sanitizare, fallback ═════════════════════════
san = core.sanitize_history_line
check("sanitize: păstrează SGR (culori)", san("\x1b[31mred\x1b[0m") == "\x1b[31mred\x1b[0m")
check("sanitize: scoate alt-screen, ED/clear, RIS, CUP, scroll-region",
      san("a\x1b[?1049hb\x1b[2Jc\x1b[3Jd\x1bce\x1b[5;1Hf\x1b[1;23rg") == "abcdefg",
      repr(san("a\x1b[?1049hb\x1b[2Jc\x1b[3Jd\x1bce\x1b[5;1Hf\x1b[1;23rg")))
check("sanitize: scoate OSC (titlu, 133) şi DCS", san("x\x1b]0;t\x07y\x1b]133;A\x1b\\z\x1bPtmux;q\x1b\\w") == "xyzw",
      repr(san("x\x1b]0;t\x07y\x1b]133;A\x1b\\z\x1bPtmux;q\x1b\\w")))
check("sanitize: scoate C1 (U+009B = CSI pentru xterm.js) şi controale C0, păstrează TAB",
      san("a\u009b?1049hb\rc\x08d\te") == "a?1049hbcd\te", repr(san("a\u009b?1049hb\rc\x08d\te")))
check("sanitize: spaţiile de la coadă (din -J) dispar, şi înaintea unui SGR final",
      san("abc   ") == "abc" and san("abc  \x1b[0m") == "abc\x1b[0m")
check("sanitize: ESC orfan la final de rând", san("abc\x1b") == "abc")

rawcap = b"".join(b"line %d\n" % i for i in range(1, 101)) + b"\x1b[?1049h\x1b[2Jevil\n"
blk = core.build_history_block(rawcap, 50, 24)
check("block: nicio comutare de ecran / ştergere nu supravieţuieşte (ALT_SCREEN_RE)",
      not core.ALT_SCREEN_RE.search(blk) and b"evil" in blk)
check("block: doar ultimele max_lines rânduri, CRLF între ele",
      b"line 51\r" not in blk and b"line 52\r\nline 53\r\n" in blk and b"line 100\r\n" in blk)
check("block: îmbinarea marcată + ecranul împins în scrollback (rows-1 LF) + cursor sus",
      blk.endswith(core.HISTORY_SEAM + b"\r\n" + b"\n" * 23 + b"\x1b[H"), repr(blk[-80:]))
check("block: niciun LF fără CR în corpul istoricului (xterm: LF singur nu face CR)",
      b"\n" not in blk.split(core.HISTORY_SEAM)[0].replace(b"\r\n", b""))
check("block: captură goală → b'' (replay-ul de azi)", core.build_history_block(b"", 100, 24) == b""
      and core.build_history_block(b"x\n", 0, 24) == b"")
check("block: rows plafonat (un client nu poate cere 10^6 LF)",
      core.build_history_block(b"x\n", 10, 10 ** 6).count(b"\n") <= core.HISTORY_MAX_ROWS + 2)


def enc(data):
    return {"ok": True, "z": base64.b64encode(zlib.compress(data)).decode()}


check("decode: round-trip", core.decode_history_reply(enc(b"a\nb\n")) == b"a\nb\n")
check("decode: bombă de decompresie (> 4 MiB decomprimat) → None",
      core.decode_history_reply(enc(b"\0" * (core.HISTORY_MAX_BYTES + 10))) is None)
check("decode: base64 invalid / z lipsă / ok:false / non-dict → None",
      core.decode_history_reply({"ok": True, "z": "@@@"}) is None
      and core.decode_history_reply({"ok": True}) is None
      and core.decode_history_reply({"ok": False, "z": enc(b"x")["z"]}) is None
      and core.decode_history_reply("x") is None)
check("decode: z peste plafon → None (nu decodăm deloc)",
      core.decode_history_reply({"ok": True, "z": "A" * (core.HISTORY_MAX_Z + 4)}) is None)

prp = core.parse_replay_params
check("params: lipsă → (0, 0) = replay-ul istoric", prp({}) == (0, 0))
check("params: plafonate server-side",
      prp({"sb": "999999", "rows": "99999"}) == (core.HISTORY_MAX_LINES, core.HISTORY_MAX_ROWS))
check("params: invalide / negative → 0", prp({"sb": "abc", "rows": "-4"}) == (0, 0))
check("params: valori normale trec", prp({"sb": "10000", "rows": "40"}) == (10000, 40))
check("limit: pty + desktop → 2 MiB", core.replay_tail_limit(10000, True) == config.BROWSER_TAIL_BYTES_LARGE)
check("limit: pty + mobil → fereastra istorică", core.replay_tail_limit(3000, True) == config.BROWSER_TAIL_BYTES)
check("limit: tmux → fereastra istorică", core.replay_tail_limit(10000, False) == config.BROWSER_TAIL_BYTES)


class HConn(FakeConn):
    def __init__(self, version, backend, reply=None, gone=False, delay=0.0):
        super().__init__(1, version, reply=reply, gone=gone)
        self.backend = backend
        self.delay = delay

    async def request(self, op, timeout=20.0, **fields):
        self.sent.append(dict(fields, op=op))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.gone:
            raise core.AgentGone()
        return self.reply


class HHub:
    def __init__(self, src, rows=24):
        self.src, self.rows, self.locked = src, rows, False

    def _source(self):
        return self.src


async def gw_history():
    sid = uuid.uuid4().hex
    out_path, _ = core.transcript_paths(sid)
    out_path.write_bytes(b"\x1b[?1049h" + b"T" * 300000 + b"\x1b]133;A\x07$ ")
    good = enc(b"\x1b[32mold 1\x1b[0m\nold 2\n")
    plain_tail = core.read_tail(sid)

    c = HConn(56, "tmux", reply=good)
    got = await core.attach_replay(sid, HHub(c), 10000, 30)
    check("fallback: agent v56 → EXACT replay-ul de azi, agentul necontactat", got == plain_tail and c.sent == [])
    c = HConn(57, "pty", reply=good)
    got = await core.attach_replay(sid, HHub(c), 10000, 30)
    check("pty + desktop: fără op history, fereastra mare (> 256 KiB)",
          c.sent == [] and len(got) > config.BROWSER_TAIL_BYTES
          and got == core.read_tail(sid, limit=config.BROWSER_TAIL_BYTES_LARGE))
    got = await core.attach_replay(sid, HHub(HConn(57, "pty")), 3000, 30)
    check("pty + mobil: fereastra istorică", got == plain_tail)
    for name, conn in (("agent plecat", HConn(57, "tmux", gone=True)),
                       ("ok:false", HConn(57, "tmux", reply={"ok": False, "code": "multi_pane"})),
                       ("răspuns corupt", HConn(57, "tmux", reply={"ok": True, "z": "!!"}))):
        got = await core.attach_replay(sid, HHub(conn), 10000, 30)
        check("fallback tăcut (%s) → replay-ul de azi" % name, got == plain_tail)
    t0 = time.time()
    got = await core.attach_replay(sid, HHub(HConn(57, "tmux", reply=good, delay=30)), 10000, 30)
    check("fallback: agentul nu răspunde → timeout mărginit, replay-ul de azi",
          got == plain_tail and time.time() - t0 < core.HISTORY_TIMEOUT + 2, time.time() - t0)
    got = await core.attach_replay(sid, HHub(HConn(57, "tmux", reply=good)), 0, 30)
    check("sb=0 (frontend vechi) → replay-ul de azi", got == plain_tail)

    c = HConn(57, "tmux", reply=good)
    got = await core.attach_replay(sid, HHub(c), 10000, 30)
    # `pane: "active"` (gateway 3.6): un agent 57 ignoră câmpul — vezi agent_v58_test
    check("tmux v57: op history cerut cu sid + lines = sb",
          c.sent == [{"sid": sid, "lines": 10000, "pane": "active", "op": "history"}], c.sent)
    check("tmux v57: istoric (cu culori) + îmbinare DEASUPRA cozii neschimbate",
          got.startswith(b"\x1b[0m\x1b[32mold 1\x1b[0m\r\nold 2") and got.endswith(plain_tail)
          and core.HISTORY_SEAM in got and got.index(core.HISTORY_SEAM) < len(got) - len(plain_tail))
    check("tmux v57: padding = rows-1 din client", (b"\r\n" + b"\n" * 29 + b"\x1b[H") in got)
    check("tmux v57: marcajele OSC 133 din coadă rămân (panoul de comenzi)", b"\x1b]133;A\x07" in got)
    check("tmux v57: nicio comutare alt-screen / ştergere în tot replay-ul", not core.ALT_SCREEN_RE.search(got))
    got = await core.attach_replay(sid, HHub(HConn(57, "tmux", reply=good), rows=40), 10000, 0)
    check("rows lipsă → rândurile hub-ului", (b"\r\n" + b"\n" * 39 + b"\x1b[H") in got)
    got = await core.attach_replay(sid, None, 10000, 30)
    check("sesiune închisă (fără hub): fără istoric tmux, fereastra mare pe desktop",
          got == core.read_tail(sid, limit=config.BROWSER_TAIL_BYTES_LARGE))
    check("stream_is_plain: necunoscut (fără sursă) şi SSH (tmux remote) → nu",
          not core.stream_is_plain(HHub(None)) and not core.stream_is_plain(HHub(HConn(57, "ssh"))))
    check("stream_is_plain: pty / telnet / serial / închisă → da",
          all(core.stream_is_plain(HHub(HConn(57, b))) for b in ("pty", "telnet", "telnet-fwd", "serial-fwd"))
          and core.stream_is_plain(None))
    out_path.unlink()


asyncio.run(gw_history())

print("\n%d/%d checks passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
