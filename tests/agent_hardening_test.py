"""Hardening agent (v20): G3 (run cu output mărginit + kill la runaway), G7 (rotaţie
log), G1 (watchdog pe liveness). Fără proces gateway; apelăm metodele direct cu un self
minimal (send_ctrl capturează reply-ul)."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeSelf:
    def __init__(self):
        self.reply = None

    def send_ctrl(self, obj):
        self.reply = obj


# ================= G3: run cu output mărginit =================
# comandă NORMALĂ
fs = FakeSelf()
ptyd.Agent._run_command(fs, "r1", "echo salut", 10)
check("G3 comandă normală: exit 0 + output", fs.reply and fs.reply["exit_code"] == 0
      and "salut" in fs.reply["stdout"], fs.reply)

# comandă RUNAWAY (output infinit) → capată repede, memorie mărginită, NU rulează timeout-ul
orig_hard = ptyd.RUN_CAPTURE_HARD
ptyd.RUN_CAPTURE_HARD = 2 * 1024 * 1024      # 2MB pt. test rapid
fs = FakeSelf()
t0 = time.time()
ptyd.Agent._run_command(fs, "r2", "yes ABCDEFGHIJ", 30)   # output infinit
dt = time.time() - t0
ptyd.RUN_CAPTURE_HARD = orig_hard
check("G3 runaway: reply prezent (nu atârnă)", fs.reply is not None)
check("G3 runaway: stdout mărginit (≤ RUN_OUTPUT_CAP)",
      fs.reply and len(fs.reply["stdout"].encode()) <= ptyd.RUN_OUTPUT_CAP + 256,
      len(fs.reply["stdout"]) if fs.reply else None)
check("G3 runaway: OMORÂT la cap, NU după timeout (dt<10s, timeout era 30s)", dt < 10, "%.1fs" % dt)
check("G3 runaway: marcat oprit (exit None)", fs.reply and fs.reply["exit_code"] is None)

# comandă care depăşeşte TIMEOUT-ul
fs = FakeSelf()
t0 = time.time()
ptyd.Agent._run_command(fs, "r3", "sleep 5", 1)
dt = time.time() - t0
check("G3 timeout: marcat timed_out", fs.reply and fs.reply["timed_out"] is True)
check("G3 timeout: oprit la ~1s (nu 5s)", dt < 3, "%.1fs" % dt)

# comandă inexistentă → exit non-zero, fără crash
fs = FakeSelf()
ptyd.Agent._run_command(fs, "r4", "comanda_inexistenta_xyz", 5)
check("G3 comandă invalidă: reply ok cu exit != 0",
      fs.reply and fs.reply["ok"] and fs.reply["exit_code"] not in (0, None), fs.reply)

# ================= G7: rotaţie log =================
d = tempfile.mkdtemp()
ptyd.LOG_PATH = os.path.join(d, "ptyd.log")
ptyd.LOG_MAX = 4096
with open(ptyd.LOG_PATH, "wb") as f:
    f.write(b"x" * 8192)          # peste plafon
ag = FakeSelf()
ag._last_logcheck = 0.0
ptyd.Agent._rotate_log(ag)
check("G7 log peste plafon → trunchiat", os.path.getsize(ptyd.LOG_PATH) < 4096,
      os.path.getsize(ptyd.LOG_PATH))

# ================= G1: watchdog pe liveness =================
ptyd.ALIVE_PATH = os.path.join(d, "alive")
check("G1 fişier lipsă → not hung", ptyd.agent_hung() is False)
open(ptyd.ALIVE_PATH, "w").write("x")
check("G1 proaspăt → not hung", ptyd.agent_hung() is False)
os.utime(ptyd.ALIVE_PATH, (time.time() - (ptyd.AGENT_HUNG_AFTER + 50),) * 2)
check("G1 stale → hung", ptyd.agent_hung() is True)

check("AGENT_VERSION bumped (>=20)", ptyd.AGENT_VERSION >= 20, ptyd.AGENT_VERSION)

# ============ metrics.sample(): fără f_fsid, ca pe Python-uri vechi ============
# Bug real (server vechi, 2026-09-03): samplerul deduplica filesystem-urile prin `st.f_fsid`,
# dar `os.statvfs_result` din Python-uri mai vechi NU are câmpul → AttributeError la
# conectare, agentul nu pornea deloc. Acum dedup pe `st_dev`. Simulăm statvfs FĂRĂ f_fsid.
import collections  # noqa: E402
_m = ptyd.Metrics().sample()
check("sample() întoarce metrici de disc", "disk_total" in _m and "disk_used" in _m, str(_m.keys()))
_Fake = collections.namedtuple(
    "_Fake", "f_bsize f_frsize f_blocks f_bfree f_bavail f_files f_ffree f_favail f_flag f_namemax")
_real_statvfs = os.statvfs
os.statvfs = lambda p: _Fake(*(getattr(_real_statvfs(p), f) for f in _Fake._fields))
try:
    _m2 = ptyd.Metrics().sample()
    check("sample() nu crapă cu statvfs FĂRĂ f_fsid (Python vechi)", "disk_total" in _m2, str(_m2.keys()))
finally:
    os.statvfs = _real_statvfs

# ============ tmux vechi: opţiunile 2.1+ nu ajung în config ============
# Bug real (server vechi, 2026-09-03): `set -g prefix None` (şi `mouse`/`set-clipboard`)
# sunt din tmux 2.1; un tmux mai vechi le respinge → `tmux.conf:2: bad key: None`. Gate pe
# versiune: pe < 2.1 emitem doar opţiunile de bază, dar PĂSTRĂM `default-shell` (altfel s-ar
# reîntoarce bug-ul cu shell-ul din cron). Verificăm parsarea versiunii şi conţinutul config-ului.


def _conf_for(version_bytes):
    _orig = ptyd.subprocess.run
    ptyd.subprocess.run = lambda *a, **k: type("R", (), {"stdout": version_bytes})()
    try:
        v = ptyd._tmux_version()
        has21 = v is None or v >= (2, 1)
        hasnone = v is None or v >= (2, 4)
        conf = ('set -g default-terminal "xterm-256color"\n'
                + ("set -g prefix None\n" if hasnone else "")
                + "".join("set -g %s %s\n" % (k, ptyd._tmux_q(val))
                          for k, val in (ptyd._TMUX_BASE_OPTIONS
                                         + (ptyd._TMUX_21_OPTIONS if has21 else []))))
        return v, conf
    finally:
        ptyd.subprocess.run = _orig


check("_tmux_version parsează 'tmux 3.4'", _conf_for(b"tmux 3.4\n")[0] == (3, 4))
check("_tmux_version parsează 'tmux 2.1a'", _conf_for(b"tmux 2.1a\n")[0] == (2, 1))
check("_tmux_version parsează 'tmux next-3.5'", _conf_for(b"tmux next-3.5\n")[0] == (3, 5))
# tmux 2.1 (fix cazul mailer): acceptă `mouse`, dar RESPINGE `prefix None` (bad key)
_v21, _c21 = _conf_for(b"tmux 2.1\n")
check("tmux 2.1: config FĂRĂ 'prefix None' (cazul mailer — fără bad key)", "prefix None" not in _c21)
check("tmux 2.1: config CU 'mouse' (valid pe 2.1)", "mouse" in _c21)
check("tmux 2.1: config PĂSTREAZĂ 'default-shell'", "default-shell" in _c21)
# tmux 2.0: nici mouse, nici prefix None
_v20, _c20 = _conf_for(b"tmux 2.0\n")
check("tmux 2.0: config FĂRĂ 'prefix None' şi FĂRĂ 'mouse'",
      "prefix None" not in _c20 and "mouse" not in _c20)
check("tmux 2.0: config PĂSTREAZĂ 'default-shell' (nu reintroduce bug-ul cron)",
      "default-shell" in _c20)
# tmux 2.4+ / modern: config complet
_v34, _c34 = _conf_for(b"tmux 3.4\n")
check("tmux 3.4: config CU 'prefix None' şi 'mouse'", "prefix None" in _c34 and "mouse" in _c34)

# ============ _login_shell: nologin/false din passwd NU devin default-shell ============
# Audit 2026-08: un cont de serviciu are `/usr/sbin/nologin` în passwd — există, e
# executabil, trece testele de fişier, dar fiecare sesiune nouă ar muri instant.
# Ordinea corectă: passwd (utilizabil) → $SHELL (utilizabil) → /bin/bash → /bin/sh.
class _Pw:
    def __init__(self, sh):
        self.pw_shell = sh


_orig_getpwuid = ptyd.pwd.getpwuid
_orig_env_shell = os.environ.get("SHELL")
try:
    ptyd.pwd.getpwuid = lambda _uid: _Pw("/usr/sbin/nologin")
    os.environ["SHELL"] = "/bin/bash"
    check("nologin în passwd + $SHELL valid → $SHELL", ptyd._login_shell() == "/bin/bash",
          ptyd._login_shell())
    os.environ["SHELL"] = "/opt/nu-exista"
    got = ptyd._login_shell()
    check("nologin + $SHELL invalid → fallback sănătos, nu nologin",
          got in ("/bin/bash", "/bin/sh"), got)
    ptyd.pwd.getpwuid = lambda _uid: _Pw("/bin/false")
    got = ptyd._login_shell()
    check("/bin/false respins la fel", got != "/bin/false", got)
    ptyd.pwd.getpwuid = lambda _uid: _Pw("/bin/bash")
    os.environ["SHELL"] = "/bin/sh"
    check("passwd utilizabil rămâne sursa de adevăr (nu $SHELL — bug-ul cu cron)",
          ptyd._login_shell() == "/bin/bash", ptyd._login_shell())
finally:
    ptyd.pwd.getpwuid = _orig_getpwuid
    if _orig_env_shell is None:
        os.environ.pop("SHELL", None)
    else:
        os.environ["SHELL"] = _orig_env_shell

# ============ Audit de securitate 2026-08: întăriri ============
# sid non-hex respins la create (numele de sesiune tmux nu poate purta sintaxă de țintă)
check("sid hex acceptat", ptyd._is_hex_sid("a" * 32) and ptyd._is_hex_sid("0f9e" * 8))
check("sid cu sintaxă tmux respins", not ptyd._is_hex_sid("=" + "a" * 31))
check("sid cu majuscule/altele respins", not ptyd._is_hex_sid("A" * 32) and not ptyd._is_hex_sid("g" * 32))

# default-shell cu apostrofă e escapat în conf (nu rupe linia / nu injectează)
check("_tmux_q escapează apostrofa", ptyd._tmux_q("/bin/o'sh") == "'/bin/o'\\''sh'")
check("conf-ul folosește quoting-ul", "set -g default-shell '" in ptyd.TMUX_CONF_CONTENT)

print(f"\n{ok}/{total} PASS")
sys.exit(0 if ok == total else 1)
