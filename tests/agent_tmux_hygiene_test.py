"""Igienă tmux în agent (ptyd.py): predicatul care decide ce procese `tmux -L <socket>`
sunt omorâte când serverul e înțepenit (_kill_tmux_procs). E criteriul cel mai riscant —
un fals-pozitiv ar SIGKILL-ui procese greșite — deci îl testăm izolat (funcție pură).

Modulul ptyd se importă fără efecte secundare (main() e gard-uit de __main__)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import ptyd  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


m = ptyd.tmux_cmdline_matches
SOCK = "webterm"

# --- potriviri corecte (server + client pe socketul nostru) ---
check("server tmux pe socketul nostru",
      m([b"/usr/bin/tmux", b"-L", b"webterm", b"-f", b"/x", b"new-session", b"-A", b"-s", b"wt-abc"], SOCK))
check("basename simplu 'tmux'",
      m([b"tmux", b"-L", b"webterm", b"attach"], SOCK))

# --- NU trebuie să prindă: alt socket ---
check("alt socket tmux → NU",
      not m([b"/usr/bin/tmux", b"-L", b"altul", b"new-session"], SOCK))
# tmux implicit (fără -L) → NU (nu e serverul nostru dedicat)
check("tmux fără -L → NU", not m([b"/usr/bin/tmux", b"new-session"], SOCK))
# proces non-tmux care întâmplător are -L webterm în argumente → NU
check("non-tmux cu -L webterm → NU",
      not m([b"/usr/bin/python3", b"-L", b"webterm"], SOCK))
# cmdline gol / degenerat
check("cmdline gol → NU", not m([], SOCK))
check("primul argument gol → NU", not m([b""], SOCK))
# -L la coadă fără valoare de socket după el → NU (off-by-one)
check("-L fără socket după → NU", not m([b"/usr/bin/tmux", b"-L"], SOCK))
# socketul e substring dar nu egal (webterm2) → NU (potrivire exactă)
check("socket substring (webterm2) → NU",
      not m([b"/usr/bin/tmux", b"-L", b"webterm2", b"x"], SOCK))

# --- constantele de igienă există (contract cu _tick / cooldown) ---
check("TMUX_SWEEP_INTERVAL definit", isinstance(ptyd.TMUX_SWEEP_INTERVAL, float))
check("TMUX_SERVER_KILL_COOLDOWN definit", isinstance(ptyd.TMUX_SERVER_KILL_COOLDOWN, float))
check("AGENT_VERSION bumped (>=19)", ptyd.AGENT_VERSION >= 19, ptyd.AGENT_VERSION)


# ========================================================================
# v19: detecţie server tmux ÎNŢEPENIT (bug igienă v17) + CLOEXEC pe master
# ========================================================================
import subprocess  # noqa: E402


class _R:
    def __init__(self, rc, err=b""):
        self.returncode = rc
        self.stderr = err
        self.stdout = b""


def _patch(fn):
    ptyd.tmux_cmd = fn


_orig_tmux_cmd = ptyd.tmux_cmd

# server sănătos (rc=0) → NU e înţepenit
_patch(lambda *a, **k: _R(0))
check("server sănătos → nu-i înţepenit", ptyd.tmux_server_wedged() is False)

# niciun server pornit (rc=1, 'no server running') → NU e înţepenit (normal)
_patch(lambda *a, **k: _R(1, b"no server running on /tmp/tmux-0/webterm"))
check("niciun server → nu-i înţepenit (normal)", ptyd.tmux_server_wedged() is False)

# server ÎNŢEPENIT ('server exited unexpectedly') → DA
_patch(lambda *a, **k: _R(1, b"server exited unexpectedly"))
check("'server exited unexpectedly' → înţepenit", ptyd.tmux_server_wedged() is True)

# 'lost server' → DA
_patch(lambda *a, **k: _R(1, b"lost server"))
check("'lost server' → înţepenit", ptyd.tmux_server_wedged() is True)

# timeout/OSError la comandă → tratat ca ne-înţepenit (nu escaladăm pe erori tranzitorii)
def _raise(*a, **k):
    raise subprocess.TimeoutExpired("tmux", 10)
_patch(_raise)
check("timeout tmux → nu-i (fals) înţepenit", ptyd.tmux_server_wedged() is False)

ptyd.tmux_cmd = _orig_tmux_cmd

# --- CLOEXEC funcţional: un fd marcat set_inheritable(False) se închide la exec ---
# (aşa moare clientul tmux vechi la re-exec-ul agentului → fără acumulare)
import os as _os  # noqa: E402
mfd, sfd = _os.openpty()
_os.set_inheritable(mfd, False)
child = subprocess.run(
    [sys.executable, "-c",
     "import os,sys\n"
     "try:\n os.fstat(%d); print('OPEN')\n"
     "except OSError:\n print('CLOSED')" % mfd],
    capture_output=True, pass_fds=())
check("CLOEXEC: master ne-moştenit e ÎNCHIS după exec",
      b"CLOSED" in child.stdout, child.stdout + child.stderr)
_os.close(mfd); _os.close(sfd)

print(f"\n{ok}/{total} PASS")
sys.exit(0 if ok == total else 1)
