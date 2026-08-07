"""Server tmux izolat pentru testele care pornesc agentul REAL (agent/ptyd.py).

De ce există fișierul ăsta: `ptyd.py` are `TMUX_SOCKET = "webterm"` hardcodat, iar tmux
pune socketul în `$TMUX_TMPDIR/tmux-<uid>/<nume>` — cheia e UID-ul, NU `$HOME`. Un test
care sandboxează doar `HOME` ajunge deci pe EXACT acelaşi server tmux ca agentul de
producţie de pe maşină: îi adoptă sesiunile vii (`new-session -A -D` detaşează clientul
agentului real → ping-pong de reataşări → agentul real renunţă şi face `kill-session`),
iar teardown-ul îi dă oricum `kill-server`.

Aşa au fost distruse sesiunile live pe 2026-08-05 (rulare de teste pe maşina de producţie,
chiar înainte de release-ul v1.0.119): `ptyd.log` arată „tmux client died, reattaching" x3
urmat de „respawn loop, giving up" pe ambele sesiuni, în aceeaşi secundă.

Prin urmare: orice test care lansează `ptyd.py` foloseşte `agent_env()` pentru env-ul
agentului şi `kill_server()` pentru curăţenie. Nimic nu mai atinge socketul de producţie.
"""

import os
import socket
import subprocess
import time

# HOME-ul REAL, capturat la import — testele îl suprascriu doar în env-ul copiilor, dar
# îl citim aici ca să găsim agentul de producţie (~/.webterm/alive) indiferent de ordine.
_REAL_HOME = os.path.expanduser("~")
_PROD_SOCKET = os.path.join(os.environ.get("TMUX_TMPDIR") or "/tmp",
                            "tmux-%d" % os.getuid(), "webterm")
_ALIVE_FRESH = 180.0        # agentul îşi rescrie ~/.webterm/alive periodic (zeci de secunde)


def _socket_path(tmux_tmpdir):
    return os.path.join(tmux_tmpdir, "tmux-%d" % os.getuid(), "webterm")


def _prod_agent_live():
    """True dacă pe maşina asta rulează un agent webterm de producţie: fişierul de
    liveness e proaspăt SAU socketul tmux de producţie acceptă conexiuni."""
    try:
        if time.time() - os.stat(os.path.join(_REAL_HOME, ".webterm", "alive")).st_mtime < _ALIVE_FRESH:
            return True
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(1)
            s.connect(_PROD_SOCKET)
            return True
        finally:
            s.close()
    except OSError:
        return False


def _guard(tmux_tmpdir):
    """Refuză să pornim testul dacă izolarea nu ţine şi un agent viu ar plăti nota."""
    if os.path.realpath(_socket_path(tmux_tmpdir)) != os.path.realpath(_PROD_SOCKET):
        return                                   # izolat — nu atingem producţia
    if os.environ.get("WEBTERM_TESTS_ALLOW_LIVE_AGENT") == "1":
        return                                   # portiţă explicită, pe răspunderea celui care o setează
    if not _prod_agent_live():
        return
    raise SystemExit(
        "REFUZ: testul ar folosi serverul tmux de producţie (%s) cât timp un agent webterm\n"
        "e viu — i-ar adopta şi apoi omorî sesiunile utilizatorului (incidentul din 2026-08-05).\n"
        "Rulează testele pe alt UID/maşină, sau setează WEBTERM_TESTS_ALLOW_LIVE_AGENT=1 dacă\n"
        "chiar vrei să sacrifici sesiunile vii." % _PROD_SOCKET)


def agent_env(home, **extra):
    """Env pentru un `ptyd.py` de test: HOME sandboxat + server tmux propriu.

    `TMUX_TMPDIR` se propagă singur la tot ce lansează agentul (clienţii tmux din
    `pty.fork`+`execve` moştenesc `os.environ`, iar `tmux_cmd` rulează fără `env=`),
    şi ptyd nu filtrează decât `SSH_*`."""
    tmux_tmpdir = os.path.join(home, "tmuxtmp")
    os.makedirs(tmux_tmpdir, mode=0o700, exist_ok=True)
    _guard(tmux_tmpdir)
    return dict(os.environ, HOME=home, TMUX_TMPDIR=tmux_tmpdir, **extra)


def kill_server(env):
    """Omoară serverul tmux AL TESTULUI. `env` trebuie să fie cel de la `agent_env()` —
    un kill-server fără sandbox e o eroare de programare, nu un incident de producţie."""
    tmux_tmpdir = env.get("TMUX_TMPDIR")
    if not tmux_tmpdir or os.path.realpath(_socket_path(tmux_tmpdir)) == os.path.realpath(_PROD_SOCKET):
        raise AssertionError(
            "kill-server fără TMUX_TMPDIR izolat ar omorî sesiunile de producţie "
            "(env TMUX_TMPDIR=%r)" % tmux_tmpdir)
    subprocess.run(["tmux", "-L", "webterm", "kill-server"], env=env,
                   stderr=subprocess.DEVNULL)
