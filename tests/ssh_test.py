"""Conectare directă SSH (Faza 1): dial + PTY tmux, host-key TOFU/pinning,
respingere la nepotrivire (MITM), eșec de auth, și NICIUN secret în transcript.
Rulează contra sshd-ului local, cu un user de test efemer (necesită sudo)."""
import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import asyncssh  # noqa: E402
from app import config, core, db, security  # noqa: E402

USER = "wtsshtest"
KEY = "/tmp/wt_ssh_test_key"
ok = 0
total = 0


def check(name, cond):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def setup_user():
    teardown_user()
    sh(f"ssh-keygen -t ed25519 -f {KEY} -N '' -q")
    sh(f"sudo useradd -m -s /bin/bash {USER}")
    home = f"/home/{USER}"
    sh(f"sudo mkdir -p {home}/.ssh")
    with open(f"{KEY}.pub") as f:
        pub = f.read()
    sh(f"echo {json.dumps(pub)} | sudo tee {home}/.ssh/authorized_keys >/dev/null")
    sh(f"sudo chown -R {USER}:{USER} {home}/.ssh")
    sh(f"sudo chmod 700 {home}/.ssh && sudo chmod 600 {home}/.ssh/authorized_keys")


def teardown_user():
    # Testul deschide o sesiune PTY prin SSH, iar sursa pornește `tmux new -A` pe host →
    # rămân un server tmux, shell-uri și un `systemd --user` DUPĂ ce testul se termină.
    # `userdel` refuză un cont cu procese vii („currently used by process"), deci fără
    # pașii de mai jos contul supraviețuiește tăcut — pe mașina asta a stat 21 de zile,
    # cu 13 shell-uri, până l-am găsit. Ordinea contează: sesiunea logind (care ține
    # managerul systemd al userului) → procesele rămase → abia apoi ștergerea contului.
    uid = sh(f"id -u {USER} 2>/dev/null").stdout.strip()   # înainte de userdel
    sh(f"sudo loginctl disable-linger {USER} 2>/dev/null")
    sh(f"sudo loginctl terminate-user {USER} 2>/dev/null")
    sh(f"sudo pkill -9 -u {USER} 2>/dev/null")
    time.sleep(0.5)
    sh(f"sudo userdel -r {USER} 2>/dev/null")
    if uid.isdigit():
        sh(f"sudo rm -rf /tmp/tmux-{uid}")                 # socketul tmux al userului
    for p in (KEY, KEY + ".pub"):
        try:
            os.unlink(p)
        except OSError:
            pass


async def new_ssh_host(auth_method="key", cred=None):
    if cred is None:
        with open(KEY) as f:
            cred = {"key": f.read()}
    blob = security.encrypt_secret(json.dumps(cred))
    hid = await db.execute(
        "INSERT INTO hosts(name, token_hash, token_encrypted, created, connection_type,"
        " hostname, ssh_username, ssh_port, auth_method, credential_encrypted, credential_policy)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        "sshbox", security.new_token(), "x", time.time(), "ssh",
        "127.0.0.1", USER, 22, auth_method, blob, "stored")
    return await db.fetchone("SELECT * FROM hosts WHERE id=?", hid)


async def main():
    security.init_crypto(b"0" * 32)
    config.ensure_dirs()
    await db.connect()

    # ── happy path: dial + sesiune PTY (tmux) + comandă + output ──
    row = await new_ssh_host()
    cred = json.loads(security.decrypt_secret(row["credential_encrypted"]))
    await core.dial_ssh(row, cred)
    check("dial SSH cu cheie reușește", core.source_for(row["id"]) is not None)

    res = await core.create_session(row["id"], "t", 24, 80)
    sid = res["id"]
    await asyncio.sleep(2.0)                      # tmux pornește
    src = core.source_for(row["id"])
    await src.send_data(sid, b"echo HELLO_SSH_MARKER\n")
    await asyncio.sleep(1.8)
    out = core.transcript_paths(sid)[0].read_bytes()
    check("comanda rulează prin PTY (output în transcript)", b"HELLO_SSH_MARKER" in out)

    # resize nu crapă
    await src.resize(sid, 40, 120)
    check("resize acceptat", True)

    # ── host key a fost pinat (TOFU) ──
    row2 = await db.fetchone("SELECT * FROM hosts WHERE id=?", row["id"])
    pinned = row2["known_hosts"]
    check("host key pinat după prima conectare", bool(pinned) and "ssh-" in pinned)

    # ── NICIUN secret în transcript ──
    priv = cred["key"]
    cast = core.transcript_paths(sid)[1].read_bytes()
    leak = (priv.encode() in out or priv.encode() in cast
            or b"BEGIN OPENSSH PRIVATE KEY" in out)
    check("cheia privată NU apare în transcript (.out/.cast)", not leak)

    await core.kill_session(sid)          # închide și conexiunea (sursa se golește)
    await asyncio.sleep(0.5)

    # ── a doua conectare verifică cheia pinată (fără re-pin) ──
    row3 = await db.fetchone("SELECT * FROM hosts WHERE id=?", row["id"])
    await core.dial_ssh(row3, cred)
    check("reconectare cu host key pinat reușește", core.source_for(row["id"]) is not None)
    core.sources.pop(row["id"])._conn.close()

    # ── host key MISMATCH → oprit (anti-MITM); pinăm o cheie validă dar greșită ──
    sh(f"ssh-keygen -t ed25519 -f {KEY}_bogus -N '' -q")
    with open(f"{KEY}_bogus.pub") as f:
        bogus = f.read().strip()
    await db.execute("UPDATE hosts SET known_hosts=? WHERE id=?", bogus, row["id"])
    row4 = await db.fetchone("SELECT * FROM hosts WHERE id=?", row["id"])
    mismatch = False
    try:
        await core.dial_ssh(row4, cred)
    except (core.HostKeyMismatch, asyncssh.Error, ValueError):
        mismatch = True
    check("host key schimbat → conectare respinsă (MITM)", mismatch)
    core.sources.pop(row["id"], None)
    os.unlink(f"{KEY}_bogus"); os.unlink(f"{KEY}_bogus.pub")

    # ── auth greșit (cheie care nu e autorizată) → respins ──
    sh(f"ssh-keygen -t ed25519 -f {KEY}_bad -N '' -q")
    with open(f"{KEY}_bad") as f:
        bad = f.read()
    row5 = await new_ssh_host(cred={"key": bad})
    denied = False
    try:
        await core.dial_ssh(row5, {"key": bad})
    except asyncssh.Error:
        denied = True
    check("cheie neautorizată → auth respins", denied)
    core.sources.pop(row5["id"], None)
    os.unlink(f"{KEY}_bad"); os.unlink(f"{KEY}_bad.pub")

    # curăță orice conexiune rămasă ca asyncio.run să se închidă curat
    for s in list(core.sources.values()):
        try:
            s._conn.close()
        except Exception:
            pass
    core.sources.clear()
    await db.close()

    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    setup_user()
    try:
        success = asyncio.run(main())
    finally:
        teardown_user()
    sys.exit(0 if success else 1)
