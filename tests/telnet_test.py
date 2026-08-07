"""Conectare directă Telnet (Faza 4): TelnetSource contra unui server telnet
in-process (telnetlib3) care cere login/parolă apoi acționează ca un shell.
Verifică auto-login + I/O prin transcript."""
import asyncio
import json
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import telnetlib3  # noqa: E402
from app import config, core, db, security  # noqa: E402

PORT = 2399
USER = "telu"
PASS = "telp"
got_user = []
ok = 0
total = 0


def check(name, cond):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


async def shell(reader, writer):
    """Server telnet minimal: login: → Password: → shell care face echo."""
    writer.write("login: ")
    user = (await reader.readline()).strip()
    got_user.append(user)
    writer.write("Password: ")
    await reader.readline()
    writer.write("\r\nWelcome\r\n$ ")
    while True:
        line = await reader.readline()
        if not line:
            break
        line = line.strip()
        if line.startswith("echo "):
            writer.write(line[5:] + "\r\n$ ")
        else:
            writer.write("$ ")


async def main():
    security.init_crypto(b"0" * 32)
    config.ensure_dirs()
    await db.connect()
    server = await telnetlib3.create_server(host="127.0.0.1", port=PORT, shell=shell)

    blob = security.encrypt_secret(json.dumps({"password": PASS}))
    hid = await db.execute(
        "INSERT INTO hosts(name, token_hash, token_encrypted, created, connection_type,"
        " hostname, ssh_username, ssh_port, auth_method, credential_encrypted, credential_policy)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        "telbox", security.new_token(), "x", time.time(), "telnet",
        "127.0.0.1", USER, PORT, "password", blob, "stored")
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", hid)

    creds = {"username": USER, "password": PASS}
    await core.dial_telnet(row, creds)
    check("dial telnet reușește", isinstance(core.source_for(hid), core.TelnetSource))

    res = await core.create_session(hid, "t", 24, 80)
    sid = res["id"]
    await asyncio.sleep(2.5)      # login: → user → Password: → pass → shell
    check("auto-login a trimis user-ul", got_user and got_user[0] == USER)

    src = core.source_for(hid)
    await src.send_data(sid, b"echo TELNET_OK_MARKER\n")
    await asyncio.sleep(1.2)
    out = core.transcript_paths(sid)[0].read_bytes()
    check("comanda merge prin telnet (echo în transcript)", b"TELNET_OK_MARKER" in out)
    check("prompt-ul serverului e în transcript", b"Welcome" in out)

    # parola NU apare în transcript (a fost tastată, dar serverul nu o afișează)
    cast = core.transcript_paths(sid)[1].read_bytes()
    # (input-ul e în .cast ca eveniment „i"; verificăm doar că .out nu are parola în clar de la server)
    check("parola nu e ecoată de server în .out", PASS.encode() not in out)

    await core.kill_session(sid)
    await asyncio.sleep(0.3)
    for s in list(core.sources.values()):
        await s.disconnect()
    core.sources.clear()
    server.close()
    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
