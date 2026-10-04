"""Hermetic: destinaţia de backup SFTP (app/backup_dest.py) contra unui server SFTP asyncssh
in-process. Verifică probe host-key (TOFU), upload/list/delete, şi PINUIREA host-key — o cheie
schimbată trebuie să ducă la refuz (anti-MITM). FTPS nu e testat aici (ar cere un server FTP-TLS
extern); e acoperit la nivel de construcţie de context TLS + manual."""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import asyncssh  # noqa: E402
from app import backup_dest  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


async def main():
    tmp = tempfile.mkdtemp()
    root = os.path.join(tmp, "backups")
    os.makedirs(root, exist_ok=True)

    server_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    client_priv = client_key.export_private_key().decode()
    caw = asyncssh.import_authorized_keys(client_key.export_public_key().decode())

    server = await asyncssh.create_server(
        lambda: asyncssh.SSHServer(), "127.0.0.1", 0,
        server_host_keys=[server_key], authorized_client_keys=caw,
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=root))
    port = server.sockets[0].getsockname()[1]

    try:
        # 1. probe host-key (TOFU) — validează auth + întoarce cheia/amprenta serverului
        pr = await backup_dest.probe_hostkey("127.0.0.1", port, "u", ssh_key=client_priv)
        expected = " ".join(server_key.export_public_key().decode().split()[:2])
        check("probe întoarce host-key-ul serverului", pr["hostkey"] == expected, pr.get("hostkey"))
        check("probe întoarce o amprentă SHA256", pr.get("fingerprint", "").startswith("SHA256:"),
              pr.get("fingerprint"))

        cfg = {"host": "127.0.0.1", "port": port, "user": "u", "ssh_key": client_priv,
               "hostkey": pr["hostkey"], "path": "."}

        # 2. upload → fişierul apare pe server
        await backup_dest.sftp_upload(cfg, "webterm-20260101-000000.wtbk", b"ciphertext-here")
        landed = os.path.join(root, "webterm-20260101-000000.wtbk")
        check("upload SFTP a scris fişierul pe server", os.path.exists(landed))
        check("conţinutul urcat e intact",
              os.path.exists(landed) and open(landed, "rb").read() == b"ciphertext-here")

        check("upload în nume temporar + rename: niciun .part rămas",
              not [n for n in os.listdir(root) if n.endswith(backup_dest.PART_SUFFIX)], str(os.listdir(root)))

        # 3. list → conţine fişierul, dar NU un upload parţial (.part) rămas pe server
        open(os.path.join(root, "webterm-20260102-000000.wtbk.part"), "wb").write(b"partial")
        files = await backup_dest.sftp_list(cfg)
        check("list SFTP arată arhiva", any(f["name"] == "webterm-20260101-000000.wtbk" for f in files),
              str(files))
        check("list SFTP ignoră .part (upload parţial ≠ arhivă validă)",
              not any(f["name"].endswith(".part") for f in files), str(files))
        os.unlink(os.path.join(root, "webterm-20260102-000000.wtbk.part"))

        # 4. delete → dispare
        await backup_dest.sftp_delete(cfg, "webterm-20260101-000000.wtbk")
        check("delete SFTP a şters fişierul", not os.path.exists(landed))

        # 5. PINUIRE host-key: o cheie de host GREŞITĂ ⇒ refuz (posibil MITM)
        wrong = asyncssh.generate_private_key("ssh-ed25519")
        bad_cfg = dict(cfg, hostkey=" ".join(wrong.export_public_key().decode().split()[:2]))
        raised = False
        try:
            await backup_dest.sftp_upload(bad_cfg, "x.wtbk", b"x")
        except backup_dest.DestError:
            raised = True
        check("host-key schimbat ⇒ DestError (anti-MITM)", raised)

        # 6. fără host-key pinuit ⇒ refuz (nu ne conectăm orbeşte în producţie)
        nohk = dict(cfg); nohk.pop("hostkey")
        raised2 = False
        try:
            await backup_dest.sftp_upload(nohk, "x.wtbk", b"x")
        except backup_dest.DestError:
            raised2 = True
        check("fără host-key pinuit ⇒ DestError", raised2)
    finally:
        server.close()
        await server.wait_closed()

    # ── G-14: timeout PER OPERAŢIE — un server care acceptă scrierea şi apoi tace nu mai
    #    blochează task-ul de backup; eroarea e DestError şi niciun fişier final nu apare ──
    root2 = os.path.join(tmp, "hang")
    os.makedirs(root2, exist_ok=True)

    release = asyncio.Event()           # ţinut de test până la final, ca serverul să se poată opri

    class HangingSFTP(asyncssh.SFTPServer):
        def __init__(self, chan):
            super().__init__(chan, chroot=root2)

        async def write(self, file_obj, offset, data):      # half-open: nu răspunde niciodată
            await release.wait()

    hang = await asyncssh.create_server(
        lambda: asyncssh.SSHServer(), "127.0.0.1", 0,
        server_host_keys=[server_key], authorized_client_keys=caw, sftp_factory=HangingSFTP)
    hport = hang.sockets[0].getsockname()[1]
    hcfg = {"host": "127.0.0.1", "port": hport, "user": "u", "ssh_key": client_priv,
            "hostkey": expected, "path": "."}
    orig_op, orig_close = backup_dest.OP_TIMEOUT, backup_dest.CLOSE_TIMEOUT
    backup_dest.OP_TIMEOUT = backup_dest.CLOSE_TIMEOUT = 0.5
    try:
        t0 = asyncio.get_running_loop().time()
        raised, msg = False, ""
        try:
            await backup_dest.sftp_upload(hcfg, "webterm-20260103-000000.wtbk", b"x" * 10)
        except backup_dest.DestError as e:
            raised, msg = True, str(e)
        took = asyncio.get_running_loop().time() - t0
        check("scriere blocată ⇒ DestError cu timeout, task-ul revine", raised and "write" in msg, msg)
        check("revine în timp util (nu atârnă)", took < 10, "%.1fs" % took)
        check("niciun fişier FINAL după upload eşuat",
              not os.path.exists(os.path.join(root2, "webterm-20260103-000000.wtbk")), str(os.listdir(root2)))
        files = await backup_dest.sftp_list(hcfg)
        check("listarea de după eşec nu arată arhiva parţială", files == [], str(files))
    finally:
        backup_dest.OP_TIMEOUT, backup_dest.CLOSE_TIMEOUT = orig_op, orig_close
        release.set()
        hang.close()
        await hang.wait_closed()

    # un port care acceptă TCP dar nu vorbeşte SSH ⇒ timeout de conectare, nu blocaj
    # (ţinem socket-urile acceptate deschise cât durează testul şi le închidem noi la final —
    # pe Python 3.12 `Server.wait_closed()` aşteaptă TOATE conexiunile)
    writers = []
    silent = await asyncio.start_server(lambda r, w: writers.append(w), "127.0.0.1", 0)
    sport = silent.sockets[0].getsockname()[1]
    orig_ct = backup_dest.CONNECT_TIMEOUT
    backup_dest.CONNECT_TIMEOUT = 0.5
    try:
        raised = False
        try:
            await backup_dest.sftp_upload(dict(hcfg, port=sport), "x.wtbk", b"x")
        except backup_dest.DestError:
            raised = True
        check("server mut ⇒ DestError la conectare (timeout)", raised)
    finally:
        backup_dest.CONNECT_TIMEOUT = orig_ct
        for w in writers:
            w.close()
        silent.close()
        await silent.wait_closed()

    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
