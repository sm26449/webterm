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

        # 3. list → conţine fişierul
        files = await backup_dest.sftp_list(cfg)
        check("list SFTP arată arhiva", any(f["name"] == "webterm-20260101-000000.wtbk" for f in files),
              str(files))

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

    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
