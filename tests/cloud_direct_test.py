"""Hermetic: destinaţia de backup DIRECTĂ (SFTP) prin cloudbackup — end-to-end.
Verifică: save_config_direct stochează credenţialele CRIPTAT (nu în clar), status() nu întoarce
secretele, iar upload_backup dispecerizează spre serverul SFTP (arhiva criptată chiar ajunge)."""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import asyncssh  # noqa: E402
from app import cloudbackup, config, db, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()

    tmp = tempfile.mkdtemp()
    root = os.path.join(tmp, "bk"); os.makedirs(root, exist_ok=True)
    skey = asyncssh.generate_private_key("ssh-ed25519")
    ckey = asyncssh.generate_private_key("ssh-ed25519")
    client_priv = ckey.export_private_key().decode()
    caw = asyncssh.import_authorized_keys(ckey.export_public_key().decode())
    server = await asyncssh.create_server(
        lambda: asyncssh.SSHServer(), "127.0.0.1", 0,
        server_host_keys=[skey], authorized_client_keys=caw,
        sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=root))
    port = server.sockets[0].getsockname()[1]

    try:
        pr = await cloudbackup.probe("127.0.0.1", port, "u", ssh_key=client_priv)
        check("probe prin cloudbackup întoarce amprenta", pr.get("fingerprint", "").startswith("SHA256:"))

        await cloudbackup.save_config_direct(
            "sftp", "127.0.0.1", port, "u", ".", client_priv, "", pr["hostkey"], "",
            "passphrase-buna", 5, False)

        # SECURITATE: cheia SSH e stocată CRIPTAT în app_settings (nu în clar)
        raw = await db.fetchone("SELECT value FROM app_settings WHERE key=?", cloudbackup.K_SSH_KEY)
        stored = raw["value"] if raw else ""
        check("cheia SSH e stocată criptat (nu în clar)",
              bool(stored) and "PRIVATE KEY" not in stored and stored != client_priv)
        check("get_config o decriptează înapoi corect",
              (await cloudbackup.get_config())["ssh_key"] == client_priv)

        # status() NU întoarce secretele
        st = await cloudbackup.status()
        blob = str(st)
        check("status nu scurge cheia SSH / parola", "PRIVATE KEY" not in blob and client_priv not in blob)
        check("status: configured + connected pentru sftp", st["configured"] and st["connected"])
        check("status.direct spune doar has_key (fără cheie)",
              st["direct"]["has_key"] and "ssh_key" not in st["direct"])

        # dispecerizare: upload_backup cu date deja făcute → ajunge pe serverul SFTP
        await cloudbackup.upload_backup(data=b"encrypted-archive-bytes", name="webterm-20260101-000000.wtbk")
        landed = os.path.join(root, "webterm-20260101-000000.wtbk")
        check("upload_backup a dispecerizat spre SFTP (arhiva a ajuns)", os.path.exists(landed))
        check("conţinutul e intact",
              os.path.exists(landed) and open(landed, "rb").read() == b"encrypted-archive-bytes")

        # retenţie: mai urcăm câteva, keep=5 → cele mai vechi se şterg
        for i in range(1, 8):
            await cloudbackup.upload_backup(data=b"x", name="webterm-2026010%d-000000.wtbk" % i)
        left = [f for f in os.listdir(root) if f.startswith("webterm-")]
        check("retenţia păstrează cel mult keep(5) arhive", len(left) <= 5, "rămase: %d" % len(left))

        # ştergerea destinaţiei directe ŞTERGE credenţialele (nu doar „uită tokenul” ca la OAuth)
        await cloudbackup.disconnect()
        c2 = await cloudbackup.get_config()
        check("disconnect a şters credenţialele + providerul",
              not c2["provider"] and not c2["ssh_key"] and not c2["host"] and not c2["hostkey"])
    finally:
        server.close()
        await server.wait_closed()
        await db.close()

    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
