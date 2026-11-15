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

        # ── lot 3 (raport de securitate 2026-11): SFTP cu PAROLĂ ─────────────────────────
        tries = {"n": 0}

        class _PwServer(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                tries["n"] += 1
                return password == "pw-bun"
        pkey = asyncssh.generate_private_key("ssh-ed25519")
        psrv = await asyncssh.create_server(_PwServer, "127.0.0.1", 0, server_host_keys=[pkey],
                                            sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=root))
        pport = psrv.sockets[0].getsockname()[1]
        ppub = " ".join(pkey.export_public_key().decode().split()[:2])
        try:
            pr = await cloudbackup.probe("127.0.0.1", pport, "u", password="pw-bun")
            check("probe cu parolă, fără amprentă acceptată → doar cheia (auth_tested=False)",
                  pr.get("auth_tested") is False and pr["hostkey"] == ppub, pr)
            check("…şi parola NU a plecat la server", tries["n"] == 0, tries)
            other = " ".join(asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().split()[:2])
            try:
                await cloudbackup.probe("127.0.0.1", pport, "u", password="pw-bun", trust_hostkey=other)
                check("trust_hostkey ≠ cheia serverului → refuzat", False, "a trecut")
            except cloudbackup.CloudError:
                check("trust_hostkey ≠ cheia serverului → refuzat", True)
            check("…fără nicio parolă trimisă", tries["n"] == 0, tries)
            pr = await cloudbackup.probe("127.0.0.1", pport, "u", password="pw-bun", trust_hostkey=ppub)
            check("cu amprenta acceptată → parola testată (auth_tested=True)",
                  pr.get("auth_tested") is True and tries["n"] == 1, (pr, tries))

            try:
                await cloudbackup.save_config_direct("sftp", "127.0.0.1", pport, "u", ".", "", "pw-bun",
                                                     other, "", "passphrase-buna", 5, False)
                check("salvare cu o cheie de host NEVĂZUTĂ la Probe → refuzată", False, "a trecut")
            except cloudbackup.CloudError as e:
                check("salvare cu o cheie de host NEVĂZUTĂ la Probe → refuzată",
                      "not seen" in str(e), str(e))
            await cloudbackup.save_config_direct("sftp", "127.0.0.1", pport, "u", ".", "", "pw-bun",
                                                 ppub, "", "passphrase-buna", 5, False)
            check("salvare cu cheia văzută la Probe → ok", (await cloudbackup.get_config())["hostkey"] == ppub)

            try:
                await cloudbackup.save_config_direct("sftp", "localhost", pport, "u", ".", "", "",
                                                     ppub, "", "passphrase-buna", 5, False)
                check("destinaţie mutată (alt host) fără parolă nouă → refuzată", False, "a trecut")
            except cloudbackup.CloudError as e:
                check("destinaţie mutată (alt host) fără parolă nouă → refuzată",
                      "destination changed" in str(e), str(e))
            try:
                await cloudbackup.save_config_direct("ftps", "127.0.0.1", pport, "u", ".", "", "",
                                                     "", "", "passphrase-buna", 5, False)
                check("…şi trecerea pe FTPS (parola ar pleca la alt serviciu) → refuzată", False, "a trecut")
            except cloudbackup.CloudError as e:
                check("…şi trecerea pe FTPS (parola ar pleca la alt serviciu) → refuzată",
                      "destination changed" in str(e), str(e))
            await cloudbackup.save_config_direct("sftp", "127.0.0.1", pport, "u", "./alt", "", "",
                                                 "", "", "passphrase-buna", 5, False)
            check("aceeaşi destinaţie, parola goală → păstrată (alt folder e ok)",
                  (await cloudbackup.get_config())["password"] == "pw-bun")
            await cloudbackup.save_config_direct("sftp", "127.0.0.1", pport, "u", ".", client_priv, "",
                                                 "", "", "passphrase-buna", 5, False)
            cfg = await cloudbackup.get_config()
            check("trecerea pe cheie SSH şterge parola veche (metode exclusive)",
                  cfg["ssh_key"] == client_priv and not cfg["password"], {k: bool(v) for k, v in cfg.items()})

            # review lot 3 (H): ocolul prin OAuth nu mai păstrează secretul pentru o destinaţie nouă
            await cloudbackup.save_config_direct("sftp", "127.0.0.1", pport, "u", ".", "", "pw-bun",
                                                 "", "", "passphrase-buna", 5, False)
            gid = next(iter(cloudbackup.PROVIDERS))
            await cloudbackup.save_config(gid, "client-id", "client-secret", "passphrase-buna", 5, False)
            cfg = await cloudbackup.get_config()
            check("trecerea pe OAuth şterge credenţialele destinaţiei directe",
                  not cfg["password"] and not cfg["ssh_key"] and not cfg["host"] and not cfg["hostkey"],
                  {k: bool(v) for k, v in cfg.items()})
            await cloudbackup.save_config_direct("ftps", "evil.example", 21, "u", ".", "", "",
                                                 "", "", "passphrase-buna", 5, False)
            check("…deci înapoi pe o destinaţie directă nouă NU mai are parola veche",
                  not (await cloudbackup.get_config())["password"])

            # review lot 3 (M): mutată pe alt server, pinul vechi nu se păstrează fără Probe
            await cloudbackup.save_config_direct("sftp", "127.0.0.1", pport, "u", ".", "", "pw-bun",
                                                 ppub, "", "passphrase-buna", 5, False)
            try:
                await cloudbackup.save_config_direct("sftp", "localhost", pport, "u", ".", "", "pw-nou",
                                                     ppub, "", "passphrase-buna", 5, False)
                check("destinaţie mutată + pinul vechi (fără Probe pe noul server) → refuzată", False, "a trecut")
            except cloudbackup.CloudError as e:
                check("destinaţie mutată + pinul vechi (fără Probe pe noul server) → refuzată",
                      "not seen" in str(e), str(e))
            # CA-ul FTPS: gol pe aceeaşi destinaţie = păstrat (cum promite UI-ul); mutată = golit
            pem = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----"
            await cloudbackup.save_config_direct("ftps", "ftp.example", 21, "u", ".", "", "pw-ftp",
                                                 "", pem, "passphrase-buna", 5, False)
            await cloudbackup.save_config_direct("ftps", "FTP.example", 0, "u", "./alt", "", "",
                                                 "", "", "passphrase-buna", 9, False)
            check("CA-ul FTPS rămâne la o re-salvare cu câmpul gol (aceeaşi destinaţie)",
                  (await cloudbackup.get_config())["ca"] == pem)
            await cloudbackup.save_config_direct("ftps", "ftp2.example", 21, "u", ".", "", "pw-2",
                                                 "", "", "passphrase-buna", 9, False)
            check("…dar NU urmează o destinaţie mutată (CA-ul era al serverului vechi)",
                  not (await cloudbackup.get_config())["ca"])
            check("port 0 = implicitul protocolului (aceeaşi destinaţie, nu „mutată\")",
                  cloudbackup._dport("sftp", 0) == 22 and cloudbackup._dport("ftps", 0) == 21)
        finally:
            psrv.close()
    finally:
        server.close()
        await server.wait_closed()
        await db.close()

    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
