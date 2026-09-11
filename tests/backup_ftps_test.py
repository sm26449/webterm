"""Hermetic: destinaţia de backup FTPS (app/backup_dest.py) contra unui server FTP-TLS real, pornit
in-process cu pyftpdlib şi un certificat self-signed. Închide golul lăsat de backup_dest_test (care
acoperă doar SFTP): aici verificăm end-to-end upload/list/delete PESTE TLS, plus că certificatul
serverului chiar e VERIFICAT — un CA greşit sau lipsa lui duce la refuz (fără TLS-încredere-oarbă).

pyftpdlib e dependenţă doar de TEST (gateway/requirements-dev.txt), nu de runtime — la runtime
folosim ftplib din stdlib."""
import logging
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

logging.getLogger("pyftpdlib").setLevel(logging.CRITICAL)   # fără zgomot de sesiune în output

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from pyftpdlib.authorizers import DummyAuthorizer  # noqa: E402
from pyftpdlib.handlers import TLS_FTPHandler  # noqa: E402
from pyftpdlib.servers import FTPServer  # noqa: E402

from app import backup_dest  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def _self_signed(dirpath, cn="localhost"):
    """Un cert self-signed cu SAN IP:127.0.0.1 (ne conectăm la 127.0.0.1, iar clientul verifică
    hostname-ul → SAN-ul trebuie să conţină IP-ul). Întoarce (certfile, keyfile, pem_text)."""
    cert = os.path.join(dirpath, "cert-%s.pem" % cn.replace(".", "_"))
    key = os.path.join(dirpath, "key-%s.pem" % cn.replace(".", "_"))
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=%s" % cn,
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, capture_output=True)
    return cert, key, open(cert).read()


def _serve(root, cert, key):
    """Porneşte un server FTPS in-process (TLS obligatoriu pe control ŞI date). Întoarce (port,
    stop) — `stop()` opreşte serverul. Rulează pe un thread daemon."""
    auth = DummyAuthorizer()
    auth.add_user("u", "pw", root, perm="elradfmw")
    handler = TLS_FTPHandler
    handler.certfile = cert
    handler.keyfile = key
    handler.authorizer = auth
    handler.tls_control_required = True
    handler.tls_data_required = True
    server = FTPServer(("127.0.0.1", 0), handler)
    port = server.socket.getsockname()[1]
    th = threading.Thread(target=server.serve_forever, kwargs={"timeout": 0.2}, daemon=True)
    th.start()
    # aşteaptă până acceptă conexiuni
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)

    def stop():
        server.close_all()
        th.join(timeout=3)
    return port, stop


def main():
    tmp = tempfile.mkdtemp()
    root = os.path.join(tmp, "ftproot"); os.makedirs(root, exist_ok=True)
    cert, key, ca_pem = _self_signed(tmp)
    _, _, other_ca = _self_signed(tmp, cn="other")     # un CA complet nepotrivit

    port, stop = _serve(root, cert, key)
    cfg = {"host": "127.0.0.1", "port": port, "user": "u", "password": "pw", "path": "", "ca": ca_pem}
    try:
        import asyncio

        async def run():
            # 1. upload PESTE TLS → fişierul apare pe server
            await backup_dest.ftps_upload(cfg, "webterm-20260101-000000.wtbk", b"ciphertext-here")
            landed = os.path.join(root, "webterm-20260101-000000.wtbk")
            check("upload FTPS a scris fişierul (peste TLS)", os.path.exists(landed))
            check("conţinutul urcat e intact",
                  os.path.exists(landed) and open(landed, "rb").read() == b"ciphertext-here")

            # 2. list → conţine arhiva
            files = await backup_dest.ftps_list(cfg)
            check("list FTPS arată arhiva",
                  any(f["name"] == "webterm-20260101-000000.wtbk" for f in files), str(files))

            # 3. delete → dispare
            await backup_dest.ftps_delete(cfg, "webterm-20260101-000000.wtbk")
            check("delete FTPS a şters fişierul", not os.path.exists(landed))

            # 4. certificatul serverului E VERIFICAT: un CA nepotrivit ⇒ refuz
            bad = dict(cfg, ca=other_ca)
            raised = False
            try:
                await backup_dest.ftps_upload(bad, "x.wtbk", b"x")
            except backup_dest.DestError:
                raised = True
            check("CA greşit ⇒ DestError (certul chiar e verificat)", raised)

            # 5. fără CA pinuit, certul self-signed nu e în magazinul de sistem ⇒ refuz
            #    (dovedeşte că NU dezactivăm verificarea TLS)
            nover = dict(cfg, ca="")
            raised2 = False
            try:
                await backup_dest.ftps_upload(nover, "x.wtbk", b"x")
            except backup_dest.DestError:
                raised2 = True
            check("self-signed fără CA pinuit ⇒ DestError (TLS nu e ocolit)", raised2)

        asyncio.run(run())
    finally:
        stop()

    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
