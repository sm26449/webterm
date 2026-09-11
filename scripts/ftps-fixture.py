"""Server FTP-TLS minimal pentru fixture-ul de CI/e2e al backup-ului FTPS (vezi scripts/e2e-backup.mjs
şi pasul „Backup UI" din docker-publish.yml / ci-local.sh). TLS OBLIGATORIU pe control ŞI date.

Rulat într-un container `python:3.12-alpine` cu `pip install pyftpdlib pyopenssl`, cu certul
self-signed montat la /certs şi datele scrise în /data. Nu e cod de producţie — la runtime,
clientul FTPS e `ftplib` din stdlib (app/backup_dest.py)."""
import os

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer

USER = os.environ.get("FTPS_USER", "backup")
PASSWORD = os.environ.get("FTPS_PASS", "backup-pass-eval")

os.makedirs("/data/backups", exist_ok=True)
auth = DummyAuthorizer()
auth.add_user(USER, PASSWORD, "/data", perm="elradfmw")

handler = TLS_FTPHandler
handler.certfile = "/certs/cert.pem"
handler.keyfile = "/certs/key.pem"
handler.authorizer = auth
handler.tls_control_required = True
handler.tls_data_required = True
handler.passive_ports = range(30000, 30011)

FTPServer(("0.0.0.0", 21), handler).serve_forever()
