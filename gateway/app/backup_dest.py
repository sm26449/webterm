"""Destinaţii de backup DIRECTE (fără OAuth), configurabile din UI: SFTP şi FTPS.

De ce nu `rsync`: gateway-ul rulează într-un container întărit (rootfs read-only, cap_drop ALL,
fără shell-out) şi fără binarul `rsync`/`ssh`. Facem acelaşi lucru PUR ÎN PYTHON:
  · SFTP prin `asyncssh` (deja dependinţă, folosit la conexiunile SSH) — acelaşi transport şi
    aceeaşi securitate ca rsync-over-SSH, fără proces extern;
  · FTPS prin `ftplib.FTP_TLS` (stdlib), cu TLS OBLIGATORIU pe control ŞI date (`prot_p`).

Securitate (arhiva urcată e DEJA criptată de `cloudbackup`, deci serverul vede doar ciphertext):
  · SFTP: cheia de host a serverului e PINUITĂ (TOFU) — `known_hosts=None` NU se foloseşte în
    producţie, doar la `probe_hostkey`, o singură dată, ca să arătăm userului fingerprint-ul de
    confirmat. O cheie schimbată ⇒ refuz (posibil MITM).
  · FTPS: certificatul serverului e VERIFICAT (CA de sistem implicit; opţional un CA/cert pinuit
    pentru servere self-signed). Niciodată dezactivat.
Credenţialele (cheie SSH / parolă) vin decriptate din seif de la `cloudbackup`; aici nu atingem
niciun secret la persistenţă.
"""
from __future__ import annotations

import asyncio
import ftplib
import io
import ssl

import asyncssh


class DestError(Exception):
    """Eroare de destinaţie (conexiune, auth, host-key, cert) — mesaj sigur de arătat în UI."""


# Timeout-uri PER OPERAŢIE (audit G-14). Doar `asyncssh.connect` avea timeout; makedirs/open/write
# nu — un server SFTP half-open bloca `_scheduled_backup` pentru totdeauna, deci nici backup-uri
# locale ulterioare, nici alertă. Scrierea e pe bucăţi, fiecare cu propriul timeout: un upload
# lent dar care avansează trece, unul care STĂ peste `OP_TIMEOUT` pică şi task-ul revine.
CONNECT_TIMEOUT = 30.0
OP_TIMEOUT = 60.0                 # makedirs / open / write(chunk) / rename / listdir / remove
WRITE_CHUNK = 1024 * 1024         # 1 MiB per write
FTPS_SOCKET_TIMEOUT = 30          # ftplib: timeout de socket = per operaţie de reţea
# Upload-ul merge într-un nume TEMPORAR şi se redenumeşte la final: un upload parţial nu mai
# apare ca `webterm-*.wtbk` valid care să conteze la retenţie şi să evacueze o arhivă bună.
PART_SUFFIX = ".part"


def is_temp_name(name: str) -> bool:
    return name.endswith(PART_SUFFIX) or name.endswith(".tmp")


CLOSE_TIMEOUT = 5.0               # închiderea politicoasă; peste → abort (serverul nu răspunde)


async def _close(conn, sftp=None) -> None:
    """Închidere MĂRGINITĂ. `async with start_sftp_client()` aştepta la ieşire ca SERVERUL să
    închidă canalul SFTP — un server half-open nu o face niciodată, deci task-ul rămânea blocat
    chiar şi cu timeout pe fiecare operaţie. După CLOSE_TIMEOUT tăiem transportul (abort)."""
    try:
        if sftp is not None:
            sftp.exit()
            await asyncio.wait_for(sftp.wait_closed(), CLOSE_TIMEOUT)
        conn.close()
        await asyncio.wait_for(conn.wait_closed(), CLOSE_TIMEOUT)
    except Exception:                 # noqa: BLE001 — timeout sau canal deja rupt: tăiem
        conn.abort()


async def _t(aw, what: str, timeout: float | None = None):
    """`asyncio.wait_for` cu mesaj de eroare util: ce operaţie a expirat şi după cât.
    Constanta se citeşte la APEL (nu ca default de argument), ca să poată fi reglată/injectată."""
    timeout = OP_TIMEOUT if timeout is None else timeout
    try:
        return await asyncio.wait_for(aw, timeout=timeout)
    except asyncio.TimeoutError:
        raise DestError("SFTP: operaţia „%s” nu a răspuns în %ds" % (what, int(timeout)))


# ── SFTP (asyncssh) ──────────────────────────────────────────────────────────────

def _known_hosts(host: str, port: int, hostkey_line: str) -> bytes:
    """Un known_hosts în memorie care PINUIEŞTE exact cheia dată pentru acest host:port."""
    hp = host if port == 22 else "[%s]:%d" % (host, port)
    return ("%s %s\n" % (hp, hostkey_line.strip())).encode()


async def _sftp_connect(cfg: dict):
    """Deschide o conexiune SSH cu host-key PINUIT + auth pe cheie sau parolă."""
    if not cfg.get("hostkey"):
        raise DestError("host-key negăsit — confirmă amprenta serverului mai întâi (probe)")
    kw = dict(host=cfg["host"], port=int(cfg.get("port") or 22),
              username=cfg["user"], known_hosts=_known_hosts(cfg["host"], int(cfg.get("port") or 22),
                                                             cfg["hostkey"]))
    if cfg.get("ssh_key"):
        try:
            kw["client_keys"] = [asyncssh.import_private_key(cfg["ssh_key"])]
        except (asyncssh.KeyImportError, ValueError) as e:
            raise DestError("cheia SSH nu a putut fi citită: %s" % e)
    elif cfg.get("password"):
        kw["password"] = cfg["password"]
    else:
        raise DestError("lipseşte cheia SSH sau parola")
    try:
        return await asyncio.wait_for(asyncssh.connect(**kw), timeout=CONNECT_TIMEOUT)
    except asyncssh.HostKeyNotVerifiable:
        raise DestError("cheia de host a serverului s-a SCHIMBAT faţă de cea confirmată — posibil "
                        "MITM; upload refuzat")
    except (asyncssh.PermissionDenied, asyncssh.Error) as e:
        raise DestError("conexiune SFTP eşuată: %s" % e)
    except (OSError, asyncio.TimeoutError) as e:
        raise DestError("serverul SFTP nu răspunde: %s" % e)


async def sftp_upload(cfg: dict, name: str, data: bytes) -> None:
    conn = await _sftp_connect(cfg)
    sftp = None
    try:
        sftp = await _t(conn.start_sftp_client(), "open sftp")
        path = (cfg.get("path") or ".").rstrip("/")
        try:
            await _t(sftp.makedirs(path, exist_ok=True), "mkdir")
        except asyncssh.SFTPError:
            pass                                    # dir există deja / permisiuni — lăsăm scrierea să decidă
        final = "%s/%s" % (path, name)
        tmp = final + PART_SUFFIX
        try:
            f = await _t(sftp.open(tmp, "wb"), "open")
            try:
                for off in range(0, len(data), WRITE_CHUNK):
                    await _t(f.write(data[off:off + WRITE_CHUNK]), "write")
            finally:
                # închiderea handle-ului e best-effort şi mărginită: nu maschează eroarea
                # scrierii şi nu atârnă dacă serverul a amuţit
                try:
                    await asyncio.wait_for(f.close(), OP_TIMEOUT)
                except Exception:                   # noqa: BLE001
                    pass
            # SFTP v3 refuză rename peste o ţintă existentă; numele final e unic (timestamp),
            # dar la o reîncercare în aceeaşi secundă curăţăm întâi, apoi redenumim atomic.
            try:
                await _t(sftp.remove(final), "remove")
            except asyncssh.SFTPError:
                pass
            await _t(sftp.rename(tmp, final), "rename")
        except BaseException:
            # best-effort: nu lăsăm `.part` orfan; dacă şi asta expiră, listarea îl ignoră oricum
            try:
                await asyncio.wait_for(sftp.remove(tmp), timeout=CLOSE_TIMEOUT)
            except Exception:                       # noqa: BLE001
                pass
            raise
    except asyncssh.SFTPError as e:
        raise DestError("SFTP: scrierea a eşuat: %s" % e)
    finally:
        await _close(conn, sftp)


async def sftp_list(cfg: dict) -> list:
    conn = await _sftp_connect(cfg)
    sftp = None
    try:
        sftp = await _t(conn.start_sftp_client(), "open sftp")
        path = (cfg.get("path") or ".").rstrip("/")
        out = []
        for n in await _t(sftp.listdir(path), "list"):
            if n in (".", "..") or is_temp_name(n):   # un `.part` NU e o arhivă validă
                continue
            try:
                st = await _t(sftp.stat("%s/%s" % (path, n)), "stat")
                out.append({"name": n, "id": n, "ts": getattr(st, "mtime", 0) or 0})
            except asyncssh.SFTPError:
                continue
        out.sort(key=lambda f: f["ts"], reverse=True)
        return out
    except asyncssh.SFTPError as e:
        raise DestError("SFTP: listarea a eşuat: %s" % e)
    finally:
        await _close(conn, sftp)


async def sftp_delete(cfg: dict, name: str) -> None:
    conn = await _sftp_connect(cfg)
    sftp = None
    try:
        sftp = await _t(conn.start_sftp_client(), "open sftp")
        path = (cfg.get("path") or ".").rstrip("/")
        await _t(sftp.remove("%s/%s" % (path, name)), "remove")
    except asyncssh.SFTPError as e:
        raise DestError("SFTP: ştergerea a eşuat: %s" % e)
    finally:
        await _close(conn, sftp)


async def probe_hostkey(host: str, port: int, user: str,
                        ssh_key: str = "", password: str = "") -> dict:
    """TOFU: se conectează O DATĂ acceptând orice cheie de host (known_hosts=None), autentifică cu
    credenţialele date (deci validează şi auth-ul), şi întoarce cheia + amprenta serverului ca
    userul s-o confirme. Cheia confirmată se pinuieşte apoi în config; conexiunile reale o impun."""
    kw = dict(host=host, port=int(port or 22), username=user, known_hosts=None)
    if ssh_key:
        try:
            kw["client_keys"] = [asyncssh.import_private_key(ssh_key)]
        except (asyncssh.KeyImportError, ValueError) as e:
            raise DestError("cheia SSH nu a putut fi citită: %s" % e)
    elif password:
        kw["password"] = password
    else:
        raise DestError("lipseşte cheia SSH sau parola")
    try:
        conn = await asyncio.wait_for(asyncssh.connect(**kw), timeout=CONNECT_TIMEOUT)
    except (asyncssh.PermissionDenied, asyncssh.Error) as e:
        raise DestError("conexiune/autentificare SFTP eşuată: %s" % e)
    except (OSError, asyncio.TimeoutError) as e:
        raise DestError("serverul SFTP nu răspunde: %s" % e)
    try:
        key = conn.get_server_host_key()
        line = key.export_public_key().decode().strip()          # "ssh-ed25519 AAAA..."
        fp = key.get_fingerprint()                               # "SHA256:..."
        return {"hostkey": " ".join(line.split()[:2]), "fingerprint": fp,
                "type": line.split()[0]}
    finally:
        await _close(conn)


# ── FTPS (ftplib.FTP_TLS) ────────────────────────────────────────────────────────

def _ftps_context(ca_pem: str = "") -> ssl.SSLContext:
    """Context TLS care VERIFICĂ mereu certul serverului. `ca_pem` (opţional) pinuieşte un CA/cert
    propriu pentru servere self-signed; fără el, se foloseşte magazinul de CA al sistemului."""
    ctx = ssl.create_default_context()          # check_hostname=True, verify_mode=CERT_REQUIRED
    if ca_pem.strip():
        try:
            ctx.load_verify_locations(cadata=ca_pem)
        except ssl.SSLError as e:
            raise DestError("certificatul/CA pinuit e invalid: %s" % e)
    return ctx


def _ftps_op(cfg: dict, op, *args):
    ctx = _ftps_context(cfg.get("ca") or "")
    # timeout de SOCKET = per operaţie de reţea (connect/login/STOR/MDTM...), nu pe total
    ftps = ftplib.FTP_TLS(context=ctx, timeout=FTPS_SOCKET_TIMEOUT)
    try:
        ftps.connect(cfg["host"], int(cfg.get("port") or 21))
        ftps.auth()                              # AUTH TLS pe canalul de control (explicit FTPS)
        ftps.login(cfg["user"], cfg.get("password") or "")
        ftps.prot_p()                            # ...şi criptăm ŞI canalul de date
        path = (cfg.get("path") or "").strip("/")
        if path:
            ftps.cwd("/" + path)
        return op(ftps, *args)
    except (ftplib.all_errors) as e:             # noqa: E501 — orice eroare ftplib/socket/ssl
        raise DestError("FTPS eşuat (server fără TLS, cert, credenţiale sau cale): %s" % e)
    except ssl.SSLError as e:
        raise DestError("verificarea TLS a serverului FTPS a eşuat: %s" % e)
    finally:
        try:
            ftps.quit()
        except Exception:                        # noqa: BLE001
            ftps.close()


async def ftps_upload(cfg: dict, name: str, data: bytes) -> None:
    def _up(ftps):
        # STOR în nume temporar + RNFR/RNTO la final: un upload parţial nu devine arhivă validă
        tmp = name + PART_SUFFIX
        try:
            ftps.storbinary("STOR " + tmp, io.BytesIO(data))
            try:
                ftps.delete(name)                # ţinta nu există normal; curăţăm o reîncercare
            except ftplib.all_errors:
                pass
            ftps.rename(tmp, name)
        except BaseException:
            try:
                ftps.delete(tmp)
            except Exception:                    # noqa: BLE001 — best-effort
                pass
            raise
    await asyncio.to_thread(_ftps_op, cfg, _up)


async def ftps_list(cfg: dict) -> list:
    def _ls(ftps):
        names = []
        try:
            names = ftps.nlst()
        except ftplib.error_perm:
            names = []
        out = []
        for n in names:
            b = n.rsplit("/", 1)[-1]
            if is_temp_name(b):                  # un `.part` NU e o arhivă validă
                continue
            ts = 0
            try:
                r = ftps.sendcmd("MDTM " + n)     # "213 YYYYMMDDhhmmss"
                ts = r.split()[-1] if r[:3] == "213" else 0
            except ftplib.all_errors:
                ts = 0
            out.append({"name": b, "id": n, "ts": ts})
        out.sort(key=lambda f: f["ts"], reverse=True)
        return out
    return await asyncio.to_thread(_ftps_op, cfg, _ls)


async def ftps_delete(cfg: dict, name: str) -> None:
    def _del(ftps):
        ftps.delete(name)
    await asyncio.to_thread(_ftps_op, cfg, _del)


# ── dispecer comun ───────────────────────────────────────────────────────────────

async def upload(kind: str, cfg: dict, name: str, data: bytes) -> None:
    await (sftp_upload if kind == "sftp" else ftps_upload)(cfg, name, data)


async def list_backups(kind: str, cfg: dict) -> list:
    return await (sftp_list if kind == "sftp" else ftps_list)(cfg)


async def delete(kind: str, cfg: dict, name: str) -> None:
    await (sftp_delete if kind == "sftp" else ftps_delete)(cfg, name)
