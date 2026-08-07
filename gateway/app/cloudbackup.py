"""Backup off-host către un cloud personal (Google Drive / Dropbox), configurat din UI.

De ce: un backup care stă pe mașina pe care o salvezi nu te apără de pierderea mașinii.
`scripts/backup.sh` acoperă asta pe partea de ops (rclone), dar cere linie de comandă;
aici e varianta la îndemână — te conectezi cu un buton, iar backup-ul programat pleacă
singur în contul tău.

Reguli care NU se negociază:
- **Se urcă doar arhive CRIPTATE.** Snapshot-ul brut conține `data/secret` (cheia seifului,
  deci toate credențialele SSH) și cheia de semnare a flotei. Îl criptăm cu parola ta
  (scrypt→AES-GCM, `backup.encrypt`) ÎNAINTE de upload; fără parolă configurată, refuzăm.
- **Cel mai mic scope posibil.** Drive: `drive.file` — aplicația vede exclusiv fișierele
  pe care le-a creat ea, nu restul Drive-ului. Dropbox: aplicație de tip *App folder*, deci
  scrie doar în `/Apps/<numele-aplicației-tale>`.
- **Secretele stau criptate** cu cheia seifului (ca parolele SSH), niciodată în clar în DB.

Fără dependințe noi: HTTP prin `urllib` (ca `updatecheck.py`), apelat din `asyncio.to_thread`
— providerul e la capătul internetului, nu vrem să blocăm event-loop-ul.
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

from . import backup, config, db, security

log = logging.getLogger("webterm")

_TIMEOUT = 30
_UA = "WebTerm/%s" % config.GATEWAY_VERSION

# chei în app_settings (valorile sensibile sunt criptate cu cheia seifului)
K_PROVIDER = "cloud_provider"          # "" | "gdrive" | "dropbox"
K_CLIENT_ID = "cloud_client_id"
K_CLIENT_SECRET = "cloud_client_secret"        # criptat
K_REFRESH = "cloud_refresh_token"              # criptat
K_PASSPHRASE = "cloud_passphrase"              # criptat
K_FOLDER = "cloud_folder"                      # id (Drive) / cale (Dropbox)
K_KEEP = "cloud_keep"                          # câte arhive păstrăm la distanță
K_ACCOUNT = "cloud_account"                    # afișat în UI (email / nume cont)
K_LAST = "cloud_last"                          # JSON: {ts, ok, name, error}
K_INCLUDE_TX = "cloud_include_tx"

DEFAULT_KEEP = 14
FOLDER_NAME = "WebTerm Backups"


# ── HTTP mic și explicit (stdlib) ───────────────────────────────────────────────

def _request(method: str, url: str, *, headers=None, data=None, form=None, timeout=_TIMEOUT):
    """Întoarce (status, headers, body_bytes). Ridică CloudError pe eșec HTTP, cu textul
    providerului păstrat — mesajele Google/Dropbox spun exact ce lipsește din configurare."""
    h = {"User-Agent": _UA}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        body = e.read()[:800].decode("utf-8", "replace")
        raise CloudError("%s %s: %s" % (e.code, e.reason, body)) from None
    except OSError as e:
        raise CloudError("network: %s" % e) from None


def _json(method: str, url: str, **kw):
    _, _, body = _request(method, url, **kw)
    return json.loads(body or b"{}")


class CloudError(Exception):
    """Eroare de provider, cu mesaj destinat UI-ului (nu stack trace)."""


# ── provideri ───────────────────────────────────────────────────────────────────

class Provider:
    id = ""
    label = ""
    console_url = ""          # de unde își ia userul client id/secret
    app_type = ""             # ce fel de aplicație trebuie creată acolo

    def authorize_url(self, client_id: str, redirect_uri: str, state: str) -> str: ...
    def exchange(self, cid, secret, code, redirect_uri) -> dict: ...
    def refresh(self, cid, secret, refresh_token) -> str: ...
    def account(self, token: str) -> str: ...
    def ensure_folder(self, token: str, current: str) -> str: ...
    def upload(self, token: str, folder: str, name: str, data: bytes) -> None: ...
    def list_files(self, token: str, folder: str) -> list: ...   # [{id, name, ts}] recente întâi
    def delete(self, token: str, file_id: str) -> None: ...


class GoogleDrive(Provider):
    id = "gdrive"
    label = "Google Drive"
    console_url = "https://console.cloud.google.com/apis/credentials"
    app_type = "OAuth client ID → Web application"
    SCOPE = "https://www.googleapis.com/auth/drive.file"

    def authorize_url(self, client_id, redirect_uri, state):
        q = {
            "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
            "scope": self.SCOPE, "state": state,
            # offline + consent: fără ele Google NU dă refresh token la a doua autorizare,
            # iar backup-ul programat ar muri tăcut când expiră access token-ul (1h)
            "access_type": "offline", "prompt": "consent",
            "include_granted_scopes": "true",
        }
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(q)

    def exchange(self, cid, secret, code, redirect_uri):
        d = _json("POST", "https://oauth2.googleapis.com/token", form={
            "client_id": cid, "client_secret": secret, "code": code,
            "grant_type": "authorization_code", "redirect_uri": redirect_uri})
        if not d.get("refresh_token"):
            raise CloudError("Google returned no refresh token — reauthorize with "
                             "access_type=offline and prompt=consent")
        return {"refresh": d["refresh_token"], "access": d.get("access_token", "")}

    def refresh(self, cid, secret, refresh_token):
        d = _json("POST", "https://oauth2.googleapis.com/token", form={
            "client_id": cid, "client_secret": secret,
            "refresh_token": refresh_token, "grant_type": "refresh_token"})
        return d["access_token"]

    def account(self, token):
        d = _json("GET", "https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)",
                  headers={"Authorization": "Bearer " + token})
        return (d.get("user") or {}).get("emailAddress", "")

    def ensure_folder(self, token, current):
        auth = {"Authorization": "Bearer " + token}
        if current:
            try:                       # dosarul poate fi șters/mutat la coș din Drive între rulări
                d = _json("GET",
                          "https://www.googleapis.com/drive/v3/files/%s?fields=id,trashed" % current,
                          headers=auth)
                # la coş = invizibil pentru user şi golit automat după 30 de zile: ar însemna
                # backup-uri care „se fac" şi dispar tăcut. Facem unul nou.
                if not d.get("trashed"):
                    return current
            except CloudError:
                pass
        d = _json("POST", "https://www.googleapis.com/drive/v3/files",
                  headers=dict(auth, **{"Content-Type": "application/json"}),
                  data=json.dumps({"name": FOLDER_NAME,
                                   "mimeType": "application/vnd.google-apps.folder"}).encode())
        return d["id"]

    def upload(self, token, folder, name, data):
        # resumable: init (metadate) → PUT (conținut). Multipart e limitat la 5 MB, iar
        # arhivele cresc cu transcripturile — nu vrem să pice tăcut peste un prag.
        st, hdrs, _ = _request(
            "POST", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                     "X-Upload-Content-Type": "application/octet-stream",
                     "X-Upload-Content-Length": str(len(data))},
            data=json.dumps({"name": name, "parents": [folder]}).encode())
        session = hdrs.get("Location") or hdrs.get("location")
        if not session:
            raise CloudError("Drive nu a deschis sesiunea de upload")
        _request("PUT", session, data=data,
                 headers={"Content-Type": "application/octet-stream",
                          "Content-Length": str(len(data))}, timeout=300)

    def list_files(self, token, folder):
        q = urllib.parse.quote("'%s' in parents and trashed=false" % folder)
        d = _json("GET", "https://www.googleapis.com/drive/v3/files"
                         "?q=%s&fields=files(id,name,createdTime)&orderBy=createdTime desc" % q,
                  headers={"Authorization": "Bearer " + token})
        return [{"id": f["id"], "name": f["name"], "ts": f.get("createdTime", "")}
                for f in d.get("files", [])]

    def delete(self, token, file_id):
        _request("DELETE", "https://www.googleapis.com/drive/v3/files/" + file_id,
                 headers={"Authorization": "Bearer " + token})


class Dropbox(Provider):
    id = "dropbox"
    label = "Dropbox"
    console_url = "https://www.dropbox.com/developers/apps"
    app_type = "Scoped access → App folder (files.content.write + files.content.read)"

    def authorize_url(self, client_id, redirect_uri, state):
        q = {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
             "state": state,
             # offline: altfel Dropbox dă doar un access token de 4h, iar programarea moare
             "token_access_type": "offline"}
        return "https://www.dropbox.com/oauth2/authorize?" + urllib.parse.urlencode(q)

    def exchange(self, cid, secret, code, redirect_uri):
        d = _json("POST", "https://api.dropboxapi.com/oauth2/token", form={
            "client_id": cid, "client_secret": secret, "code": code,
            "grant_type": "authorization_code", "redirect_uri": redirect_uri})
        if not d.get("refresh_token"):
            raise CloudError("Dropbox returned no refresh token (token_access_type=offline)")
        return {"refresh": d["refresh_token"], "access": d.get("access_token", "")}

    def refresh(self, cid, secret, refresh_token):
        d = _json("POST", "https://api.dropboxapi.com/oauth2/token", form={
            "client_id": cid, "client_secret": secret,
            "refresh_token": refresh_token, "grant_type": "refresh_token"})
        return d["access_token"]

    def account(self, token):
        d = _json("POST", "https://api.dropboxapi.com/2/users/get_current_account",
                  headers={"Authorization": "Bearer " + token})
        return (d.get("email") or (d.get("name") or {}).get("display_name") or "")

    def ensure_folder(self, token, current):
        return ""      # aplicație de tip App folder: rădăcina ei E dosarul nostru

    def upload(self, token, folder, name, data):
        arg = json.dumps({"path": "/" + name, "mode": "add", "autorename": True, "mute": True})
        _request("POST", "https://content.dropboxapi.com/2/files/upload", data=data,
                 headers={"Authorization": "Bearer " + token, "Dropbox-API-Arg": arg,
                          "Content-Type": "application/octet-stream"}, timeout=300)

    def list_files(self, token, folder):
        d = _json("POST", "https://api.dropboxapi.com/2/files/list_folder",
                  headers={"Authorization": "Bearer " + token,
                           "Content-Type": "application/json"},
                  data=json.dumps({"path": "", "limit": 200}).encode())
        out = [{"id": e["path_lower"], "name": e["name"],
                "ts": e.get("server_modified", "")}
               for e in d.get("entries", []) if e.get(".tag") == "file"]
        out.sort(key=lambda f: f["ts"], reverse=True)
        return out

    def delete(self, token, file_id):
        _json("POST", "https://api.dropboxapi.com/2/files/delete_v2",
              headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
              data=json.dumps({"path": file_id}).encode())


PROVIDERS = {p.id: p for p in (GoogleDrive(), Dropbox())}


def provider_catalog() -> list:
    """Ce arătăm în UI ca să știe userul ce să creeze la providerul lui."""
    return [{"id": p.id, "label": p.label, "console_url": p.console_url,
             "app_type": p.app_type} for p in PROVIDERS.values()]


def redirect_uri() -> str:
    """Trebuie pusă EXACT așa în consola providerului (Google/Dropbox compară literal)."""
    return config.PUBLIC_URL + "/api/backup/cloud/callback"


# ── configurare (app_settings, secretele criptate cu cheia seifului) ────────────

async def _get(key, default=""):
    row = await db.fetchone("SELECT value FROM app_settings WHERE key=?", key)
    return row["value"] if row and row["value"] is not None else default


async def _set(key, value):
    await db.execute("INSERT INTO app_settings(key, value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, str(value))


async def _get_secret(key):
    v = await _get(key)
    if not v:
        return ""
    try:
        return security.decrypt_secret(v)
    except Exception:                      # noqa: BLE001 — cheie schimbată / restore parțial
        return ""


async def get_config() -> dict:
    pid = await _get(K_PROVIDER)
    return {
        "provider": pid,
        "client_id": await _get(K_CLIENT_ID),
        "client_secret": await _get_secret(K_CLIENT_SECRET),
        "refresh": await _get_secret(K_REFRESH),
        "passphrase": await _get_secret(K_PASSPHRASE),
        "folder": await _get(K_FOLDER),
        "keep": int(await _get(K_KEEP, str(DEFAULT_KEEP)) or DEFAULT_KEEP),
        "account": await _get(K_ACCOUNT),
        "include_transcripts": (await _get(K_INCLUDE_TX, "0")) == "1",
    }


async def status() -> dict:
    """Ce vede UI-ul — fără niciun secret (nici măcar mascat: nu le trimitem înapoi)."""
    c = await get_config()
    try:
        last = json.loads(await _get(K_LAST, "") or "{}")
    except ValueError:
        last = {}
    return {
        "provider": c["provider"],
        "configured": bool(c["provider"] and c["client_id"] and c["client_secret"]),
        "connected": bool(c["refresh"]),
        "has_passphrase": bool(c["passphrase"]),
        "account": c["account"],
        "keep": c["keep"],
        "include_transcripts": c["include_transcripts"],
        "last": last,
        "redirect_uri": redirect_uri(),
        "providers": provider_catalog(),
    }


async def save_config(provider: str, client_id: str, client_secret: str,
                      passphrase: str, keep: int, include_transcripts: bool) -> None:
    if provider not in PROVIDERS:
        raise CloudError("provider necunoscut")
    if len(passphrase) < 8:
        raise CloudError("the encryption passphrase must be at least 8 characters")
    prev = await get_config()
    # schimbarea providerului/clientului invalidează autorizarea existentă
    if prev["provider"] != provider or prev["client_id"] != client_id:
        await _set(K_REFRESH, "")
        await _set(K_ACCOUNT, "")
        await _set(K_FOLDER, "")
    await _set(K_PROVIDER, provider)
    await _set(K_CLIENT_ID, client_id.strip())
    if client_secret:                      # gol la salvare = păstrează secretul existent
        await _set(K_CLIENT_SECRET, security.encrypt_secret(client_secret.strip()))
    await _set(K_PASSPHRASE, security.encrypt_secret(passphrase))
    await _set(K_KEEP, max(1, min(365, int(keep))))
    await _set(K_INCLUDE_TX, "1" if include_transcripts else "0")


async def disconnect() -> None:
    """Uită autorizarea (tokenul), păstrează client id/secret ca să te poți reconecta."""
    await _set(K_REFRESH, "")
    await _set(K_ACCOUNT, "")
    await _set(K_FOLDER, "")


async def forget_all() -> None:
    for k in (K_PROVIDER, K_CLIENT_ID, K_CLIENT_SECRET, K_REFRESH, K_PASSPHRASE,
              K_FOLDER, K_ACCOUNT, K_LAST):
        await _set(k, "")


# ── flux OAuth ─────────────────────────────────────────────────────────────────

_states: dict = {}          # state -> (user_id, expiră_la)
_STATE_TTL = 600


def _sweep_states(now: float) -> None:
    for s, (_, exp) in list(_states.items()):
        if exp < now:
            _states.pop(s, None)


async def authorize_url(user_id: int) -> str:
    c = await get_config()
    p = PROVIDERS.get(c["provider"])
    if not p or not c["client_id"] or not c["client_secret"]:
        raise CloudError("save the Client ID and Client Secret first")
    now = time.time()
    _sweep_states(now)
    state = security.new_token()
    _states[state] = (user_id, now + _STATE_TTL)
    return p.authorize_url(c["client_id"], redirect_uri(), state)


async def finish_authorization(user_id: int, code: str, state: str) -> str:
    """Schimbă `code` pe refresh token. `state` e legat de userul care a pornit fluxul —
    fără el, un link fabricat ar putea lega contul TĂU de Drive-ul altcuiva."""
    owner = _states.pop(state, None)
    if not owner or owner[0] != user_id or owner[1] < time.time():
        raise CloudError("authorization expired or invalid — connect again")
    c = await get_config()
    p = PROVIDERS[c["provider"]]
    tok = await _to_thread(p.exchange, c["client_id"], c["client_secret"], code, redirect_uri())
    await _set(K_REFRESH, security.encrypt_secret(tok["refresh"]))
    access = tok["access"] or await _to_thread(p.refresh, c["client_id"], c["client_secret"],
                                               tok["refresh"])
    try:
        await _set(K_ACCOUNT, await _to_thread(p.account, access))
    except CloudError:
        pass                                # contul e doar cosmetic în UI
    return c["provider"]


async def _to_thread(fn, *a):
    import asyncio
    return await asyncio.to_thread(fn, *a)


async def _access_token(c: dict) -> str:
    p = PROVIDERS[c["provider"]]
    return await _to_thread(p.refresh, c["client_id"], c["client_secret"], c["refresh"])


# ── upload ─────────────────────────────────────────────────────────────────────

async def upload_backup(data: bytes | None = None, name: str = "") -> str:
    """Criptează (dacă nu e deja) și urcă o arhivă, apoi aplică retenția la distanță.
    `data` gol = facem un snapshot nou. Întoarce numele urcat."""
    import asyncio

    c = await get_config()
    if not c["provider"] or not c["refresh"]:
        raise CloudError("you are not connected to a cloud provider")
    if not c["passphrase"]:
        # invariantul: arhiva conține cheia seifului; necriptată la un terț = joc încheiat
        raise CloudError("the encryption passphrase is missing — unencrypted archives are not uploaded")
    p = PROVIDERS[c["provider"]]
    if data is None:
        snap = await asyncio.to_thread(backup.make_snapshot, c["include_transcripts"])
        name = "webterm-%s.wtbk" % time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        data = await asyncio.to_thread(backup.encrypt, snap, c["passphrase"])
    token = await _access_token(c)
    folder = await _to_thread(p.ensure_folder, token, c["folder"])
    if folder != c["folder"]:
        await _set(K_FOLDER, folder)
    await _to_thread(p.upload, token, folder, name, data)
    await _prune_remote(p, token, folder, c["keep"])
    await _set(K_LAST, json.dumps({"ts": time.time(), "ok": True, "name": name,
                                   "size": len(data), "error": ""}))
    return name


async def _prune_remote(p: Provider, token: str, folder: str, keep: int) -> None:
    """Retenție la distanță: păstrăm cele mai recente `keep` arhive DE-ALE NOASTRE.
    Ștergem doar fișiere `webterm-*.wtbk` — dosarul poate fi al userului, nu al nostru."""
    try:
        files = [f for f in await _to_thread(p.list_files, token, folder)
                 if f["name"].startswith("webterm-") and f["name"].endswith(".wtbk")]
        for f in files[keep:]:
            await _to_thread(p.delete, token, f["id"])
    except CloudError as e:
        log.warning("remote retention failed: %s", e)   # backup-ul urcat rămâne valid


async def upload_scheduled(local_name: str) -> None:
    """Chemat după backup-ul programat: urcă ACEA arhivă, criptată. Eșecul se
    înregistrează pentru UI, dar nu rupe programarea locală."""
    c = await get_config()
    if not c["provider"] or not c["refresh"]:
        return
    import asyncio
    try:
        if not c["passphrase"]:
            raise CloudError("the encryption passphrase is missing")
        blob = await asyncio.to_thread(backup.encrypt_stored, local_name, c["passphrase"])
        await upload_backup(blob, local_name.replace(".wtsnap", ".wtbk"))
        log.info("backup uploaded to %s: %s", c["provider"], local_name)
    except Exception as e:                  # noqa: BLE001 — orice eșec e informativ, nu fatal
        log.warning("cloud upload failed: %s", e)
        await _set(K_LAST, json.dumps({"ts": time.time(), "ok": False, "name": local_name,
                                       "error": str(e)[:300]}))
