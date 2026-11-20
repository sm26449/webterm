"""Deploy keys (Toolbox → SSH keys): a host-to-host SSH key whose private half is born and stays on
the source host (`~/.ssh/webterm_ed25519`); the gateway keeps only the public key and the
deployment graph. Generate, deploy (one or a batch of targets), revoke, verify, delete, test,
the ssh config snippet, rotation, and the deploy-key policy in Settings. Everything goes through
the agent's existing `run` op (`hostcmd.host_run`) and `fs_read`. Deploying grants durable
access, so it asks for a fresh factor (`stepup.require_fresh_factor`). Moved out of api.py;
nothing here imports api.py.
"""
import asyncio
import base64
import hashlib
import json
import logging
import re
import shlex
import sqlite3
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .errors import ApiError
from . import audit, authz, conntypes, core, db, email_alerts, hostcmd, security, stepup

log = logging.getLogger("webterm")
# Aceeaşi gardă ca api.router (fail-closed): o rută fără permisiune declarată → 500 authz.undeclared.
router = APIRouter(dependencies=[Depends(authz.declared)])


# ── [deploy-keys] Chei de deploy host→host (Toolbox → SSH keys) ────────────────────────────
# Scop: un host de dev face `ssh` pe hosturi de prod fără agenţi AI acolo. PRIVATA se naşte
# şi RĂMÂNE pe hostul sursă (~/.ssh/webterm_ed25519); gateway-ul ţine DOAR publica + graful
# de deploy. Totul prin op-ul `run` + `fs_read` existente — agentul NU e atins (zero bump de
# flotă). Modelul de securitate: privatele există DOAR pe surse (produl poartă doar material
# public → un prod compromis nu poate sări mai departe), iar deploy-ul = acordare de acces
# DURABIL, deci cere un factor PROASPĂT indiferent de flag-ul 2FA al hostului (H-3): paguba
# unui cookie furat ar supravieţui revocării cookie-ului şi chiar opririi WebTerm.
_DK_PATH = '"$HOME/.ssh/webterm_ed25519"'          # constante server-side, fără input de user


_DK_PUB = "~/.ssh/webterm_ed25519.pub"             # pt. fs_read (agentul expandează ~)


# publica întoarsă de host e input NESIGUR (hostul sursă e fix maşina cu agenţi AI): o
# „cheie" cu \n ar strecura linii suplimentare în authorized_keys pe TOATE ţintele, iar
# shlex.quote protejează shell-ul, nu formatul fişierului. O linie, charset închis, comentariu
# restrâns — şi blob-ul se re-verifică prin decode (tipul din interior trebuie să coincidă).
_DK_PUBKEY_RE = re.compile(r"^ssh-ed25519 ([A-Za-z0-9+/]{60,120}={0,3})( [A-Za-z0-9@._-]{1,64})?$")


_DK_FROM_RE = re.compile(r"^[0-9A-Fa-f:.,/]{1,128}$")   # from="…" — doar IP-uri/CIDR, fără ghilimele


def _dk_validate(pub: str) -> tuple[str, str]:
    """Validează linia publică şi întoarce (blob_b64, fingerprint SHA256:…). Fingerprint-ul se
    calculează AICI, din blob (nu parsat din stdout-ul lui `ssh-keygen -lf` — shell-ul de login
    poate murdări stdout-ul cu zgomot de profil)."""
    m = _DK_PUBKEY_RE.match((pub or "").strip())
    if not m:
        raise ApiError(400, "sshkey.badPublic", "the public key returned by the host is not a clean ssh-ed25519 line")
    blob = m.group(1)
    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception:
        raise ApiError(400, "sshkey.badPublic", "the public key blob is not valid base64")
    # interiorul blob-ului îşi declară tipul (string length-prefixed) — trebuie să coincidă
    if not raw.startswith(b"\x00\x00\x00\x0bssh-ed25519"):
        raise ApiError(400, "sshkey.badPublic", "the key blob does not declare ssh-ed25519")
    fp = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return blob, "SHA256:" + fp


async def _dk_key_row(source_host_id: int):
    row = await db.fetchone("SELECT * FROM ssh_keys WHERE host_id=?", source_host_id)
    if not row:
        raise ApiError(404, "sshkey.noKey", "this host has no deploy key yet")
    return row


async def _dk_agent_host(host_id: int):
    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", host_id)
    if not row:
        raise HTTPException(404)
    if not conntypes.is_agent(row):
        raise ApiError(400, "sshkey.notAgent", "deploy keys work on agent hosts only")
    return row


def _dk_dep_json(d) -> dict:
    return {"id": d["id"], "key_id": d["key_id"], "target_host_id": d["target_host_id"],
            "target_name": d["target_name"] if "target_name" in d.keys() else "",
            "target_hostname": d["target_hostname"] if "target_hostname" in d.keys() else "",
            "target_user": d["agent_user"] if "agent_user" in d.keys() else "",
            "options": d["options"] or "", "status": d["status"],
            "deployed_at": d["deployed_at"], "revoked_at": d["revoked_at"]}


@router.get("/api/hosts/{host_id}/deploy-key")
async def deploy_key_get(host_id: int, request: Request,
                         user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Starea cheii de deploy a hostului: cheia (doar material public), unde e deployată,
    plus cheile ALTOR hosturi deployate AICI (inbound — vizibilitate pe graful de acces,
    inclusiv pentru garda anti-pivot din UI)."""
    await _dk_agent_host(host_id)
    # graful de acces SSH al hostului (fingerprints, ce ţinte poate atinge, ce chei intră aici)
    # e topologie sensibilă → pe host 2FA, aceeaşi poartă de step-up ca services/docker-logs/fs
    await stepup.require_host_stepup(host_id, user)
    key = await db.fetchone("SELECT * FROM ssh_keys WHERE host_id=?", host_id)
    deps = []
    if key:
        # LEFT JOIN, nu JOIN: un host ŞTERS din flotă nu face să dispară şi evidenţa — cheia e
        # ÎNCĂ autorizată pe maşina aia, iar rândul rămas e singura urmă că uşa există (M-6).
        deps = await db.fetchall(
            "SELECT d.*, h.name AS target_name, h.hostname AS target_hostname, h.agent_user"
            " FROM ssh_key_deployments d"
            " LEFT JOIN hosts h ON h.id=d.target_host_id WHERE d.key_id=? ORDER BY h.name", key["id"])
    inbound = await db.fetchall(
        "SELECT d.*, k.host_id AS source_host_id, h.name AS source_name,"
        " k.fingerprint AS fp FROM ssh_key_deployments d"
        " JOIN ssh_keys k ON k.id=d.key_id LEFT JOIN hosts h ON h.id=k.host_id"
        " WHERE d.target_host_id=? AND d.revoked_at IS NULL ORDER BY h.name", host_id)
    # 3.6: muchiile spre/de la hosturi pe care contul NU le vede rămân în listă (o uşă deschisă
    # nu dispare din inventar), dar fără nume, adresă sau id — altfel graful ar fi un oracol.
    vis = await authz.visible_hosts(authz.grants_of(request), "host.view")
    deployments = []
    for d in deps:
        j = _dk_dep_json(d)
        if j["target_host_id"] is not None and not authz.in_visible(vis, j["target_host_id"]):
            j.update(target_host_id=0, target_name="", target_hostname="", target_user="",
                     hidden=True)
        deployments.append(j)
    inbound_out = []
    for d in inbound:
        sid_, sname = d["source_host_id"], d["source_name"]
        hidden = sid_ is not None and not authz.in_visible(vis, sid_)
        inbound_out.append({"source_host_id": 0 if hidden else sid_,
                            "source_name": "" if hidden else sname,
                            "fingerprint": d["fp"], "status": d["status"],
                            **({"hidden": True} if hidden else {})})
    return {
        "key": {"id": key["id"], "public_key": key["public_key"], "fingerprint": key["fingerprint"],
                "created": key["created"]} if key else None,
        "deployments": deployments,
        "inbound": inbound_out,
    }


class DeployKeyIn(BaseModel):
    key_host_id: int = 0        # sursa cheii (pt. deploy/revoke/verify pe ruta ţintei)
    target_host_id: int = 0     # ţinta unică (test / ssh-config, pe ruta sursei)
    target_host_ids: list[int] = []   # deploy multi-ţintă (pe ruta sursei) — un singur factor
    from_ip: str = ""           # opţional: restricţie from="…" pe linia deployată
    restrict: bool = False      # opţional: `restrict` (no-pty/-forwarding/-agent/-X11) pe linie
    command: str = ""           # opţional: forced command=`…` (cheie care face DOAR o treabă)
    confirmed: bool = False     # garda anti-pivot cere un DA explicit
    stepup_grant: str = ""
    stepup_password: str = ""
    stepup_totp: str = ""       # 2FA: cod TOTP/recovery (conturi cu TOTP fără passkey, fix 3)


# command= poate conţine spaţii/flaguri, dar NU newline (ar rupe linia din authorized_keys —
# aceeaşi clasă H-1) şi nici caractere de control. Interiorul se escapează pentru ghilimelele
# din `command="…"` (doar \ şi " contează acolo).
_DK_CMD_RE = re.compile(r"^[\x20-\x7e]{1,300}$")


def _dk_cmd_quote(cmd: str) -> str:
    return cmd.replace("\\", "\\\\").replace('"', '\\"')


async def _dk_policy() -> dict:
    """Politica de securitate a cheilor de deploy (opţională, din Settings → Security).
    `require_2fa_source`: nu generezi o cheie pe un host-sursă fără require_2fa (sursele =
    bijuteriile coroanei; un dev compromis poate sări pe ţinte). `require_restrict`: nu
    deployezi o cheie de shell complet — trebuie `restrict` şi/sau un `command=` forţat."""
    raw = await db.get_setting("deploykey_policy")
    cfg = {"require_2fa_source": False, "require_restrict": False}
    if raw:
        try:
            cfg.update({k: bool(v) for k, v in json.loads(raw).items() if k in cfg})
        except (ValueError, TypeError, AttributeError):
            pass
    return cfg


class DeployKeyPolicyIn(BaseModel):
    require_2fa_source: bool = False
    require_restrict: bool = False


@router.get("/api/settings/deploy-key-policy")
async def get_deploy_key_policy(user=Depends(authz.perm('settings.manage'))):
    return await _dk_policy()


@router.post("/api/settings/deploy-key-policy")
async def set_deploy_key_policy(body: DeployKeyPolicyIn, user=Depends(authz.perm('settings.manage'))):
    cfg = {"require_2fa_source": body.require_2fa_source, "require_restrict": body.require_restrict}
    await db.set_setting("deploykey_policy", json.dumps(cfg))
    return cfg


def _dk_deploy_recipe(line: str, blob: str) -> str:
    """append idempotent al `line` în authorized_keys, scoţând întâi orice linie veche cu acelaşi
    blob (re-deploy cu alt from= → o singură linie per cheie). Perms 700/600 înainte de scriere."""
    q, qb = shlex.quote(line), shlex.quote(blob)
    return ("umask 077; mkdir -p \"$HOME/.ssh\" && chmod 700 \"$HOME/.ssh\" || exit 1; "
            "ak=\"$HOME/.ssh/authorized_keys\"; touch \"$ak\" && chmod 600 \"$ak\" || exit 1; "
            "if ! command grep -qxF %(l)s \"$ak\"; then "
            "if command grep -qF %(b)s \"$ak\"; then "
            "t=$(mktemp \"$HOME/.ssh/.ak.XXXXXX\") || exit 1; "
            "command grep -vF %(b)s \"$ak\" > \"$t\"; rc=$?; "
            "[ \"$rc\" -le 1 ] || { rm -f \"$t\"; exit \"$rc\"; }; "
            "chmod 600 \"$t\" && mv \"$t\" \"$ak\" || exit 1; fi; "
            "command printf '%%s\\n' %(l)s >> \"$ak\" || exit 1; fi; "
            "command grep -qxF %(l)s \"$ak\"" % {"l": q, "b": qb})


def _dk_revoke_recipe(blob: str) -> str:
    """scoate DOAR liniile cu `blob` (câmpul 2), distingând grep-nu-poate-citi (exit 2 → WT_ERROR,
    nu atingem nimic) de cheie-absentă (exit 1 → WT_NONE). Emite WT_REMOVED:n / WT_NONE / WT_ERROR."""
    qb = shlex.quote(blob)
    return ("umask 077; f=\"$HOME/.ssh/authorized_keys\"; "
            "[ -f \"$f\" ] || { echo WT_NONE; exit 0; }; "
            "n=$(command grep -cF %(b)s \"$f\" 2>/dev/null); grc=$?; "
            "[ \"$grc\" -ge 2 ] && { echo WT_ERROR; exit 3; }; "
            "[ \"$grc\" -eq 1 ] && { echo WT_NONE; exit 0; }; "
            "t=$(mktemp \"$HOME/.ssh/.ak.XXXXXX\") || { echo WT_ERROR; exit 1; }; "
            "command grep -vF %(b)s \"$f\" > \"$t\"; rc=$?; "
            "[ \"$rc\" -le 1 ] || { rm -f \"$t\"; echo WT_ERROR; exit \"$rc\"; }; "
            "chmod 600 \"$t\" && mv \"$t\" \"$f\" && echo \"WT_REMOVED:$n\" || { echo WT_ERROR; exit 1; }"
            % {"b": qb})


def _dk_options(from_ip: str, restrict: bool = False, command: str = "") -> str:
    """Opţiunile de început de linie din authorized_keys (listă separată prin virgulă):
    `restrict,command="…",from="…"`. `restrict` e default-deny (no-pty/-forwarding/-agent/-X11),
    superior enumerării manuale; `command=` forţează exact o comandă (cheie care face O treabă)."""
    opts = []
    if restrict:
        opts.append("restrict")
    cmd = (command or "").strip()
    if cmd:
        if not _DK_CMD_RE.match(cmd):
            raise ApiError(400, "sshkey.badCommand", "command: one printable line, no control characters")
        opts.append('command="%s"' % _dk_cmd_quote(cmd))
    ip = (from_ip or "").strip()
    if ip:
        if not _DK_FROM_RE.match(ip):
            raise ApiError(400, "sshkey.badFrom", "from= accepts IPs/CIDRs only (digits, hex, : . , /)")
        opts.append('from="%s"' % ip)
    return ",".join(opts)


async def _dk_require_restrict() -> bool:
    return bool((await _dk_policy()).get("require_restrict"))


async def _dk_deploy_one(key, target_id: int, from_ip: str, confirmed: bool,
                         user, request, restrict: bool = False, command: str = "",
                         raw_options=None) -> dict:
    """Mecanica unui singur deploy sursă→ţintă (fără gate-ul de factor — apelantul îl face O
    dată). Ridică ApiError la eşec, ca batch-ul să prindă per-ţintă. Idempotent.
    `raw_options` (rotire): foloseşte opţiunile stocate ale muchiei verbatim şi sare peste
    politica require_restrict — e un re-deploy al unei muchii deja aprobate, nu una nouă."""
    # 3.6 (§A.11.3): o cheie de deploy întinde încrederea A→B, deci `deploykey.manage` pe AMBELE.
    # Sursa e verificată de rută; ţinta aici — înainte de existenţă (404 identic), per ţintă în
    # batch/rotire. Fără cerere (apel intern) = refuz, fail-closed.
    await authz.require_on(request, target_id, "deploykey.manage")
    target = await _dk_agent_host(target_id)
    source = await db.fetchone("SELECT * FROM hosts WHERE id=?", key["host_id"])
    if key["host_id"] == target_id:
        raise ApiError(400, "sshkey.selfDeploy", "a host does not deploy its own key to itself")
    # H-2: scrierea în authorized_keys pe ŢINTĂ e o acţiune sensibilă PE ŢINTĂ, iar factorul
    # proaspăt al apelantului e legat de SURSĂ (decizia e despre CHEIE, nu despre fiecare ţintă).
    # Deci fiecare ţintă `require_2fa` cere FEREASTRA ei de step-up (deschisă din UI pe ţintă);
    # fără ea e SĂRITĂ cu un cod stabil — batch/rotate o raportează per-ţintă, nu o scriu tăcut.
    # Ruta single-deploy deschide fereastra pe ţintă chiar înainte (factor proaspăt pe ţintă),
    # deci rămâne consistentă.
    if target["require_2fa"] and not security.stepup_window_ok(user["id"], target_id):
        raise ApiError(403, "sshkey.targetNeeds2fa",
                       "the target requires 2FA — open a step-up window on it first")
    if raw_options is None:
        # politica „numai chei restricţionate": refuză un deploy de shell complet dacă e cerut
        if await _dk_require_restrict() and not (restrict or (command or "").strip()):
            raise ApiError(400, "sshkey.restrictRequired",
                           "policy requires a restriction (restrict and/or a forced command) on deploy keys")
        options = _dk_options(from_ip, restrict, command)
    else:
        options = raw_options or ""
    # anti-pivot: ţinta e ea însăşi o sursă cu deploy-uri active → lanţ de acces
    own = await db.fetchone(
        "SELECT k.id FROM ssh_keys k JOIN ssh_key_deployments d ON d.key_id=k.id"
        " WHERE k.host_id=? AND d.revoked_at IS NULL LIMIT 1", target_id)
    if own and not confirmed:
        raise ApiError(409, "sshkey.pivot", "the target has its own active deploy key — this creates an access chain")
    line = (options + " " if options else "") + key["public_key"]
    blob, _fp = _dk_validate(key["public_key"])     # H-1: re-validare la DEPLOY, din DB
    resp = await hostcmd.host_run(target_id, _dk_deploy_recipe(line, blob), timeout=20)
    if resp.get("exit_code") != 0:
        raise ApiError(502, "sshkey.deployFailed",
                       ("deploy failed: " + (resp.get("stderr") or ""))[:300])
    now = time.time()
    existing = await db.fetchone(
        "SELECT id FROM ssh_key_deployments WHERE key_id=? AND target_host_id=?",
        key["id"], target_id)
    if existing:
        await db.execute(
            "UPDATE ssh_key_deployments SET options=?, line=?, status='deployed',"
            " deployed_at=?, deployed_by=?, revoked_at=NULL WHERE id=?",
            options, line, now, user["email"], existing["id"])
    else:
        await db.execute(
            "INSERT INTO ssh_key_deployments(key_id, target_host_id, options, line, status,"
            " deployed_at, deployed_by) VALUES(?,?,?,?,'deployed',?,?)",
            key["id"], target_id, options, line, now, user["email"])
    email_alerts.notify_ssh_key_action("DEPLOYED", source["name"] if source else "?",
                                       target["name"], key["fingerprint"],
                                       security.client_ip(request), user["email"], host_id=target_id)
    if request is not None:
        audit.detail(request, "deploy-key %s -> %s" % (key["fingerprint"], target["name"]))
    return {"ok": True, "line": line, "target_user": target["agent_user"] or ""}


@router.post("/api/hosts/{host_id}/deploy-key/generate")
async def deploy_key_generate(host_id: int, body: DeployKeyIn, request: Request,
                              user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Generează perechea pe HOSTUL sursă (ssh-keygen local, prin `run`); privata nu apare în
    nicio comandă, stdout sau log — citim doar .pub, prin fs_read, şi îl validăm strict."""
    host = await _dk_agent_host(host_id)
    # Politica „2FA pe surse" (opţională): o cheie de deploy face hostul o SURSĂ — bijuteria
    # coroanei, de pe care un atacator poate sări pe ţinte. Dacă politica e activă, refuzăm
    # să generăm pe un host fără require_2fa (mesaj acţionabil — nu flip-uim tăcut flag-ul).
    if (await _dk_policy())["require_2fa_source"] and not (host["require_2fa"] or 0):
        raise ApiError(400, "sshkey.needs2faSource",
                       "policy requires 2FA on deploy-key sources — enable 2FA on this host first")
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    if await db.fetchone("SELECT id FROM ssh_keys WHERE host_id=?", host_id):
        raise ApiError(409, "sshkey.exists", "this host already has a deploy key")
    # Garda anti-pivot: dacă hostul e deja ŢINTA unei chei active, a genera o cheie pe el
    # creează un lanţ (compromiterea sursei lui sare două hopuri). Cere confirmare explicită.
    pivot = await db.fetchone(
        "SELECT 1 FROM ssh_key_deployments WHERE target_host_id=? AND revoked_at IS NULL LIMIT 1",
        host_id)
    if pivot and not body.confirmed:
        raise ApiError(409, "sshkey.pivot", "this host is already a deploy TARGET — generating a key here creates an access chain")
    # `command ssh-keygen`: shell de login (bash -lc) = aliasurile userului se aplică; le ocolim.
    # Dacă fişierul există deja pe disc (DB pierdut / instalare veche), îl ADOPTĂM (idempotent).
    cmd = ("umask 077; mkdir -p \"$HOME/.ssh\" || exit 1; "
           "[ -e %s ] || command ssh-keygen -q -t ed25519 -N '' -C webterm-deploy -f %s || exit 1"
           % (_DK_PATH, _DK_PATH))
    resp = await hostcmd.host_run(host_id, cmd, timeout=30)
    if resp.get("exit_code") != 0:
        raise ApiError(502, "sshkey.keygenFailed",
                       ("ssh-keygen failed: " + (resp.get("stderr") or ""))[:300])
    conn = core.source_for(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise HTTPException(409, "host offline or has no agent")
    try:
        r = await conn.request("fs_read", path=_DK_PUB, offset=0, timeout=20)
    except (core.AgentGone, TimeoutError, asyncio.TimeoutError):
        raise HTTPException(504, "the host did not answer in time")
    if not r.get("ok"):
        raise ApiError(502, "sshkey.keygenFailed", "could not read the public key back")
    pub = base64.b64decode(r.get("data_b64") or "").decode("utf-8", "replace").strip()
    _blob, fp = _dk_validate(pub)         # H-1: validare strictă la CITIRE
    try:
        await db.execute(
            "INSERT INTO ssh_keys(host_id, public_key, fingerprint, comment, created, created_by)"
            " VALUES(?,?,?,?,?,?)", host_id, pub, fp, "webterm-deploy", time.time(), user["email"])
    except sqlite3.IntegrityError:
        # două generate concurente: check-then-insert nu e atomic, UNIQUE(host_id) e gardul real
        # — al doilea primeşte acelaşi răspuns ca la re-apel, nu un 500
        raise ApiError(409, "sshkey.exists", "this host already has a deploy key")
    audit.detail(request, "deploy-key generated on %s (%s)" % (host["name"], fp))
    log.info("deploy key generated on host #%d (%s) by %s", host_id, fp, user["email"])
    return {"public_key": pub, "fingerprint": fp}


@router.post("/api/hosts/{host_id}/deploy-key/deploy")
async def deploy_key_deploy(host_id: int, body: DeployKeyIn, request: Request,
                            user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Deploy single-ţintă: ruta = ŢINTA (host_id), factor proaspăt legat de ţintă. Păstrat pt.
    compatibilitate; UI-ul foloseşte batch-ul source-routed de mai jos."""
    await authz.require_on(request, body.key_host_id, "deploykey.manage")   # 3.6: şi pe SURSĂ
    key = await _dk_key_row(body.key_host_id)
    if key["host_id"] == host_id:      # validare de formă înaintea cererii de factor
        raise ApiError(400, "sshkey.selfDeploy", "a host does not deploy its own key to itself")
    # Şi SURSA e gardată (3.5.13), ca batch/rotate (unde ruta = sursa, deci factorul proaspăt e
    # chiar pe ea): cheia privată stă pe sursă, iar deploy-ul îi lărgeşte accesul — pe o sursă
    # `require_2fa` cerem fereastra ei de step-up. Verificat ÎNAINTEA factorului de pe ţintă,
    # ca un grant single-use să nu fie consumat degeaba. Cod dedicat (nu `stepup.*`): un 403
    # de step-up pe ruta ŢINTEI ar face clientul să deschidă fereastra pe hostul greşit.
    src = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", key["host_id"])
    if src and src["require_2fa"]:
        if isinstance(user, dict) and user.get("is_token"):
            raise ApiError(403, "host.needs2faNoToken",
                           "deploy keys are not reachable with an automation token")
        if not security.stepup_window_ok(user["id"], key["host_id"]):
            raise ApiError(403, "sshkey.sourceNeeds2fa",
                           "the source host requires 2FA — open a step-up window on it first")
    await stepup.require_fresh_factor(host_id, user, body.stepup_grant, body.stepup_password,
                               body.stepup_totp)   # H-3
    return await _dk_deploy_one(key, host_id, body.from_ip, body.confirmed, user, request,
                                body.restrict, body.command)


@router.post("/api/hosts/{host_id}/deploy-key/deploy-batch")
async def deploy_key_deploy_batch(host_id: int, body: DeployKeyIn, request: Request,
                                  user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Deploy multi-ţintă: ruta = SURSA (host_id = hostul cheii), UN SINGUR factor proaspăt (decizia
    de acces e despre CHEIE, nu despre fiecare ţintă), apoi deploy la fiecare ţintă cu rezultat
    individual. Eşecul unei ţinte nu opreşte restul — ca fleet-run."""
    key = await _dk_key_row(host_id)
    await stepup.require_fresh_factor(host_id, user, body.stepup_grant, body.stepup_password,
                               body.stepup_totp)   # H-3
    results = []
    for tid in body.target_host_ids[:64]:
        try:
            await _dk_deploy_one(key, tid, body.from_ip, body.confirmed, user, request,
                                 body.restrict, body.command)
            results.append({"target_host_id": tid, "ok": True})
        except ApiError as e:
            results.append({"target_host_id": tid, "ok": False, "code": e.code, "error": e.detail})
        except HTTPException as e:
            results.append({"target_host_id": tid, "ok": False, "error": str(e.detail)})
    return {"results": results}


@router.post("/api/hosts/{host_id}/deploy-key/revoke")
async def deploy_key_revoke(host_id: int, body: DeployKeyIn, request: Request,
                            user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Scoate cheia de pe ŢINTĂ. Potrivim pe BLOB (nu pe linia întreagă): o linie editată
    manual (opţiuni adăugate pe ţintă) tot dispare — altfel revoke-ul „reuşea" degeaba."""
    target = await _dk_agent_host(host_id)
    await authz.require_on(request, body.key_host_id, "deploykey.manage")   # 3.6: şi pe SURSĂ
    key = await _dk_key_row(body.key_host_id)
    source = await db.fetchone("SELECT * FROM hosts WHERE id=?", key["host_id"])
    audit.detail(request, "deploy-key revoke %s from %s" % (key["fingerprint"], target["name"]))
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    blob, _fp = _dk_validate(key["public_key"])
    resp = await hostcmd.host_run(host_id, _dk_revoke_recipe(blob), timeout=20)
    out = resp.get("stdout") or ""
    # marcăm revoked DOAR când chiar am scos linia (WT_REMOVED) sau am CONFIRMAT că nu era
    # (WT_NONE, fişier lizibil). WT_ERROR / marker lipsă → NU atingem evidenţa: cheia poate fi
    # încă vie, iar un „revoked" fals ar ascunde o uşă deschisă.
    if resp.get("exit_code") != 0 or ("WT_REMOVED" not in out and "WT_NONE" not in out):
        raise ApiError(502, "sshkey.revokeFailed",
                       ("revoke failed (the key may still be live on the target): "
                        + (resp.get("stderr") or ""))[:300])
    await db.execute(
        "UPDATE ssh_key_deployments SET status='revoked', revoked_at=? WHERE key_id=? AND target_host_id=?",
        time.time(), key["id"], host_id)
    email_alerts.notify_ssh_key_action("REVOKED", source["name"] if source else "?",
                                       target["name"], key["fingerprint"],
                                       security.client_ip(request), user["email"], host_id=host_id)
    return {"ok": True, "removed": "WT_REMOVED" in out}


@router.post("/api/hosts/{host_id}/deploy-key/verify")
async def deploy_key_verify(host_id: int, body: DeployKeyIn, request: Request,
                            user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Reconciliere: linia deployată mai e pe ţintă aşa cum am scris-o? `deployed` = identică,
    `edited` = blob-ul e acolo dar linia diferă (opţiuni schimbate manual), `missing` = deloc."""
    await _dk_agent_host(host_id)
    await authz.require_on(request, body.key_host_id, "deploykey.manage")   # 3.6: şi pe SURSĂ
    key = await _dk_key_row(body.key_host_id)
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    dep = await db.fetchone(
        "SELECT * FROM ssh_key_deployments WHERE key_id=? AND target_host_id=?",
        key["id"], host_id)
    if not dep:
        raise HTTPException(404)
    blob, _fp = _dk_validate(key["public_key"])
    cmd = ("f=\"$HOME/.ssh/authorized_keys\"; [ -f \"$f\" ] || { echo WT_MISSING; exit 0; }; "
           "if command grep -qxF %s \"$f\"; then echo WT_OK; "
           "elif command grep -qF %s \"$f\"; then echo WT_EDITED; else echo WT_MISSING; fi"
           % (shlex.quote(dep["line"]), shlex.quote(blob)))
    resp = await hostcmd.host_run(host_id, cmd, timeout=20)
    out = resp.get("stdout") or ""
    status = ("deployed" if "WT_OK" in out else
              "edited" if "WT_EDITED" in out else "missing")
    if dep["revoked_at"] is None:
        await db.execute("UPDATE ssh_key_deployments SET status=? WHERE id=?", status, dep["id"])
    return {"status": status}


@router.delete("/api/hosts/{host_id}/deploy-key")
async def deploy_key_delete(host_id: int, request: Request, stepup_grant: str = "",
                            stepup_password: str = "", stepup_totp: str = "", user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Şterge cheia de pe hostul SURSĂ (fişiere + evidenţă). Refuză cât timp există deploy-uri
    active: altfel rămân uşi deschise pe ţinte fără nicio urmă în inventar — revocă-le întâi."""
    host = await _dk_agent_host(host_id)
    key = await _dk_key_row(host_id)
    await stepup.require_host_stepup(host_id, user, stepup_grant, stepup_password, stepup_totp)
    # doar deploy-urile pe ţinte care ÎNCĂ există blochează ştergerea: o ţintă scoasă din flotă
    # nu mai e revocabilă de aici oricum (rândul orfan a stat vizibil în UI drept avertisment),
    # altfel cheia devenea de neşters pentru totdeauna
    active = await db.fetchone(
        "SELECT 1 FROM ssh_key_deployments d JOIN hosts h ON h.id=d.target_host_id"
        " WHERE d.key_id=? AND d.revoked_at IS NULL AND d.status != 'missing' LIMIT 1", key["id"])
    if active:
        raise ApiError(409, "sshkey.hasDeployments", "revoke the key from all targets first")
    resp = await hostcmd.host_run(host_id, "rm -f %s %s.pub" % (_DK_PATH, _DK_PATH), timeout=20)
    if resp.get("exit_code") != 0:
        raise ApiError(502, "sshkey.deleteFailed",
                       ("could not remove the key files: " + (resp.get("stderr") or ""))[:300])
    await db.execute("DELETE FROM ssh_key_deployments WHERE key_id=?", key["id"])
    await db.execute("DELETE FROM ssh_keys WHERE id=?", key["id"])
    audit.detail(request, "deploy-key deleted on %s (%s)" % (host["name"], key["fingerprint"]))
    return {"ok": True}


async def _dk_ssh_target(target_id: int) -> tuple[str, str]:
    """(user@host) pentru comanda ssh de pe sursă — hostname pinuit din diagnostic, userul
    agentului ţintei. Validate strict: fără metacaractere (intră shlex-quotate oricum)."""
    t = await db.fetchone("SELECT hostname, agent_user, name FROM hosts WHERE id=?", target_id)
    if not t:
        raise HTTPException(404)
    host = (t["hostname"] or "").strip()
    tuser = (t["agent_user"] or "").strip()
    if not host:
        raise ApiError(400, "sshkey.noHostname", "the target has not reported a hostname yet")
    return tuser, host


@router.post("/api/hosts/{host_id}/deploy-key/test")
async def deploy_key_test(host_id: int, body: DeployKeyIn, request: Request,
                          user=Depends(authz.perm("deploykey.manage", host="host_id"))):
    """Probează `ssh sursă→ţintă` cu cheia de deploy (rulează PE sursă, prin op-ul `run`).
    BatchMode → nu atârnă la niciun prompt; accept-new → TOFU (scrie known_hosts la prima
    conectare). Întoarce reachable + detaliu, fără să schimbe nimic pe ţintă."""
    await _dk_agent_host(host_id)
    await authz.require_on(request, body.target_host_id, "deploykey.manage")   # 3.6: şi pe ŢINTĂ
    await _dk_key_row(host_id)      # sursa trebuie să aibă cheia
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    tuser, thost = await _dk_ssh_target(body.target_host_id)
    dest = ("%s@%s" % (tuser, thost)) if tuser else thost
    cmd = ("command ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "
           "-o ConnectTimeout=8 -o PasswordAuthentication=no -i %s %s true 2>&1; "
           "echo \"WT_SSH_RC:$?\"" % (_DK_PATH, shlex.quote(dest)))
    resp = await hostcmd.host_run(host_id, cmd, timeout=20)
    out = (resp.get("stdout") or "") + (resp.get("stderr") or "")
    m = re.search(r"WT_SSH_RC:(\d+)", out)
    rc = int(m.group(1)) if m else 1
    # marcajul de la coadă, scos fără regex (SonarQube S8786: `\s*…\s*$` era pătratic pe ieşiri lungi)
    head, sep, tail = out.rpartition("WT_SSH_RC:")
    detail = (head if sep and tail.strip().isdigit() else out).strip()[:400]
    return {"ok": rc == 0, "rc": rc, "detail": detail, "dest": dest}


@router.post("/api/hosts/{host_id}/deploy-key/ssh-config")
async def deploy_key_ssh_config(host_id: int, body: DeployKeyIn, request: Request,
                                user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Scrie idempotent un bloc marcat în ~/.ssh/config pe SURSĂ pentru o ţintă, ca `ssh <alias>`
    să meargă fără `-i` (util agenţilor AI). Aliasul = numele ţintei, sanitizat. Revocabil: blocul
    e delimitat de markere WebTerm, deci re-scrierea/ştergerea nu atinge restul config-ului."""
    await _dk_agent_host(host_id)
    await authz.require_on(request, body.target_host_id, "deploykey.manage")   # 3.6: şi pe ŢINTĂ
    await _dk_key_row(host_id)
    await stepup.require_host_stepup(host_id, user, body.stepup_grant, body.stepup_password, body.stepup_totp)
    trow = await db.fetchone("SELECT name FROM hosts WHERE id=?", body.target_host_id)
    tuser, thost = await _dk_ssh_target(body.target_host_id)
    alias = re.sub(r"[^A-Za-z0-9._-]", "-", (trow["name"] if trow else "") or thost)[:48]
    beg, end = "# >>> webterm %s >>>" % alias, "# <<< webterm %s <<<" % alias
    block = "\n".join([beg, "Host %s" % alias, "    HostName %s" % thost]
                      + (["    User %s" % tuser] if tuser else [])
                      + ["    IdentityFile ~/.ssh/webterm_ed25519", end])
    # awk cu comparaţie LITERALĂ pe markere (fără regex — `>>>`/`<<<` ar fi capcane în sed BRE):
    # scoate blocul vechi între markere (idempotent), apoi append blocul nou. perms 600.
    cmd = ("umask 077; mkdir -p \"$HOME/.ssh\" && chmod 700 \"$HOME/.ssh\"; "
           "c=\"$HOME/.ssh/config\"; touch \"$c\" && chmod 600 \"$c\" || exit 1; "
           "t=$(mktemp \"$HOME/.ssh/.cfg.XXXXXX\") || exit 1; "
           "command awk -v b=%s -v e=%s 'BEGIN{s=0} $0==b{s=1;next} $0==e{s=0;next} !s' \"$c\" > \"$t\" || exit 1; "
           "printf '%%s\\n' %s >> \"$t\"; chmod 600 \"$t\" && mv \"$t\" \"$c\""
           % (shlex.quote(beg), shlex.quote(end), shlex.quote(block)))
    resp = await hostcmd.host_run(host_id, cmd, timeout=20)
    if resp.get("exit_code") != 0:
        raise ApiError(502, "sshkey.configFailed",
                       ("could not write ~/.ssh/config: " + (resp.get("stderr") or ""))[:300])
    audit.detail(request, "deploy-key ssh-config alias %s on host #%d" % (alias, host_id))
    return {"ok": True, "alias": alias}


@router.post("/api/hosts/{host_id}/deploy-key/rotate")
async def deploy_key_rotate(host_id: int, body: DeployKeyIn, request: Request,
                            user=Depends(authz.perm('deploykey.manage', host='host_id'))):
    """Rotire ghidată, în ordinea care NU lasă sursa fără acces (audit 2026-10-04, §5):
      1. perechea NOUĂ se generează ALĂTURI de cea veche (`webterm_ed25519.new`), nu peste ea;
      2. noua cheie publică se deployează pe fiecare ţintă activă (cu opţiunile stocate ale muchiei)
         — o ţintă offline/eşuată NU opreşte bucla: e marcată `missing` şi raportată;
      3. abia apoi sursa trece pe noua cheie (mv atomic) şi evidenţa primeşte noul fingerprint;
      4. la final scoatem blob-ul VECHI de pe ţintele unde noua cheie a aterizat.
    Înainte, evidenţa şi cheia privată se schimbau ÎNAINTE de redeploy, iar prima ţintă offline
    (HTTPException 409, neprinsă) întrerupea bucla: restul ţintelor rămâneau cu cheia veche,
    în timp ce sursa n-o mai avea — acces pierdut, UI verde. Un singur factor proaspăt."""
    host = await _dk_agent_host(host_id)
    key = await _dk_key_row(host_id)
    # 3.6: rotirea re-scrie cheia pe FIECARE ţintă activă → `deploykey.manage` pe toate, verificat
    # ÎNAINTE de orice efect (altfel o ţintă din afara scope-ului ar rămâne la jumătatea rotirii)
    for d in await db.fetchall(
            "SELECT target_host_id FROM ssh_key_deployments WHERE key_id=? AND revoked_at IS NULL"
            " AND status != 'missing'", key["id"]):
        await authz.require_on(request, d["target_host_id"], "deploykey.manage")
    await stepup.require_fresh_factor(host_id, user, body.stepup_grant, body.stepup_password,
                               body.stepup_totp)
    old_blob, _ = _dk_validate(key["public_key"])
    old_fp = key["fingerprint"]
    new_path = _DK_PATH[:-1] + '.new"'          # "$HOME/.ssh/webterm_ed25519.new" (ghilimelele rămân)
    # keygen ALĂTURI (rm întâi doar temporarele — ssh-keygen refuză să suprascrie fără prompt)
    resp = await hostcmd.host_run(host_id,
                           "umask 077; rm -f %s %s.pub && command ssh-keygen -q -t ed25519 -N '' "
                           "-C webterm-deploy -f %s" % (new_path, new_path, new_path), timeout=30)
    if resp.get("exit_code") != 0:
        raise ApiError(502, "sshkey.keygenFailed",
                       ("ssh-keygen failed: " + (resp.get("stderr") or ""))[:300])
    conn = core.source_for(host_id)
    if not isinstance(conn, core.AgentConnection):
        raise HTTPException(409, "host offline or has no agent")
    r = await conn.request("fs_read", path=_DK_PUB[:-4] + ".new.pub", offset=0, timeout=20)
    if not r.get("ok"):
        raise ApiError(502, "sshkey.keygenFailed", "could not read the new public key back")
    newpub = base64.b64decode(r.get("data_b64") or "").decode("utf-8", "replace").strip()
    _nb, newfp = _dk_validate(newpub)
    # cheia „nouă" ca dict, NU în DB încă: _dk_deploy_one compune linia din key["public_key"]
    newkey = dict(key)
    newkey["public_key"], newkey["fingerprint"] = newpub, newfp
    deps = await db.fetchall(
        "SELECT d.target_host_id, d.options, h.name AS target_name FROM ssh_key_deployments d"
        " JOIN hosts h ON h.id=d.target_host_id"
        " WHERE d.key_id=? AND d.revoked_at IS NULL AND d.status != 'missing'", key["id"])
    results, landed = [], []
    for d in deps:
        tid = d["target_host_id"]
        entry = {"target_host_id": tid, "target_name": d["target_name"]}
        try:
            # păstrează opţiunile existente ale muchiei (restrict/command/from) la rotire
            await _dk_deploy_one(newkey, tid, "", True, user, request, raw_options=d["options"])
            landed.append(tid)
            results.append(entry | {"ok": True})
        except ApiError as e:
            results.append(entry | {"ok": False, "code": e.code, "error": e.detail})
        except HTTPException as e:
            # ţintă offline (409) / fără răspuns (504): NU oprim bucla, nu minţim evidenţa.
            results.append(entry | {"ok": False, "code": "sshkey.targetOffline", "error": str(e.detail)})
        if not results[-1]["ok"]:
            # ţinta rămâne cu linia VECHE (pe care sursa n-o va mai putea folosi) → `missing`,
            # ca Verify/Deploy să o arate drept „de redeployat", nu drept `deployed`
            await db.execute(
                "UPDATE ssh_key_deployments SET status='missing' WHERE key_id=? AND target_host_id=?",
                key["id"], tid)
    # abia ACUM sursa trece pe noua cheie: mv atomic, pub-ul după privată. Dacă pică, vechea
    # pereche e intactă pe sursă şi ţintele poartă AMBELE linii — nimic pierdut, raportăm.
    resp = await hostcmd.host_run(host_id, "umask 077; mv -f %s %s && mv -f %s.pub %s.pub"
                           % (new_path, _DK_PATH, new_path, _DK_PATH), timeout=20)
    if resp.get("exit_code") != 0:
        raise ApiError(502, "sshkey.rotateSwapFailed",
                       ("could not install the new key on the source (targets now hold both keys): "
                        + (resp.get("stderr") or ""))[:300])
    await db.execute("UPDATE ssh_keys SET public_key=?, fingerprint=?, created=? WHERE id=?",
                     newpub, newfp, time.time(), key["id"])
    # scoate blob-ul vechi DOAR de unde a aterizat cel nou; un eşec aici nu e pierdere de acces
    for entry in results:
        if not entry["ok"]:
            continue
        try:
            await hostcmd.host_run(entry["target_host_id"], _dk_revoke_recipe(old_blob), timeout=20)
            entry["old_removed"] = True
        except HTTPException as e:
            entry["old_removed"] = False
            entry["error"] = "old key still authorized: " + str(e.detail)
    left_old = [{"target_host_id": e["target_host_id"], "target_name": e["target_name"]}
                for e in results if not e["ok"]]
    audit.detail(request, "deploy-key rotated on %s (%s → %s; %d/%d targets)"
                 % (host["name"], old_fp, newfp, len(landed), len(results)))
    return {"fingerprint": newfp, "public_key": newpub, "results": results,
            "left_with_old_key": left_old}
