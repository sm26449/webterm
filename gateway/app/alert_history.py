"""Istoricul de alerte în aplicaţie + preferinţele per eveniment (3.5.11).

Până acum alertele existau DOAR ca email/webhook (`email_alerts._fire`): fără SMTP configurat,
un login de pe un IP nou sau un host căzut nu lăsa nicio urmă vizibilă în interfaţă. Aici fiecare
eveniment care pleacă (sau ar pleca) pe email se înregistrează şi în DB, câte un rând per cont
căruia îi priveşte, iar clopoţelul din UI le arată.

Cui îi priveşte un eveniment:
  * `scope="account"` — evenimentele unui cont anume (login nou, parolă/2FA/passkey schimbate,
    ataşare la o sesiune de pe un loc nou, deblocarea unui host 2FA): doar contul acela;
  * `scope="fleet"` — tot restul (host căzut, praguri, chei SSH, tokenuri, backup, discul
    gateway-ului): FIECARE cont. Nu există roluri — orice cont e administrator deplin peste
    flotă (docs/THREAT-MODEL.md) — deci „vizibil adminilor" înseamnă „vizibil tuturor".
    Fan-out la inserare (un rând per cont), ca citit/necitit şi ştergerea să fie per cont, iar
    izolarea între conturi să fie un simplu `WHERE user_id=?`.

Preferinţele (tabela `alert_prefs`) ţin doar abaterile de la implicit: email ON, în aplicaţie ON
— adică exact comportamentul de dinainte. Emailul e o cutie COMUNĂ a instanţei (`smtp_to`), nu
una per cont, deci regula e:
  * eveniment de cont → contează preferinţa contului respectiv;
  * eveniment de flotă → pleacă dacă MĂCAR UN cont îl vrea (un cont nu poate reduce la tăcere,
    singur, o alertă pe care alt administrator o aşteaptă).
Toggle-ul „email" acoperă şi webhook-ul: e acelaşi `_fire`, acelaşi canal extern.

Tipurile de SECURITATE (`security=True`) se înregistrează în aplicaţie ÎNTOTDEAUNA: emailul se
poate opri (cu un avertisment în UI), dar urma din aplicaţie nu — e ultimul loc în care un
compromis se mai vede dacă emailul a fost oprit chiar de cel care a compromis contul.
"""

import logging
import re
import time

from . import db

log = logging.getLogger("webterm")

KEEP_PER_USER = 500
KEEP_DAYS = 30
SEVERITIES = ("critical", "warning", "info", "ok")

# id stabil → grup (pentru UI), scope, securitate. Ordinea e ordinea din Setări.
KINDS: dict = {
    # contul tău
    "new_login":        {"group": "account",  "scope": "account", "security": True},
    "session_attach":   {"group": "account",  "scope": "account", "security": True},
    "account_change":   {"group": "account",  "scope": "account", "security": True},
    "host_unlocked":    {"group": "account",  "scope": "account", "security": False},
    # link-uri de replay (3.5.12): crearea e o cale nouă de acces PUBLIC → securitate (mereu în
    # aplicaţie); deschiderea e informativă, throttle-uită per link
    "replay_link":      {"group": "account",  "scope": "account", "security": True},
    "replay_opened":    {"group": "account",  "scope": "account", "security": False},
    # securitatea instanţei
    "admin_change":     {"group": "security", "scope": "fleet", "security": True},
    "ssh_key":          {"group": "security", "scope": "fleet", "security": True},
    "host_key_changed": {"group": "security", "scope": "fleet", "security": True},
    "agent_relocation": {"group": "security", "scope": "fleet", "security": True},
    "host_enrolled":    {"group": "security", "scope": "fleet", "security": True},
    "lockout":          {"group": "security", "scope": "fleet", "security": False},
    # hosturi
    "host_offline":     {"group": "hosts", "scope": "fleet", "security": False},
    "resource":         {"group": "hosts", "scope": "fleet", "security": False},
    "agent_ip_change":  {"group": "hosts", "scope": "fleet", "security": False},
    "update_refused":   {"group": "hosts", "scope": "fleet", "security": False},
    # gateway
    "gateway_disk":     {"group": "gateway", "scope": "fleet", "security": False},
    "signing_locked":   {"group": "gateway", "scope": "fleet", "security": False},
    "backup_failed":    {"group": "gateway", "scope": "fleet", "security": False},
    # rezervă pentru apeluri `_fire` fără tip (teste, cod vechi) — nu apare în Setări
    "system":           {"group": "gateway", "scope": "fleet", "security": False, "hidden": True},
}


def kind_meta(kind: str) -> dict:
    return KINDS.get(kind) or KINDS["system"]


# ── igienă: nimic secret în `details` ─────────────────────────────────────────────────────
# Corpurile de alertă sunt compuse de noi şi nu conţin secrete — dar unele citează texte venite
# din afară (eroarea unui upload de backup, motivul unui refuz de update). Un URL cu credenţiale
# (`sftp://user:parola@…`) sau un token în mesajul de eroare ar ajunge altfel în DB şi în UI.
#
# 3.5.12: aceleaşi tipare servesc şi mascarea înregistrărilor partajate prin link de replay
# (`replay.py`), deci sunt scrise ca (regex, GRUPUL de ascuns):
#   * alertele înlocuiesc grupul cu `***` (o cheie privată dispare cu totul, cu BEGIN/END);
#   * replay-ul îl înlocuieşte cu `*` de ACEEAŞI lungime, ca poziţionarea din terminal să nu
#     se strice — vezi `replay.mask_secrets`.
# Valorile exclud caracterele de control (`\x00-\x1f`, `\x7f`): într-un flux de terminal o valoare
# e urmată adesea direct de o secvenţă de culoare (`\x1b[0m`), care altfel ar fi înghiţită şi
# mascată — adică stricată. Separatorul `cheie=valoare` e `[ \t]*`, nu `\s*`: un prompt
# `Password:` urmat de rând nou nu trebuie să mascheze primul cuvânt al rândului următor.
_V = r"[^\s\x00-\x1f\x7f\"'&,;]"           # un caracter de valoare „simplă"
_PRIVATE_KEY = re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----|\Z)",
                          re.S)
SECRET_PATTERNS = [
    (re.compile(r"\b(wt_)([A-Za-z0-9_\-]{8,})"), 2),                  # token de automatizare
    (re.compile(r"(?i)\b(bearer[ \t]+)([A-Za-z0-9._~+/=\-]{8,})"), 2),
    (re.compile(r"(?i)(://[^/\s:@\x00-\x1f]+:)([^@/\s\x00-\x1f]+)(@)"), 2),   # user:parola@ în URL
    (re.compile(r"(?i)\b([A-Za-z0-9_\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|"
                r"access[_-]?key|private[_-]?key|client[_-]?secret|passphrase)[A-Za-z0-9_\-]*)"
                # o culoare între `=` şi valoare (`password=\x1b[31mhunter2`) nu salvează valoarea
                r"([ \t]*[=:][ \t]*)((?:\x1b\[[0-9;]*m)*)([\"']?)(" + _V + r"+)"), 5),
    (re.compile(r"(?i)([?&](?:token|key|sig|signature|code|access_token)=)([^&\s\x00-\x1f\x7f]+)"), 2),
    (_PRIVATE_KEY, 2),          # replay: corpul cheii (BEGIN/END rămân, ca omul să vadă ce era)
    # chei de cloud / forje, recunoscute după formă (fără „cheie=" în faţă)
    (re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16})\b"), 1),   # AWS
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,})"), 1),                 # GitHub (clasic)
    (re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,})"), 1),               # GitHub (fine-grained)
    (re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})"), 1),                  # GitLab
    (re.compile(r"\b(xox[abposr]-[A-Za-z0-9\-]{10,})"), 1),             # Slack
    (re.compile(r"\b(sk-[A-Za-z0-9_\-]{20,})"), 1),                     # OpenAI / Anthropic (sk-ant-…)
    (re.compile(r"\b([rs]k_(?:live|test)_[A-Za-z0-9]{16,})"), 1),       # Stripe
    (re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})"), 1),                     # Google API key
    (re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"), 1),  # JWT
]


def secret_spans(s: str) -> list:
    """[(start, end)] — porţiunile de ascuns din `s`, nesuprapuse, în ordine. Porţiunile care
    se suprapun (două tipare pe acelaşi secret) se UNESC: altfel cea pierzătoare ar lăsa la
    vedere tocmai coada pe care n-o acoperea cealaltă."""
    found = []
    for rx, grp in SECRET_PATTERNS:
        for m in rx.finditer(s):
            a, b = m.span(grp)
            if b > a:
                found.append((a, b))
    found.sort()
    out: list = []
    for a, b in found:
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def scrub(text: str, limit: int = 2000) -> str:
    s = _PRIVATE_KEY.sub("[private key redacted]", str(text or ""))
    parts, pos = [], 0
    for a, b in secret_spans(s):
        parts.append(s[pos:a] + "***")
        pos = b
    parts.append(s[pos:])
    return "".join(parts)[:limit]


# ── înregistrare ──────────────────────────────────────────────────────────────────────────
async def _target_users(scope: str, user_id, user_email) -> list:
    """Conturile cărora le priveşte evenimentul. Un eveniment de cont al cărui cont nu mai
    poate fi găsit (ex. emailul tocmai s-a schimbat şi apelantul a dat adresa veche) cade pe
    fan-out — mai bine vizibil tuturor administratorilor decât pierdut."""
    if scope == "account":
        if user_id:
            row = await db.fetchone("SELECT id FROM users WHERE id=?", int(user_id))
            if row:
                return [row["id"]]
        if user_email:
            row = await db.fetchone("SELECT id FROM users WHERE email=?", user_email)
            if row:
                return [row["id"]]
    return [r["id"] for r in await db.fetchall("SELECT id FROM users")]


async def _prefs_for(uids: list, kind: str) -> dict:
    if not uids:
        return {}
    rows = await db.fetchall(
        "SELECT user_id, email, inapp FROM alert_prefs WHERE kind=? AND user_id IN (%s)"
        % ",".join("?" * len(uids)), kind, *uids)
    return {r["user_id"]: (bool(r["email"]), bool(r["inapp"])) for r in rows}


async def _prune(uid: int, now: float) -> None:
    """Retenţie ieftină, la inserare: ultimele KEEP_PER_USER rânduri ŞI cel mult KEEP_DAYS."""
    await db.execute(
        "DELETE FROM alerts WHERE user_id=? AND (ts < ? OR id <= COALESCE("
        "(SELECT id FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 1 OFFSET ?), -1))",
        uid, now - KEEP_DAYS * 86400, uid, KEEP_PER_USER)


_KEY_RE = re.compile(r"^[a-z0-9_]{1,48}$")
_PARAM_RE = re.compile(r"^[a-z0-9_]{1,32}$")


def message_params(params) -> str:
    """JSON-ul parametrilor unui mesaj localizabil (3.5.15) — sau '' dacă nu sunt.

    UI-ul traduce titlul/detaliile din cheia mesajului + aceşti parametri, deci parametrii ajung
    în DB şi în UI exact ca textul englezesc: trec prin ACELAŞI `scrub` (o eroare de upload cu
    `user:parola@` în URL nu scapă pe aici). Doar scalari, nume de parametru simple, valori
    mărginite — un apelant nu poate strecura obiecte sau chei arbitrare în catalog."""
    import json
    out = {}
    for k, v in (params or {}).items():
        if not _PARAM_RE.match(str(k)):
            continue
        if isinstance(v, bool):
            out[k] = v
        elif isinstance(v, (int, float)):
            out[k] = v
        elif v is not None:
            out[k] = scrub(str(v), 500)
    return json.dumps(out, separators=(",", ":"), ensure_ascii=False) if out else ""


async def record(kind: str, severity: str, title: str, details: str = "",
                 host_id=None, user_id=None, user_email=None, key=None, params=None) -> bool:
    """Înregistrează evenimentul pentru conturile cărora le priveşte şi întoarce dacă trebuie
    trimis şi pe canalul extern (email/webhook), după preferinţe. Best-effort: fără DB (startup/
    shutdown) nu înregistrează nimic şi lasă emailul să plece, ca înainte.

    `key` + `params` (3.5.15): cheia STABILĂ a mesajului şi parametrii lui, ca panoul din
    aplicaţie să afişeze alerta în limba interfeţei. `title`/`details` rămân textul englezesc
    (emailul/webhook-ul îl folosesc, iar rândurile vechi fără cheie se afişează aşa)."""
    if not db.connected():
        return True
    meta = kind_meta(kind)
    if severity not in SEVERITIES:
        severity = "info"
    uids = await _target_users(meta["scope"], user_id, user_email)
    if not uids:
        return True                         # instanţă fără cont încă: nimic de înregistrat
    prefs = await _prefs_for(uids, kind)
    want_email = any(prefs.get(u, (True, True))[0] for u in uids)
    now = time.time()
    t, d = scrub(title, 200), scrub(details)
    hid = int(host_id) if host_id else None
    mk = key if key and _KEY_RE.match(str(key)) else None
    mp = message_params(params) if mk else ""
    for u in uids:
        if not (meta["security"] or prefs.get(u, (True, True))[1]):
            continue
        await db.execute(
            "INSERT INTO alerts(user_id, ts, kind, severity, title, details, host_id, read,"
            " msg_key, msg_params) VALUES(?,?,?,?,?,?,?,0,?,?)", u, now, kind, severity, t, d, hid,
            mk, mp or None)
        await _prune(u, now)
    return want_email


# ── citire / stare (folosite de rutele din api.py; TOATE filtrate pe user_id) ──────────────
def _row(r) -> dict:
    import json
    params = {}
    if r["msg_key"] and r["msg_params"]:
        try:
            params = json.loads(r["msg_params"])
        except ValueError:
            params = {}
    return {"id": r["id"], "ts": r["ts"], "kind": r["kind"], "severity": r["severity"],
            "title": r["title"], "details": r["details"] or "", "host_id": r["host_id"],
            "read": bool(r["read"]),
            # rândurile de dinainte de 3.5.15 n-au cheie → UI-ul arată textul stocat
            "msg_key": r["msg_key"] or None,
            "msg_params": params if isinstance(params, dict) else {}}


async def unread_count(uid: int) -> int:
    row = await db.fetchone("SELECT COUNT(*) AS c FROM alerts WHERE user_id=? AND read=0", uid)
    return int(row["c"]) if row else 0


async def list_for(uid: int, limit: int = 50, before=None, unread_only: bool = False) -> dict:
    limit = max(1, min(200, int(limit)))
    sql = "SELECT * FROM alerts WHERE user_id=?"
    args: list = [uid]
    if before:
        sql += " AND id < ?"
        args.append(int(before))
    if unread_only:
        sql += " AND read=0"
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit + 1)                  # +1 = „mai există o pagină?" fără un COUNT separat
    rows = await db.fetchall(sql, *args)
    items = [_row(r) for r in rows[:limit]]
    nxt = items[-1]["id"] if len(rows) > limit and items else None
    return {"alerts": items, "unread": await unread_count(uid), "next_before": nxt}


async def mark_read(uid: int, ids=None) -> int:
    if ids is None:
        await db.execute("UPDATE alerts SET read=1 WHERE user_id=? AND read=0", uid)
    else:
        ids = [int(i) for i in ids][:500]
        if ids:
            await db.execute("UPDATE alerts SET read=1 WHERE user_id=? AND id IN (%s)"
                             % ",".join("?" * len(ids)), uid, *ids)
    return await unread_count(uid)


async def clear(uid: int) -> int:
    row = await db.fetchone("SELECT COUNT(*) AS c FROM alerts WHERE user_id=?", uid)
    await db.execute("DELETE FROM alerts WHERE user_id=?", uid)
    return int(row["c"]) if row else 0


async def get_prefs(uid: int) -> list:
    rows = await db.fetchall("SELECT kind, email, inapp FROM alert_prefs WHERE user_id=?", uid)
    have = {r["kind"]: (bool(r["email"]), bool(r["inapp"])) for r in rows}
    out = []
    for kind, m in KINDS.items():
        if m.get("hidden"):
            continue
        email, inapp = have.get(kind, (True, True))
        out.append({"kind": kind, "group": m["group"], "scope": m["scope"],
                    "security": m["security"], "email": email,
                    # securitate: în aplicaţie e mereu ON, indiferent ce e stocat
                    "inapp": True if m["security"] else inapp})
    return out


async def set_prefs(uid: int, prefs: dict) -> list:
    """`prefs` = {kind: {"email": bool, "inapp": bool}}; tipuri necunoscute → ValueError.
    Rândurile egale cu implicitul se şterg (tabela ţine doar abaterile)."""
    for kind in prefs:
        if kind not in KINDS or KINDS[kind].get("hidden"):
            raise ValueError(kind)
    for kind, p in prefs.items():
        email = bool(p.get("email", True))
        inapp = True if KINDS[kind]["security"] else bool(p.get("inapp", True))
        if email and inapp:
            await db.execute("DELETE FROM alert_prefs WHERE user_id=? AND kind=?", uid, kind)
        else:
            await db.execute(
                "INSERT INTO alert_prefs(user_id, kind, email, inapp) VALUES(?,?,?,?)"
                " ON CONFLICT(user_id, kind) DO UPDATE SET email=excluded.email, inapp=excluded.inapp",
                uid, kind, int(email), int(inapp))
    return await get_prefs(uid)


async def forget_user(uid: int) -> None:
    """Ştergerea unui cont: istoricul şi preferinţele lui pleacă odată cu el."""
    await db.execute("DELETE FROM alerts WHERE user_id=?", uid)
    await db.execute("DELETE FROM alert_prefs WHERE user_id=?", uid)
