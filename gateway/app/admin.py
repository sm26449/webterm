"""Recuperare de pe server, prin SSH — `python3 -m app.admin …`.

De ce există: fiecare poartă adăugată în UI (cod pe email, TOTP la passkey-uri, step-up pe
hosturi cu 2FA) e o cale în plus prin care te poţi bloca singur. Un produs self-hosted îşi poate
permite să fie strict în interfaţă exact fiindcă are ieşirea asta: cine are shell pe server are
deja fişierul DB, cheia seifului şi containerul — deci comanda nu acordă nimic nou, doar face
corect ce altfel ai fi făcut cu SQL scris de mână la 2 noaptea.

RUNBOOK-ul documenta procedura ca heredoc cu `UPDATE users SET password_hash=…`. Funcţiona, dar
lăsa în urmă exact ce nu trebuie după o compromitere: sesiunile web deschise rămâneau valide,
share-urile continuau să meargă, iar ferestrele de step-up rămâneau deschise. Adică schimbai
parola şi atacatorul rămânea înăuntru. Aici se închid — şi ce nu se poate închide dintr-un alt
proces se spune explicit, în loc să se pretindă făcut.

    docker exec -it webterm-app-1 python3 -m app.admin list
    docker exec -it webterm-app-1 python3 -m app.admin passwd you@example.com
    docker exec -it webterm-app-1 python3 -m app.admin disable-2fa you@example.com
    docker exec -it webterm-app-1 python3 -m app.admin logout-all you@example.com
    docker exec -it webterm-app-1 python3 -m app.admin roles you@example.com
    docker exec -it webterm-app-1 python3 -m app.admin promote you@example.com
    docker exec -it webterm-app-1 python3 -m app.admin sso-only someone@example.com [--force]
    docker exec webterm-app-1 python3 -m app.admin health [--json] [--all] [--wait S --newer-than T]
    docker exec -u webterm webterm-app-1 python3 -m app.admin vacuum

`promote` (3.6) e calea break-glass a rolurilor: face contul Owner peste toată flota. Cine are
shell pe server are deja DB-ul şi cheia seifului, deci comanda nu acordă nimic nou — doar
repară corect o instalare în care nimeni nu mai e Owner (ex. un restore parţial).

`sso-only` (3.6.5) face din server exact ce face „Scoate parola locală" din Setări: contul nu mai
are parolă locală, passkey-uri, TOTP, coduri de recuperare şi sesiuni — intră doar prin SSO, iar
grupurile lui din IdP încep să-i dea roluri. Refuzat pentru un cont nelegat de SSO şi pentru
ultimul Owner care încă are parolă locală (contul break-glass), în afară de `--force`.
"""
import argparse
import asyncio
import getpass
import sys
import time

from . import config, db, security


async def _find(email: str):
    row = await db.fetchone("SELECT * FROM users WHERE lower(email)=?", email.strip().lower())
    if not row:
        print("no account with that email: %s" % email, file=sys.stderr)
        raise SystemExit(2)
    return row


async def _revoke_everything(user_id: int, why: str) -> None:
    """Tot ce ar putea supravieţui unei rotiri de credenţiale, în acelaşi loc — dacă apare un
    tip nou de acces derivat, aici trebuie adăugat.

    Comanda rulează în ALT proces decât gateway-ul (`docker exec`), deci putem revoca doar ce
    stă în DB. Ferestrele de step-up şi epoca token-urilor de forward trăiesc în memoria
    procesului gateway şi nu se pot atinge de aici — de asta e important că ştergem sesiunile
    web: fără cookie valid, o fereastră de step-up nu mai e accesibilă de nimeni. Biletele de
    forward sunt singurele care chiar supravieţuiesc (HMAC de sine stătător, max 12h) — pentru
    ele repornirea containerului e răspunsul, şi o spunem pe faţă în loc s-o pretindem făcută."""
    await db.execute("DELETE FROM web_sessions WHERE user_id=?", user_id)
    await db.execute("UPDATE sessions SET share_token=NULL, share_expires=NULL"
                     " WHERE share_by_id=?", user_id)
    await db.execute("DELETE FROM replay_opens WHERE link_id IN"
                     " (SELECT id FROM replay_links WHERE user_id=?)", user_id)
    await db.execute("DELETE FROM replay_links WHERE user_id=?", user_id)
    print("· revoked: web sessions, share links and replay links (%s)" % why)
    print("· port-forward tickets live in the gateway's memory (max 12h):"
          " `docker compose restart app` kills them now")


async def _bindings_text(user_id: int) -> str:
    rows = await db.fetchall(
        "SELECT r.key, r.name, b.scope_kind, b.scope_value, b.source FROM role_bindings b"
        " JOIN roles r ON r.id=b.role_id WHERE b.user_id=? ORDER BY b.id", user_id)
    if not rows:
        return "(no access)"
    # rolurile custom (3.6.2) n-au cheie: numele lor, între ghilimele; legăturile SSO marcate
    return ", ".join("%s@%s%s" % (r["key"] or repr(r["name"]),
                                  r["scope_kind"] if r["scope_kind"] == "all"
                                  else "%s:%s" % (r["scope_kind"], r["scope_value"]),
                                  " (sso)" if r["source"] == "sso" else "") for r in rows)


async def _bump_authz_epoch() -> None:
    """Gateway-ul rulează în ALT proces; îi spunem prin DB că legăturile s-au schimbat (bucla
    lui de 60 s citeşte cheia şi invalidează cache-ul de permisiuni + re-verifică socket-urile)."""
    await db.execute(
        "INSERT INTO app_settings(key, value) VALUES('authz_epoch', ?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value", "%.6f" % time.time())


async def cmd_list(_args) -> None:
    rows = await db.fetchall(
        "SELECT u.id, u.email, u.created, u.totp_enabled,"
        " (SELECT COUNT(*) FROM webauthn_credentials c WHERE c.user_id=u.id) AS passkeys,"
        " (SELECT COUNT(*) FROM web_sessions w WHERE w.user_id=u.id AND w.expires > ?) AS live"
        " FROM users u ORDER BY u.created", time.time())
    if not rows:
        print("(no accounts — the instance has not been set up yet)")
        return
    print("%-34s %-6s %-9s %-14s %s" % ("EMAIL", "2FA", "PASSKEYS", "LIVE SESSIONS", "ROLES"))
    for r in rows:
        print("%-34s %-6s %-9d %-14d %s" % (r["email"], "on" if r["totp_enabled"] else "off",
                                            r["passkeys"], r["live"],
                                            await _bindings_text(r["id"])))


async def cmd_roles(args) -> None:
    user = await _find(args.email)
    print("%s: %s" % (user["email"], await _bindings_text(user["id"])))


async def cmd_promote(args) -> None:
    """Owner @ all, idempotent. Auditat în jurnalul aplicaţiei, ca orice schimbare de acces."""
    user = await _find(args.email)
    role = await db.fetchone("SELECT id FROM roles WHERE key='owner'")
    if not role:
        print("the built-in roles are missing — start the gateway once first", file=sys.stderr)
        raise SystemExit(2)
    await db.execute(
        "INSERT OR IGNORE INTO role_bindings(user_id, role_id, scope_kind, scope_value, source,"
        " created) VALUES(?,?,'all','','manual',?)", user["id"], role["id"], time.time())
    await db.execute(
        "INSERT INTO audit_log(ts, actor, ip, method, path, status, detail, actor_id, via)"
        " VALUES(?,?,?,?,?,?,?,?,?)", time.time(), "admin-cli", "-", "CLI", "/admin/promote", 200,
        "promoted %s to Owner @ all hosts (break-glass)" % user["email"], user["id"], "cli")
    await _bump_authz_epoch()
    print("✓ %s is now Owner over all hosts (%s)" % (user["email"], await _bindings_text(user["id"])))
    print("· the running gateway picks this up within about a minute")


def _read_new_password() -> str:
    pw = getpass.getpass("new password: ")
    if len(pw) < 8:
        print("the password must be at least 8 characters", file=sys.stderr)
        raise SystemExit(2)
    if pw != getpass.getpass("repeat: "):
        print("the two entries differ", file=sys.stderr)
        raise SystemExit(2)
    return pw


async def cmd_passwd(args) -> None:
    user = await _find(args.email)
    # Hash-ul se produce cu argon2 al aplicaţiei, cu parametrii ei. De asta comanda trăieşte
    # ÎN imagine şi nu într-un script de pe host: parametrii se pot schimba, iar un hash generat
    # cu altă configuraţie ar fi respins la login fără niciun mesaj util.
    pw_hash = security.hash_password(_read_new_password())
    await db.execute("UPDATE users SET password_hash=?, local_password=1 WHERE id=?",
                     pw_hash, user["id"])
    # 3.6.2: cu o parolă locală, rolurile venite din grupuri SSO pleacă (cine ştie parola nu
    # trebuie să moştenească ce dau grupurile omului) — acelaşi lucru ca în /api/account
    n = (await db.fetchone("SELECT COUNT(*) AS c FROM role_bindings WHERE user_id=? AND source='sso'",
                           user["id"]))["c"]
    if n:
        await db.execute("DELETE FROM role_bindings WHERE user_id=? AND source='sso'", user["id"])
        await _bump_authz_epoch()
        print("· %d SSO-derived role binding(s) removed (an account with a local password gets no "
              "roles from groups)" % n)
    print("✓ password changed for %s" % user["email"])
    await _revoke_everything(user["id"], "password rotated")


async def _owner_ids() -> set:
    return {r["user_id"] for r in await db.fetchall(
        "SELECT DISTINCT b.user_id FROM role_bindings b JOIN roles r ON r.id=b.role_id"
        " WHERE r.key='owner' AND b.scope_kind='all' AND (b.expires IS NULL OR b.expires > ?)",
        time.time())}


async def cmd_sso_only(args) -> None:
    """Acelaşi efect ca „Scoate parola locală" (api.update_account, remove_password), de pe
    server: parola devine un hash aleator (local_password=0), passkey-urile, TOTP-ul, codurile de
    recuperare şi sesiunile pleacă, epoca de autorizare creşte."""
    user = await _find(args.email)
    if not user["sso_subject"]:
        print("%s is not linked to SSO (it has never signed in with SSO): removing its local "
              "password would lock it out. Nothing changed." % user["email"], file=sys.stderr)
        raise SystemExit(2)
    if not config.OIDC_ENABLED and not args.force:
        print("SSO is not configured on this instance (WEBTERM_OIDC_*): an SSO-only account could "
              "not sign in at all. Nothing changed (use --force to do it anyway).", file=sys.stderr)
        raise SystemExit(2)
    owners = await _owner_ids()
    if user["id"] in owners:
        with_pw = 0
        for o in owners - {user["id"]}:
            r = await db.fetchone("SELECT COALESCE(local_password, 1) AS lp FROM users WHERE id=?", o)
            if r is not None and r["lp"]:
                with_pw += 1
        if not with_pw and not args.force:
            print("%s is the last Owner with a local password (the break-glass account). Without "
                  "it, an IdP outage locks every Owner out. Make another account Owner with a "
                  "local password first, or pass --force. Nothing changed." % user["email"],
                  file=sys.stderr)
            raise SystemExit(3)
    locked = security.hash_password(security.new_token())    # nimeni nu-l ştie
    await db.execute(
        "UPDATE users SET password_hash=?, local_password=0, totp_enabled=0,"
        " totp_secret_encrypted=NULL, totp_last_counter=NULL WHERE id=?", locked, user["id"])
    for sql in ("DELETE FROM webauthn_credentials WHERE user_id=?",
                "DELETE FROM recovery_codes WHERE user_id=?",
                "DELETE FROM email_challenges WHERE user_id=?"):
        await db.execute(sql, user["id"])
    await db.execute(
        "INSERT INTO audit_log(ts, actor, ip, method, path, status, detail, actor_id, via)"
        " VALUES(?,?,?,?,?,?,?,?,?)", time.time(), "admin-cli", "-", "CLI", "/admin/sso-only", 200,
        "%s made SSO-only from the server%s: local password, passkeys, 2FA, recovery codes and "
        "sessions removed" % (user["email"], " (--force)" if args.force else ""), user["id"], "cli")
    await _bump_authz_epoch()
    print("✓ %s now signs in with SSO only (local password, passkeys, 2FA and recovery codes "
          "removed)" % user["email"])
    print("· its SSO groups give it roles from its next SSO sign-in")
    await _revoke_everything(user["id"], "account made SSO-only")


async def cmd_disable_2fa(args) -> None:
    user = await _find(args.email)
    await db.execute(
        "UPDATE users SET totp_enabled=0, totp_secret_encrypted=NULL, totp_last_counter=NULL"
        " WHERE id=?", user["id"])
    await db.execute("DELETE FROM recovery_codes WHERE user_id=?", user["id"])
    print("✓ 2FA disabled for %s (enrol it again from Settings → Sign-in & 2FA)" % user["email"])
    # Ferestrele de step-up NU se închid aici: dezactivarea 2FA e ce faci când eşti deja blocat
    # afară, iar a te tăia din propria sesiune în acel moment ar fi exact pe dos.
    await db.execute("DELETE FROM web_sessions WHERE user_id=?", user["id"])
    print("· revoked: web sessions (log in again with the password)")


async def cmd_logout_all(args) -> None:
    user = await _find(args.email)
    await _revoke_everything(user["id"], "requested")
    print("✓ every session and derived link for %s is gone" % user["email"])


def cmd_health(args) -> int:
    """`python3 -m app.admin health` (3.6.8): the System health list as the gateway last stored
    it — the SAME rows Settings → System health shows (one source of truth; upgrade.sh prints
    this). Read-only: the DB is opened `mode=ro`, no migrations, nothing written."""
    import json
    import sqlite3
    from . import syshealth
    deadline = time.time() + max(0, args.wait)

    def load():
        try:
            con = sqlite3.connect("file:%s?mode=ro" % config.DB_PATH, uri=True, timeout=5)
        except sqlite3.Error:
            return None, []
        try:
            con.row_factory = sqlite3.Row
            last = con.execute("SELECT value FROM app_settings WHERE key=?",
                               (syshealth.K_LAST_RUN,)).fetchone()
            rows = [dict(r) for r in con.execute("SELECT * FROM health_checks")]
            return float(last[0]) if last and last[0] else None, rows
        except (sqlite3.Error, ValueError):
            return None, []
        finally:
            con.close()

    last, rows = load()
    while (last is None or last < args.newer_than) and time.time() < deadline:
        time.sleep(2)
        last, rows = load()
    now = time.time()
    views = [syshealth.view(r, now) for r in rows]
    if args.json:
        print(json.dumps({"checked_at": last, "checks": views}, indent=1))
        return 0
    if last is None or not rows:
        print("not checked yet (the gateway runs the checks ~20 s after it starts)")
        return 0
    if args.newer_than and last < args.newer_than:
        print("(results from %d s before this run — the gateway has not re-checked yet)"
              % int(args.newer_than - last))
    shown = [v for v in views if syshealth.RANK.get(v["severity"], 0) >= syshealth.RANK["info"]
             and (args.all or not v["muted"])]
    shown.sort(key=lambda v: (-syshealth.RANK.get(v["severity"], 0), v["id"]))
    if not shown:
        print("all %d checks OK" % len(views))
        return 0
    for v in shown:
        print("[%s] %s%s" % (v["severity"].upper(), v["message"], " (muted)" if v["muted"] else ""))
        why = syshealth.WHY.get(v["why_key"], "")
        if why:
            print("    why: %s" % why)
        rec = syshealth.RECS.get(v["recommendation_key"], "")
        if rec:
            print("    fix: %s" % rec)
        for c in v["commands"]:
            print("    $ %s" % c["text"])
        if v["doc"]:
            print("    see: %s" % v["doc"])
    hidden = len([v for v in views if v["muted"]]) if not args.all else 0
    if hidden:
        print("(%d muted — `health --all` shows them)" % hidden)
    return 0


async def cmd_vacuum(_args) -> None:
    """`python3 -m app.admin vacuum` (3.6.8): compact the database (System health "db.size").
    VACUUM takes an exclusive lock while it runs — seconds on a typical instance — so the gateway
    may answer slowly meanwhile; it is never run automatically."""
    row = await db.fetchone("PRAGMA page_count")
    size = await db.fetchone("PRAGMA page_size")
    before = int(row[0]) * int(size[0])
    print("compacting %s (%.1f MB)…" % (config.DB_PATH, before / 1024 ** 2))
    await db.execute("VACUUM")
    row = await db.fetchone("PRAGMA page_count")
    after = int(row[0]) * int(size[0])
    print("✓ %.1f MB → %.1f MB" % (before / 1024 ** 2, after / 1024 ** 2))


async def main() -> None:
    ap = argparse.ArgumentParser(
        prog="python3 -m app.admin",
        description="WebTerm recovery from the server (see docs/RUNBOOK.md §5).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="accounts, their factors and live sessions")
    p = sub.add_parser("passwd", help="set a new password (prompts; never on the command line)")
    p.add_argument("email")
    p = sub.add_parser("disable-2fa", help="turn TOTP off when the phone and the codes are gone")
    p.add_argument("email")
    p = sub.add_parser("logout-all", help="kill every web session and share link of the account")
    p.add_argument("email")
    p = sub.add_parser("roles", help="show the account's role bindings")
    p.add_argument("email")
    p = sub.add_parser("promote", help="make the account Owner over all hosts (break-glass)")
    p.add_argument("email")
    p = sub.add_parser("sso-only", help="remove the local password, passkeys and 2FA of an SSO "
                                        "account: it signs in with SSO only")
    p.add_argument("email")
    p.add_argument("--force", action="store_true",
                   help="also for the last Owner with a local password, or with SSO not configured")
    p = sub.add_parser("health", help="the System health list, as Settings shows it (read-only)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--all", action="store_true", help="include muted checks")
    p.add_argument("--wait", type=float, default=0, help="seconds to wait for a fresh run")
    p.add_argument("--newer-than", type=float, default=0, dest="newer_than",
                   help="wait (up to --wait) for a run after this epoch time")
    sub.add_parser("vacuum", help="compact the database (locks it for the duration)")
    args = ap.parse_args()

    if args.cmd == "health":
        raise SystemExit(cmd_health(args))
    await db.connect()
    try:
        await {"list": cmd_list, "passwd": cmd_passwd,
               "disable-2fa": cmd_disable_2fa, "logout-all": cmd_logout_all,
               "roles": cmd_roles, "promote": cmd_promote,
               "sso-only": cmd_sso_only, "vacuum": cmd_vacuum}[args.cmd](args)
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
