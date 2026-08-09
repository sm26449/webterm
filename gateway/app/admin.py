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
"""
import argparse
import asyncio
import getpass
import sys
import time

from . import db, security


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
    print("· revoked: web sessions and share links (%s)" % why)
    print("· port-forward tickets live in the gateway's memory (max 12h):"
          " `docker compose restart app` kills them now")


async def cmd_list(_args) -> None:
    rows = await db.fetchall(
        "SELECT u.id, u.email, u.created, u.totp_enabled,"
        " (SELECT COUNT(*) FROM webauthn_credentials c WHERE c.user_id=u.id) AS passkeys,"
        " (SELECT COUNT(*) FROM web_sessions w WHERE w.user_id=u.id AND w.expires > ?) AS live"
        " FROM users u ORDER BY u.created", time.time())
    if not rows:
        print("(no accounts — the instance has not been set up yet)")
        return
    print("%-34s %-6s %-9s %s" % ("EMAIL", "2FA", "PASSKEYS", "LIVE SESSIONS"))
    for r in rows:
        print("%-34s %-6s %-9d %d" % (r["email"], "on" if r["totp_enabled"] else "off",
                                      r["passkeys"], r["live"]))


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
    await db.execute("UPDATE users SET password_hash=? WHERE id=?", pw_hash, user["id"])
    print("✓ password changed for %s" % user["email"])
    await _revoke_everything(user["id"], "password rotated")


async def cmd_disable_2fa(args) -> None:
    user = await _find(args.email)
    await db.execute(
        "UPDATE users SET totp_enabled=0, totp_secret_encrypted=NULL, totp_last_counter=NULL"
        " WHERE id=?", user["id"])
    await db.execute("DELETE FROM recovery_codes WHERE user_id=?", user["id"])
    print("✓ 2FA disabled for %s (enrol it again from Settings → Security)" % user["email"])
    # Ferestrele de step-up NU se închid aici: dezactivarea 2FA e ce faci când eşti deja blocat
    # afară, iar a te tăia din propria sesiune în acel moment ar fi exact pe dos.
    await db.execute("DELETE FROM web_sessions WHERE user_id=?", user["id"])
    print("· revoked: web sessions (log in again with the password)")


async def cmd_logout_all(args) -> None:
    user = await _find(args.email)
    await _revoke_everything(user["id"], "requested")
    print("✓ every session and derived link for %s is gone" % user["email"])


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
    args = ap.parse_args()

    await db.connect()
    try:
        await {"list": cmd_list, "passwd": cmd_passwd,
               "disable-2fa": cmd_disable_2fa, "logout-all": cmd_logout_all}[args.cmd](args)
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
