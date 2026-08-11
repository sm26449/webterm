"""2FA step-up (Faza 2): logica grant-urilor + poarta server-side din
create_session (host cu require_2fa e blocat fără grant; un grant valid
deblochează; grant-ul e single-use). Rulează in-process prin ASGI."""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
# Testăm calea de grant (passkey), care e activă DOAR când WebAuthn e disponibil —
# adică pe un host cu domeniu sau `localhost` (nu IP). Forțăm localhost ca testul să fie
# hermetic indiferent de WEBTERM_PUBLIC_URL din mediul CI (un IP ar dezactiva WebAuthn →
# poarta ar cere parolă în loc de grant, iar check-ul de grant ar da 403 fals).
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, security  # noqa: E402

# Middleware-ul `csrf_guard` cere `Origin` pe metodele care schimbă ceva şi refuză
# lipsa lui (ca `_origin_ok` pentru WebSocket). Testele imită un BROWSER, deci trimit
# antetul; fără el ar testa o cale pe care niciun browser n-o produce.
_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0


def check(name, cond):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


async def main():
    # ── unit: issue / consume / single-use / binding / expiry ──
    g = security.issue_stepup_grant(1, 7)
    check("grant valid se consumă o dată", security.consume_stepup_grant(g, 1, 7))
    check("grant e single-use (a doua oară eșuează)", not security.consume_stepup_grant(g, 1, 7))
    g2 = security.issue_stepup_grant(1, 7)
    check("grant legat de host: alt host respins", not security.consume_stepup_grant(g2, 1, 9))
    g3 = security.issue_stepup_grant(1, 7)
    check("grant legat de user: alt user respins", not security.consume_stepup_grant(g3, 2, 7))
    g4 = security.issue_stepup_grant(1, 7)
    security._stepup_grants[g4] = (1, 7, time.time() - 1)   # expirat
    check("grant expirat respins", not security.consume_stepup_grant(g4, 1, 7))
    check("grant inexistent respins", not security.consume_stepup_grant("nope", 1, 7))

    # ── fereastra de step-up: sliding la folosire, mărginit de un plafon absolut ──
    security._stepup_windows.clear()
    now = time.time()
    security.open_stepup_window(1, 7)
    security._stepup_windows[(1, 7)] = (now, now + 5)      # deschisă acum, aproape de expirare
    check("fereastra validă → ok", security.stepup_window_ok(1, 7))
    check("fereastra s-a prelungit la folosire (sliding)",
          security._stepup_windows[(1, 7)][1] > time.time() + 100)
    # plafon absolut: deschisă cu mult timp în urmă → sliding-ul NU o duce peste opened_at+MAX
    security._stepup_windows[(1, 7)] = (now - security.STEPUP_WINDOW_MAX + 10, now + 5)
    security.stepup_window_ok(1, 7)
    check("sliding-ul nu depășește plafonul absolut (opened_at + MAX)",
          security._stepup_windows[(1, 7)][1] <= now - security.STEPUP_WINDOW_MAX + 10 + security.STEPUP_WINDOW_MAX + 1)
    security._stepup_windows[(1, 7)] = (now - 10, now - 1)  # expirată
    check("fereastra expirată → nu ok", not security.stepup_window_ok(1, 7))
    security._stepup_windows.clear()

    # ── poarta din create_session, in-process ──
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1", "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200)
        # host cu 2FA (agent — nu contează, testăm poarta înainte de conectare)
        r = await c.post("/api/hosts", json={"name": "h2fa", "require_2fa": True})
        hid = r.json()["id"]
        uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]

        security.clear_stepup_for(uid)
        r = await c.post(f"/api/hosts/{hid}/sessions", json={})
        check("conectare FĂRĂ grant → 403 (2FA cerut)", r.status_code == 403)

        # H1: NU doar sesiunea — și acțiunile de host (run/fs/update) sunt gate-uite
        r = await c.get(f"/api/hosts/{hid}/fs?path=~")
        check("fs FĂRĂ step-up → 403 (H1)", r.status_code == 403)
        r = await c.post(f"/api/hosts/{hid}/run", json={"command": "id"})
        check("run FĂRĂ step-up → 403 (H1)", r.status_code == 403)

        grant = security.issue_stepup_grant(uid, hid)
        r = await c.post(f"/api/hosts/{hid}/sessions", json={"stepup_grant": grant})
        # a trecut de poartă → eșuează mai departe (agent offline = 409), NU 403
        check("conectare CU grant valid → trece de poartă (nu 403)", r.status_code != 403)

        # după un step-up reușit se deschide o FEREASTRĂ pe host (ca `sudo`): acțiunile
        # ulterioare trec fără un grant nou, cât timp fereastra e validă.
        r = await c.get(f"/api/hosts/{hid}/fs?path=~")
        check("în fereastra de step-up → fs fără grant nou (nu 403)", r.status_code != 403)
        r = await c.post(f"/api/hosts/{hid}/sessions", json={})
        check("în fereastra de step-up → sesiune fără grant nou (nu 403)", r.status_code != 403)

        # grant single-use la nivel de endpoint: cu fereastra ÎNCHISĂ, un grant deja
        # consumat nu mai deblochează.
        grant2 = security.issue_stepup_grant(uid, hid)
        await c.post(f"/api/hosts/{hid}/sessions", json={"stepup_grant": grant2})  # consumă + deschide fereastra
        security.clear_stepup_for(uid)                                             # închide fereastra
        r = await c.post(f"/api/hosts/{hid}/sessions", json={"stepup_grant": grant2})
        check("grant refolosit (fereastră închisă) → 403 (single-use)", r.status_code == 403)

        # GAP-fix: pe un host 2FA dedicat — dezactivarea 2FA + porțile paralele cer step-up
        security.clear_stepup_for(uid)
        r = await c.post("/api/hosts", json={"name": "gap", "require_2fa": True})
        hidg = r.json()["id"]
        r = await c.post(f"/api/hosts/{hidg}/require-2fa", json={"enabled": False})
        check("dezactivare 2FA fără step-up → 403", r.status_code == 403)
        row = await db.fetchone("SELECT require_2fa FROM hosts WHERE id=?", hidg)
        check("2FA rămâne activ după 403", bool(row["require_2fa"]))
        g_dis = security.issue_stepup_grant(uid, hidg)
        r = await c.post(f"/api/hosts/{hidg}/require-2fa", json={"enabled": False, "stepup_grant": g_dis})
        check("dezactivare 2FA CU step-up → 200", r.status_code == 200)
        # renew_enroll (provisioning) e gate-uit; create_forward NU (config, nu pivotul — vezi api.py)
        security.clear_stepup_for(uid)
        await c.post(f"/api/hosts/{hidg}/require-2fa", json={"enabled": True, "stepup_grant": security.issue_stepup_grant(uid, hidg)})
        security.clear_stepup_for(uid)
        r = await c.post(f"/api/hosts/{hidg}/enroll", json={})
        check("renew_enroll pe host 2FA fără step-up → 403", r.status_code == 403)

        # host fără 2FA nu cere nimic
        r = await c.post("/api/hosts", json={"name": "plain"})
        hid2 = r.json()["id"]
        r = await c.post(f"/api/hosts/{hid2}/sessions", json={})
        check("host fără 2FA → nu cere grant (nu 403)", r.status_code != 403)

        # toggle require_2fa
        r = await c.post(f"/api/hosts/{hid2}/require-2fa", json={"enabled": True})
        r = await c.post(f"/api/hosts/{hid2}/sessions", json={})
        check("după toggle 2FA on → conectare blocată fără grant", r.status_code == 403)

        # ── istoricul de comenzi respectă aceeaşi graniţă ca transcriptul şi căutarea ──
        # `command_history` conţine comenzile EXECUTATE şi cwd-ul. Toate celelalte citiri de
        # conţinut (`/transcript`, `/preview`, `/search`, `/agent-log`) cer o fereastră de
        # step-up pe hosturile cu `require_2fa`; asta nu o cerea, deci un cookie furat citea de
        # pe un host „cere 2FA" exact ce restul refuzau. Filtrarea e TĂCUTĂ, ca la `/api/search`.
        await db.execute(
            "INSERT INTO command_history(host_id, host_name, command, source, created)"
            " VALUES(?,?,?,?,?)", hid2, "critic", "cat /etc/shadow", "session", 1.0)
        # host CHIAR normal: `hid` şi `hid2` cer amândouă 2FA, deci nu pot proba „se vede"
        hidn = (await c.post("/api/hosts", json={"name": "fara-2fa"})).json()["id"]
        await db.execute(
            "INSERT INTO command_history(host_id, host_name, command, source, created)"
            " VALUES(?,?,?,?,?)", hidn, "normal", "uptime", "session", 2.0)
        rows = (await c.get("/api/history")).json()
        cmds = {r["command"] for r in rows}
        check("istoricul ASCUNDE comenzile de pe hostul 2FA fără step-up",
              "cat /etc/shadow" not in cmds)
        check("…dar arată în continuare hosturile normale", "uptime" in cmds)
        check("filtrarea e tăcută (200, nu 403 — altfel devine oracol)",
              (await c.get("/api/history")).status_code == 200)

        # ── jurnalul de audit nu e accesibil cu un token de automatizare ──
        # `detail` conţine textul complet al comenzilor şi interogările de căutare.
        import inspect as _i
        sig = str(_i.signature(api.audit_list))
        check("/api/audit cere require_user, nu require_scope",
              "require_user" in sig and "require_scope" not in sig)

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
