"""Întărirea step-up-ului (audit 2026-10-05) — regresii HERMETICE, in-process prin ASGI.

Acoperă:
  · fix 2 — deploy-key batch: o ţintă `require_2fa` fără fereastră de step-up e SĂRITĂ cu codul
            stabil `sshkey.targetNeeds2fa`, nu scrisă tăcut; ţinta CU fereastră trece de poartă.
  · fix 3 — TOTP la step-up: un cont cu TOTP activ şi FĂRĂ passkey nu mai deschide fereastra cu
            parola singură (403 `stepup.totp`); codul corect o deschide; un cod reluat e respins.
  · fix 4 — delete_session / revoke_share cer step-up pe un host 2FA (ca `kill`).
  · fix 5 — `stepup_window_is_open` NU gliseză fereastra (spre deosebire de `stepup_window_ok`);
            deblocarea cere factor PROASPĂT (o fereastră veche ţinută în viaţă de trafic nu ajunge).
  · fix 6 — meta-leak: `/api/sessions` cu token ascunde sesiunile hosturilor 2FA; host_sessions
            cere step-up; `/api/audit` redactează detaliul comenzilor de pe hosturi 2FA fără fereastră.
  · fix 11 — `totp/disable` închide ferestrele de step-up (clear_stepup_for).
  · 3.8.1 — după fereastra de 5 min, `/api/sessions` şi split-view-urile păstrează DOAR sesiunile la
            care contul e ataşat deblocat (tabul nu mai dispare); restul hostului, alt cont, un hub
            blocat şi un token rămân ascunse.
"""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, db, security  # noqa: E402
from app import totp as totp_mod  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
from app.main import app  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    # ── fix 5 (unit): is_open citeşte fără să gliseze; window_ok glisează ──
    security._stepup_windows.clear()
    now = time.time()
    security._stepup_windows[(1, 7)] = (now - 10, now + 5)      # expiră curând
    exp_before = security._stepup_windows[(1, 7)][1]
    check("stepup_window_is_open → True pe fereastră validă", security.stepup_window_is_open(1, 7))
    check("stepup_window_is_open NU gliseză (exp neschimbat)",
          security._stepup_windows[(1, 7)][1] == exp_before)
    security.stepup_window_ok(1, 7)
    check("stepup_window_ok (control) CHIAR gliseză",
          security._stepup_windows[(1, 7)][1] > exp_before)
    security._stepup_windows[(1, 7)] = (now - 10, now - 1)      # expirată
    check("is_open → False pe fereastră expirată", not security.stepup_window_is_open(1, 7))
    # fix 5 (unit): deblocarea cere factor PROASPĂT — o fereastră VECHE ţinută vie de trafic
    # (opened_at demult, exp împins de sliding) NU e „fresh", deci _require_fresh_factor ar cere
    # un factor. stepup_window_fresh e exact verificarea pe care se bazează.
    security._stepup_windows[(1, 7)] = (now - 600, now + 200)   # veche, dar încă deschisă
    check("fereastră veche dar deschisă NU e fresh (unlock ar cere factor)",
          not security.stepup_window_fresh(1, 7) and security.stepup_window_is_open(1, 7))
    security._stepup_windows.clear()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "a@b.co", "password": "parolabuna1",
                                             "setup_token": "test-setup"})
        check("cont creat", r.status_code == 200)
        uid = (await db.fetchone("SELECT id FROM users LIMIT 1"))["id"]
        hid2fa = (await c.post("/api/hosts", json={"name": "critic", "require_2fa": True})).json()["id"]

        # ── fix 3: TOTP la step-up ───────────────────────────────────────────
        secret = totp_mod.new_secret()
        await db.execute("UPDATE users SET totp_enabled=1, totp_secret_encrypted=? WHERE id=?",
                         security.encrypt_secret(secret), uid)
        security.clear_stepup_for(uid)
        r = await c.post(f"/api/hosts/{hid2fa}/stepup", json={"stepup_password": "parolabuna1"})
        check("TOTP activ fără passkey: parola SINGURĂ nu deschide fereastra (403 stepup.totp)",
              r.status_code == 403 and r.json().get("code") == "stepup.totp", r.text[:140])
        code = totp_mod.generate(secret)
        r = await c.post(f"/api/hosts/{hid2fa}/stepup", json={"stepup_totp": code})
        check("TOTP corect deschide fereastra", r.status_code == 200, r.text[:140])
        r = await c.post(f"/api/hosts/{hid2fa}/stepup", json={"stepup_totp": code})
        check("TOTP reluat (replay) e respins (403 stepup.totp)",
              r.status_code == 403 and r.json().get("code") == "stepup.totp", r.text[:140])

        # ── fix 4: delete_session + revoke_share cer step-up pe host 2FA ──────
        sid = "a" * 32   # id de sesiune valid (hex), ca archive_transcript să nu crape
        await db.execute(
            "INSERT INTO sessions(id,host_id,title,state,created,rows,cols,share_token,share_expires)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            sid, hid2fa, "t", "closed", time.time(), 24, 80, security.sha256_hex("x"),
            time.time() + 3600)
        security.clear_stepup_for(uid)
        # starea share-ului (3.5.3): pe host 2FA fără fereastră → „inactiv" (meta-leak), iar
        # cu fereastră → activ, FĂRĂ url/token în răspuns (token-ul e hash-uit, nu se reconstruieşte)
        r = await c.get(f"/api/sessions/{sid}/share")
        check("share_state pe host 2FA fără fereastră → inactiv",
              r.status_code == 200 and r.json() == {"active": False}, r.text[:120])
        security.open_stepup_window(uid, hid2fa)
        r = await c.get(f"/api/sessions/{sid}/share")
        j = r.json() if r.status_code == 200 else {}
        check("share_state cu fereastră → activ, fără url/token",
              j.get("active") is True and "url" not in j and "token" not in j
              and security.sha256_hex("x") not in r.text, r.text[:160])
        security.clear_stepup_for(uid)
        r = await c.request("DELETE", f"/api/sessions/{sid}/share")
        check("revoke_share pe host 2FA fără fereastră → 403", r.status_code == 403, r.text[:120])
        r = await c.request("DELETE", f"/api/sessions/{sid}")
        check("delete_session pe host 2FA fără fereastră → 403", r.status_code == 403, r.text[:120])
        security.open_stepup_window(uid, hid2fa)
        r = await c.request("DELETE", f"/api/sessions/{sid}/share")
        check("revoke_share cu fereastră deschisă → 200", r.status_code == 200, r.text[:120])
        r = await c.get(f"/api/sessions/{sid}/share")
        check("share_state după revocare → inactiv", r.json() == {"active": False}, r.text[:120])
        r = await c.request("DELETE", f"/api/sessions/{sid}")
        check("delete_session cu fereastră deschisă → 200", r.status_code == 200, r.text[:120])

        # ── fix 6: host_sessions cere step-up ────────────────────────────────
        security.clear_stepup_for(uid)
        r = await c.get(f"/api/hosts/{hid2fa}/sessions")
        check("host_sessions pe host 2FA fără fereastră → 403", r.status_code == 403, r.text[:120])
        security.open_stepup_window(uid, hid2fa)
        r = await c.get(f"/api/hosts/{hid2fa}/sessions")
        check("host_sessions cu fereastră → 200", r.status_code == 200, r.text[:120])

        # ── 3.8.1: tabul terminalului 2FA nu dispare după fereastra de 5 min ──
        # Fereastra nu glisează pe tastare; lista păstrează DOAR sesiunile la care contul e ataşat
        # deblocat (client-owner), nu restul hostului, nu pentru alt cont şi nu pentru un token.
        from types import SimpleNamespace as NS
        from app import core
        s_mine, s_other, s_locked, s_foreign = ("b" * 32, "c" * 32, "d" * 32, "e" * 32)
        s_watch, s_guest = "f" * 32, "1" * 32
        all_sids = (s_mine, s_other, s_locked, s_foreign, s_watch, s_guest)
        for s in all_sids:
            await db.execute("INSERT INTO sessions(id,host_id,title,state,created,rows,cols)"
                             " VALUES(?,?,?,?,?,?,?)", s, hid2fa, "t-" + s[0], "live",
                             time.time(), 24, 80)

        # excepţia e legată de AUTENTIFICARE (hash-ul cookie-ului), nu de cont (review M1)
        th_mine = security.sha256_hex(c.cookies.get(security.COOKIE_NAME))
        tok2 = await security.create_web_session(uid)        # al doilea login al ACELUIAŞI cont
        th_other = security.sha256_hex(tok2)

        def cli(user_id, locked=False, owner=True, th=th_mine, writable=True):
            return NS(is_owner=owner, user_id=user_id, locked=locked, web_tok_hash=th,
                      writable=writable)

        def hub(clients, locked=False, closed=False):
            return NS(locked=locked, closed=closed, clients=list(clients), agent_offset=0, last_output_at=None)
        core.hubs[s_mine] = hub([cli(uid)])
        core.hubs[s_locked] = hub([cli(uid)], locked=True)          # plafonul de 60 min a lovit
        core.hubs[s_foreign] = hub([cli(uid + 999), cli(None, owner=False)])
        core.hubs[s_watch] = hub([cli(uid, writable=False)])     # watcher read-only: inclus
        core.hubs[s_guest] = hub([cli(uid, owner=False)])        # client ne-autentificat: exclus
        c2 = httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN,
                               cookies={security.COOKIE_NAME: tok2})
        try:
            security.clear_stepup_for(uid)
            ids = {s["id"] for s in (await c.get("/api/sessions")).json()}
            check("fără fereastră: sesiunea ataşată deblocată rămâne în listă", s_mine in ids, str(ids))
            check("fără fereastră: restul sesiunilor hostului 2FA rămân ascunse",
                  not ids & {s_other, s_locked, s_foreign, s_guest}, str(ids))
            check("fără fereastră: watcher read-only al aceluiaşi login rămâne în listă",
                  s_watch in ids, str(ids))
            check("client ne-owner (cli owner=False) al contului → ascunsă", s_guest not in ids, str(ids))
            r = await c2.get("/api/sessions")
            ids2 = {s["id"] for s in r.json()} if r.status_code == 200 else {"?"}
            check("altă autentificare a aceluiaşi cont: nicio sesiune 2FA ataşată",
                  r.status_code == 200 and not ids2 & set(all_sids), r.text[:160])
            check("attached_unlocked_sids fără hash → nimic (fail-closed)",
                  core.attached_unlocked_sids(uid, None) == set())
            acc = await api._split_pane_access({"id": uid}, [s_mine, s_other, s_locked], th_mine)
            check("split-view: panoul ataşat deblocat rămâne vizibil, restul nu",
                  acc == {s_mine: True, s_other: False, s_locked: False}, str(acc))
            acc = await api._split_pane_access({"id": uid}, [s_mine, s_watch], th_other)
            check("split-view, alt login: panourile ataşate de primul login rămân ascunse",
                  acc == {s_mine: False, s_watch: False}, str(acc))
            # rutele: POST şi PATCH cu fereastra închisă
            r = await c.post("/api/split-views", json={"name": "sv", "panes": [s_mine, s_watch]})
            check("split-view POST fără fereastră, acelaşi login, panouri ataşate → 200",
                  r.status_code == 200 and r.json().get("panes") == [s_mine, s_watch], r.text[:160])
            sv_id = r.json().get("id") if r.status_code == 200 else None
            r = await c2.post("/api/split-views", json={"name": "sv2", "panes": [s_mine, s_watch]})
            check("split-view POST fără fereastră, alt login → refuzat", r.status_code >= 400, r.text[:160])
            r = await c.patch(f"/api/split-views/{sv_id}", json={"ratio": 0.4})
            check("split-view PATCH fără fereastră, acelaşi login → 200", r.status_code == 200, r.text[:160])
            r = await c.post("/api/split-views", json={"name": "sv3", "panes": [s_mine, s_other]})
            check("split-view POST cu un panou neataşat al hostului 2FA → refuzat",
                  r.status_code >= 400, r.text[:160])
            # acelaşi split-view, văzut din alt login: panourile sunt ascunse → PATCH refuzat (409)
            await db.execute("UPDATE split_views SET user_id=? WHERE id=?", uid, sv_id)
            r = await c2.patch(f"/api/split-views/{sv_id}", json={"ratio": 0.3})
            check("split-view PATCH fără fereastră, alt login → 409 splitview.hiddenPanes",
                  r.status_code == 409 and r.json().get("code") == "splitview.hiddenPanes", r.text[:160])
            r = await c2.get("/api/split-views")
            svs = r.json().get("split_views", []) if r.status_code == 200 else []
            check("split-view GET, alt login: panourile ataşate de primul login ascunse",
                  all(not (set(v["panes"]) & {s_mine, s_watch}) for v in svs), r.text[:160])
            await db.execute("DELETE FROM split_views WHERE id=?", sv_id)
            core.hubs[s_mine] = hub([cli(uid, locked=True)])         # clientul propriu blocat
            ids = {s["id"] for s in (await c.get("/api/sessions")).json()}
            check("client propriu blocat → ascunsă", s_mine not in ids, str(ids))
            core.hubs[s_mine] = hub([cli(uid)], closed=True)
            ids = {s["id"] for s in (await c.get("/api/sessions")).json()}
            check("hub închis → ascunsă", s_mine not in ids, str(ids))
            core.hubs[s_mine] = hub([cli(uid)])
            security.open_stepup_window(uid, hid2fa)
            ids = {s["id"] for s in (await c.get("/api/sessions")).json()}
            check("cu fereastră: toate sesiunile hostului (comportament neschimbat)",
                  set(all_sids) <= ids, str(ids))
            # crearea tokenului cere TOTP (codul de mai sus e deja consumat): oprit doar pe durata
            # creării, repornit imediat (fix 11 de mai jos are nevoie de el)
            await db.execute("UPDATE users SET totp_enabled=0 WHERE id=?", uid)
            r = await c.post("/api/tokens", json={"name": "lista", "scopes": ["read"], "days": 1,
                                                  "current_password": "parolabuna1"})
            await db.execute("UPDATE users SET totp_enabled=1 WHERE id=?", uid)
            tok = r.json().get("token", "") if r.status_code == 200 else ""
            check("token de citire creat", bool(tok), r.text[:140])
            async with httpx.AsyncClient(transport=transport, base_url="http://t",
                                         headers={"Authorization": "Bearer " + tok}) as t:
                r = await t.get("/api/sessions")
                ids = {s["id"] for s in r.json()} if r.status_code == 200 else {"?"}
            check("token: nicio sesiune a hostului 2FA, nici cea ataşată de creator",
                  not ids & set(all_sids), r.text[:160])
        finally:
            await c2.aclose()
            for s in all_sids:
                core.hubs.pop(s, None)
            await db.execute("DELETE FROM sessions WHERE id IN (%s)" % ",".join("?" * len(all_sids)),
                             *all_sids)

        # ── fix 6: /api/audit redactează comenzile de pe hosturi 2FA fără fereastră ──
        await db.execute(
            "INSERT INTO audit_log(ts, actor, ip, method, path, status, detail)"
            " VALUES(?,?,?,?,?,?,?)",
            time.time(), "a@b.co", "1.2.3.4", "POST", f"/api/hosts/{hid2fa}/run", 200,
            "cmd: cat /etc/shadow")
        security.clear_stepup_for(uid)
        entries = (await c.get("/api/audit")).json()["entries"]
        hit = next((e for e in entries if e["path"] == f"/api/hosts/{hid2fa}/run"), None)
        check("audit: comanda de pe host 2FA e redactată fără fereastră",
              hit is not None and "cat /etc/shadow" not in (hit["detail"] or "")
              and "redactat" in (hit["detail"] or ""), str(hit))
        security.open_stepup_window(uid, hid2fa)
        entries = (await c.get("/api/audit")).json()["entries"]
        hit = next((e for e in entries if e["path"] == f"/api/hosts/{hid2fa}/run"), None)
        check("audit: cu fereastră deschisă, comanda e vizibilă",
              hit is not None and "cat /etc/shadow" in (hit["detail"] or ""), str(hit))

        # ── fix 11: totp/disable închide ferestrele de step-up ───────────────
        security.open_stepup_window(uid, hid2fa)
        # resetăm contorul anti-replay ca să putem folosi un cod valid ACUM (cel curent a fost deja
        # consumat de testul fix 3); în producţie userul ar aştepta pasul următor de 30s.
        await db.execute("UPDATE users SET totp_last_counter=NULL WHERE id=?", uid)
        dcode = totp_mod.generate(secret)
        r = await c.post("/api/totp/disable",
                         json={"current_password": "parolabuna1", "totp_code": dcode})
        check("totp/disable reuşeşte", r.status_code == 200, r.text[:140])
        check("totp/disable a închis ferestrele de step-up (clear_stepup_for)",
              not security.stepup_window_is_open(uid, hid2fa))

        # ── fix 2: deploy-key batch — ţintă 2FA fără fereastră e SĂRITĂ ───────
        src = (await c.post("/api/hosts", json={"name": "sursa"})).json()["id"]
        tA = (await c.post("/api/hosts", json={"name": "tintaA", "require_2fa": True})).json()["id"]
        tB = (await c.post("/api/hosts", json={"name": "tintaB", "require_2fa": True})).json()["id"]
        await db.execute(
            "INSERT INTO ssh_keys(host_id, public_key, fingerprint, comment, created, created_by)"
            " VALUES(?,?,?,?,?,?)",
            src, "ssh-ed25519 AAAAdummy webterm-deploy", "SHA256:dummy", "webterm-deploy",
            time.time(), "a@b.co")
        security.clear_stepup_for(uid)
        security.open_stepup_window(uid, src)        # factor proaspăt pe SURSĂ (ruta batch-ului)
        security.open_stepup_window(uid, tB)         # fereastra ţintei B, dar NU şi a lui A
        r = await c.post(f"/api/hosts/{src}/deploy-key/deploy-batch",
                         json={"target_host_ids": [tA, tB], "confirmed": True})
        check("deploy-batch răspunde 200 (rezultate per-ţintă)", r.status_code == 200, r.text[:160])
        res = {x["target_host_id"]: x for x in r.json().get("results", [])}
        check("ţinta 2FA FĂRĂ fereastră e sărită cu sshkey.targetNeeds2fa",
              res.get(tA, {}).get("code") == "sshkey.targetNeeds2fa", str(res.get(tA)))
        check("ţinta 2FA CU fereastră trece de poartă (eşuează abia la host offline)",
              res.get(tB, {}).get("code") != "sshkey.targetNeeds2fa", str(res.get(tB)))

    await db.close()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
