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
        r = await c.request("DELETE", f"/api/sessions/{sid}/share")
        check("revoke_share pe host 2FA fără fereastră → 403", r.status_code == 403, r.text[:120])
        r = await c.request("DELETE", f"/api/sessions/{sid}")
        check("delete_session pe host 2FA fără fereastră → 403", r.status_code == 403, r.text[:120])
        security.open_stepup_window(uid, hid2fa)
        r = await c.request("DELETE", f"/api/sessions/{sid}/share")
        check("revoke_share cu fereastră deschisă → 200", r.status_code == 200, r.text[:120])
        r = await c.request("DELETE", f"/api/sessions/{sid}")
        check("delete_session cu fereastră deschisă → 200", r.status_code == 200, r.text[:120])

        # ── fix 6: host_sessions cere step-up ────────────────────────────────
        security.clear_stepup_for(uid)
        r = await c.get(f"/api/hosts/{hid2fa}/sessions")
        check("host_sessions pe host 2FA fără fereastră → 403", r.status_code == 403, r.text[:120])
        security.open_stepup_window(uid, hid2fa)
        r = await c.get(f"/api/hosts/{hid2fa}/sessions")
        check("host_sessions cu fereastră → 200", r.status_code == 200, r.text[:120])

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
