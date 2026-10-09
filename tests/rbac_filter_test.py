"""Listele şi agregatele trans-host se filtrează TĂCUT după rol (3.6, §A.6.3).

Două foldere (`prod` cu host A, `lab` cu host B) şi doi oameni: un Operator pe `prod` şi un
Viewer pe host B. Fiecare trebuie să vadă EXACT partea lui — sesiuni, istoric, căutare, audit,
alerte, status, rezumatul de securitate, aplicaţii, share-uri, tokenuri, conturi — fără 403
(care ar fi un oracol) şi fără să afle câte lucruri există dincolo de scope (numerele mint
altfel). Căutarea e verificată şi pe CALEA de execuţie: transcripturile din afara scope-ului nu
sunt nici măcar deschise (filtrul e în SQL, înainte de citire — §A.11.12).
"""
import asyncio
import time

import rbac_util as U
from app import alert_history, audit, authz, core, db, email_alerts

check = U.Checker()


async def main():
    await U.boot()
    owner = await U.owner_client()
    a = await U.add_host(owner, "alpha", folder="prod")
    b = await U.add_host(owner, "beta", folder="lab")
    op_id = await U.add_user("op@x.co", bindings=[("operator", "folder", "prod")])
    vb_id = await U.add_user("vb@x.co", bindings=[("viewer", "host", b)])
    nob_id = await U.add_user("nob@x.co")
    op, vb, nob = await U.login("op@x.co"), await U.login("vb@x.co"), await U.login("nob@x.co")

    sa = await U.add_session(a, state="live", created_by=op_id)
    sb = await U.add_session(b, state="closed")
    await db.execute("UPDATE sessions SET title='needle A' WHERE id=?", sa)
    await db.execute("UPDATE sessions SET title='needle B' WHERE id=?", sb)

    # ── hosturi + status ─────────────────────────────────────────────────────────────────
    ids = lambda r: sorted(h["id"] for h in r.json())          # noqa: E731
    check("Owner vede ambele hosturi", ids(await owner.get("/api/hosts")) == sorted([a, b]))
    check("Operator@prod vede DOAR A", ids(await op.get("/api/hosts")) == [a])
    check("Viewer@host:B vede DOAR B", ids(await vb.get("/api/hosts")) == [b])
    r = await nob.get("/api/hosts")
    check("fără legături: lista e GOALĂ (200, nu 403)", r.status_code == 200 and r.json() == [])
    st = (await op.get("/api/status")).json()
    check("status: totalul de hosturi numără doar ce vezi (fără oracol de mărime)",
          st["hosts"]["total"] == 1, str(st["hosts"]))
    check("status: sesiunile numără doar hosturile tale", st["sessions"]["live"] == 1,
          str(st["sessions"]))
    check("status: discul/sănătatea gateway-ului doar cu security.view",
          st["storage"] is None and st["gateway"] is None)
    st_o = (await owner.get("/api/status")).json()
    check("status Owner: neschimbat (totaluri + disc + sănătate)",
          st_o["hosts"]["total"] == 2 and st_o["storage"] is not None and st_o["gateway"] is not None)
    st_n = (await nob.get("/api/status")).json()
    check("status fără legături: zero peste tot", st_n["hosts"]["total"] == 0
          and st_n["sessions"]["live"] == 0 and st_n["sessions"]["closed"] == 0)

    # ── sesiuni ──────────────────────────────────────────────────────────────────────────
    sids = lambda r: {s["id"] for s in r.json()}               # noqa: E731
    check("sesiuni: Operator@prod doar pe A", sids(await op.get("/api/sessions")) == {sa})
    check("sesiuni: Viewer@B doar pe B", sids(await vb.get("/api/sessions")) == {sb})
    check("sesiuni: Owner pe ambele", sids(await owner.get("/api/sessions")) == {sa, sb})
    check("sesiuni: fără legături → []", (await nob.get("/api/sessions")).json() == [])

    # ── căutare: filtrul e ÎNAINTE de citirea transcripturilor ───────────────────────────
    seen = []
    orig = core.search_transcripts

    def spy(rows, q):
        seen.extend(r["id"] for r in rows)
        return orig(rows, q)
    core.search_transcripts = spy
    try:
        r = await op.get("/api/search", params={"q": "needle"})
        got = {x["id"] for x in r.json()["sessions"]}
        check("căutare: Operator@prod găseşte doar A", got == {sa}, str(got))
        check("căutare: transcripturile din afara scope-ului NU sunt nici măcar deschise",
              sb not in seen, str(seen))
        seen.clear()
        r = await nob.get("/api/search", params={"q": "needle"})
        check("căutare fără legături: nimic, şi nimic citit", r.json()["sessions"] == [] and not seen)
    finally:
        core.search_transcripts = orig

    # ── istoric ──────────────────────────────────────────────────────────────────────────
    for hid, cmd in ((a, "echo A"), (b, "echo B"), (None, "echo NULL")):
        await db.execute("INSERT INTO command_history(host_id, host_name, command, source, created)"
                         " VALUES(?,?,?,?,?)", hid, "", cmd, "session", time.time())
    cmds = lambda r: {x["command"] for x in r.json()}          # noqa: E731
    check("istoric: Operator@prod doar comenzile de pe A",
          cmds(await op.get("/api/history")) == {"echo A"})
    check("istoric: rândurile FĂRĂ host doar cu audit.view (Owner)",
          cmds(await owner.get("/api/history")) == {"echo A", "echo B", "echo NULL"})
    check("istoric: fără legături → nimic", cmds(await nob.get("/api/history")) == set())
    r = await op.post("/api/history", json={"host_id": b, "command": "forged"})
    check("istoric: scrierea pe un host invizibil → 404 (nu se poate injecta)",
          r.status_code == 404, "%s %s" % (r.status_code, r.text[:100]))
    r = await vb.post("/api/history", json={"host_id": b, "command": "x"})
    check("istoric: Viewer (fără shell) nu scrie istoric → 403", r.status_code == 403
          and U.code(r) == "authz.denied")
    r = await op.post("/api/history", json={"host_id": a, "command": "real"})
    row = await db.fetchone("SELECT user_id FROM command_history WHERE command='real'")
    check("istoric: rândul poartă contul care l-a scris (user_id)", r.status_code == 200
          and row and row["user_id"] == op_id)

    # ── audit ────────────────────────────────────────────────────────────────────────────
    now = time.time()
    await audit.record(now, "owner@x.co", "1.1.1.1", "POST", "/api/hosts/%d/run" % a, 200, "on A",
                       actor_id=1, host_id=a)
    await audit.record(now, "owner@x.co", "1.1.1.1", "POST", "/api/hosts/%d/run" % b, 200, "on B",
                       actor_id=1, host_id=b)
    await audit.record(now, "owner@x.co", "1.1.1.1", "POST", "/api/hosts/%d/run" % b, 200,
                       "legacy B")          # rând vechi: host_id dedus din cale
    await audit.record(now, "op@x.co", "1.1.1.1", "POST", "/api/settings/x", 403, "op own",
                       actor_id=op_id)
    det = lambda r: {e["detail"] for e in r.json()["entries"]}  # noqa: E731
    d = det(await op.get("/api/audit"))
    check("audit fără audit.view: DOAR propriile rânduri (inclusiv căutarea lui, auditată)",
          "op own" in d and not ({"on A", "on B", "legacy B"} & d), str(d))
    d = det(await owner.get("/api/audit"))
    check("audit Owner: tot", {"on A", "on B", "legacy B", "op own"} <= d, str(d))
    adm = await U.add_user("adm@x.co", bindings=[("admin", "folder", "prod")])
    adm_c = await U.login("adm@x.co")
    d = det(await adm_c.get("/api/audit"))
    check("audit.view doar dintr-o legătură @all: Admin@prod NU are audit global (vede doar ale lui)",
          "on A" not in d and "on B" not in d, str(d))
    await U.bind(adm, "viewer", "all")
    # Admin@prod + Viewer@all: audit.view tot NU (Viewer n-are audit.view)
    d = det(await adm_c.get("/api/audit"))
    check("audit.view rămâne GLOBAL: din Viewer@all nu se capătă", "on B" not in d)
    await U.unbind_all(adm)
    await U.bind(adm, "admin", "all")
    d = det(await adm_c.get("/api/audit"))
    check("Admin@all: audit întreg", {"on A", "on B", "legacy B"} <= d, str(d))

    # ── alerte: fan-out după rol ─────────────────────────────────────────────────────────
    await db.execute("DELETE FROM alerts")
    await alert_history.record("host_offline", "warning", "A down", host_id=a)
    await alert_history.record("host_offline", "warning", "B down", host_id=b)
    await alert_history.record("gateway_disk", "warning", "disk low")
    who = {}
    for r in await db.fetchall("SELECT user_id, title FROM alerts"):
        who.setdefault(r["title"], set()).add(r["user_id"])
    check("alertă de host A → cei cu host.view pe A (Owner, Operator@prod, Admin), nu Viewer@B",
          op_id in who.get("A down", set()) and vb_id not in who.get("A down", set())
          and 1 in who.get("A down", set()), str(who))
    check("alertă de host B → Viewer@B o primeşte, Operator@prod nu",
          vb_id in who.get("B down", set()) and op_id not in who.get("B down", set()), str(who))
    check("alertă de instanţă → doar security.view (Owner/Admin@all), nu Operator/Viewer",
          who.get("disk low", set()) & {op_id, vb_id, nob_id} == set()
          and 1 in who.get("disk low", set()), str(who))
    r = (await vb.get("/api/alerts")).json()
    check("/api/alerts arată fiecăruia doar rândurile lui",
          {x["title"] for x in r["alerts"]} == {"B down"}, str(r))
    await db.execute("DELETE FROM alerts")
    email_alerts.notify_security_change("x", "1.1.1.1", "owner@x.co", fleet=True)
    await asyncio.sleep(0.2)
    rows = {r["user_id"] for r in await db.fetchall("SELECT user_id FROM alerts")}
    check("schimbare de securitate a instanţei → doar security.view", op_id not in rows
          and vb_id not in rows, str(rows))

    # ── rezumatul de securitate ──────────────────────────────────────────────────────────
    ch = {c["id"] for c in (await op.get("/api/security/summary")).json()["checks"]}
    check("rezumat de securitate fără security.view: doar verificarea contului",
          ch == {"account2fa"}, str(ch))
    ch = {c["id"] for c in (await owner.get("/api/security/summary")).json()["checks"]}
    check("rezumat de securitate Owner: complet", {"shares", "guardrail", "signingKey", "backup",
                                                   "agents"} <= ch, str(ch))

    # ── aplicaţii (forward-uri promovate) ────────────────────────────────────────────────
    await U.add_forward(a, "app-a", app_type="custom")
    await U.add_forward(b, "app-b", app_type="custom")
    apps = lambda r: {x["host_id"] for x in r.json()}          # noqa: E731
    check("aplicaţii: Operator@prod doar pe A", apps(await op.get("/api/apps")) == {a})
    check("aplicaţii: Viewer@B doar pe B (forward.use e în Viewer)",
          apps(await vb.get("/api/apps")) == {b})

    # ── share-uri: proprii, fără numărătoarea celor din afara scope-ului ──────────────────
    await db.execute("UPDATE sessions SET share_token='h1', share_expires=?, share_by_id=1 WHERE id=?",
                     time.time() + 600, sb)
    r = (await op.get("/api/shares")).json()
    check("share-uri: Operator nu vede (nici nu numără) share-ul de pe B",
          r["shares"] == [] and r["hidden"] == 0, str(r))
    r = (await owner.get("/api/shares")).json()
    check("share-uri: Owner (shares.manage) le vede", len(r["shares"]) == 1, str(r))

    # ── tokenuri + conturi ───────────────────────────────────────────────────────────────
    await owner.post("/api/tokens", json={"name": "own", "scopes": ["read"],
                                          "current_password": U.OWNER_PW})
    r = await op.get("/api/tokens")
    check("tokenuri: tokens.create e GLOBAL — Operator@prod (legătură scoped) nu-l are → 403",
          r.status_code == 403 and U.code(r) == "authz.denied", r.text[:100])
    opall = await U.add_user("opall@x.co", bindings=[("operator", "all", "")])
    opall_c = await U.login("opall@x.co")
    r = await opall_c.get("/api/tokens")
    check("tokenuri: Operator@all (tokens.create) vede doar ale lui — zero aici, nu pe ale Owner-ului",
          r.status_code == 200 and r.json() == [], r.text[:100])
    await opall_c.aclose()
    del opall
    r = await vb.get("/api/tokens")
    check("tokenuri: Viewer (fără tokens.create) → 403", r.status_code == 403)
    r = await op.get("/api/users")
    check("conturi: fără users.manage → doar propriul rând",
          [u["email"] for u in r.json()] == ["op@x.co"], r.text[:200])
    r = await owner.get("/api/users")
    check("conturi: Owner le vede pe toate, cu legături",
          len(r.json()) >= 4 and all("bindings" in u for u in r.json()))

    # ── /api/state + export CSV ──────────────────────────────────────────────────────────
    await db.execute("UPDATE hosts SET hostkey_alarm=? WHERE id=?",
                     '{"old_fp":"a","new_fp":"b","changed_at":1}', b)
    r = (await op.get("/api/state")).json()
    check("state: alarmele de host-key doar pe hosturile vizibile",
          r["hostkey_changed"] == [], str(r["hostkey_changed"]))
    check("state: punctele backup/semnare doar pentru cine le poate rezolva",
          r["backup_ready"] is False and r["signing_missing"] is False)
    r = await adm_c.get("/api/hosts/export.csv", params={"ids": "%d,%d" % (a, b)})
    check("export CSV (Admin@all): ambele", r.status_code == 200 and "alpha" in r.text
          and "beta" in r.text)
    r = await op.get("/api/hosts/export.csv", params={"ids": "%d" % a})
    check("export CSV fără hosts.export → 403", r.status_code == 403)

    # ── me/permissions ───────────────────────────────────────────────────────────────────
    me = (await op.get("/api/me/permissions")).json()
    check("me/permissions: Operator@prod — nimic pe toate hosturile, A în `hosts`",
          me["all_hosts"] == [] and str(a) in me["hosts"] and str(b) not in me["hosts"], str(me))
    check("me/permissions: arată cine poate acorda acces (admins)", "owner@x.co" in me["admins"])
    me = (await owner.get("/api/me/permissions")).json()
    check("me/permissions Owner: toate permisiunile pe toate hosturile",
          set(me["all_hosts"]) == set(authz.HOST_PERMS) and me["owner"] is True)

    for c in (owner, op, vb, nob, adm_c):
        await c.aclose()
    await db.close()
    return check.summary()


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(main()) else 1)
