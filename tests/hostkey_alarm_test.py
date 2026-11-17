"""Alarma de host-key schimbat (SSH direct / jump) — audit UX §6.e:

  * la mismatch, gateway-ul CAPTUREAZĂ cheia oferită (asyncssh spunea doar „not trusted"),
    persistă {old_fp, new_fp, changed_at} pe host, scrie `hostkey_changed` în jurnalul
    hostului şi alertează — totul ÎNAINTE de autentificare (parola nu ajunge la un MITM);
  * cât alarma e activă, orice conectare e refuzată FĂRĂ dial (409 ssh.hostKeyChanged, cu
    amprentele în vars) — fail-closed, dar vizibil;
  * `GET /hostkey` arată amprentele; `POST /hostkey/accept` re-pinează cheia nouă, stinge
    alarma, auditează şi alertează; pe un host 2FA cere step-up (403 fără grant);
  * PATCH cu hostname nou resetează pinul ŞI alarma.

Server SSH real in-process (asyncssh), API in-process (ASGI) — fără reţea.
"""
import asyncio
import json
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import asyncssh  # noqa: E402
import httpx  # noqa: E402
from app import api, config, core, db, email_alerts, security, hosts_api  # noqa: E402
from app.main import app  # noqa: E402

_ORIGIN = {"origin": os.environ["WEBTERM_PUBLIC_URL"]}
PW = "parola-cont-123456"
ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


AUTH = {"begun": 0}


class _Server(asyncssh.SSHServer):
    def connection_made(self, conn):
        AUTH["conns"] = AUTH.get("conns", 0) + 1

    def begin_auth(self, username):
        AUTH["begun"] += 1    # a ajuns la autentificare (parola ar fi plecat)
        return False          # fără auth: testăm host-key-ul, nu autentificarea


async def _insert_host(name, port, known):
    tok = security.new_token()
    await db.execute(
        "INSERT INTO hosts(name, token_hash, token_encrypted, created, connection_type, hostname,"
        " ssh_port, ssh_username, auth_method, credential_encrypted, credential_policy, known_hosts)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        name, security.sha256_hex(tok), security.encrypt_secret(tok), time.time(), "ssh",
        "127.0.0.1", port, "tester", "password",
        security.encrypt_secret(json.dumps({"password": ""})), "stored", known)
    return (await db.fetchone("SELECT id FROM hosts WHERE name=?", name))["id"]


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    cols = {r["name"] for r in await db.fetchall("PRAGMA table_info(hosts)")}
    check("migraţia hosts.hostkey_alarm e aplicată", "hostkey_alarm" in cols)

    hostkey = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(_Server, "127.0.0.1", 0, server_host_keys=[hostkey])
    port = server.sockets[0].getsockname()[1]
    server_fp = hostkey.get_fingerprint()
    server_pub = hostkey.export_public_key().decode().strip()

    # cheie pinată DIFERITĂ de cea a serverului (host re-provizionat sau MITM)
    old_key = asyncssh.generate_private_key("ssh-ed25519")
    old_pub = old_key.export_public_key().decode().strip()
    old_fp = old_key.get_fingerprint()
    hid = await _insert_host("victim", port, old_pub)

    emails = []
    email_alerts.notify_host_key_changed = lambda host, detail, **k: emails.append((host, detail))
    changes = []
    email_alerts.notify_security_change = lambda what, ip, email, **k: changes.append(what)

    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", hid)
    raised = None
    try:
        await core.dial_ssh(row, {"password": ""})
    except core.HostKeyMismatch as e:
        raised = e
    check("mismatch → HostKeyMismatch", raised is not None)
    check("excepţia poartă amprenta VECHE (pinată)", raised is not None and raised.old_fp == old_fp,
          getattr(raised, "old_fp", None))
    check("excepţia poartă amprenta NOUĂ (cheia oferită de server, capturată)",
          raised is not None and raised.new_fp == server_fp, getattr(raised, "new_fp", None))
    check("sursa NU e înregistrată (fail-closed)", core.sources.get(hid) is None)

    row = await db.fetchone("SELECT * FROM hosts WHERE id=?", hid)
    alarm = json.loads(row["hostkey_alarm"] or "null")
    check("alarma e persistată pe host: {old_fp, new_fp, new_key, changed_at}",
          alarm and alarm["old_fp"] == old_fp and alarm["new_fp"] == server_fp
          and alarm["new_key"] == server_pub and abs(alarm["changed_at"] - time.time()) < 60, str(alarm)[:160])
    check("pinul VECHI rămâne neatins (nu re-pinăm singuri)", row["known_hosts"] == old_pub)
    ev = await db.fetchall("SELECT event, reason, detail FROM agent_events WHERE host_id=?", hid)
    check("jurnalul hostului: eveniment hostkey_changed cu ambele amprente",
          any(e["event"] == "hostkey_changed" and old_fp in e["detail"] and server_fp in e["detail"] for e in ev),
          str([dict(e) for e in ev]))
    check("alerta e-mail conţine amprentele", emails and old_fp in emails[-1][1] and server_fp in emails[-1][1],
          str(emails)[:200])

    # ── API ──
    dialed = {"n": 0}
    orig_dial = core.dial_ssh

    async def _no_dial(*a, **k):
        dialed["n"] += 1
        return await orig_dial(*a, **k)
    core.dial_ssh = _no_dial

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=_ORIGIN) as c:
        r = await c.post("/api/setup", json={"email": "admin@x.co", "password": PW, "setup_token": "test-setup"})
        check("setup cont", r.status_code == 200, r.text[:120])

        r = await c.post("/api/hosts/%d/sessions" % hid, json={"title": "t"})
        check("conectare cu alarmă activă → 409 ssh.hostKeyChanged",
              r.status_code == 409 and r.headers.get("x-webterm-error") == "ssh.hostKeyChanged", r.text[:160])
        check("… FĂRĂ dial (nu redialăm o ţintă suspectă la fiecare click)", dialed["n"] == 0)
        body = r.json()
        check("… vars = {old_fp, new_fp}", body.get("vars", {}).get("old_fp") == old_fp
              and body["vars"].get("new_fp") == server_fp, str(body)[:200])

        r = await c.get("/api/hosts")
        h = next(x for x in r.json() if x["id"] == hid)
        check("GET /api/hosts: hostkey_alarm pe host (badge persistent, nu toast)",
              h.get("hostkey_alarm", {}).get("new_fp") == server_fp, str(h.get("hostkey_alarm")))
        check("… fără cheia brută în JSON", "new_key" not in (h.get("hostkey_alarm") or {}))
        r = await c.get("/api/state")
        hc = r.json().get("hostkey_changed") or []
        check("GET /api/state: hostkey_changed listează alarma cu host_id/host_name",
              len(hc) == 1 and hc[0]["host_id"] == hid and hc[0]["host_name"] == "victim"
              and hc[0]["old_fp"] == old_fp and hc[0]["new_fp"] == server_fp, str(hc))

        r = await c.get("/api/hosts/%d/hostkey" % hid)
        j = r.json()
        check("GET /hostkey: {fingerprint=nouă, previous=veche, changed_at, pinned, alarm}",
              r.status_code == 200 and j["fingerprint"] == server_fp and j["previous"] == old_fp
              and j["changed_at"] and j["pinned"] is True and j["alarm"] is True, str(j))

        # step-up pe host 2FA: fără grant → 403 (orice factor lipsă = refuz)
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", hid)
        r = await c.post("/api/hosts/%d/hostkey/accept" % hid, json={"fingerprint": server_fp})
        check("accept pe host 2FA fără step-up → 403", r.status_code == 403, "%s %s" % (r.status_code, r.text[:100]))
        row = await db.fetchone("SELECT hostkey_alarm FROM hosts WHERE id=?", hid)
        check("… alarma rămâne (nimic nu s-a schimbat)", bool(row["hostkey_alarm"]))
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", hid)

        r = await c.post("/api/hosts/%d/hostkey/accept" % hid, json={"fingerprint": old_fp})
        check("accept cu o amprentă care NU e a alarmei (dialog vechi) → 409 ssh.hostKeyStale, nimic pinat",
              r.status_code == 409 and r.headers.get("x-webterm-error") == "ssh.hostKeyStale"
              and (await db.fetchone("SELECT known_hosts FROM hosts WHERE id=?", hid))["known_hosts"] == old_pub,
              r.text[:150])
        r = await c.post("/api/hosts/%d/hostkey/accept" % hid, json={"fingerprint": server_fp})
        check("accept → 200 cu amprenta nouă", r.status_code == 200 and r.json().get("fingerprint") == server_fp
              and r.json().get("pinned") is True, r.text[:160])
        row = await db.fetchone("SELECT known_hosts, hostkey_alarm FROM hosts WHERE id=?", hid)
        check("accept: cheia NOUĂ e pinată", row["known_hosts"] == server_pub)
        check("accept: alarma e stinsă", row["hostkey_alarm"] is None)
        check("accept: alertă de securitate (e-mail) cu amprentele",
              any("re-pinned" in w and server_fp in w for w in changes), str(changes))
        ev = await db.fetchall("SELECT event, detail FROM agent_events WHERE host_id=? AND event='hostkey_accepted'", hid)
        check("accept: eveniment hostkey_accepted cu autorul", len(ev) == 1 and "admin@x.co" in ev[0]["detail"])
        au = await db.fetchall("SELECT path, detail FROM audit_log WHERE path LIKE '%/hostkey/accept' ORDER BY id DESC")
        check("accept: rând de audit cu detaliu (old → new)",
              au and "host-key accepted" in (au[0]["detail"] or "") and server_fp in au[0]["detail"],
              str([dict(a) for a in au])[:200])

        r = await c.get("/api/hosts/%d/hostkey" % hid)
        j = r.json()
        check("GET /hostkey după accept: fără alarmă, amprenta = cea pinată",
              j["alarm"] is False and j["fingerprint"] == server_fp and j["previous"] is None, str(j))
        r = await c.post("/api/hosts/%d/hostkey/accept" % hid, json={"fingerprint": server_fp})
        check("accept fără alarmă → 409 ssh.noHostKeyAlarm", r.status_code == 409
              and r.headers.get("x-webterm-error") == "ssh.noHostKeyAlarm")

        # cu cheia bună pinată, dial-ul REAL trece (TOFU nu mai e necesar, pinul e cel corect)
        try:
            src = await orig_dial(await db.fetchone("SELECT * FROM hosts WHERE id=?", hid), {"password": ""})
            check("după accept: dial_ssh reuşeşte cu cheia re-pinată", isinstance(src, core.SshSource))
            await src.disconnect()
        except Exception as e:      # noqa: BLE001
            check("după accept: dial_ssh reuşeşte", False, repr(e))
        core.sources.pop(hid, None)

        # PATCH cu hostname nou resetează pinul ŞI alarma
        await db.execute("UPDATE hosts SET hostkey_alarm=? WHERE id=?",
                         json.dumps({"old_fp": "a", "new_fp": "b", "new_key": "", "changed_at": time.time()}), hid)
        # lot 2: parola stocată nu se mută odată cu hostul — ţinta nouă cere parola din nou
        await db.execute("UPDATE hosts SET credential_encrypted=? WHERE id=?",
                         security.encrypt_secret(json.dumps({"password": "VICTIM-PW"})), hid)

        async def target_of(h):
            r_ = await db.fetchone("SELECT connection_type, hostname, ssh_port, via_host_id,"
                                   " credential_encrypted FROM hosts WHERE id=?", h)
            return (r_["connection_type"], r_["hostname"], r_["ssh_port"], r_["via_host_id"],
                    bool(r_["credential_encrypted"]))
        before = await target_of(hid)
        # ocolirile găsite de review (C1): adresa mutată ÎMPREUNĂ cu tipul / politica / metoda
        for label, patch in (
                ("politica „ask\"", {"hostname": "10.66.0.1", "credential_policy": "ask"}),
                ("metoda „key\"", {"hostname": "10.66.0.1", "auth_method": "key"}),
                ("tipul telnet (parola ar pleca în clar)", {"hostname": "10.66.0.1", "connection_type": "telnet"}),
                ("telnet pe aceeaşi adresă (alt protocol/port)", {"connection_type": "telnet"})):
            r = await c.patch("/api/hosts/%d" % hid, json=patch)
            check("C1: mutare + %s → 400 host.retargetNeedsPassword" % label,
                  r.status_code == 400 and r.headers.get("x-webterm-error") == "host.retargetNeedsPassword"
                  and await target_of(hid) == before, "%s %s" % (r.status_code, r.text[:120]))
        r = await c.patch("/api/hosts/%d" % hid, json={"credential_policy": "ask", "connection_type": "ssh"})
        row = await db.fetchone("SELECT credential_encrypted FROM hosts WHERE id=?", hid)
        check("C1: politica „ask\" pe aceeaşi ţintă → secretul e ŞTERS din seif (nu reînvie la „stored\")",
              r.status_code == 200 and row["credential_encrypted"] is None, r.text[:120])
        await db.execute("UPDATE hosts SET credential_policy='stored', credential_encrypted=? WHERE id=?",
                         security.encrypt_secret(json.dumps({"password": "VICTIM-PW"})), hid)
        r = await c.patch("/api/hosts/%d" % hid, json={"hostname": "127.0.0.2", "connection_type": "ssh"})
        row = await db.fetchone("SELECT hostname, known_hosts FROM hosts WHERE id=?", hid)
        check("PATCH hostname nou FĂRĂ parolă → 400 host.retargetNeedsPassword, nimic schimbat",
              r.status_code == 400 and r.headers.get("x-webterm-error") == "host.retargetNeedsPassword"
              and row["hostname"] == "127.0.0.1", "%s %s" % (r.status_code, r.text[:120]))
        r = await c.patch("/api/hosts/%d" % hid, json={"ssh_port": port + 1, "connection_type": "ssh"})
        check("…la fel pentru alt port", r.status_code == 400, r.text[:120])
        r = await c.patch("/api/hosts/%d" % hid, json={"name": "victim-renamed", "connection_type": "ssh"})
        check("…dar o redenumire (aceeaşi ţintă) nu cere parola", r.status_code == 200, r.text[:120])
        r = await c.patch("/api/hosts/%d" % hid, json={"hostname": "127.0.0.2", "connection_type": "ssh",
                                                       "credential": "parolanoua"})
        row = await db.fetchone("SELECT known_hosts, hostkey_alarm FROM hosts WHERE id=?", hid)
        check("PATCH hostname nou cu parolă → known_hosts=NULL şi alarma stinsă (prim contact la dial)",
              r.status_code == 200 and row["known_hosts"] is None and row["hostkey_alarm"] is None,
              "%s %s" % (r.status_code, r.text[:100]))

        # ── lot 2: PRIMUL contact cu parolă — amprenta se confirmă înainte de autentificare ──
        hid2 = await _insert_host("fresh", port, None)
        await db.execute("UPDATE hosts SET credential_encrypted=? WHERE id=?",
                         security.encrypt_secret(json.dumps({"password": "secret"})), hid2)
        row2 = await db.fetchone("SELECT * FROM hosts WHERE id=?", hid2)
        AUTH["begun"] = 0
        raised = None
        try:
            await orig_dial(row2, {"password": "secret"})
        except core.HostKeyUnverified as e:
            raised = e
        check("prim contact cu parolă → HostKeyUnverified (fără conectare)", raised is not None
              and core.sources.get(hid2) is None, repr(raised))
        check("…serverul NU a ajuns la autentificare (parola n-a plecat)", AUTH["begun"] == 0, AUTH)
        r2 = await db.fetchone("SELECT known_hosts, hostkey_alarm FROM hosts WHERE id=?", hid2)
        a2 = json.loads(r2["hostkey_alarm"] or "{}")
        check("…alarma de prim contact (first) cu amprenta serverului, nimic pinat",
              a2.get("first") is True and a2.get("new_fp") == server_fp and r2["known_hosts"] is None, a2)
        r = await c.get("/api/hosts/%d/hostkey" % hid2)
        check("GET hostkey: first=true + amprenta oferită", r.json().get("first") is True
              and r.json().get("fingerprint") == server_fp, r.text[:150])
        r = await c.post("/api/hosts/%d/sessions" % hid2, json={})
        check("pornirea unei sesiuni → 409 ssh.hostKeyUnverified (fără dial)",
              r.status_code == 409 and r.headers.get("x-webterm-error") == "ssh.hostKeyUnverified",
              r.text[:150])
        n_changes = len(changes)
        r = await c.post("/api/hosts/%d/hostkey/accept" % hid2, json={"fingerprint": server_fp})
        r2 = await db.fetchone("SELECT known_hosts, hostkey_alarm FROM hosts WHERE id=?", hid2)
        check("accept → cheia pinată, alarma stinsă", r.status_code == 200 and r2["hostkey_alarm"] is None
              and (r2["known_hosts"] or "").split()[:2] == server_pub.split()[:2], r.text[:150])
        check("…fără alertă de re-pinare (e un pin iniţial)", len(changes) == n_changes, changes[n_changes:])
        AUTH["begun"] = 0
        try:
            src = await orig_dial(await db.fetchone("SELECT * FROM hosts WHERE id=?", hid2),
                                  {"password": "secret"})
            check("după accept: dial-ul autentifică pe cheia pinată", isinstance(src, core.SshSource)
                  and AUTH["begun"] == 1, AUTH)
            await src.disconnect()
        except Exception as e:      # noqa: BLE001
            check("după accept: dial-ul autentifică pe cheia pinată", False, repr(e))
        core.sources.pop(hid2, None)

        # ── review lot 2: alarma de prim contact pendinte → un nou dial NU mai deschide conexiuni ──
        hid3 = await _insert_host("fresh3", port, None)
        row3 = await db.fetchone("SELECT * FROM hosts WHERE id=?", hid3)
        try:
            await orig_dial(row3, {"password": "secret"})
        except core.HostKeyUnverified:
            pass
        AUTH["conns"] = 0
        n_ev = (await db.fetchone("SELECT COUNT(*) n FROM agent_events WHERE host_id=?", hid3))["n"]
        for _ in range(3):
            try:
                await orig_dial(await db.fetchone("SELECT * FROM hosts WHERE id=?", hid3), {"password": "secret"})
            except core.HostKeyUnverified:
                pass
        n_ev2 = (await db.fetchone("SELECT COUNT(*) n FROM agent_events WHERE host_id=?", hid3))["n"]
        check("alarmă de prim contact pendinte: dial-uri repetate → nicio conexiune nouă, niciun eveniment",
              AUTH["conns"] == 0 and n_ev2 == n_ev, "%s %s→%s" % (AUTH, n_ev, n_ev2))
        check("parola goală contează şi ea ca prim contact (fără TOFU tăcut)",
              core._needs_first_contact({"known_hosts": None, "auth_method": "password"}, {"password": ""}))

        # ── M4: un pin verificat de test înlocuieşte alarma de prim contact; „Trust" vechi nu-l suprascrie ──
        hosts_api._hosttest_hits.clear()
        r = await c.post("/api/hosts/test", json={
            "connection_type": "ssh", "hostname": "127.0.0.1", "ssh_port": port, "ssh_username": "tester",
            "auth_method": "password", "credential": "secret", "trust_hostkey": server_pub})
        check("precondiţie M4: testul cu amprenta acceptată trece", r.json().get("ok") is True, r.text[:200])
        a3 = json.loads((await db.fetchone("SELECT hostkey_alarm FROM hosts WHERE id=?", hid3))["hostkey_alarm"])
        r = await c.patch("/api/hosts/%d" % hid3, json={"pin_hostkey": server_pub, "connection_type": "ssh"})
        r3 = await db.fetchone("SELECT known_hosts, hostkey_alarm FROM hosts WHERE id=?", hid3)
        check("M4: PATCH cu pinul testat → pinat ŞI alarma de prim contact stinsă",
              r.status_code == 200 and r3["known_hosts"] and r3["hostkey_alarm"] is None, r.text[:150])
        await db.execute("UPDATE hosts SET hostkey_alarm=? WHERE id=?", json.dumps(a3), hid3)
        r = await c.post("/api/hosts/%d/hostkey/accept" % hid3, json={"fingerprint": a3["new_fp"]})
        check("M4: „Trust\" pe o alarmă de prim contact când hostul are deja pin → 409, pinul neatins",
              r.status_code == 409 and (await db.fetchone("SELECT known_hosts FROM hosts WHERE id=?", hid3))
              ["known_hosts"] == r3["known_hosts"], r.text[:150])

        # ── review 2: ocolirea prin tipul `agent` (ssh → agent + adresă nouă → ssh/telnet) ──
        async def pw_host(name, ctype="ssh"):
            h = await _insert_host(name, 22, server_pub)
            await db.execute("UPDATE hosts SET connection_type=?, hostname='10.0.0.5', credential_encrypted=?"
                             " WHERE id=?", ctype, security.encrypt_secret(json.dumps({"password": "VICTIM-PW"})), h)
            return h

        async def secret_of(h):
            return (await db.fetchone("SELECT credential_encrypted FROM hosts WHERE id=?", h))["credential_encrypted"]
        ha = await pw_host("flip-a")
        r = await c.patch("/api/hosts/%d" % ha, json={"connection_type": "agent", "hostname": "evil.example"})
        check("agent + adresă nouă → secretul ŞTERS din seif (pe agent nu e folosit)",
              r.status_code == 200 and await secret_of(ha) is None, r.text[:120])
        r = await c.patch("/api/hosts/%d" % ha, json={"connection_type": "ssh"})
        check("…înapoi pe ssh la evil.example → nicio parolă de trimis (cere una nouă)",
              r.status_code == 400 and await secret_of(ha) is None, r.text[:120])
        hb = await pw_host("flip-b")
        await c.patch("/api/hosts/%d" % hb, json={"connection_type": "agent", "ssh_port": 2323})
        r = await c.patch("/api/hosts/%d" % hb, json={"connection_type": "telnet"})
        check("ssh → agent + port nou → telnet: parola NU ajunge în telnet (în clar; seiful e gol)",
              await secret_of(hb) is None, r.text[:120])
        hc = await pw_host("flip-c", ctype="agent")
        r = await c.patch("/api/hosts/%d" % hc, json={"connection_type": "telnet"})
        check("agent (parolă din provisioning SSH) → telnet pe aceeaşi adresă → 400 (alt protocol)",
              r.status_code == 400 and r.headers.get("x-webterm-error") == "host.retargetNeedsPassword",
              r.text[:120])
        r = await c.patch("/api/hosts/%d" % hc, json={"connection_type": "ssh"})
        check("agent → ssh pe aceeaşi adresă → 200 (aceeaşi ţintă, salvarea clasică)", r.status_code == 200,
              r.text[:120])

        # ── review 2: cheie → parolă pe aceeaşi ţintă: pinul pus tăcut (TOFU) nu e moştenit ──
        hk = await _insert_host("key-to-pw", port, server_pub)
        await db.execute("UPDATE hosts SET auth_method='key' WHERE id=?", hk)
        r = await c.patch("/api/hosts/%d" % hk, json={"auth_method": "password", "credential": "pw-nou",
                                                       "connection_type": "ssh"})
        rk = await db.fetchone("SELECT known_hosts FROM hosts WHERE id=?", hk)
        check("cheie → parolă: pinul TOFU e şters (prima conectare cu parola cere confirmarea)",
              r.status_code == 200 and rk["known_hosts"] is None, r.text[:120])
        check("blob fără `password` pe un host cu parolă → tot prim contact (fără TOFU tăcut)",
              core._needs_first_contact({"known_hosts": None, "auth_method": "password"}, {"key": "x"}))

        # ── H2: ssh-jump → ssh direct (alt drum) e o mutare: cere parola ──
        r = await c.post("/api/hosts", json={"name": "agentA", "connection_type": "agent"})
        aid = r.json()["id"]
        hj = await _insert_host("jumped", 22, server_pub)
        await db.execute("UPDATE hosts SET connection_type='ssh-jump', via_host_id=?, hostname='10.1.1.5',"
                         " credential_encrypted=? WHERE id=?", aid,
                         security.encrypt_secret(json.dumps({"password": "VICTIM-PW"})), hj)
        r = await c.patch("/api/hosts/%d" % hj, json={"connection_type": "ssh"})
        check("H2: ssh-jump → ssh fără via şi fără parolă → 400 host.retargetNeedsPassword",
              r.status_code == 400 and r.headers.get("x-webterm-error") == "host.retargetNeedsPassword",
              r.text[:150])

    # ── M3: un server cu CERTIFICAT de host OpenSSH — cheia hostului se poate citi (şi pina) ──
    ca = asyncssh.generate_private_key("ssh-ed25519")
    hk_c = asyncssh.generate_private_key("ssh-ed25519")
    cert = ca.generate_host_certificate(hk_c, "certhost", principals=["127.0.0.1"])
    srv_c = await asyncssh.create_server(_Server, "127.0.0.1", 0, server_host_keys=[(hk_c, cert)])
    cport = srv_c.sockets[0].getsockname()[1]
    got = await core.peek_host_key(dict(host="127.0.0.1", port=cport, username="tester"))
    check("M3: host cu certificat → cheia simplă a hostului e citită (nu None)",
          got is not None and got.get_fingerprint() == hk_c.get_fingerprint(), repr(got))
    probe_row = {"id": 0, "name": "c", "connection_type": "ssh", "hostname": "127.0.0.1", "ssh_port": cport,
                 "ssh_username": "tester", "auth_method": "password", "via_host_id": None, "known_hosts": None}
    res = await core.probe_ssh(probe_row, None, await core.resolve_target("127.0.0.1", cport), "")
    check("M3: testul de conexiune vede amprenta hostului cu certificat",
          (res.get("hostkey") or {}).get("fingerprint_sha256") == hk_c.get_fingerprint(), str(res)[:200])
    srv_c.close()

    core.dial_ssh = orig_dial
    server.close()
    await db.close()
    print(f"\n{ok}/{total} teste trecute")
    sys.stdout.flush()
    os._exit(0 if ok == total else 1)


asyncio.run(main())
