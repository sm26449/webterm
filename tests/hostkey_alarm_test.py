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
from app import api, config, core, db, email_alerts, security  # noqa: E402
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


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
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
    email_alerts.notify_host_key_changed = lambda host, detail: emails.append((host, detail))
    changes = []
    email_alerts.notify_security_change = lambda what, ip, email: changes.append(what)

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
        r = await c.post("/api/hosts/%d/hostkey/accept" % hid, json={})
        check("accept pe host 2FA fără step-up → 403", r.status_code == 403, "%s %s" % (r.status_code, r.text[:100]))
        row = await db.fetchone("SELECT hostkey_alarm FROM hosts WHERE id=?", hid)
        check("… alarma rămâne (nimic nu s-a schimbat)", bool(row["hostkey_alarm"]))
        await db.execute("UPDATE hosts SET require_2fa=0 WHERE id=?", hid)

        r = await c.post("/api/hosts/%d/hostkey/accept" % hid, json={})
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
        r = await c.post("/api/hosts/%d/hostkey/accept" % hid, json={})
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
        r = await c.patch("/api/hosts/%d" % hid, json={"hostname": "127.0.0.2", "connection_type": "ssh"})
        row = await db.fetchone("SELECT known_hosts, hostkey_alarm FROM hosts WHERE id=?", hid)
        check("PATCH hostname nou → known_hosts=NULL şi alarma stinsă (TOFU la următorul dial)",
              r.status_code == 200 and row["known_hosts"] is None and row["hostkey_alarm"] is None,
              "%s %s" % (r.status_code, r.text[:100]))

    core.dial_ssh = orig_dial
    server.close()
    await db.close()
    print(f"\n{ok}/{total} teste trecute")
    sys.stdout.flush()
    os._exit(0 if ok == total else 1)


asyncio.run(main())
