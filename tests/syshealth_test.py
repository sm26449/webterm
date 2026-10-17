"""System health (3.6.8): syshealth.py, hoststatus.py, healthcmd.py and the /api/health routes.

The principle under test: whatever WebTerm cannot fix from the UI it detects, notifies, explains
and recommends — with an exact command that comes ONLY from a server-side allow-list, and with no
new privilege for the gateway. All hermetic (temp DB, temp data dir, no agent, no network):
  * the host status parser against hostile files: huge, malformed, wrong types, NaN, a far-future
    timestamp, a symlinked file, a symlinked directory, HTML/script and control characters in the
    message, unknown keys, deep nesting — refused or neutralised, never trusted;
  * the command allow-list: every template round-trips; injection attempts in every parameter
    (`;`, `$(…)`, backticks, newlines, spaces, option injection, `..` in the install dir) give NO
    command; no-parameter templates refuse parameters;
  * each check: ok / warning / critical / stale / not applicable;
  * alerting: one alert per transition, escalation alerts again, de-escalation does not,
    recovery sends "resolved", nothing while muted, no duplicate after a restart (state reloaded
    from the DB), the update notice once per version;
  * the alert-delivery check: in-app ONLY — no email, no webhook, no loop, however often it runs;
  * mute: 7 d / 30 d / until it changes (lifted when the result changes), audited;
  * the routes for Owner / Admin / Operator / Viewer / token / anonymous; the health terminal:
    Owner-only, designated host, the server re-derives the command (a client `command` field is
    ignored), fresh factor BEFORE anything is created, private session (origin health-fix);
  * backup verification records `restore_verified_at`; the admin CLI reads the same rows;
  * the English catalog in Python and en.ts / ro.ts stay in step (keys and placeholders).
"""
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rbac_util as U  # noqa: E402  (sets the env before `app` is imported)
from app import (alert_history, api, audit, config, core, db, email_alerts, healthcmd,  # noqa: E402
                 hoststatus, main as app_main, oidc, security, syshealth, updatecheck)

ok = 0
total = 0
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def status_doc(sid, status="ok", ts=None, message="fine", data=None, **extra):
    d = {"v": 1, "id": sid, "status": status, "ts": int(time.time()) if ts is None else ts,
         "message": message, "data": data or {}}
    d.update(extra)
    return d


def write_status(base, sid, doc):
    os.makedirs(base, exist_ok=True)
    p = os.path.join(base, sid + ".json")
    if os.path.islink(p) or os.path.exists(p):
        os.remove(p)
    with open(p, "w") as f:
        f.write(doc if isinstance(doc, str) else json.dumps(doc))
    return p


# ── 1. host status parser ──────────────────────────────────────────────────────────────────────
def test_parser():
    print("── host status files are untrusted input")
    base = tempfile.mkdtemp()
    hs = os.path.join(base, "host-status")
    now = time.time()
    write_status(hs, "backup", status_doc("backup", data={"archive": "webterm-1.tar.gz.enc", "encrypted": True,
                                                          "offhost": "ok", "evil": "x" * 50}))
    r = hoststatus.read("backup", now, hs)
    check("a valid file is read", r["state"] == "ok" and r["status"] == "ok" and not r["stale"], r)
    check("unknown data keys are dropped", "evil" not in r["data"] and r["data"]["offhost"] == "ok", r["data"])
    check("missing file → missing (not an error)", hoststatus.read("cert-check", now, hs) == {"state": "missing"})
    check("unknown id → refused", hoststatus.read("../../etc/passwd", now, hs)["state"] == "invalid")

    write_status(hs, "backup", "x" * (hoststatus.MAX_BYTES + 1))
    r = hoststatus.read("backup", now, hs)
    check("a file over 4 KiB is refused unread", r["state"] == "invalid" and "large" in r["error"], r)
    write_status(hs, "backup", "{not json")
    check("malformed JSON → invalid", hoststatus.read("backup", now, hs)["state"] == "invalid")
    write_status(hs, "backup", "[" * 3000 + "]" * 3000)
    check("deep nesting does not crash the parser (refused)", hoststatus.read("backup", now, hs)["state"] == "invalid")
    for bad, why in ((status_doc("backup", status="pwned"), "status outside the enum"),
                     (status_doc("backup", ts="yesterday"), "ts not a number"),
                     (status_doc("backup", ts=True), "ts a bool"),
                     (status_doc("backup", ts=now + 400 * 86400), "ts a year in the future"),
                     (status_doc("backup", ts=100), "ts before 2020"),
                     (dict(status_doc("backup"), v=2), "unknown schema version"),
                     (dict(status_doc("backup"), id="cert-check"), "id does not match the file")):
        write_status(hs, "backup", bad)
        check("refused: %s" % why, hoststatus.read("backup", now, hs)["state"] == "invalid")
    write_status(hs, "backup", '{"v":1,"id":"backup","status":"ok","ts":NaN,"message":"x"}')
    check("refused: NaN timestamp", hoststatus.read("backup", now, hs)["state"] == "invalid")

    msg = "<script>alert(1)</script>\n\x1b[31mred\x00 ‮evil" + "y" * 500
    write_status(hs, "backup", status_doc("backup", status="error", message=msg))
    r = hoststatus.read("backup", now, hs)
    check("HTML in a message stays literal text (escaped by React, never rendered)",
          r["message"].startswith("<script>alert(1)</script>"), r["message"][:60])
    check("control and bidi-override characters are removed, the message is cut to 200",
          "\n" not in r["message"] and "\x1b" not in r["message"] and "\x00" not in r["message"]
          and "‮" not in r["message"] and len(r["message"]) <= 200, repr(r["message"][:80]))
    write_status(hs, "backup", status_doc("backup", data={"archive": "../../etc/shadow", "offhost": "maybe",
                                                          "encrypted": "yes"}))
    r = hoststatus.read("backup", now, hs)
    check("data values are type-checked (path, enum, bool)", r["data"] == {}, r["data"])
    write_status(hs, "backup", status_doc("backup", ts=int(now - 3 * 86400)))
    r = hoststatus.read("backup", now, hs)
    check("staleness comes from the server table (2× interval), not from the file", r["stale"] is True, r)
    write_status(hs, "restore-verify", status_doc("restore-verify", ts=int(now - 400 * 86400)))
    check("an on-demand status (restore-verify) is never stale",
          hoststatus.read("restore-verify", now, hs)["stale"] is False)

    # symlinks: a file → refused (not followed); the directory itself a symlink → refused
    secret = os.path.join(base, "secret.json")
    with open(secret, "w") as f:
        json.dump(status_doc("cert-check", message="from a symlink target"), f)
    link = os.path.join(hs, "cert-check.json")
    os.symlink(secret, link)
    r = hoststatus.read("cert-check", now, hs)
    check("a symlinked status file is refused, not followed", r["state"] == "invalid", r)
    other = tempfile.mkdtemp()
    write_status(other, "backup", status_doc("backup"))
    linked_dir = os.path.join(base, "linked")
    os.symlink(other, linked_dir)
    check("a symlinked status DIRECTORY is refused", hoststatus.read("backup", now, linked_dir)["state"] == "invalid")
    fifo = os.path.join(hs, "docker-cleanup.json")
    os.mkfifo(fifo)
    check("a FIFO is refused without blocking", hoststatus.read("docker-cleanup", now, hs)["state"] == "invalid")
    write_status(hs, "cloudflare-token", status_doc("cloudflare-token", status="warn",
                                                    data={"token_status": "active", "expires_on": "2026-11-01T00:00:00Z"}))
    r = hoststatus.read("cloudflare-token", now, hs)
    check("cloudflare data: enum + ISO date accepted", r["data"] == {"token_status": "active",
                                                                     "expires_on": "2026-11-01T00:00:00Z"}, r)
    write_status(hs, "authentik-image", status_doc("authentik-image", status="warn",
                                                   data={"running": "2024.10.5; rm -rf /", "pinned": "2026.8.3"}))
    r = hoststatus.read("authentik-image", now, hs)
    check("a version with shell junk is dropped", "running" not in r["data"] and r["data"]["pinned"] == "2026.8.3", r)
    write_status(hs, "authentik-image", status_doc("authentik-image", status="warn",
                                                   data={"running": "2026.8.2", "pinned": "2026.8.3", "layout": "separate",
                                                         "project": "authentik"}))
    r = hoststatus.read("authentik-image", now, hs)
    check("layout + project (from the compose project label) accepted", r["data"].get("layout") == "separate"
          and r["data"].get("project") == "authentik", r)
    write_status(hs, "authentik-image", status_doc("authentik-image", data={"layout": "pwned", "project": "a;b"}))
    r = hoststatus.read("authentik-image", now, hs)
    check("…an unknown layout / hostile project is dropped", "layout" not in r["data"] and "project" not in r["data"], r)


# ── 2. the command allow-list ──────────────────────────────────────────────────────────────────
def test_commands():
    print("── the command allow-list")
    D = "/opt/webterm"
    want = {
        ("host_health", None): "sudo -k /opt/webterm/scripts/host-health.sh",
        ("host_health_install", None): "sudo -k /opt/webterm/scripts/host-health.sh --install",
        ("unit_start", "webterm-backup.service"): "sudo -k systemctl start webterm-backup.service",
        ("unit_journal", "webterm-backup.service"):
            "sudo -k journalctl -u webterm-backup.service -n 50 --no-pager",
        ("upgrade", "v3.6.9"): "sudo -k /opt/webterm/upgrade.sh v3.6.9",
        ("db_vacuum", None): "cd /opt/webterm && sudo -k docker compose -f docker-compose.prod.yml exec -u webterm app python3 -m app.admin vacuum",
        ("cf_token_edit", None): "sudo -k -e /opt/webterm/secrets/cf_dns_api_token",
        ("ntp_status", None): "timedatectl status",
        ("cert_renew", "*.wt.example.com"): "sudo -k /opt/webterm/scripts/cert-renew.sh --domain '*.wt.example.com'",
    }
    for (tpl, arg), cmd in want.items():
        p = {}
        if tpl in ("unit_start", "unit_journal"):
            p = {"unit": arg}
        elif tpl == "upgrade":
            p = {"tag": arg}
        elif tpl == "cert_renew":
            p = {"domain": arg}
        try:
            got = healthcmd.render(tpl, p, D)["text"]
        except healthcmd.CommandError as e:
            got = "ERR %s" % e
        check("%s renders exactly" % tpl, got == cmd, got)
    check("requires_root is declared per template", healthcmd.render("ntp_status", {}, D)["requires_root"] is False
          and healthcmd.render("host_health", {}, D)["requires_root"] is True)

    def refused(tpl, p, d=D):
        try:
            healthcmd.render(tpl, p, d)
            return False
        except healthcmd.CommandError:
            return True
    hostile = ["webterm-backup.service; rm -rf /", "$(id)", "`id`", "webterm-backup.service\nid",
               "ssh.service", "../webterm-backup.service", "--help", "webterm-backup.service && id"]
    for u in hostile:
        check("unit %r → no command" % u[:30], refused("unit_start", {"unit": u}) and refused("unit_journal", {"unit": u}))
    for tag in ("v1.2.3;id", "v1.2.3 && id", "$(curl x|sh)", "latest", "v1.2", "-v1.2.3", "v1.2.3\n"):
        check("tag %r → no command" % tag, refused("upgrade", {"tag": tag}))
    for dom in ("evil.com;id", "$(id).example.com", "-x.example.com", "a b.example.com", "*.*.example.com"):
        check("domain %r → no command" % dom, refused("cert_renew", {"domain": dom}))
    check("cert_renew refuses extra parameters", refused("cert_renew", {"domain": "wt.example.com", "x": "1"}))
    check("a no-parameter template refuses parameters", refused("host_health", {"x": "--install; id"}))
    check("unknown template → no command", refused("bash", {}) and refused(None, {}) and refused("__class__", {}))
    for d in ("/opt/web term", "/opt/../etc", "relative", "/opt/webterm;id", "/opt/$(id)", "/opt/./x"):
        check("install dir %r → no command" % d, refused("host_health", {}, d))
    lst = healthcmd.render_list([{"t": "host_health", "p": {}}, {"t": "unit_start", "p": {"unit": "evil"}},
                                 "not a dict", {"t": "nope"}], D)
    check("render_list keeps only valid entries (fail closed)", [c["template"] for c in lst] == ["host_health"], lst)


# ── 3. checks + alerting (DB, no HTTP) ─────────────────────────────────────────────────────────
HS = None
sent = {"email": [], "webhook": []}


def _hs_dir():
    return str(config.DATA_DIR / hoststatus.DIRNAME)


async def _alerts(kind=None):
    rows = await db.fetchall("SELECT kind, severity, title, msg_key, msg_params FROM alerts ORDER BY id")
    return [dict(r) for r in rows if kind is None or r["kind"] == kind]


async def _settle():
    for _ in range(5):
        await asyncio.sleep(0)
    await asyncio.sleep(0.05)


async def run_check(cid):
    c = syshealth.BY_ID[cid]
    syshealth._host_snapshot()
    await syshealth._run_one(c, time.time())
    await _settle()
    return syshealth._rows.get(cid)


def _http_err(code, body):
    import io
    import urllib.error
    return urllib.error.HTTPError("http://idp/token", code, "x", {}, io.BytesIO(body))


async def test_sso_review_m1():
    """Security review 3.6.8 (M1): an anonymous caller must not be able to raise "SSO broken"
    (critical with WEBTERM_OIDC_SSO_ONLY=1) with bogus callbacks, nor hide a real one."""
    import urllib.error
    from app import oidc_api
    print("── SSO: bogus callbacks are not an outage (review M1)")
    cl = oidc._classify_token_error
    check("400 invalid_grant (a bogus code) → user",
          cl(_http_err(400, b'{"error":"invalid_grant"}')) == "user")
    check("400 whose DESCRIPTION echoes 'invalid_client' (attacker-chosen code) → still user",
          cl(_http_err(400, b'{"error":"invalid_grant","error_description":"code invalid_client"}')) == "user")
    check("400 with a non-JSON body that mentions invalid_client → user",
          cl(_http_err(400, b"invalid_client")) == "user")
    check("413 / 429 / other 4xx → user", cl(_http_err(413, b"")) == "user" and cl(_http_err(429, b"")) == "user")
    check("400 error=invalid_client → invalid_client", cl(_http_err(400, b'{"error":"invalid_client"}')) == "invalid_client")
    check("401 → invalid_client", cl(_http_err(401, b"")) == "invalid_client")
    check("500 / 503 → token_endpoint", cl(_http_err(500, b"")) == "token_endpoint"
          and cl(_http_err(503, b"")) == "token_endpoint")
    check("connection refused → token_endpoint", cl(urllib.error.URLError("refused")) == "token_endpoint")

    # end to end: /login hands out a valid state; /callback?code=bogus → the IdP says invalid_grant
    saved_disco, saved_http = oidc._disco, oidc._http_json
    answer = {"err": (400, b'{"error":"invalid_grant","error_description":"invalid_client?"}')}

    def fake_http(url, data=None, headers=None):
        raise _http_err(*answer["err"])
    oidc._disco = {"issuer": "http://idp", "authorization_endpoint": "http://idp/authorize",
                   "token_endpoint": "http://idp/token", "jwks_uri": "http://idp/jwks"}
    oidc._http_json = fake_http
    import httpx
    from urllib.parse import parse_qs, urlparse
    clients = {}

    def anon_from(ip):
        # a distinct client address per caller (the socket peer: no proxy header is trusted here)
        if ip not in clients:
            clients[ip] = httpx.AsyncClient(transport=httpx.ASGITransport(app=U.app, client=(ip, 40000)),
                                            base_url="http://t")
        return clients[ip]

    async def bogus_callback(ip="203.0.113.7"):
        c = anon_from(ip)
        r = await c.get("/api/oidc/login")
        state = parse_qs(urlparse(r.headers.get("location", "")).query).get("state", [""])[0]
        c.cookies.set(oidc_api.STATE_COOKIE, state)
        return await c.get("/api/oidc/callback", params={"code": "bogus", "state": state})
    try:
        oidc.reset_failures()
        r = None
        for _ in range(12):
            r = await bogus_callback()
        check("…the callback refuses ('denied', not 'unavailable')", r is not None and r.status_code == 303
              and "sso_error=denied" in r.headers.get("location", ""), r and r.headers.get("location"))
        st = oidc.failure_stats()
        check("12 bogus-code callbacks → no SYSTEM failure counted", st["count"] == 0, st)
        r = await run_check("oidc.sso")
        check("…and System health stays 'SSO works' (no sso_broken)", r["severity"] == "ok"
              and r["message_key"] == "sso_ok", r)
        # a REAL invalid_client (the IdP rejects our client credentials) still raises it at once
        answer["err"] = (401, b'{"error":"invalid_client"}')
        await bogus_callback()
        r = await run_check("oidc.sso")
        check("a real invalid_client still raises sso_broken (critical with SSO_ONLY)",
              r["severity"] == "critical" and r["message_key"] == "sso_broken" and "invalid_client" in r["params"], r)
        # eviction: a flood of user failures must not push the system failure out of the window
        answer["err"] = (400, b'{"error":"invalid_grant"}')
        for _ in range(300):
            oidc.note_failure("user", "198.51.100.1")
        st = oidc.failure_stats()
        check("300 user failures after it do not evict the system failure", st["kinds"].get("invalid_client") == 1, st)
        r = await run_check("oidc.sso")
        check("…sso_broken still shown", r["message_key"] == "sso_broken" and r["severity"] == "critical", r)

        # unconfirmed: 5xx from the token endpoint, all from ONE caller → a warning, not critical
        oidc.reset_failures()
        answer["err"] = (502, b"bad gateway")
        for _ in range(4):
            await bogus_callback("203.0.113.9")
        st = oidc.failure_stats()
        check("5xx failures from one source are counted but not confirmed", st["count"] == 4
              and st["sources"] == 1 and not st["confirmed"], st)
        r = await run_check("oidc.sso")
        check("…sso_broken only as a WARNING with SSO_ONLY (needs confirmation for critical)",
              r["message_key"] == "sso_broken" and r["severity"] == "warning", r)
        oidc._probe.update(ts=0.0)
        syshealth._probe_kick.update(at=0.0, task=None)
        saved_probe = oidc.probe
        probed = []
        oidc.probe = lambda: (probed.append(1), oidc._probe.update(ts=time.time(), ok=False, kind="discovery",
                                                                    error="connection refused"))[1]
        try:
            await run_check("oidc.sso")
            t = syshealth._probe_kick.get("task")
            if t:
                await t
            check("…and it asks the IdP probe to run now", probed == [1], probed)
            r = await run_check("oidc.sso")
            check("the probe confirms the outage → full severity (critical)", r["severity"] == "critical"
                  and r["message_key"] == "sso_probe_failed", r)
            await run_check("oidc.sso")
            check("the probe is not re-kicked within 5 minutes", probed == [1], probed)
        finally:
            oidc.probe = saved_probe
            oidc._probe.update(ts=time.time(), ok=True, kind="", error="")
        oidc.reset_failures()
        await bogus_callback("203.0.113.9")
        await bogus_callback("203.0.113.10")
        await bogus_callback("203.0.113.11")
        r = await run_check("oidc.sso")
        check("5xx failures from several sources → confirmed → critical", r["severity"] == "critical"
              and r["message_key"] == "sso_broken", r)
    finally:
        oidc._disco, oidc._http_json = saved_disco, saved_http
        oidc.reset_failures()
        for c in clients.values():
            await c.aclose()


async def test_checks(owner_uid):
    print("── checks: host helpers")
    hs = _hs_dir()
    os.makedirs(hs, exist_ok=True)
    for f in os.listdir(hs):
        os.remove(os.path.join(hs, f))
    r = await run_check("host.helper")
    check("helper never ran → info + the install command", r["severity"] == "info"
          and r["message_key"] == "helper_missing" and "host_health_install" in r["commands"], r)
    # FL-12 (audit 2026-10-17): after an upgrade from < 3.6.9 in one jump the host kit is simply
    # not there; once the gateway has been up for HELPER_GRACE this is a WARNING that says to run
    # upgrade.sh a second time — not an info item nobody reads
    started = syshealth._STARTED
    syshealth._STARTED = time.time() - syshealth.HELPER_GRACE - 60
    try:
        r = await run_check("host.helper")
        check("…never ran and the gateway has been up > 10 min → WARNING, same install command",
              r["severity"] == "warning" and r["message_key"] == "helper_missing"
              and "host_health_install" in r["commands"], r)
        check("…the recommendation names the second upgrade.sh run (upgrade from < 3.6.9)",
              r["recommendation_key"] == "helper_never_ran" and "second time" in syshealth.RECS["helper_never_ran"]
              and "3.6.9" in syshealth.RECS["helper_never_ran"], r.get("recommendation_key"))
    finally:
        syshealth._STARTED = started
    write_status(hs, "host-health", status_doc("host-health", ts=int(time.time() - 3 * 3600)))
    r = await run_check("host.helper")
    check("helper stale (> 2 h) → warning", r["severity"] == "warning" and r["message_key"] == "helper_stale", r)
    timers = {"webterm-backup.timer": "enabled", "webterm-cert-check.timer": "enabled",
              "webterm-host-health.timer": "enabled", "webterm-docker-cleanup.timer": "missing"}
    write_status(hs, "host-health", status_doc("host-health", status="warn", data={"timers": timers}))
    r = await run_check("host.helper")
    check("a timer missing → warning naming it", r["severity"] == "warning" and "docker-cleanup" in r["params"], r)
    timers["webterm-docker-cleanup.timer"] = "enabled"
    write_status(hs, "host-health", status_doc("host-health", data={"timers": timers}))
    r = await run_check("host.helper")
    check("all timers on, fresh → ok", r["severity"] == "ok", r)
    write_status(hs, "docker-cleanup", "garbage")
    r = await run_check("host.helper")
    check("a refused status file is reported (which and why)", r["severity"] == "warning"
          and r["message_key"] == "helper_invalid" and "docker-cleanup.json" in r["params"], r)
    os.remove(os.path.join(hs, "docker-cleanup.json"))

    r = await run_check("host.backup")
    check("backup timer enabled but never reported → warning", r and r["severity"] == "warning"
          and r["message_key"] == "host_backup_missing", r)
    # 3.6.9: the kit report (host-health.sh ≥ 3.6.9) tells "outdated script" from "not run yet"
    now = time.time()
    kit = dict(timers=timers, kit_backup=True, since_backup=int(now - 3600), next_backup=int(now + 5.5 * 3600))
    write_status(hs, "host-health", status_doc("host-health", data=kit))
    r = await run_check("host.backup")
    check("current script, updated 1 h ago, timer not fired yet → INFO 'pending' with the next run",
          r and r["severity"] == "info" and r["message_key"] == "host_backup_pending"
          and "5 h" in r["params"] and "unit_start" in r["commands"] and r["recommendation_key"] == "timer_pending", r)
    kit.update(next_backup=0)
    write_status(hs, "host-health", status_doc("host-health", data=kit))
    r = await run_check("host.backup")
    check("…next run unknown → estimated from install time + interval",
          r and r["severity"] == "info" and ("22 h" in r["params"] or "23 h" in r["params"]), r)
    kit.update(since_backup=int(now - 31 * 3600))
    write_status(hs, "host-health", status_doc("host-health", data=kit))
    r = await run_check("host.backup")
    check("current script but > interval + grace without a report → warning, check the timer (not 'upgrade')",
          r and r["severity"] == "warning" and r["message_key"] == "host_backup_missing"
          and r["recommendation_key"] == "check_timer", r)
    kit.update(kit_backup=False, since_backup=int(now - 3600))
    write_status(hs, "host-health", status_doc("host-health", data=kit))
    r = await run_check("host.backup")
    check("script cannot report (predates 3.6.8) → warning, run upgrade.sh",
          r and r["severity"] == "warning" and r["recommendation_key"] == "run_upgrade", r)
    write_status(hs, "host-health", status_doc("host-health", data={"timers": timers}))
    write_status(hs, "backup", status_doc("backup", status="error", message="REFUSING: volume missing"))
    r = await run_check("host.backup")
    check("host backup failed → CRITICAL, the message shown, journal + start commands",
          r["severity"] == "critical" and "volume missing" in r["params"]
          and "unit_journal" in r["commands"] and "unit_start" in r["commands"], r)
    write_status(hs, "backup", status_doc("backup", status="warn", message="off-host copy failed"))
    r = await run_check("host.backup")
    check("partly failed (warn) → warning", r["severity"] == "warning", r)
    write_status(hs, "backup", status_doc("backup", ts=int(time.time() - 3 * 86400)))
    r = await run_check("host.backup")
    check("host backup stale (3 days) → warning", r["severity"] == "warning" and r["message_key"] == "host_backup_stale", r)
    write_status(hs, "backup", status_doc("backup", data={"offhost": "ok"}))
    r = await run_check("host.backup")
    check("host backup fresh → ok", r["severity"] == "ok", r)

    write_status(hs, "cloudflare-token", status_doc("cloudflare-token", status="skipped"))
    r = await run_check("host.cloudflare")
    check("no Cloudflare token (HTTP-01) → not applicable", r is None, r)
    write_status(hs, "cloudflare-token", status_doc("cloudflare-token", status="error",
                                                    data={"token_status": "invalid"}))
    r = await run_check("host.cloudflare")
    check("Cloudflare token invalid → critical + edit/recreate commands", r["severity"] == "critical"
          and "cf_token_edit" in r["commands"] and "traefik_recreate" in r["commands"], r)
    write_status(hs, "cloudflare-token", status_doc("cloudflare-token", status="warn",
                                                    data={"token_status": "active", "expires_on": "2026-11-01"}))
    r = await run_check("host.cloudflare")
    check("Cloudflare token expiring → warning with the date", r["severity"] == "warning"
          and "2026-11-01" in r["params"], r)
    # prod's real layout: a separate stack (compose project `authentik`, /opt/authentik) on 2026.8.2
    write_status(hs, "authentik-image", status_doc("authentik-image", status="warn",
                                                   data={"running": "2026.8.2", "pinned": "2026.8.3",
                                                         "layout": "separate", "project": "authentik"}))
    r = await run_check("host.authentik")
    check("Authentik drift (separate stack) → warning naming the project + the upgrade doc, NO command",
          r["severity"] == "warning" and r["doc"] == "authentik_upgrade" and "2026.8.2" in r["params"]
          and '"project":"authentik"' in r["params"] and json.loads(r["commands"]) == [], r)
    check("…the recommendation says: step through minors, 2026.5.x straight to ≥ 2026.8.3",
          "never skip" in syshealth.RECS["authentik_steps"] and "2026.8.3" in syshealth.RECS["authentik_steps"]
          and "scripts/authentik-upgrade.sh" in syshealth.RECS["authentik_steps"])
    v = syshealth.view(r)
    check("…the view links docs/AUTHENTIK-UPGRADE.md", v["doc"] == "docs/AUTHENTIK-UPGRADE.md", v)

    print("── checks: gateway")

    class FakeVfs:
        def __init__(self, pct):
            self.f_frsize, self.f_blocks = 4096, 1000000
            self.f_bavail = int(self.f_blocks * pct / 100)
    orig = syshealth.os.statvfs
    try:
        for pct, sev in ((50, "ok"), (15, "warning"), (5, "critical")):
            syshealth.os.statvfs = lambda _p, pct=pct: FakeVfs(pct)
            r = await run_check("gateway.disk")
            check("disk %d%% free → %s" % (pct, sev), r["severity"] == sev, r)
    finally:
        syshealth.os.statvfs = orig
    ds = await _alerts("gateway_disk")
    check("the disk alert keeps its 3.6.7 kind (gateway_disk) — preferences carry over",
          ds and ds[-1]["severity"] == "critical", ds)

    print("── checks: agents and sessions")
    owner = await U.login(U.OWNER_EMAIL, U.OWNER_PW)
    h1 = await U.add_host(owner, "old-agent")
    h2 = await U.add_host(owner, "new-agent")
    exp = core.agent_expected()["version"]
    await db.execute("UPDATE hosts SET agent_version=? WHERE id=?", exp - 1, h1)
    await db.execute("UPDATE hosts SET agent_version=? WHERE id=?", exp, h2)
    core.sources[h1] = object()
    try:
        r = await run_check("agents.outdated")
        check("an agent just behind → info (not yet a problem)", r["severity"] == "info", r)
        await db.execute("UPDATE app_settings SET value=? WHERE key=?",
                         json.dumps({str(h1): time.time() - 8 * 86400}), syshealth.K_BEHIND)
        r = await run_check("agents.outdated")
        check("behind for > 7 days and connected → warning naming the host", r["severity"] == "warning"
              and json.loads(r["hosts"]) == [h1] and r["action"] == "agent_update", r)
    finally:
        core.sources.pop(h1, None)
    r = await run_check("agents.outdated")
    check("the same host offline → not counted (it updates on reconnect)", r["severity"] == "info", r)
    await db.execute("UPDATE hosts SET supervision_summary=? WHERE id=?",
                     json.dumps({"mode": "none", "linger": False, "boot": False}), h2)
    r = await run_check("agents.autostart")
    check("an agent that does not start at boot → warning + the toggle action", r["severity"] == "warning"
          and json.loads(r["hosts"]) == [h2] and r["action"] == "autostart", r)
    for i in range(syshealth.SESSION_WARN):
        await U.add_session(h2, sid="cap%02d" % i)
    r = await run_check("sessions.cap")
    check("28 of 32 sessions → warning", r["severity"] == "warning" and json.loads(r["hosts"]) == [h2], r)
    await db.execute("DELETE FROM sessions WHERE id LIKE 'cap%'")
    core.agent_clock[h2] = (400.0, time.time())
    core.sources[h2] = object()
    try:
        r = await run_check("agents.clock")
        check("an agent clock 400 s ahead → warning", r["severity"] == "warning" and r["params"].find("400") >= 0, r)
    finally:
        core.sources.pop(h2, None)
        core.agent_clock.clear()
    import socket
    r = await run_check("forward.dns")
    check("no forwards → forward DNS not applicable", r is None, r)
    await U.add_forward(h2, "grafana")
    saved_fwd = api._fwd_domain_cache
    api._fwd_domain_cache = "apps.example.com"
    orig_ghbn, asked = socket.gethostbyname, []

    def fake_ghbn(name):
        asked.append(name)
        raise socket.gaierror("NXDOMAIN")
    socket.gethostbyname = fake_ghbn
    try:
        r = await run_check("forward.dns")
        check("forward DNS missing → warning (DNS only, the wtcheck.<domain> name)", r["severity"] == "warning"
              and asked and asked[0].startswith("wtcheck."), (r, asked))
        socket.gethostbyname = lambda name: "203.0.113.7"
        r = await run_check("forward.dns")
        check("forward DNS answers → ok", r["severity"] == "ok", r)
    finally:
        socket.gethostbyname = orig_ghbn
        api._fwd_domain_cache = saved_fwd
        await db.execute("DELETE FROM port_forwards")
    core._note_agent_clock(h2, float("nan"))
    core._note_agent_clock(h2, "soon")
    check("agent clock: junk collected_at values are ignored", h2 not in core.agent_clock, core.agent_clock)

    print("── checks: SSO, config, janitor, backup, clock")
    saved = (config.OIDC_ENABLED, config.OIDC_SSO_ONLY, config.OIDC_ALLOWED_GROUPS)
    try:
        config.OIDC_ENABLED, config.OIDC_SSO_ONLY = True, False
        oidc._probe.update(ts=time.time(), ok=False, kind="discovery", error="connection refused")
        r = await run_check("oidc.sso")
        check("IdP probe failing → warning", r["severity"] == "warning" and r["message_key"] == "sso_probe_failed", r)
        config.OIDC_SSO_ONLY = True
        r = await run_check("oidc.sso")
        check("…CRITICAL with WEBTERM_OIDC_SSO_ONLY=1", r["severity"] == "critical", r)
        # a recent probe: c_sso must not kick a real one at the (unset) issuer during the test
        oidc._probe.update(ts=time.time(), ok=True, kind="", error="")
        oidc.reset_failures()
        for _ in range(3):
            oidc.note_failure("clock_skew")
        r = await run_check("oidc.sso")
        check("3 classified failures, no success since → sso_broken (kind clock_skew) + clock command",
              r["severity"] == "critical" and '"clock_skew"' in r["params"] and "ntp_status" in r["commands"], r)
        oidc.reset_failures()
        for _ in range(5):
            oidc.note_failure("user")
        r = await run_check("oidc.sso")
        check("people not in the group are NOT 'SSO broken'", r["severity"] == "ok", r)
        oidc.note_failure("invalid_client")
        r = await run_check("oidc.sso")
        check("one invalid_client (a config error) is enough", r["severity"] == "critical", r)
        oidc.reset_failures()
        await test_sso_review_m1()
        config.OIDC_ALLOWED_GROUPS = []
        r = await run_check("config.sso_ungated")
        check("SSO without ALLOWED_GROUPS → warning", r["severity"] == "warning", r)
        e = oidc.OidcError("x", kind="weird")
        check("an unknown error kind is classified 'other'", e.kind == "other")
    finally:
        config.OIDC_ENABLED, config.OIDC_SSO_ONLY, config.OIDC_ALLOWED_GROUPS = saved
        oidc._probe.update(ts=0.0, ok=None, kind="", error="")
    r = await run_check("oidc.sso")
    check("SSO off → not applicable", r is None)

    orig_prune = audit.prune

    async def broken_prune():
        raise RuntimeError("database is locked")
    audit.prune = broken_prune
    try:
        errs = await app_main._janitor_once()
    finally:
        audit.prune = orig_prune
    check("a failing audit prune no longer vanishes: the janitor records it", errs == ["audit"], errs)
    r = await run_check("janitor")
    check("…and System health shows it", r["severity"] == "warning" and "audit" in r["params"], r)
    errs = await app_main._janitor_once()
    r = await run_check("janitor")
    check("a clean run → ok", errs == [] and r["severity"] == "ok", (errs, r))
    await db.execute("UPDATE app_settings SET value=? WHERE key=?",
                     json.dumps({"last_run": time.time() - 3 * 86400, "last_ok": time.time() - 3 * 86400,
                                 "errors": []}), syshealth.K_JANITOR)
    r = await run_check("janitor")
    check("janitor not run for 3 days → warning", r["severity"] == "warning" and r["message_key"] == "janitor_stale", r)
    r = await run_check("db.size")
    check("db size reported (info/ok, never alerted)", r["severity"] in ("ok", "info") and "MB" in r["params"], r)

    for f in os.listdir(hs):
        os.remove(os.path.join(hs, f))
    syshealth._host_snapshot()
    r = await run_check("backup.coverage")
    check("no automatic backup at all → warning", r["severity"] == "warning", r)
    r = await run_check("backup.offhost")
    check("no off-host copy → warning", r["severity"] == "warning", r)
    r = await run_check("backup.restore")
    check("never verified → info", r["severity"] == "info", r)
    await db.execute("INSERT INTO app_settings(key, value) VALUES('backup_schedule','daily')"
                     " ON CONFLICT(key) DO UPDATE SET value='daily'")
    r = await run_check("backup.coverage")
    check("scheduled backup on → coverage ok", r["severity"] == "ok", r)
    await db.execute("INSERT INTO app_settings(key, value) VALUES('backup_last_error', ?)",
                     json.dumps({"ts": time.time(), "error": "disk full", "stage": "snapshot"}))
    r = await run_check("backup.inapp")
    check("scheduled backup failing → warning (alerted elsewhere: mode none)", r["severity"] == "warning"
          and syshealth.BY_ID["backup.inapp"].alert == "none", r)
    await db.execute("DELETE FROM app_settings WHERE key IN ('backup_schedule','backup_last_error')")

    saved_clock = dict(updatecheck.clock)
    try:
        for skew, sev in ((5.0, "ok"), (60.0, "warning"), (-400.0, "critical")):
            updatecheck.clock.update(skew=skew, uncertainty=1.0, at=time.time())
            r = await run_check("clock.gateway")
            check("gateway clock off by %+d s → %s" % (skew, sev), r["severity"] == sev, r)
        updatecheck.clock.update(skew=100.0, uncertainty=90.0, at=time.time())
        r = await run_check("clock.gateway")
        check("a slow round-trip (large uncertainty) is not blamed on the clock", r["severity"] == "ok", r)
    finally:
        updatecheck.clock.clear()
        updatecheck.clock.update(saved_clock)
    updatecheck._note_clock("Tue, 13 Oct 2026 10:00:00 GMT", 1791885590.0, 1791885610.0)
    check("Date header parsed: skew and uncertainty from the round-trip",
          updatecheck.clock["skew"] == 0.0 and updatecheck.clock["uncertainty"] == 11.0, updatecheck.clock)
    updatecheck._note_clock("garbage", 1.0, 2.0)
    check("a junk Date header changes nothing", updatecheck.clock["skew"] == 0.0)
    updatecheck.clock.update(skew=None, uncertainty=None, at=0.0)

    print("── a check that crashes is shown, never silently ok")
    orig_fn = syshealth.BY_ID["db.size"].fn

    async def boom():
        raise ValueError("kaboom")
    syshealth.BY_ID["db.size"].fn = boom
    try:
        r = await run_check("db.size")
        check("a raising check → warning 'check_failed' with the error", r["severity"] == "warning"
              and r["message_key"] == "check_failed" and "kaboom" in r["params"], r)
    finally:
        syshealth.BY_ID["db.size"].fn = orig_fn


async def test_roles_checks(owner_uid):
    """RB-01 / FL-14 (audit 2026-10-17): is there a way to administer this instance tomorrow
    (a PERMANENT Owner), and when the IdP is down (one WITH a local password)? Detected and
    said, with `app.admin promote` in the recommendation — typed by a person, never run."""
    print("── checks: permanent Owner / break-glass Owner")
    r = await run_check("roles.permanent_owner")
    check("one permanent Owner → ok, count 1", r["severity"] == "ok" and r["message_key"] == "permanent_owner_ok"
          and '"count":1' in r["params"], r)
    r = await run_check("roles.break_glass")
    check("…with a local password → break-glass ok", r["severity"] == "ok" and r["message_key"] == "break_glass_ok", r)
    bid = (await db.fetchone("SELECT b.id FROM role_bindings b JOIN roles r ON r.id=b.role_id"
                             " WHERE b.user_id=? AND r.key='owner' AND b.scope_kind='all'", owner_uid))["id"]
    try:
        await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() + 10 * 86400, bid)
        r = await run_check("roles.permanent_owner")
        check("only a time-bound Owner (10 days left) → WARNING no_permanent_owner with the days",
              r["severity"] == "warning" and r["message_key"] == "no_permanent_owner" and '"days":9' in r["params"], r)
        check("…recommendation: app.admin promote, typed not run (no command template → no button)",
              r["recommendation_key"] == "promote_owner" and "app.admin promote" in syshealth.RECS["promote_owner"]
              and "never runs it" in syshealth.RECS["promote_owner"] and r["commands"] in ("[]", "", None), r)
        check("…doc link to the break-glass section", r["doc"] == "break_glass" and "ROLES.md" in syshealth.DOCS["break_glass"], r)
        await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() + 3 * 86400, bid)
        r = await run_check("roles.permanent_owner")
        check("…ends in 3 days (< 7) → CRITICAL permanent_owner_expiring", r["severity"] == "critical"
              and r["message_key"] == "permanent_owner_expiring" and '"days":2' in r["params"], r)
        r = await run_check("roles.break_glass")
        check("a time-bound Owner is no break-glass account → warning no_break_glass", r["severity"] == "warning"
              and r["message_key"] == "no_break_glass" and r["recommendation_key"] == "break_glass_password", r)
        await db.execute("UPDATE role_bindings SET expires=? WHERE id=?", time.time() - 60, bid)
        r = await run_check("roles.permanent_owner")
        check("an expired last Owner → CRITICAL no_owner", r["severity"] == "critical" and r["message_key"] == "no_owner", r)
        await db.execute("UPDATE role_bindings SET expires=NULL WHERE id=?", bid)
        await db.execute("UPDATE users SET local_password=0 WHERE id=?", owner_uid)
        r = await run_check("roles.permanent_owner")
        check("permanent again → ok", r["severity"] == "ok", r)
        r = await run_check("roles.break_glass")
        check("…but SSO-only (no local password) → warning no_break_glass", r["severity"] == "warning"
              and r["message_key"] == "no_break_glass", r)
        check("…its recommendation names app.admin passwd / promote, typed not run",
              "app.admin passwd" in syshealth.RECS["break_glass_password"]
              and "app.admin promote" in syshealth.RECS["break_glass_password"]
              and "never runs them" in syshealth.RECS["break_glass_password"])
        await db.execute("UPDATE users SET disabled=1 WHERE id=?", owner_uid)
        r = await run_check("roles.permanent_owner")
        check("a disabled Owner does not count → critical no_owner", r["severity"] == "critical"
              and r["message_key"] == "no_owner", r)
    finally:
        await db.execute("UPDATE role_bindings SET expires=NULL WHERE id=?", bid)
        await db.execute("UPDATE users SET local_password=1, disabled=0 WHERE id=?", owner_uid)
    r = await run_check("roles.break_glass")
    check("restored → break-glass ok", r["severity"] == "ok", r)
    check("the permanent-Owner check is declared critical-capable (Owner-only mute)",
          syshealth.BY_ID["roles.permanent_owner"].critical is True)
    check("the break-glass check never escalates past warning (not critical-capable)",
          syshealth.BY_ID["roles.break_glass"].critical is False)


async def test_alerting(owner_uid):
    print("── alerting: transitions, dedup, recovery, mute, restart")
    await db.execute("DELETE FROM alerts")
    hs = _hs_dir()
    write_status(hs, "host-health", status_doc("host-health", data={"timers": {
        "webterm-backup.timer": "enabled", "webterm-cert-check.timer": "enabled",
        "webterm-host-health.timer": "enabled", "webterm-docker-cleanup.timer": "enabled"}}))
    write_status(hs, "backup", status_doc("backup"))
    await run_check("host.backup")
    syshealth._rows["host.backup"].update(alerted_severity=None, alerted_at=0)
    write_status(hs, "backup", status_doc("backup", ts=int(time.time() - 3 * 86400)))
    await run_check("host.backup")
    a = await _alerts("health")
    check("ok → warning: one alert", len(a) == 1 and a[0]["severity"] == "warning", a)
    check("…localizable: msg_key 'health' + the check's message key", a and a[0]["msg_key"] == "health"
          and json.loads(a[0]["msg_params"]).get("msg") == "host_backup_stale", a)
    await run_check("host.backup")
    await run_check("host.backup")
    check("the same warning again → no new alert", len(await _alerts("health")) == 1)
    write_status(hs, "backup", status_doc("backup", status="error", message="boom"))
    await run_check("host.backup")
    a = await _alerts("health")
    check("warning → critical: escalation alerts again", len(a) == 2 and a[-1]["severity"] == "critical", a)
    write_status(hs, "backup", status_doc("backup", ts=int(time.time() - 3 * 86400)))
    await run_check("host.backup")
    check("critical → warning: de-escalation does not alert", len(await _alerts("health")) == 2)
    # restart: drop the in-memory state, reload from the DB
    syshealth._rows.clear()
    syshealth._loaded = False
    await syshealth._load()
    await run_check("host.backup")
    check("after a restart the same state does not re-alert", len(await _alerts("health")) == 2)
    write_status(hs, "backup", status_doc("backup"))
    await run_check("host.backup")
    a = await _alerts("health")
    check("back to ok → one 'resolved' alert", len(a) == 3 and a[-1]["severity"] == "ok"
          and a[-1]["msg_key"] == "health_resolved", a)

    # mute until it changes
    write_status(hs, "backup", status_doc("backup", status="error", message="boom"))
    syshealth._rows["host.backup"]["alerted_at"] = 0
    await run_check("host.backup")
    n = len(await _alerts("health"))
    await syshealth.mute("host.backup", "change", "owner@x.co", owner=True)
    syshealth._rows["host.backup"].update(alerted_severity=None, alerted_at=0)
    await run_check("host.backup")
    check("muted 'until it changes' → no alert while the result is the same", len(await _alerts("health")) == n)
    check("…and it does not count in the badge", syshealth.attention(await syshealth.rows())["count"] == 0
          or all(r["id"] != "host.backup" or syshealth._is_muted(r, time.time()) for r in await syshealth.rows()))
    write_status(hs, "backup", status_doc("backup", status="error", message="another failure"))
    await run_check("host.backup")
    row = syshealth._rows["host.backup"]
    check("a different result lifts the mute (and alerts)", float(row.get("muted_until") or 0) == 0
          and len(await _alerts("health")) == n + 1, (row.get("muted_until"), n))
    await syshealth.mute("host.backup", "7d", "owner@x.co", owner=True)
    row = syshealth._rows["host.backup"]
    check("mute 7 d → muted_until about a week ahead", 6.9 * 86400 < float(row["muted_until"]) - time.time() < 7.1 * 86400)
    db_row = await db.fetchone("SELECT muted_until, muted_by FROM health_checks WHERE id='host.backup'")
    check("…persisted, with who muted it", db_row and db_row["muted_by"] == "owner@x.co")
    row["muted_until"] = time.time() - 1
    await run_check("host.backup")
    check("an expired mute is lifted at the next run", float(syshealth._rows["host.backup"]["muted_until"] or 0) == 0)
    await syshealth.mute("host.backup", "off", "owner@x.co", owner=True)

    print("── the alert-delivery check: in-app only, never a loop")
    await db.execute("DELETE FROM alerts")
    calls = {"smtp": 0, "webhook": 0}
    o_send, o_post = email_alerts._send_blocking, email_alerts._post_webhook

    def fake_send(*_a, **_k):
        calls["smtp"] += 1
        raise OSError("SMTP refused")

    def fake_post(*_a, **_k):
        calls["webhook"] += 1
        raise OSError("webhook refused")
    email_alerts._send_blocking, email_alerts._post_webhook = fake_send, fake_post
    try:
        for k, v in (("smtp_host", "smtp.invalid"), ("smtp_to", "ops@x.co"), ("smtp_from", "wt@x.co"),
                     ("alert_webhook", "https://hooks.invalid/x")):
            await db.execute("INSERT INTO app_settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET"
                             " value=excluded.value", k, v)
        await email_alerts._record(email_alerts.K_EMAIL_LAST_FAILED, "x", "535 auth failed")
        for _ in range(5):
            await run_check("alerts.delivery")
        r = syshealth._rows["alerts.delivery"]
        a = await _alerts("alert_delivery")
        check("email failing → CRITICAL", r["severity"] == "critical" and "535" in r["params"], r)
        check("…ONE in-app alert after 5 runs", len(a) == 1, a)
        check("…and nothing sent through SMTP or the webhook (no loop)", calls == {"smtp": 0, "webhook": 0}, calls)
        await email_alerts._record(email_alerts.K_EMAIL_LAST_SENT, "y")
        await email_alerts._record(email_alerts.K_WEBHOOK_LAST_SENT, "y")
        await run_check("alerts.delivery")
        a = await _alerts("alert_delivery")
        check("delivery recovers → 'resolved' in-app only", len(a) == 2 and a[-1]["severity"] == "ok"
              and calls == {"smtp": 0, "webhook": 0}, (a, calls))
        pref = await alert_history.get_prefs(owner_uid)
        check("the delivery alert cannot be switched off in the preferences",
              all(p["kind"] != "alert_delivery" for p in pref))
    finally:
        email_alerts._send_blocking, email_alerts._post_webhook = o_send, o_post
        await db.execute("DELETE FROM app_settings WHERE key IN ('smtp_host','smtp_to','smtp_from','alert_webhook',"
                         "?,?,?,?)", email_alerts.K_EMAIL_LAST_FAILED, email_alerts.K_EMAIL_LAST_SENT,
                         email_alerts.K_WEBHOOK_LAST_SENT, email_alerts.K_WEBHOOK_LAST_FAILED)
    r = await run_check("alerts.channel")
    check("no channel configured → info", r["severity"] == "info" and r["message_key"] == "no_channel", r)

    print("── the update notice: once per version")
    await db.execute("DELETE FROM alerts")
    saved = dict(updatecheck._cache)
    try:
        updatecheck._cache["data"] = {"enabled": True, "latest": "v9.9.9", "update_available": True}
        for _ in range(3):
            await run_check("update.available")
        a = await _alerts("health")
        check("a new version → one info alert", len(a) == 1 and a[0]["severity"] == "info", a)
        r = syshealth._rows["update.available"]
        check("…with the upgrade command for that exact tag",
              healthcmd.render_list(json.loads(r["commands"]))[0]["text"] == "sudo -k /opt/webterm/upgrade.sh v9.9.9", r)
        updatecheck._cache["data"] = {"enabled": True, "latest": "v9.9.9; rm -rf /", "update_available": True}
        r = await run_check("update.available")
        check("a hostile 'latest' tag → no command at all",
              healthcmd.render_list(json.loads(r["commands"])) == [], r["commands"])
        updatecheck._cache["data"] = {"enabled": True, "latest": "v9.9.10", "update_available": True}
        await run_check("update.available")
        n = len(await _alerts("health"))
        await run_check("update.available")
        check("the next version → exactly one more", len(await _alerts("health")) == n and n == 3, n)
    finally:
        updatecheck._cache.clear()
        updatecheck._cache.update(saved)

    print("── views: host names only for visible hosts")
    row = {"id": "agents.autostart", "severity": "warning", "message_key": "agents_no_autostart",
           "params": json.dumps({"count": 3}), "hosts": json.dumps([1, 2, 3]), "commands": "[]"}
    v = syshealth.view(row, time.time(), {1: "lab-1"})
    check("only the visible host is named; the others are counted", v["hosts"] == [{"id": 1, "name": "lab-1"}]
          and v["hosts_hidden"] == 2, v)
    row["commands"] = json.dumps([{"t": "unit_start", "p": {"unit": "evil.service"}}, {"t": "host_health", "p": {}}])
    v = syshealth.view(row)
    check("a stored command that no longer validates is dropped at view time",
          [c["template"] for c in v["commands"]] == ["host_health"], v["commands"])


# ── 4. routes ──────────────────────────────────────────────────────────────────────────────────
async def test_routes(owner_uid):
    print("── routes: who may see, re-check, mute, open a terminal")
    owner = await U.login(U.OWNER_EMAIL, U.OWNER_PW)
    await U.add_user("admin@x.co", bindings=[("admin", "all", "")])
    await U.add_user("op@x.co", bindings=[("operator", "all", "")])
    await U.add_user("view@x.co", bindings=[("viewer", "all", "")])
    admin, op, view = await U.login("admin@x.co"), await U.login("op@x.co"), await U.login("view@x.co")
    anon = U.client()
    tok = U.client(headers={"authorization": "Bearer wt_nope"})
    syshealth._last_manual = 0
    await syshealth.run(("fast",))

    r = await anon.get("/api/health")
    check("anonymous → 401", r.status_code == 401, r.status_code)
    r = await owner.get("/api/health")
    j = r.json()
    check("Owner: 200, can_manage + can_terminal", r.status_code == 200 and j["can_manage"] and j["can_terminal"], r.text[:200])
    check("…commands rendered by the server", any(c["commands"] for c in j["checks"]), [c["id"] for c in j["checks"]])
    r = await admin.get("/api/health")
    check("Admin (security.view + settings.manage): 200, no terminal", r.status_code == 200
          and r.json()["can_manage"] and not r.json()["can_terminal"] and r.json()["terminal_host"] is None)
    for who, c in (("Operator", op), ("Viewer", view)):
        r = await c.get("/api/health")
        check("%s → 403" % who, r.status_code == 403 and U.code(r) == "authz.denied", r.status_code)
    r = await tok.get("/api/health")
    check("a Bearer token → refused (the token allow-list is unchanged)", r.status_code in (401, 403), r.status_code)
    r = await owner.get("/api/state")
    check("/api/state carries the attention badge for security.view", isinstance(r.json().get("health_attention"), dict), r.json().get("health_attention"))
    r = await op.get("/api/state")
    check("…and not for an Operator", r.json().get("health_attention") is None)

    syshealth._last_manual = 0
    r1 = await admin.post("/api/health/check")
    r2 = await owner.post("/api/health/check")
    check("Re-check now: Admin may (settings.manage)", r1.status_code == 200, r1.text[:200])
    check("…a second within 30 s → 429 health.rateLimited + Retry-After", r2.status_code == 429
          and U.code(r2) == "health.rateLimited" and int(r2.headers.get("retry-after", "0")) > 0)
    for who, c in (("Operator", op), ("Viewer", view), ("token", tok)):
        r = await c.post("/api/health/check")
        check("Re-check: %s refused" % who, r.status_code in (401, 403), r.status_code)

    r = await view.post("/api/health/host.backup/mute", json={"mode": "7d"})
    check("Viewer cannot mute", r.status_code == 403)
    r = await owner.post("/api/health/host.backup/mute", json={"mode": "forever"})
    check("an unknown mute mode → 400", r.status_code == 400 and U.code(r) == "health.badMute")
    r = await owner.post("/api/health/no.such/mute", json={"mode": "7d"})
    check("an unknown check → 404", r.status_code == 404 and U.code(r) == "health.missing")
    r = await owner.post("/api/health/'%3B--/mute", json={"mode": "7d"})
    check("a hostile check id → 400", r.status_code in (400, 404))
    r = await admin.post("/api/health/host.helper/mute", json={"mode": "change"})
    check("Admin mutes 'until it changes'", r.status_code == 200
          and any(c["id"] == "host.helper" and c["muted"] for c in r.json()["checks"]), r.text[:300])
    aud = await db.fetchone("SELECT detail FROM audit_log WHERE path LIKE '/api/health/%/mute' ORDER BY id DESC LIMIT 1")
    check("…audited", aud and "host.helper" in aud["detail"] and "change" in aud["detail"], aud and dict(aud))
    await admin.post("/api/health/host.helper/mute", json={"mode": "off"})

    print("── mute: critical-capable checks are the Owner's (review L1)")
    await _settle()
    owner_row = await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL)
    al = await db.fetchall("SELECT kind, msg_key, msg_params, user_id FROM alerts WHERE msg_key='health_muted'")
    check("an Admin's mute → an in-app alert (admin_change) for the Owner (security.view)",
          any(a["kind"] == "admin_change" and a["user_id"] == owner_row["id"]
              and json.loads(a["msg_params"]).get("check") == "host.helper"
              and json.loads(a["msg_params"]).get("email") == "admin@x.co" for a in al), [dict(a) for a in al])
    viewer_row = await db.fetchone("SELECT id FROM users WHERE email='view@x.co'")
    check("…not for a Viewer (no security.view)", not any(a["user_id"] == viewer_row["id"] for a in al))
    n_alerts = len(al)
    r = await admin.post("/api/health/gateway.disk/mute", json={"mode": "30d"})
    check("Admin cannot mute a critical-capable check (gateway.disk) → 403 health.muteOwnerOnly",
          r.status_code == 403 and U.code(r) == "health.muteOwnerOnly", r.text[:200])
    for mode in ("7d", "change"):
        r = await admin.post("/api/health/oidc.sso/mute", json={"mode": mode})
        check("…nor pre-emptively (%s), whatever the mode" % mode, r.status_code in (403, 404), r.status_code)
    check("…and nothing was muted", not syshealth._is_muted(syshealth._rows["gateway.disk"], time.time()))
    r = await admin.get("/api/health")
    j = r.json()
    gd = next(c for c in j["checks"] if c["id"] == "gateway.disk")
    check("view(): mute_owner_only on a critical-capable check; Admin: can_mute_critical false",
          gd["mute_owner_only"] is True and j["can_mute_critical"] is False, (gd.get("mute_owner_only"), j.get("can_mute_critical")))
    ch = next((c for c in j["checks"] if c["id"] == "alerts.channel"), None)
    check("…false on one that cannot become critical", ch is None or ch["mute_owner_only"] is False, ch)
    r = await owner.post("/api/health/gateway.disk/mute", json={"mode": "7d"})
    gd = next((c for c in r.json()["checks"] if c["id"] == "gateway.disk"), {}) if r.status_code == 200 else {}
    check("the Owner may mute it; view() shows muted_by + muted_until", r.status_code == 200 and gd.get("muted")
          and gd.get("muted_by") == U.OWNER_EMAIL and gd.get("muted_until", 0) > time.time() + 6 * 86400, gd)
    check("…and an Owner's mute raises no 'muted' alert", len(await db.fetchall(
        "SELECT id FROM alerts WHERE msg_key='health_muted'")) == n_alerts)
    r = await admin.post("/api/health/gateway.disk/mute", json={"mode": "off"})
    check("an Admin may LIFT a mute (it hides nothing)", r.status_code == 200
          and not next(c for c in r.json()["checks"] if c["id"] == "gateway.disk")["muted"], r.text[:200])
    # a check NOT declared critical-capable that is critical right now: Owner only as well…
    if "alerts.channel" in syshealth._rows:
        syshealth._rows["alerts.channel"]["severity"] = "critical"
        r = await admin.post("/api/health/alerts.channel/mute", json={"mode": "7d"})
        check("a check that IS critical now → Owner only", r.status_code == 403, r.status_code)
        # …and the safety net: an Admin's earlier mute never hides a critical of such a check
        syshealth._rows["alerts.channel"].update(severity="info", muted_until=time.time() + 3600, muted_by="admin@x.co")
        syshealth._rows["alerts.channel"]["severity"] = "critical"
        check("an undeclared check turning critical is not hidden by a mute",
              not syshealth._is_muted(syshealth._rows["alerts.channel"], time.time()))
        syshealth._rows["alerts.channel"].update(severity="info", muted_until=0, muted_by=None)
    flagged = {c.id for c in syshealth.CHECKS if c.critical}
    import inspect
    unflagged_crit = [c.id for c in syshealth.CHECKS if not c.critical and c.fn.__name__.startswith("c_")
                      and re.search(r'"critical"|\bsev\b', inspect.getsource(c.fn))]
    check("every check function that can return critical is declared critical-capable", not unflagged_crit, unflagged_crit)
    check("…the declared set (host.backup via fail_sev, certs.* via _CERT_SEV)", {
        "host.backup", "host.cloudflare", "gateway.disk", "alerts.delivery", "signing.state", "oidc.sso",
        "config.forwards_http", "certs.main", "certs.forward", "certs.authentik", "clock.gateway",
        "agents.python", "roles.permanent_owner"} == flagged, flagged)

    print("── the health terminal")
    hid = await U.add_host(owner, "gw-host")
    for f in os.listdir(_hs_dir()):
        os.remove(os.path.join(_hs_dir(), f))
    await syshealth.run(("fast",))
    url = "/api/hosts/%d/health-terminal" % hid
    created = []
    orig_create = core.create_session

    async def fake_create(host_id, title, rows=24, cols=80, tz=None, cmd=None, pw=None,
                          created_by_id=None, origin=None):
        created.append({"host_id": host_id, "title": title, "cmd": cmd, "by": created_by_id, "origin": origin})
        sid = "s-health-%d" % len(created)
        await db.execute("INSERT INTO sessions(id, host_id, title, state, created, created_by_id, origin)"
                         " VALUES(?,?,?,?,?,?,?)", sid, host_id, title, "live", time.time(),
                         created_by_id, origin or "web")
        return {"id": sid, "host_id": host_id, "title": title}
    core.create_session = fake_create
    try:
        body = {"check_id": "host.helper", "index": 0, "stepup_password": U.OWNER_PW}
        r = await owner.post(url, json=body)
        check("no gateway host picked → 409 certs.noRenewHost", r.status_code == 409 and U.code(r) == "certs.noRenewHost")
        r = await owner.put("/api/certs/renew-host", json={"host_id": hid})
        check("Owner picks the gateway host", r.status_code == 200)
        r = await admin.post(url, json=dict(body, stepup_password="parolabuna1"))
        check("Admin → 403 (certs.renew is Owner-only)", r.status_code == 403 and U.code(r) == "authz.denied")
        r = await op.post(url, json=body)
        check("Operator → 403", r.status_code == 403)
        r = await tok.post(url, json=body)
        check("token → refused", r.status_code in (401, 403))
        other = await U.add_host(owner, "not-the-gw")
        r = await owner.post("/api/hosts/%d/health-terminal" % other, json=body)
        check("another host → 409 certs.wrongRenewHost", r.status_code == 409 and U.code(r) == "certs.wrongRenewHost")
        r = await owner.post(url, json=dict(body, check_id="no.such"))
        check("an unknown check → 404", r.status_code == 404 and U.code(r) == "health.missing")
        r = await owner.post(url, json=dict(body, check_id="backup.coverage"))
        check("a check without commands → 400 health.noCommand", r.status_code == 400 and U.code(r) == "health.noCommand")
        r = await owner.post(url, json=dict(body, index=2))
        check("an index past its commands → 400", r.status_code == 400 and U.code(r) == "health.noCommand")
        r = await owner.post(url, json=dict(body, index=7))
        check("an index outside 0..2 → 422", r.status_code == 422)
        r = await owner.post(url, json={"check_id": "host.helper", "index": 0})
        check("no fresh factor → stepup.*, NOTHING created", r.status_code == 403 and U.code(r).startswith("stepup.")
              and not created, "%s %s" % (r.status_code, U.code(r)))
        # OP-01 (audit 2026-10-17): a root command on the gateway host ALWAYS needs a real second
        # factor — the host is not marked require_2fa, and the password alone used to open it
        r = await owner.post(url, json=body)
        check("the account password alone → 403 stepup.needsFactor, NOTHING created (host without 2FA)",
              r.status_code == 403 and U.code(r) == "stepup.needsFactor" and not created,
              "%s %s" % (r.status_code, U.code(r)))
        check("…the message points to Settings → Sign-in & 2FA", "Sign-in & 2FA" in r.text, r.text[:200])
        security._stepup_windows.clear()
        r = await owner.post("/api/hosts/%d/stepup" % hid, json={"stepup_password": U.OWNER_PW})
        check("…a window the password opened through /stepup (host without 2FA) is not accepted either",
              r.status_code == 200 and r.json().get("opened") is True
              and (await owner.post(url, json={"check_id": "host.helper", "index": 0})).status_code == 403
              and not created, r.text[:200])
        security.open_stepup_window(owner_uid, hid)          # what a passkey / SSO / TOTP ceremony leaves
        r = await owner.post(url, json=dict(body, command="rm -rf / #", template="bash", params={"x": "$(id)"}))
        check("Owner + host + check + fresh factor → the session", r.status_code == 200 and created, r.text[:200])
        want = "sudo -k /opt/webterm/scripts/host-health.sh --install"
        check("…the command is the SERVER's (client fields ignored)", r.json().get("command") == want, r.json())
        c = created[0] if created else {}
        check("…typed, not run (read -e -i), as an argument", "read -r -e -i" in (c.get("cmd") or "")
              and "rm -rf" not in (c.get("cmd") or ""), (c.get("cmd") or "")[-200:])
        check("…private session: origin health-fix, owned by the Owner", c.get("origin") == "health-fix"
              and c.get("by") == owner_uid, c)
        r = await owner.post("/api/sessions/%s/share" % (r.json().get("id")), json={"expires_minutes": 5})
        check("…which cannot be shared", r.status_code == 403 and U.code(r) == "certs.renewSessionPrivate", r.text[:200])
        aud = await db.fetchone("SELECT detail FROM audit_log WHERE path=? ORDER BY id DESC LIMIT 1", url)
        check("…audited with the command", aud and "host-health.sh --install" in aud["detail"], aud and dict(aud))
        row = (await db.fetchone("SELECT * FROM sessions WHERE id='s-health-1'"))
        access = await api._ws_access((await db.fetchone("SELECT id FROM users WHERE email='admin@x.co'"))["id"], row)
        check("…an Admin may only watch it (ro)", access == "ro", access)
        # a tampered DB row: the stored command must still pass the allow-list at use time
        await db.execute("UPDATE health_checks SET commands=? WHERE id='host.helper'",
                         json.dumps([{"t": "unit_start", "p": {"unit": "evil.service; id"}}]))
        syshealth._rows["host.helper"]["commands"] = json.dumps([{"t": "unit_start", "p": {"unit": "evil.service; id"}}])
        n = len(created)
        r = await owner.post(url, json=body)
        check("a stored command that fails the allow-list → 400, nothing created", r.status_code == 400
              and len(created) == n, r.text[:200])
    finally:
        core.create_session = orig_create
    await syshealth.run(("fast",))

    print("── backup verification")
    from app import backup as backup_mod
    name = await asyncio.to_thread(backup_mod.run_scheduled_backup, False)
    r = await admin.post("/api/backup/stored/%s/verify" % name)
    check("Admin cannot verify (backups.manage is Owner-only)", r.status_code == 403)
    r = await owner.post("/api/backup/stored/%s/verify" % name)
    check("Owner verifies a stored snapshot → ok, nothing restored", r.status_code == 200 and r.json()["ok"]
          and r.json()["has_secret"], r.text[:200])
    r = await owner.get("/api/backup/status")
    check("…restore_verified_at recorded", (r.json().get("restore_verified_at") or 0) > time.time() - 60, r.json().get("restore_verified_at"))
    await run_check("backup.restore")
    check("…and System health says so", syshealth._rows["backup.restore"]["severity"] == "ok")
    bad = config.DATA_DIR / "backups" / "broken.wtsnap"
    bad.write_bytes(b"not a tarball")
    r = await owner.post("/api/backup/stored/broken.wtsnap/verify")
    check("a corrupt snapshot → 400", r.status_code == 400, r.text[:200])
    r = await owner.post("/api/backup/stored/..%2F..%2Fwebterm.db/verify")
    # 405 when the SPA catch-all exists (a built frontend/dist): refused either way
    check("a path in the name → refused", r.status_code in (400, 404, 405), r.status_code)
    blob = await asyncio.to_thread(backup_mod.encrypt_stored, name, "a-good-passphrase")
    r = await owner.post("/api/backup/verify", content=blob, headers={"X-Restore-Pass": "a-good-passphrase",
                                                                      "content-type": "application/octet-stream"})
    check("an uploaded .wtbk verifies (decrypt + integrity)", r.status_code == 200 and r.json()["ok"], r.text[:200])
    r = await owner.post("/api/backup/verify", content=blob, headers={"X-Restore-Pass": "wrong-passphrase",
                                                                      "content-type": "application/octet-stream"})
    check("…a wrong passphrase → 400 backup.badPassphrase", r.status_code == 400
          and U.code(r) == "backup.badPassphrase", r.text[:200])
    check("…nothing staged for restore", not (config.DATA_DIR / "restore-pending").exists())


def test_admin_cli():
    print("── the admin CLI reads the same rows")
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "gateway"))
    p = subprocess.run([sys.executable, "-m", "app.admin", "health"], env=env, capture_output=True,
                       text=True, timeout=60, cwd="/")
    out = p.stdout
    check("`admin health` exits 0 and prints severity-tagged lines", p.returncode == 0
          and re.search(r"^\[(WARNING|CRITICAL|INFO)\] ", out, re.M), out[:400] + p.stderr[-400:])
    check("…with why / fix / the exact command", "    why: " in out and "    $ sudo -k " in out, out[:600])
    p = subprocess.run([sys.executable, "-m", "app.admin", "health", "--json"], env=env, capture_output=True,
                       text=True, timeout=60, cwd="/")
    try:
        j = json.loads(p.stdout)
    except ValueError:
        j = {}
    check("`--json` is machine-readable", isinstance(j.get("checks"), list) and j["checks"], p.stdout[:200])
    t0 = time.time()
    p = subprocess.run([sys.executable, "-m", "app.admin", "health", "--wait", "3", "--newer-than",
                        str(time.time() + 3600)], env=env, capture_output=True, text=True, timeout=60, cwd="/")
    check("`--wait` is bounded and says the results are older", p.returncode == 0 and time.time() - t0 < 15
          and "has not re-checked yet" in p.stdout, p.stdout[:200])


def test_catalog():
    print("── the English catalog (Python) ↔ en.ts / ro.ts")
    KEY_RE = re.compile(r"^\s*'([a-zA-Z0-9_.]+)':\s*\"(.*)\",?\s*$", re.M)
    cats = {}
    for lang in ("en", "ro"):
        with open(os.path.join(ROOT, "frontend", "src", "lang", lang + ".ts"), encoding="utf-8") as f:
            cats[lang] = dict(KEY_RE.findall(f.read()))
    var = re.compile(r"\{([a-z_]+)\}")
    for lang, cat in cats.items():
        miss = []
        for k, txt in syshealth.MESSAGES.items():
            ui = cat.get("health.msg." + k) or cat.get("health.msg." + k + ".other")
            if ui is None or set(var.findall(ui)) != set(var.findall(txt)):
                miss.append(k)
        check("%s: every check message exists with the same placeholders" % lang, not miss, miss[:8])
        miss = [k for k in syshealth.WHY if "health.why." + k not in cat]
        check("%s: every 'why' exists" % lang, not miss, miss)
        miss = [k for k in syshealth.RECS if "health.rec." + k not in cat]
        check("%s: every recommendation exists" % lang, not miss, miss)
        miss = [c.id for c in syshealth.CHECKS if "health.check." + c.id.replace(".", "_", 1) not in cat]
        check("%s: every check has a title" % lang, not miss, miss)
    check("every check id has a 'why'", all(syshealth._why_key(c.id) in syshealth.WHY for c in syshealth.CHECKS),
          [c.id for c in syshealth.CHECKS if syshealth._why_key(c.id) not in syshealth.WHY])
    rec_used = set()
    import inspect
    src = inspect.getsource(syshealth)
    rec_used = set(re.findall(r'rec="([a-z_]+)"', src))
    check("every recommendation used by a check is in RECS", rec_used <= set(syshealth.RECS), rec_used - set(syshealth.RECS))
    keys_used = set(re.findall(r'Result\(\s*"[a-z]+",\s*"([a-z_]+)"', src))
    check("every message key used by a check is in MESSAGES", keys_used <= set(syshealth.MESSAGES),
          keys_used - set(syshealth.MESSAGES))
    ro_bad = [k for k, v in cats["ro"].items() if k.startswith("health.") and re.search("[şţŞŢ]", v)]
    check("ro: comma-below ș/ț only (no cedilla) in the health strings", not ro_bad, ro_bad[:5])


async def amain():
    await U.boot()
    owner = await U.owner_client()
    owner_uid = (await db.fetchone("SELECT id FROM users WHERE email=?", U.OWNER_EMAIL))["id"]
    await owner.aclose()
    syshealth.reset_for_tests()
    await test_checks(owner_uid)
    await test_roles_checks(owner_uid)
    await test_alerting(owner_uid)
    await test_routes(owner_uid)
    await db.close()


def main():
    test_parser()
    test_commands()
    asyncio.run(amain())
    test_admin_cli()
    test_catalog()
    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
