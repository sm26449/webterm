"""System health (3.6.8) — one list of everything that can fail silently.

The owner's principle: whatever WebTerm cannot fix from the UI, it DETECTS, NOTIFIES, EXPLAINS and
RECOMMENDS — with the exact command. Before this release each of these failed quietly somewhere:
a host timer that only told journald, a Cloudflare token revoked months ago, an SMTP server that
had been refusing alerts for weeks (visible only in the Notifications tab), an agent update
deferred forever by a session nobody closes, an SSO outage that looked like "denied", an audit
retention that swallowed its own exception…

How it works:
  * a REGISTRY of checks (`CHECKS`), each an async function returning a `Result` (or None = not
    applicable here). Three tiers: `fast` (every 30 s — memory, DB and small-file reads only),
    `hourly` (bounded network: the IdP probe), `daily` (the forward-domain DNS probe). Each check
    runs under its own timeout; a check that raises becomes a visible "the check itself failed"
    row, never a silent "ok";
  * results are persisted in `health_checks` (the admin CLI and upgrade.sh read the same rows:
    one source of truth). A result never holds a command STRING — only template ids + parameters,
    rendered by healthcmd.py when shown or typed;
  * alerting on TRANSITIONS: to warning/critical → one alert (escalation fires again, the same
    level does not, except a daily reminder for critical); back to ok/info → one "resolved".
    Per check `alert` mode: `transition` (default), `none` (another module already alerts —
    certmon, the backup scheduler, the signing-key nag), `inapp` (the alert-delivery check: it
    must NOT go through the channel that is failing, so it writes the in-app history only — no
    email, no webhook, no loop), `version` (once per new WebTerm version);
  * mute: 7 days, 30 days or "until it changes" (the result's signature), audited.

What it deliberately does NOT do: run anything privileged. The gateway gets no new privilege —
host facts arrive as status files written by root helpers on the host (hoststatus.py, untrusted
input), and every fix that needs root is a command an Owner copies or has typed (not run) into a
terminal on the gateway host.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

from . import alert_history, config, db, healthcmd, hoststatus

log = logging.getLogger("webterm")

SEVERITIES = ("ok", "info", "warning", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
FAST_TICK = 30.0
HOURLY = 3600.0
DAILY = 86400.0
CHECK_TIMEOUT = 10.0             # per check (the network ones bound themselves tighter)
NETWORK_TIMEOUT = 20.0
MANUAL_MIN_INTERVAL = 30.0       # "Re-check now": at most once per 30 s, instance-wide
REMIND_CRITICAL = 24 * 3600.0    # a critical that stays critical is re-sent once a day
MIN_REALERT = 600.0              # a flapping check does not alert more than every 10 min
PERSIST_EVERY = 600.0            # unchanged results: refresh checked_at in the DB every 10 min
SESSION_WARN = 28                # of core.MAX_SESSIONS_HINT (32)
MAX_HOSTS_IN_RESULT = 50
DOCS = {"authentik_upgrade": "docs/AUTHENTIK-UPGRADE.md", "heartbeat": "docs/INSTALL.md#dead-man-switch",
        "host_health": "docs/INSTALL.md#system-health",
        "host_requirements": "docs/INSTALL.md#supported-hosts"}
K_LAST_RUN = "health_last_run"
K_BEHIND = "health_agent_behind_since"
K_JANITOR = "janitor_state"
K_RESTORE_VERIFIED = "restore_verified_at"
K_UPDATE_ALERTED = "health_update_alerted"


@dataclass
class Result:
    severity: str
    key: str                                     # health.msg.<key> (en.ts / ro.ts / MESSAGES)
    params: dict = field(default_factory=dict)   # scalars only, bounded (see _clean_params)
    rec: str = ""                                # health.rec.<rec>
    commands: list = field(default_factory=list)  # [{"t": template, "p": {...}}] — healthcmd.py
    action: str = ""                             # a UI action id, see ACTIONS
    hosts: list = field(default_factory=list)    # host ids concerned (names resolved per viewer)
    doc: str = ""                                # key of DOCS


ACTIONS = ("settings:notifications", "settings:backup", "settings:signing", "settings:certificates",
           "settings:sso", "agent_update", "autostart", "settings:forward", "about:update")


@dataclass
class Check:
    id: str
    tier: str                     # fast | hourly | daily
    fn: Callable[[], Awaitable[Optional[Result]]]
    source: str = "gateway"       # gateway | host_helper
    alert: str = "transition"     # transition | none | inapp | version
    kind: str = "health"          # alert_history kind (preferences)
    timeout: float = CHECK_TIMEOUT
    # can this check ever return `critical`? Muting such a check needs certs.renew (the Owner):
    # security review 3.6.8 (L1) — an Admin must not silence, even pre-emptively, a check that
    # can turn critical and so hide it from the Owner. tests/syshealth_test.py keeps it honest.
    critical: bool = False


# ── English text (emails, webhook, the admin CLI). The UI uses en.ts / ro.ts with the SAME keys
# (tests/syshealth_test.py keeps them in step). {placeholders} = params.
MESSAGES = {
    # host helpers
    "helper_missing": "The host helper (scripts/host-health.sh) has never reported",
    "helper_stale": "The host helper last reported {age} ago",
    "helper_timers": "Host timers are not active: {timers}",
    "helper_invalid": "A host status file was refused ({file}: {error})",
    "helper_ok": "The host helper reports regularly",
    "host_backup_failed": "The host backup failed: {message}",
    "host_backup_stale": "The last host backup report is {age} old",
    "host_backup_missing": "The backup timer is enabled but has never reported",
    "host_backup_pending": "The host backup has not run since the host scripts were updated — next run in {next}",
    "host_backup_ok": "Host backup OK ({age} ago)",
    "cert_check_failed": "The host certificate check failed: {message}",
    "cert_check_stale": "The host certificate check last reported {age} ago",
    "cert_check_missing": "The certificate check timer is enabled but has never reported",
    "cert_check_pending": "The certificate check has not run since the host scripts were updated — next run in {next}",
    "cert_check_ok": "Host certificate check OK",
    "cleanup_failed": "The Docker cleanup failed: {message}",
    "cleanup_stale": "The Docker cleanup last reported {age} ago",
    "cleanup_missing": "The Docker cleanup timer is enabled but has never reported",
    "cleanup_pending": "The Docker cleanup has not run since the host scripts were updated — next run in {next}",
    "cleanup_ok": "Docker cleanup OK ({pct}% free after it)",
    "cf_token_invalid": "The Cloudflare DNS token is {status}",
    "cf_token_expiring": "The Cloudflare DNS token expires on {expires}",
    "cf_token_unknown": "The Cloudflare DNS token could not be checked: {message}",
    "cf_token_stale": "The Cloudflare DNS token was last checked {age} ago",
    "cf_token_ok": "The Cloudflare DNS token is active",
    "authentik_drift": "Authentik (compose project {project}) runs {running}; WebTerm pins {pinned}",
    "authentik_ok": "Authentik runs the pinned version ({running})",
    # gateway
    "disk_critical": "The gateway disk has {pct}% free ({free} of {total})",
    "disk_low": "The gateway disk has {pct}% free ({free} of {total})",
    "disk_ok": "Gateway disk: {pct}% free",
    "delivery_email_failed": "Email alerts are failing: {error}",
    "delivery_webhook_failed": "Webhook alerts are failing: {error}",
    "delivery_ok": "Alert delivery works",
    "no_channel": "No external alert channel (email or webhook) is configured",
    "channel_ok": "An external alert channel is configured",
    "agents_outdated": "{count} agent(s) have been behind v{version} for more than {days} days",
    "agents_behind_recent": "{count} agent(s) are not yet on v{version}",
    "agents_current": "Every connected agent is on v{version}",
    "agents_no_autostart": "{count} agent(s) will not start again after a reboot",
    "agents_autostart_ok": "Every agent that reports it starts at boot",
    "agents_python_old": "{count} agent(s) run on a Python older than 3.6 (the agent's minimum): file operations fail there",
    "agents_python_likely": "{count} agent(s) run on an OS whose Python is older than 3.6 (the agent's minimum): file operations will fail there",
    "agents_python_ok": "No agent shows signs of a Python older than 3.6",
    "agents_update_blocked": "{count} agent(s) refuse the signed update",
    "agents_update_ok": "No agent refuses updates",
    "agents_clock_skew": "{count} agent(s) have a clock off by up to {skew} s",
    "agents_clock_ok": "Agent clocks agree with the gateway",
    "sessions_near_cap": "{count} host(s) are at {threshold}+ of {limit} sessions",
    "sessions_ok": "No host is near its session limit",
    "signing_unsigned": "Agent updates cannot be delivered: no signing key and no signature",
    "signing_locked": "The signing key is locked: {behind} agent(s) cannot update",
    "signing_ok": "Agent updates are signed",
    "sso_broken": "SSO is failing ({kind}): {count} failed sign-in(s) in the last hour",
    "sso_probe_failed": "The identity provider is unreachable ({kind}): {error}",
    "sso_ok": "SSO works",
    "insecure_forwards": "Port forwarding is on while WebTerm runs on plain http://",
    "sso_ungated": "SSO is on without WEBTERM_OIDC_ALLOWED_GROUPS",
    "janitor_failed": "The daily cleanup failed: {steps}",
    "janitor_stale": "The daily cleanup last ran {age} ago",
    "janitor_ok": "The daily cleanup runs",
    "db_compact": "The database is {size}, {free_pct}% of it free pages",
    "db_ok": "Database: {size}",
    "backup_none": "No automatic backup is configured",
    "backup_ok": "An automatic backup runs",
    "backup_no_offhost": "No backup leaves this machine",
    "offhost_ok": "Backups are copied off this machine",
    "restore_never_verified": "No backup has ever been verified",
    "restore_verified_old": "A backup was last verified {days} days ago",
    "restore_ok": "A backup was verified {days} days ago",
    "backup_inapp_failed": "The scheduled backup failed ({stage}): {error}",
    "backup_inapp_ok": "The scheduled backup works",
    "cert_ok": "TLS certificate for {name}: {days} days left",
    "cert_expiring": "TLS certificate for {name} expires in {days} days",
    "cert_expired": "TLS certificate for {name} has expired",
    "cert_default": "Traefik serves its default certificate for {name}",
    "cert_mismatch": "The certificate served for {name} does not cover it",
    "cert_error": "The TLS certificate for {name} could not be checked",
    "heartbeat_failing": "The dead-man switch ping is failing: {error}",
    "heartbeat_off": "No dead-man switch (WEBTERM_HEARTBEAT_URL) is configured",
    "heartbeat_ok": "The dead-man switch is pinged every {minutes} min",
    "update_available": "WebTerm {latest} is available (running {current})",
    "update_current": "WebTerm is up to date ({current})",
    "clock_skew": "The gateway clock is off by {skew} s",
    "clock_ok": "The gateway clock is right",
    "forward_dns_missing": "No DNS record answers for *.{domain}",
    "forward_dns_ok": "Forward DNS for *.{domain} answers",
    "check_failed": "This check could not run: {error}",
}
WHY = {
    "host.helper": "Host timers (backup, certificate check, Docker cleanup) and the Cloudflare token are only visible to WebTerm through this helper.",
    "host.backup": "A nightly backup that fails quietly is worse than none: you believe you have one.",
    "host.cert_check": "It is the host-side second opinion on the certificate Traefik serves.",
    "host.docker_cleanup": "Without it old images and build cache fill the disk the database lives on.",
    "host.cloudflare": "DNS-01 certificates (the forward wildcard) renew only with a valid token; a revoked or expired one fails silently until the certificate expires.",
    "host.authentik": "Authentik must be upgraded one release line at a time; a large jump can break its database migration.",
    "gateway.disk": "When the data volume fills up, logins fail with 500 while the container still reports healthy.",
    "alerts.delivery": "If alerts cannot leave, every other alert is silent too. This one is shown in the app only, never through the failing channel.",
    "alerts.channel": "Without email or a webhook, alerts only reach people who open WebTerm.",
    "agents.outdated": "An agent defers its update while sessions are open; a session that never closes keeps it on old code forever.",
    "agents.autostart": "After a reboot such a host stays offline until someone starts the agent by hand.",
    "agents.python": "The agent needs Python 3.6+. On 3.5 it connects and runs terminals, but every file listing — and so every upload — fails with an internal error.",
    "agents.update_blocked": "A host that refuses updates stays without the fixes shipped since.",
    "agents.clock": "A wrong clock breaks TOTP codes, SSO tokens and the order of audit entries.",
    "sessions.cap": "At the limit, new terminals on that host are refused.",
    "signing.state": "Agents only accept signed updates; without a usable key the fleet stays on old code.",
    "oidc.sso": "When SSO fails, every SSO account is locked out; with WEBTERM_OIDC_SSO_ONLY=1 there is no other way in.",
    "config.forwards_http": "Without https the session cookie loses its __Host- prefix, so a forwarded page can plant a session cookie (session fixation).",
    "config.sso_ungated": "WebTerm does not re-check the group, so who gets in is decided entirely by the identity provider.",
    "janitor": "It applies retention (transcripts, audit log); when it stops, the disk fills slowly and old data is kept longer than promised.",
    "db.size": "Deleted rows leave free pages; compacting returns the space.",
    "backup.coverage": "Without an automatic backup, a lost disk loses every host, credential and recording.",
    "backup.offhost": "A backup on the machine it protects does not survive losing that machine.",
    "backup.restore": "A backup that was never restored is a hope, not a backup.",
    "backup.inapp": "Until fixed, the local snapshots age out and there is no fresh copy of the vault.",
    "certs": "Browsers refuse an expired or wrong certificate.",
    "heartbeat": "Nothing inside WebTerm can report that WebTerm itself is down. An outside monitor that expects a regular ping can.",
    "update.available": "New releases carry security fixes.",
    "clock.gateway": "A wrong clock breaks TOTP codes, SSO tokens and certificate checks.",
    "forward.dns": "Port-forward links open on *.<domain>; without a wildcard DNS record they do not resolve.",
}
RECS = {
    "install_helper": "Install it on the gateway host: it adds an hourly systemd timer and changes nothing else.",
    "check_timer": "Look at the unit's journal, then start it once by hand to see it succeed.",
    "timer_pending": "Nothing is wrong: the timer has not fired since the update. To see it work now, start it once.",
    "run_upgrade": "Your host scripts predate 3.6.8 — run upgrade.sh to refresh them.",
    "cf_token": "Create a new token (Zone:DNS:Edit on the zone) in the Cloudflare dashboard, put it in secrets/cf_dns_api_token, then recreate Traefik.",
    "authentik_steps": "Step through the minor releases, never skip one (2026.5.x must go straight to 2026.8.3 or later), with a database backup first — follow docs/AUTHENTIK-UPGRADE.md, or use scripts/authentik-upgrade.sh.",
    "free_disk": "Run the Docker cleanup, lower WEBTERM_ARCHIVE_DAYS / WEBTERM_TRANSCRIPT_MAX_BYTES, or grow the volume.",
    "fix_channel": "Open Settings → Notifications, fix the server or URL and send a test.",
    "add_channel": "Add an SMTP server or a webhook in Settings → Notifications.",
    "force_update": "Update the agent now from its host card (sessions survive the restart).",
    "enable_autostart": "Turn on “starts at boot” for these hosts.",
    "python_side_by_side": "Install Python 3.6 or newer next to the system one and run the agent with it (see “Supported hosts” in the install guide). Terminals keep working meanwhile.",
    "reinstall_agent": "Reinstall the agent on these hosts (they were enrolled before the signing key existed).",
    "fix_agent_clock": "Enable time sync (NTP) on these hosts.",
    "close_sessions": "Close sessions you no longer need on these hosts.",
    "signing_key": "Settings → Infrastructure → Agent signing key.",
    "sso_check": "Check the IdP is up and reachable from the gateway, the client secret, and the clock; local accounts and passkeys still work.",
    "use_https": "Serve WebTerm over https, or turn port forwarding off.",
    "sso_groups": "Bind the WebTerm application to a group in the IdP, or set WEBTERM_OIDC_ALLOWED_GROUPS. If the IdP already gates it, mute this.",
    "janitor_logs": "Look at the gateway log for “janitor”; the next run retries.",
    "compact_db": "Compacting locks the database for a moment: run it in a quiet minute.",
    "enable_backup": "Turn on the scheduled backup in Settings → Backup, or install the host backup timer.",
    "add_offhost": "Add an off-host destination (Settings → Backup → off-host copy) or WEBTERM_BACKUP_RSYNC/REMOTE for the host timer.",
    "verify_backup": "Verify a backup in Settings → Backup (it decrypts it and checks the database, nothing is restored).",
    "fix_backup": "Settings → Backup shows the last error.",
    "renew_cert": "Settings → Infrastructure → Certificates shows the renewal command.",
    "heartbeat_check": "Check WEBTERM_HEARTBEAT_URL and that the gateway can reach it.",
    "heartbeat_setup": "Set WEBTERM_HEARTBEAT_URL to a healthchecks.io (or similar) ping URL; it alerts you when the pings stop.",
    "upgrade": "Upgrade on the gateway host (it backs up first and rolls back on failure).",
    "fix_clock": "Enable time sync (NTP) on the gateway host.",
    "forward_dns": "Create a wildcard DNS record *.<domain> pointing at this server (Settings → Infrastructure → Port forwarding).",
}


# ── small helpers ────────────────────────────────────────────────────────────────────────────
def _age(seconds: float) -> str:
    s = max(0, int(seconds))
    if s < 3600:
        return "%d min" % max(1, s // 60)
    if s < 2 * 86400:
        return "%d h" % (s // 3600)
    return "%d days" % (s // 86400)


def _gb(n: float) -> str:
    return "%.1f GB" % (n / 1024 ** 3)


def _mb(n: float) -> str:
    return "%.1f MB" % (n / 1024 ** 2)


def _clean_params(p: dict) -> dict:
    """Scalars only, simple names, bounded strings, text scrubbed like alert params."""
    out = {}
    for k, v in (p or {}).items():
        if not isinstance(k, str) or not k.isidentifier() or len(k) > 32:
            continue
        if isinstance(v, bool) or isinstance(v, int):
            out[k] = v
        elif isinstance(v, float):
            out[k] = round(v, 1) if v == v else 0
        elif v is not None:
            out[k] = alert_history.scrub(hoststatus.clean_text(str(v), 200), 200)
    return out


async def _get(key: str, default: str = "") -> str:
    row = await db.fetchone("SELECT value FROM app_settings WHERE key=?", key)
    return row["value"] if row and row["value"] is not None else default


async def _set(key: str, value: str) -> None:
    await db.execute("INSERT INTO app_settings(key, value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)


async def _get_json(key: str) -> dict:
    try:
        v = json.loads(await _get(key, "") or "{}")
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def _unit_cmds(unit: str) -> list:
    return [{"t": "unit_journal", "p": {"unit": unit}}, {"t": "unit_start", "p": {"unit": unit}}]


# ── host helper checks (hoststatus.py; untrusted files, validated there) ─────────────────────
_HOST: dict = {}          # the current snapshot, read once per fast tick by _host_snapshot()


def _host_snapshot() -> dict:
    global _HOST
    _HOST = hoststatus.read_all()
    return _HOST


def _timer(name: str) -> str:
    """enabled | disabled | missing | unknown (no helper report)."""
    hh = _HOST.get("host-health") or {}
    if hh.get("state") != "ok":
        return "unknown"
    return ((hh.get("data") or {}).get("timers") or {}).get(name, "unknown")


async def c_host_helper() -> Optional[Result]:
    snap = _host_snapshot()
    bad = [(sid, st.get("error", "")) for sid, st in snap.items() if st.get("state") == "invalid"]
    if bad:
        sid, err = bad[0]
        return Result("warning", "helper_invalid", {"file": sid + ".json", "error": err},
                      rec="install_helper", commands=[{"t": "host_health", "p": {}}])
    hh = snap.get("host-health") or {}
    if hh.get("state") == "missing":
        return Result("info", "helper_missing", rec="install_helper",
                      commands=[{"t": "host_health_install", "p": {}}])
    if hh.get("stale"):
        return Result("warning", "helper_stale", {"age": _age(hh.get("age", 0))}, rec="check_timer",
                      commands=_unit_cmds("webterm-host-health.service"))
    timers = (hh.get("data") or {}).get("timers") or {}
    off = sorted(k for k, v in timers.items() if v != "enabled")
    if off:
        return Result("warning", "helper_timers", {"timers": ", ".join(off)}, rec="install_helper",
                      commands=[{"t": "host_health_install", "p": {}}])
    return Result("ok", "helper_ok")


PENDING_GRACE = 6 * 3600          # a daily timer that has not fired 30 h after an update is late
_KIT_KEY = {"backup": "backup", "cert-check": "cert_check", "docker-cleanup": "cleanup"}


def _never_reported(sid: str, unit: str, k_missing: str, k_pending: str,
                    now: Optional[float] = None) -> Result:
    """The timer is enabled but its status file does not exist. Three different situations
    (3.6.9 — right after an upgrade every daily timer looked broken):
      * the script cannot report (it predates 3.6.8) → warning, run upgrade.sh;
      * current script, installed/updated less than one interval (+ grace) ago → INFO: it has
        simply not fired yet; when it will, and how to run it now;
      * current script for longer than that → warning: the timer really is not running it.
    The kit report comes from host-health.sh ≥ 3.6.9; without it we keep the old wording."""
    now = time.time() if now is None else now
    hh = ((_HOST.get("host-health") or {}).get("data") or {})
    k = _KIT_KEY.get(sid, "")
    reports = hh.get("kit_" + k)
    if reports is None or reports is False:
        return Result("warning", k_missing, rec="run_upgrade", commands=_unit_cmds(unit))
    since = hh.get("since_" + k) or 0
    nxt = hh.get("next_" + k) or 0
    interval = hoststatus.IDS.get(sid) or 86400
    if since and now - since < interval + PENDING_GRACE:
        eta = nxt - now if nxt > now else max(60, since + interval - now)
        return Result("info", k_pending, {"next": _age(eta)}, rec="timer_pending",
                      commands=[{"t": "unit_start", "p": {"unit": unit}}])
    return Result("warning", k_missing, rec="check_timer", commands=_unit_cmds(unit))


def _status_check(sid: str, unit: str, timer: str, keys: tuple, fail_sev: str = "warning",
                  ok_params=None):
    """Shared shape for a timer that reports through a status file: failed / stale / never
    reported while its timer is enabled / ok. Not applicable when neither file nor timer exist."""
    async def fn() -> Optional[Result]:
        st = _HOST.get(sid) or hoststatus.read(sid)
        k_failed, k_stale, k_missing, k_ok = keys
        if st.get("state") != "ok":
            if st.get("state") == "missing" and _timer(timer) == "enabled":
                return _never_reported(sid, unit, k_missing, k_missing.replace("_missing", "_pending"))
            return None                 # not installed here (or refused: host.helper says why)
        if st["status"] in ("error", "warn"):
            # `warn` = it ran but part of it failed (e.g. the off-host copy, one prune step)
            return Result(fail_sev if st["status"] == "error" else "warning", k_failed,
                          {"message": st.get("message") or "?"},
                          rec="check_timer", commands=_unit_cmds(unit))
        if st.get("stale"):
            return Result("warning", k_stale, {"age": _age(st.get("age", 0))}, rec="check_timer",
                          commands=_unit_cmds(unit))
        return Result("ok", k_ok, (ok_params(st) if ok_params else {}))
    return fn


c_host_backup = _status_check(
    "backup", "webterm-backup.service", "webterm-backup.timer",
    ("host_backup_failed", "host_backup_stale", "host_backup_missing", "host_backup_ok"),
    fail_sev="critical", ok_params=lambda st: {"age": _age(st.get("age", 0))})
c_host_cert_check = _status_check(
    "cert-check", "webterm-cert-check.service", "webterm-cert-check.timer",
    ("cert_check_failed", "cert_check_stale", "cert_check_missing", "cert_check_ok"))
c_host_cleanup = _status_check(
    "docker-cleanup", "webterm-docker-cleanup.service", "webterm-docker-cleanup.timer",
    ("cleanup_failed", "cleanup_stale", "cleanup_missing", "cleanup_ok"),
    ok_params=lambda st: {"pct": (st.get("data") or {}).get("disk_free_pct", "?")})


async def c_host_cloudflare() -> Optional[Result]:
    st = _HOST.get("cloudflare-token") or hoststatus.read("cloudflare-token")
    if st.get("state") != "ok" or st["status"] == "skipped":
        return None
    cmds = [{"t": "cf_token_edit", "p": {}}, {"t": "traefik_recreate", "p": {}},
            {"t": "host_health", "p": {}}]
    data = st.get("data") or {}
    if st.get("stale"):
        return Result("warning", "cf_token_stale", {"age": _age(st.get("age", 0))},
                      rec="check_timer", commands=_unit_cmds("webterm-host-health.service"))
    if st["status"] == "error":
        return Result("critical", "cf_token_invalid",
                      {"status": data.get("token_status") or "invalid"}, rec="cf_token",
                      commands=cmds)
    if st["status"] == "warn":
        if data.get("expires_on"):
            return Result("warning", "cf_token_expiring", {"expires": data["expires_on"]},
                          rec="cf_token", commands=cmds)
        return Result("warning", "cf_token_unknown", {"message": st.get("message") or "?"},
                      commands=[{"t": "host_health", "p": {}}])
    return Result("ok", "cf_token_ok")


async def c_host_authentik() -> Optional[Result]:
    st = _HOST.get("authentik-image") or hoststatus.read("authentik-image")
    if st.get("state") != "ok" or st["status"] == "skipped":
        return None
    data = st.get("data") or {}
    if st["status"] in ("warn", "error"):
        # read-only fact; the upgrade itself is a deliberate, stepwise job for a human
        # (docs/AUTHENTIK-UPGRADE.md, scripts/authentik-upgrade.sh) — no command is offered
        return Result("warning", "authentik_drift", {"running": data.get("running") or "?",
                                                     "pinned": data.get("pinned") or "?",
                                                     "project": data.get("project") or "?"},
                      rec="authentik_steps", doc="authentik_upgrade")
    return Result("ok", "authentik_ok", {"running": data.get("running") or "?"})


# ── gateway checks ───────────────────────────────────────────────────────────────────────────
async def c_disk() -> Optional[Result]:
    try:
        st = await asyncio.to_thread(os.statvfs, config.DATA_DIR)
    except OSError:
        return None
    free, total = st.f_bavail * st.f_frsize, st.f_blocks * st.f_frsize
    if total <= 0:
        return None
    pct = free * 100.0 / total
    p = {"pct": "%.1f" % pct, "free": _gb(free), "total": _gb(total)}
    cmds = [{"t": "unit_start", "p": {"unit": "webterm-docker-cleanup.service"}}]
    if pct < config.DISK_CRIT_PCT:
        return Result("critical", "disk_critical", p, rec="free_disk", commands=cmds)
    if pct < config.DISK_WARN_PCT:
        return Result("warning", "disk_low", p, rec="free_disk", commands=cmds)
    return Result("ok", "disk_ok", {"pct": "%.0f" % pct})


async def c_delivery() -> Optional[Result]:
    from . import email_alerts
    cfg = await email_alerts.load_config()
    st = await email_alerts.alert_status()

    def failing(k_sent, k_failed):
        f = st.get(k_failed) or {}
        s = st.get(k_sent) or {}
        if not f or float(f.get("ts") or 0) <= float(s.get("ts") or 0):
            return None
        return f
    email_ok = bool(cfg.get("host") and cfg.get("to") and cfg.get("from"))
    f = failing(email_alerts.K_EMAIL_LAST_SENT, email_alerts.K_EMAIL_LAST_FAILED) if email_ok else None
    if f:
        return Result("critical", "delivery_email_failed", {"error": f.get("error") or "?"},
                      rec="fix_channel", action="settings:notifications")
    f = failing(email_alerts.K_WEBHOOK_LAST_SENT, email_alerts.K_WEBHOOK_LAST_FAILED) \
        if cfg.get("webhook") else None
    if f:
        return Result("critical", "delivery_webhook_failed", {"error": f.get("error") or "?"},
                      rec="fix_channel", action="settings:notifications")
    if not email_ok and not cfg.get("webhook"):
        return None                     # nothing to deliver through: alerts.channel says so
    return Result("ok", "delivery_ok")


async def c_channel() -> Optional[Result]:
    from . import email_alerts
    cfg = await email_alerts.load_config()
    if (cfg.get("host") and cfg.get("to") and cfg.get("from")) or cfg.get("webhook"):
        return Result("ok", "channel_ok")
    return Result("info", "no_channel", rec="add_channel", action="settings:notifications")


async def _agent_rows():
    return await db.fetchall(
        "SELECT id, agent_version, supervision_summary, update_blocked FROM hosts"
        " WHERE COALESCE(connection_type,'agent')='agent' AND COALESCE(ephemeral,0)=0"
        " AND uninstalled_at IS NULL ORDER BY id")


async def c_agents_outdated() -> Optional[Result]:
    from . import core
    expected = core.agent_expected().get("version")
    if not expected:
        return None
    now = time.time()
    since = await _get_json(K_BEHIND)
    behind_now = {}
    for r in await _agent_rows():
        v = r["agent_version"]
        if isinstance(v, int) and v < expected:
            behind_now[str(r["id"])] = float(since.get(str(r["id"])) or now)
    if behind_now != {k: float(v) for k, v in since.items() if isinstance(v, (int, float))}:
        await _set(K_BEHIND, json.dumps(behind_now))
    days = config.AGENT_OUTDATED_DAYS
    # only CONNECTED agents count: an offline host updates when it comes back (host_offline says
    # it is offline), and a connected one that stays behind is the "deferred forever" case
    online = {str(h) for h in core.sources}
    old = sorted(int(h) for h, ts in behind_now.items() if now - ts > days * 86400 and h in online)
    recent = sorted(int(h) for h in behind_now if int(h) not in old)
    if old:
        return Result("warning", "agents_outdated", {"count": len(old), "version": expected,
                                                     "days": days},
                      rec="force_update", action="agent_update", hosts=old[:MAX_HOSTS_IN_RESULT])
    if recent:
        return Result("info", "agents_behind_recent", {"count": len(recent), "version": expected},
                      rec="force_update", action="agent_update",
                      hosts=recent[:MAX_HOSTS_IN_RESULT])
    return Result("ok", "agents_current", {"version": expected})


async def c_agents_autostart() -> Optional[Result]:
    off, known = [], 0
    for r in await _agent_rows():
        try:
            s = json.loads(r["supervision_summary"] or "null")
        except ValueError:
            s = None
        if not isinstance(s, dict) or not isinstance(s.get("boot"), bool):
            continue
        known += 1
        if not s["boot"]:
            off.append(r["id"])
    if off:
        return Result("warning", "agents_no_autostart", {"count": len(off)},
                      rec="enable_autostart", action="autostart", hosts=off[:MAX_HOSTS_IN_RESULT])
    return Result("ok", "agents_autostart_ok") if known else None


async def c_agents_python() -> Optional[Result]:
    """3.6.9: agents on Python < 3.6. The agent does not report its interpreter (a v59 item), so
    the signal is core.agent_python_old: `confirmed` from the os.scandir fingerprint of a failed
    file operation, `likely` from an OS whose python3 is older (Ubuntu 16.04, Debian 9…)."""
    from . import core
    ids = {r["id"] for r in await _agent_rows()}
    seen = {h: v for h, v in list(core.agent_python_old.items()) if h in ids}
    confirmed = sorted(h for h, v in seen.items() if v == "confirmed")
    likely = sorted(h for h, v in seen.items() if v == "likely")
    if confirmed:
        return Result("critical", "agents_python_old", {"count": len(confirmed)},
                      rec="python_side_by_side", doc="host_requirements",
                      hosts=(confirmed + likely)[:MAX_HOSTS_IN_RESULT])
    if likely:
        # not proven yet (the gateway probes once with fs_list as soon as the OS is reported)
        return Result("warning", "agents_python_likely", {"count": len(likely)},
                      rec="python_side_by_side", doc="host_requirements",
                      hosts=likely[:MAX_HOSTS_IN_RESULT])
    return Result("ok", "agents_python_ok") if ids else None


async def c_agents_blocked() -> Optional[Result]:
    rows = [r["id"] for r in await _agent_rows() if r["update_blocked"]]
    if rows:
        return Result("warning", "agents_update_blocked", {"count": len(rows)},
                      rec="reinstall_agent", hosts=rows[:MAX_HOSTS_IN_RESULT])
    return Result("ok", "agents_update_ok")


AGENT_AHEAD_MAX = 120.0          # an agent clock ahead of ours by more than this is wrong
AGENT_BEHIND_MAX = 300.0         # behind: collecting a snapshot can take a while (package checks)


async def c_agents_clock() -> Optional[Result]:
    from . import core
    now = time.time()
    bad, worst = [], 0.0
    for hid, (skew, at) in list(core.agent_clock.items()):
        if now - at > 2 * 3600 or hid not in core.sources:
            continue
        if skew > AGENT_AHEAD_MAX or skew < -AGENT_BEHIND_MAX:
            bad.append(hid)
            worst = max(worst, abs(skew))
    if bad:
        return Result("warning", "agents_clock_skew", {"count": len(bad), "skew": int(worst)},
                      rec="fix_agent_clock", hosts=sorted(bad)[:MAX_HOSTS_IN_RESULT])
    return Result("ok", "agents_clock_ok") if core.agent_clock else None


async def c_sessions_cap() -> Optional[Result]:
    from . import core
    limit = core.MAX_SESSIONS_HINT
    rows = await db.fetchall(
        "SELECT host_id, COUNT(*) AS c FROM sessions WHERE state IN ('live','creating')"
        " GROUP BY host_id HAVING COUNT(*) >= ?", SESSION_WARN)
    if rows:
        return Result("warning", "sessions_near_cap",
                      {"count": len(rows), "limit": limit, "threshold": SESSION_WARN},
                      rec="close_sessions", hosts=[r["host_id"] for r in rows][:MAX_HOSTS_IN_RESULT])
    return Result("ok", "sessions_ok")


async def c_signing() -> Optional[Result]:
    from . import core, signing
    exp = core.agent_expected()
    if not signing.key_exists() and not exp.get("sig"):
        return Result("critical", "signing_unsigned", rec="signing_key", action="settings:signing")
    if signing.key_exists() and not signing.is_loaded():
        row = await db.fetchone(
            "SELECT COUNT(*) AS c FROM hosts WHERE connection_type='agent'"
            " AND agent_version IS NOT NULL AND agent_version < ?", exp.get("version") or 0)
        behind = int(row["c"]) if row else 0
        if behind:
            return Result("warning", "signing_locked", {"behind": behind}, rec="signing_key",
                          action="settings:signing")
    return Result("ok", "signing_ok")


SSO_BROKEN_MIN = 3


async def c_sso() -> Optional[Result]:
    from . import oidc
    if not config.OIDC_ENABLED:
        return None
    sev = "critical" if config.OIDC_SSO_ONLY else "warning"
    probe = oidc.probe_status()
    if probe.get("ok") is False:
        return Result(sev, "sso_probe_failed", {"kind": probe.get("kind") or "discovery",
                                                "error": probe.get("error") or "?",
                                                "sso_only": config.OIDC_SSO_ONLY},
                      rec="sso_check", commands=[{"t": "ntp_status", "p": {}}]
                      if probe.get("kind") == "clock_skew" else [])
    st = oidc.failure_stats()
    # broken = repeated SYSTEM failures with no success since the first of them, or ANY
    # invalid_client / idp_config (a configuration error fails every attempt)
    cfg_err = any(k in st["kinds"] for k in ("invalid_client", "idp_config"))
    if st["count"] and (cfg_err or (st["count"] >= SSO_BROKEN_MIN
                                    and st["last_success"] < st["first_ts"])):
        kind = max(st["kinds"], key=st["kinds"].get)
        cmds = [{"t": "ntp_status", "p": {}}] if kind == "clock_skew" else []
        # Security review 3.6.8 (M1): full severity (critical with SSO_ONLY) only when CONFIRMED
        # — a kind only the IdP can produce, or failures from two or more client addresses.
        # Unconfirmed (e.g. 5xx/network errors all from one caller) stays a warning and asks the
        # IdP probe to run now: if the IdP really is down, the probe fails and `sso_probe_failed`
        # above raises the full severity at the next tick.
        confirmed = bool(st.get("confirmed"))
        if not confirmed:
            _kick_probe()
        return Result(sev if confirmed else "warning", "sso_broken",
                      {"kind": kind, "count": st["count"], "sso_only": config.OIDC_SSO_ONLY,
                       "confirmed": confirmed},
                      rec="sso_check", commands=cmds)
    return Result("ok", "sso_ok")


PROBE_KICK_MIN = 300.0           # an unconfirmed "SSO broken" re-probes the IdP at most every 5 min
_probe_kick = {"at": 0.0, "task": None}


def _kick_probe(now: Optional[float] = None) -> bool:
    """Run the IdP probe now (in the background) unless it ran, or was asked for, recently.
    Bounded: one outbound discovery+JWKS fetch to the CONFIGURED issuer per 5 minutes at most."""
    from . import oidc
    now = time.time() if now is None else now
    if now - _probe_kick["at"] < PROBE_KICK_MIN:
        return False
    if now - float(oidc.probe_status().get("ts") or 0) < PROBE_KICK_MIN:
        return False
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return False
    _probe_kick["at"] = now
    _probe_kick["task"] = loop.create_task(jobs_hourly())   # keep a reference (no early GC)
    return True


async def c_forwards_http() -> Optional[Result]:
    from . import api
    if config.PUBLIC_URL.startswith("http://") and api.forward_domain():
        if await db.fetchone("SELECT 1 FROM port_forwards LIMIT 1"):
            return Result("critical", "insecure_forwards", rec="use_https")
    return None


async def c_sso_ungated() -> Optional[Result]:
    if config.OIDC_ENABLED and not config.OIDC_ALLOWED_GROUPS:
        return Result("warning", "sso_ungated", rec="sso_groups")
    return None


JANITOR_STALE = 2 * 86400 + 3600


async def c_janitor() -> Optional[Result]:
    st = await _get_json(K_JANITOR)
    now = time.time()
    if not st:
        return None                      # first boot: the janitor has not finished yet
    errs = [e for e in (st.get("errors") or []) if isinstance(e, str)][:6]
    if errs:
        return Result("warning", "janitor_failed", {"steps": ", ".join(errs)}, rec="janitor_logs")
    last = float(st.get("last_ok") or 0)
    if last and now - last > JANITOR_STALE:
        return Result("warning", "janitor_stale", {"age": _age(now - last)}, rec="janitor_logs")
    return Result("ok", "janitor_ok")


DB_COMPACT_MIN_FREE = 20 * 1024 * 1024
DB_COMPACT_RATIO = 0.25


async def c_db_size() -> Optional[Result]:
    pc = await db.fetchone("PRAGMA page_count")
    ps = await db.fetchone("PRAGMA page_size")
    fl = await db.fetchone("PRAGMA freelist_count")
    pages, size, free = int(pc[0] or 0), int(ps[0] or 4096), int(fl[0] or 0)
    total = pages * size
    if pages and free * size >= DB_COMPACT_MIN_FREE and free / pages >= DB_COMPACT_RATIO:
        return Result("info", "db_compact", {"size": _mb(total),
                                             "free_pct": "%.0f" % (free * 100.0 / pages)},
                      rec="compact_db", commands=[{"t": "db_vacuum", "p": {}}])
    return Result("ok", "db_ok", {"size": _mb(total)})


def _host_backup_ok() -> Optional[dict]:
    st = _HOST.get("backup") or {}
    if st.get("state") == "ok" and st.get("status") == "ok" and not st.get("stale"):
        return st
    return None


async def c_backup_coverage() -> Optional[Result]:
    sched = await _get("backup_schedule", "off")
    if sched in ("daily", "weekly") or _host_backup_ok() or _timer("webterm-backup.timer") == "enabled":
        return Result("ok", "backup_ok")
    return Result("warning", "backup_none", rec="enable_backup", action="settings:backup")


async def c_backup_offhost() -> Optional[Result]:
    from . import cloudbackup
    hb = _host_backup_ok()
    if hb and (hb.get("data") or {}).get("offhost") == "ok":
        return Result("ok", "offhost_ok")
    try:
        cs = await cloudbackup.status()
    except Exception:                    # noqa: BLE001 — a broken config row is "no off-host"
        cs = {}
    sched = await _get("backup_schedule", "off")
    if cs.get("configured") and cs.get("connected") and sched in ("daily", "weekly"):
        return Result("ok", "offhost_ok")
    return Result("warning", "backup_no_offhost", rec="add_offhost", action="settings:backup")


RESTORE_VERIFY_MAX_DAYS = 180


async def c_backup_restore() -> Optional[Result]:
    try:
        ts = float(await _get(K_RESTORE_VERIFIED, "0") or 0)
    except ValueError:
        ts = 0.0
    rv = _HOST.get("restore-verify") or {}
    if rv.get("state") == "ok" and rv.get("status") == "ok":
        ts = max(ts, float(rv.get("ts") or 0))
    if not ts:
        return Result("info", "restore_never_verified", rec="verify_backup", action="settings:backup")
    days = int((time.time() - ts) // 86400)
    if days > RESTORE_VERIFY_MAX_DAYS:
        return Result("info", "restore_verified_old", {"days": days}, rec="verify_backup",
                      action="settings:backup")
    return Result("ok", "restore_ok", {"days": days})


async def c_backup_inapp() -> Optional[Result]:
    if await _get("backup_schedule", "off") not in ("daily", "weekly"):
        return None
    err = await _get_json("backup_last_error")
    if err.get("error"):
        return Result("warning", "backup_inapp_failed", {"error": err.get("error"),
                                                         "stage": err.get("stage") or "?"},
                      rec="fix_backup", action="settings:backup")
    return Result("ok", "backup_inapp_ok")


_CERT_SEV = {"ok": "ok", "expiring": "warning", "expiring_soon": "critical", "expired": "critical",
             "default": "critical", "mismatch": "critical", "error": "warning"}


def _cert_check(role: str):
    async def fn() -> Optional[Result]:
        from . import api, certmon
        items = [i for i in certmon.status()["items"] if i.get("role") == role]
        if not items:
            return None
        it = items[0]
        state = it.get("state") or "error"
        key = {"expiring_soon": "cert_expiring"}.get(state, "cert_" + state)
        if key not in MESSAGES:
            key = "cert_error"
        p = {"name": it.get("name") or "?", "days": int(max(0, it.get("days_left") or 0))}
        cmds = []
        dom = it.get("renew_domain")
        if state != "ok" and dom in certmon.renew_domains(api.forward_domain()):
            cmds = [{"t": "cert_renew", "p": {"domain": dom}}]
        return Result(_CERT_SEV.get(state, "warning"), key, p,
                      rec="" if state == "ok" else "renew_cert", commands=cmds,
                      action="" if state == "ok" else "settings:certificates")
    return fn


# heartbeat (dead-man switch) state, written by heartbeat_loop
_hb: dict = {"last_ok": 0.0, "last_error": "", "last_try": 0.0}


async def c_heartbeat() -> Optional[Result]:
    if not config.HEARTBEAT_URL:
        return Result("info", "heartbeat_off", rec="heartbeat_setup", doc="heartbeat")
    if _hb["last_error"] and _hb["last_try"] >= _hb["last_ok"]:
        return Result("warning", "heartbeat_failing", {"error": _hb["last_error"]},
                      rec="heartbeat_check", doc="heartbeat")
    if not _hb["last_try"]:
        return None
    return Result("ok", "heartbeat_ok", {"minutes": config.HEARTBEAT_MINUTES})


async def c_update() -> Optional[Result]:
    from . import updatecheck
    data = updatecheck._cache.get("data") or {}
    if not data.get("enabled") or not data.get("latest"):
        return None
    if data.get("update_available"):
        return Result("info", "update_available", {"latest": data["latest"],
                                                   "current": config.GATEWAY_VERSION},
                      rec="upgrade", commands=[{"t": "upgrade", "p": {"tag": data["latest"]}}],
                      action="about:update")
    return Result("ok", "update_current", {"current": config.GATEWAY_VERSION})


CLOCK_WARN = 30.0
CLOCK_CRIT = 120.0


async def c_clock() -> Optional[Result]:
    from . import updatecheck
    c = updatecheck.clock
    if c.get("skew") is None or time.time() - float(c.get("at") or 0) > 3 * 86400:
        return None
    off = abs(float(c["skew"])) - float(c.get("uncertainty") or 0)
    p = {"skew": int(round(float(c["skew"])))}
    cmds = [{"t": "ntp_status", "p": {}}, {"t": "ntp_on", "p": {}}]
    if off > CLOCK_CRIT:
        return Result("critical", "clock_skew", p, rec="fix_clock", commands=cmds)
    if off > CLOCK_WARN:
        return Result("warning", "clock_skew", p, rec="fix_clock", commands=cmds)
    return Result("ok", "clock_ok")


async def c_forward_dns() -> Optional[Result]:
    from . import api
    if not await db.fetchone("SELECT 1 FROM port_forwards WHERE enabled=1 LIMIT 1"):
        return None
    domain = api.forward_domain()
    if not domain:
        return None
    if not api._valid_domain(domain):
        return None
    # DNS only (the same `wtcheck.<domain>` name the on-demand probe in Settings resolves) — no
    # outbound TCP/TLS from a background task to a name a settings.manage holder can edit
    import socket

    def resolve() -> bool:
        try:
            return bool(socket.gethostbyname("wtcheck." + domain))
        except OSError:
            return False
    if not await asyncio.to_thread(resolve):
        return Result("warning", "forward_dns_missing", {"domain": domain}, rec="forward_dns",
                      action="settings:forward")
    return Result("ok", "forward_dns_ok", {"domain": domain})


CHECKS: list = [
    Check("host.helper", "fast", c_host_helper, source="host_helper"),
    Check("host.backup", "fast", c_host_backup, source="host_helper", critical=True),
    Check("host.cert_check", "fast", c_host_cert_check, source="host_helper"),
    Check("host.docker_cleanup", "fast", c_host_cleanup, source="host_helper"),
    Check("host.cloudflare", "fast", c_host_cloudflare, source="host_helper", critical=True),
    Check("host.authentik", "fast", c_host_authentik, source="host_helper"),
    # the 3.6.7 disk alert, now with an early warning; same alert kind (preferences carry over)
    Check("gateway.disk", "fast", c_disk, kind="gateway_disk", critical=True),
    # in-app ONLY: must not go out through the channel that is failing (no loop)
    Check("alerts.delivery", "fast", c_delivery, alert="inapp", kind="alert_delivery", critical=True),
    Check("alerts.channel", "fast", c_channel, alert="none"),
    Check("agents.outdated", "fast", c_agents_outdated),
    Check("agents.autostart", "fast", c_agents_autostart),
    Check("agents.python", "fast", c_agents_python, critical=True),
    Check("agents.update_blocked", "fast", c_agents_blocked, alert="none"),   # update_refused alerts
    Check("agents.clock", "fast", c_agents_clock),
    Check("sessions.cap", "fast", c_sessions_cap),
    Check("signing.state", "fast", c_signing, alert="none", critical=True),  # signing_locked alerts
    Check("oidc.sso", "fast", c_sso, critical=True),
    Check("config.forwards_http", "fast", c_forwards_http, critical=True),
    Check("config.sso_ungated", "fast", c_sso_ungated),
    Check("janitor", "fast", c_janitor),
    Check("db.size", "hourly", c_db_size, alert="none"),
    Check("backup.coverage", "fast", c_backup_coverage),
    Check("backup.offhost", "fast", c_backup_offhost),
    Check("backup.restore", "fast", c_backup_restore, alert="none"),
    Check("backup.inapp", "fast", c_backup_inapp, alert="none"),               # backup_failed alerts
    Check("certs.main", "fast", _cert_check("main"), alert="none", critical=True),  # certmon alerts
    Check("certs.forward", "fast", _cert_check("forward"), alert="none", critical=True),
    Check("certs.authentik", "fast", _cert_check("authentik"), alert="none", critical=True),
    Check("heartbeat", "fast", c_heartbeat),
    Check("update.available", "fast", c_update, alert="version"),
    Check("clock.gateway", "fast", c_clock, critical=True),
    Check("forward.dns", "daily", c_forward_dns, timeout=NETWORK_TIMEOUT),
]
BY_ID = {c.id: c for c in CHECKS}


# ── state + persistence ──────────────────────────────────────────────────────────────────────
_rows: dict = {}              # id → the persisted row (dict), mirror of health_checks
_lock = asyncio.Lock()
_last_manual = 0.0
_loaded = False


def _sig(r: Result) -> str:
    """Everything the result says — a changed command or action is persisted at once, and
    "mute until it changes" lifts on any change."""
    return json.dumps([r.severity, r.key, r.params, sorted(r.hosts), r.rec, r.commands, r.action,
                       r.doc], sort_keys=True, separators=(",", ":"))


async def _load() -> None:
    global _loaded
    if _loaded or not db.connected():
        return
    for r in await db.fetchall("SELECT * FROM health_checks"):
        _rows[r["id"]] = dict(r)
    _loaded = True


async def _persist(row: dict) -> None:
    cols = ("id", "severity", "message_key", "params", "recommendation_key", "commands",
            "command_where", "requires_root", "action", "source", "hosts", "doc", "checked_at",
            "first_failed_at", "changed_at", "sig", "alerted_severity", "alerted_at",
            "muted_until", "muted_sig", "muted_by")
    await db.execute(
        "INSERT INTO health_checks(%s) VALUES(%s) ON CONFLICT(id) DO UPDATE SET %s"
        % (",".join(cols), ",".join("?" * len(cols)),
           ",".join("%s=excluded.%s" % (c, c) for c in cols[1:])),
        *[row.get(c) for c in cols])


def _is_muted(row: dict, now: float) -> bool:
    # safety net (security review 3.6.8, L1): a check not declared critical-capable may be muted
    # by an Admin; should it ever return critical anyway, the mute does not hide it
    if row.get("severity") == "critical" and not getattr(BY_ID.get(row.get("id")), "critical", False):
        return False
    mu = float(row.get("muted_until") or 0)
    if mu == -1:
        return row.get("muted_sig") == row.get("sig")
    return mu > now


async def _apply(check: Check, res: Optional[Result], now: float) -> None:
    """Store one result, then alert on the transition (never for a muted check)."""
    if res is None:
        if check.id in _rows:
            _rows.pop(check.id, None)
            await db.execute("DELETE FROM health_checks WHERE id=?", check.id)
        return
    if res.severity not in RANK:
        res.severity = "warning"
    res.params = _clean_params(res.params)
    res.commands = [c for c in res.commands if isinstance(c, dict)][:healthcmd.MAX_COMMANDS]
    if res.action not in ACTIONS:
        res.action = ""
    if res.doc not in DOCS:
        res.doc = ""
    prev = _rows.get(check.id) or {}
    sig = _sig(res)
    row = dict(prev)
    roots = []
    for c in res.commands:
        spec = healthcmd.TEMPLATES.get(c.get("t"))
        if spec:
            roots.append(spec[1])
    row.update({
        "id": check.id, "severity": res.severity, "message_key": res.key,
        "params": json.dumps(res.params, separators=(",", ":")),
        "recommendation_key": res.rec,
        "commands": json.dumps(res.commands, separators=(",", ":")),
        "command_where": "gateway_host" if res.commands else ("ui_action" if res.action else ""),
        "requires_root": int(any(roots)), "action": res.action, "source": check.source,
        "hosts": json.dumps(sorted(set(int(h) for h in res.hosts))[:MAX_HOSTS_IN_RESULT]),
        "doc": res.doc, "checked_at": now, "sig": sig,
    })
    bad = RANK[res.severity] >= RANK["warning"]
    if bad and not prev.get("first_failed_at"):
        row["first_failed_at"] = now
    elif not bad:
        row["first_failed_at"] = None
    changed = prev.get("sig") != sig
    if changed:
        row["changed_at"] = now
    # mute "until it changes": a different result lifts it
    if float(row.get("muted_until") or 0) == -1 and row.get("muted_sig") != sig:
        row.update(muted_until=0, muted_sig=None, muted_by=None)
    elif float(row.get("muted_until") or 0) > 0 and float(row["muted_until"]) <= now:
        row.update(muted_until=0, muted_sig=None, muted_by=None)
    alerted = await _maybe_alert(check, res, row, now)
    _rows[check.id] = row
    dirty = any(prev.get(k) != v for k, v in row.items() if k != "checked_at")
    if dirty or alerted or not prev or now - float(prev.get("checked_at") or 0) > PERSIST_EVERY:
        await _persist(row)


async def _maybe_alert(check: Check, res: Result, row: dict, now: float) -> bool:
    if check.alert == "none" or _is_muted(row, now):
        return False
    sev, prev_sev = res.severity, row.get("alerted_severity") or ""
    last = float(row.get("alerted_at") or 0)
    if check.alert == "version":
        if res.key != "update_available":
            return False
        latest = str(res.params.get("latest") or "")
        if not latest or await _get(K_UPDATE_ALERTED, "") == latest:
            return False
        await _set(K_UPDATE_ALERTED, latest)
        _send(check, res, "info")
        return True
    if RANK[sev] >= RANK["warning"]:
        escalate = RANK.get(prev_sev, 0) < RANK[sev]
        remind = (sev == "critical" and prev_sev == "critical" and now - last > REMIND_CRITICAL)
        if prev_sev and RANK.get(prev_sev, 0) > RANK[sev]:
            row["alerted_severity"] = sev   # de-escalation: remember, do not alert
            return False
        if (escalate and (now - last > MIN_REALERT or sev == "critical")) or remind:
            row.update(alerted_severity=sev, alerted_at=now)
            _send(check, res, sev)
            return True
        return False
    if prev_sev in ("warning", "critical"):
        row.update(alerted_severity=None, alerted_at=now)
        _send(check, res, "ok", resolved=True)
        return True
    return False


def render_text(key: str, params: dict) -> str:
    tpl = MESSAGES.get(key, key)
    try:
        return tpl.format(**{k: v for k, v in (params or {}).items()})
    except (KeyError, IndexError, ValueError):
        return tpl


def _send(check: Check, res: Result, severity: str, resolved: bool = False) -> None:
    from . import email_alerts
    text = render_text(res.key, res.params)
    title = ("Resolved: %s" % text) if resolved else text
    lines = [text, "", WHY.get(_why_key(check.id), "")]
    if res.rec and not resolved:
        lines += ["", RECS.get(res.rec, "")]
    if res.commands and not resolved:
        lines += [""] + ["$ " + c["text"] for c in healthcmd.render_list(res.commands)]
    lines += ["", "Settings → System health shows the details."]
    body = "\n".join(lines).strip()
    params = dict(res.params, check=check.id, msg=res.key)
    if check.alert == "inapp":
        # the delivery check: in-app history ONLY — never through email/webhook (that is what is
        # failing, and a failed send would update the status this check reads: a loop)
        email_alerts.record_inapp_only(check.kind, severity, "System health: " + title, body,
                                       key="health_resolved" if resolved else "health",
                                       params=params)
        return
    email_alerts.notify_health(check.kind, severity, "System health: " + title, body,
                               key="health_resolved" if resolved else "health", params=params)


def _why_key(cid: str) -> str:
    return "certs" if cid.startswith("certs.") else cid


# ── running ──────────────────────────────────────────────────────────────────────────────────
async def _run_one(check: Check, now: float) -> None:
    try:
        res = await asyncio.wait_for(check.fn(), timeout=check.timeout)
    except Exception as e:                  # noqa: BLE001 — a check that breaks is SHOWN, not hidden
        if isinstance(e, asyncio.TimeoutError):
            err = "timed out after %.0f s" % check.timeout
        else:
            err = (str(e) or e.__class__.__name__)[:160]
            log.exception("health check %s failed", check.id)
        res = Result("warning", "check_failed", {"error": err})
        check = Check(check.id, check.tier, check.fn, check.source, "none", check.kind)
    await _apply(check, res, now)


async def run(tiers=("fast",)) -> None:
    """Run the checks of the given tiers (serialised; a second caller waits for the first)."""
    if not db.connected():
        return
    async with _lock:
        await _load()
        now = time.time()
        if "fast" in tiers:
            _host_snapshot()
        for c in CHECKS:
            if c.tier in tiers:
                await _run_one(c, now)
        if "fast" in tiers:
            await _set(K_LAST_RUN, str(now))


async def jobs_hourly() -> None:
    """Network work that feeds fast-tier checks: the IdP probe."""
    from . import oidc
    if config.OIDC_ENABLED:
        try:
            await asyncio.wait_for(asyncio.to_thread(oidc.probe), timeout=NETWORK_TIMEOUT)
        except Exception as e:              # noqa: BLE001 — the probe result says what failed
            oidc._probe.update(ts=time.time(), ok=False, kind="discovery",
                               error=(str(e) or e.__class__.__name__)[:200])


def manual_retry_after(now: Optional[float] = None) -> int:
    now = time.time() if now is None else now
    left = MANUAL_MIN_INTERVAL - (now - _last_manual)
    return int(left) + 1 if left > 0 else 0


def mark_manual(now: Optional[float] = None) -> None:
    global _last_manual
    _last_manual = time.time() if now is None else now


async def run_all() -> None:
    await jobs_hourly()
    await run(("fast", "hourly", "daily"))


STARTUP_DELAY = 20.0


async def loop() -> None:
    """Background task: fast tier every 30 s, hourly and daily tiers on their cadence."""
    await asyncio.sleep(STARTUP_DELAY)
    next_hourly = next_daily = 0.0
    while True:
        now = time.time()
        try:
            tiers = ["fast"]
            if now >= next_hourly:
                await jobs_hourly()
                tiers.append("hourly")
                next_hourly = now + HOURLY
            if now >= next_daily:
                tiers.append("daily")
                next_daily = now + DAILY
            await run(tuple(tiers))
        except Exception:                   # noqa: BLE001 — the loop must survive anything
            log.exception("system health: the run failed")
        await asyncio.sleep(FAST_TICK)


async def heartbeat_loop() -> None:
    """Dead-man switch: GET WEBTERM_HEARTBEAT_URL every N minutes while the gateway is healthy
    (the event loop runs and the DB answers). Never logs or shows the URL (it embeds a secret)."""
    url = config.HEARTBEAT_URL
    if not url:
        return
    if not url.lower().startswith(("https://", "http://")):
        _hb.update(last_error="WEBTERM_HEARTBEAT_URL must be http(s)", last_try=time.time())
        log.error("WEBTERM_HEARTBEAT_URL is not an http(s) URL — the dead-man switch is off")
        return
    await asyncio.sleep(30)
    while True:
        _hb["last_try"] = time.time()
        try:
            await db.fetchone("SELECT 1")
            await asyncio.wait_for(asyncio.to_thread(_ping, url), timeout=15)
            _hb.update(last_ok=time.time(), last_error="")
        except Exception as e:              # noqa: BLE001
            # the URL is never part of the message (urllib puts it in some errors)
            msg = (e.__class__.__name__ if url in str(e) else str(e) or e.__class__.__name__)
            _hb["last_error"] = alert_history.scrub(msg, 160)
        await asyncio.sleep(config.HEARTBEAT_MINUTES * 60)


def _ping(url: str) -> None:
    import urllib.request
    req = urllib.request.Request(url, method="GET",  # noqa: S310 — scheme checked by the caller
                                 headers={"User-Agent": "WebTerm-heartbeat"})
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
        r.read(1024)


# ── janitor reporting (main._janitor) ────────────────────────────────────────────────────────
async def janitor_report(errors: list) -> None:
    st = await _get_json(K_JANITOR)
    now = time.time()
    st["last_run"] = now
    st["errors"] = [str(e)[:40] for e in errors][:10]
    if not errors:
        st["last_ok"] = now
    await _set(K_JANITOR, json.dumps(st))


# ── mute ─────────────────────────────────────────────────────────────────────────────────────
MUTE_MODES = {"7d": 7 * 86400, "30d": 30 * 86400, "change": -1, "off": 0}


class MuteDenied(Exception):
    """Muting this check needs certs.renew (the Owner)."""


def mute_needs_owner(check_id: str, row: Optional[dict] = None) -> bool:
    """Security review 3.6.8 (L1). Before, settings.manage (an Admin) could mute ANY check for
    30 days, even pre-emptively while it was ok, and so hide a future critical from the Owner.
    Now a check that is critical NOW or CAN become critical is muted by the Owner only.
    Why not "an Admin may use `change` only": that mode stays on for as long as the result does
    not change, and a critical that stays the same (an expired certificate, a broken SSO) would be
    hidden just as long. Lifting a mute (`off`) is never restricted: it hides nothing."""
    c = BY_ID.get(check_id)
    if c is None or c.critical:
        return True
    return bool(row and row.get("severity") == "critical")


async def mute(check_id: str, mode: str, who: str, owner: bool = False) -> dict:
    await _load()
    # under the same lock as a check run: otherwise a run that copied the row before the mute
    # could store it back afterwards and silently drop the mute (review 3.6.8, INFO)
    async with _lock:
        row = _rows.get(check_id)
        if row is None or mode not in MUTE_MODES:
            raise KeyError(check_id)
        if MUTE_MODES[mode] != 0 and not owner and mute_needs_owner(check_id, row):
            raise MuteDenied(check_id)
        d = MUTE_MODES[mode]
        if d == 0:
            row.update(muted_until=0, muted_sig=None, muted_by=None)
        elif d == -1:
            row.update(muted_until=-1, muted_sig=row.get("sig"), muted_by=who[:200])
        else:
            row.update(muted_until=time.time() + d, muted_sig=None, muted_by=who[:200])
        await _persist(row)
        return row


def notify_muted(check_id: str, mode: str, who: str, row: Optional[dict] = None) -> None:
    """A mute by someone other than the Owner → an in-app alert for everyone with security.view
    (kind admin_change: a security kind, always shown in the app, never switchable off). In-app
    only: a mute is not worth an email, but it must not be invisible to the Owner (L1)."""
    from . import email_alerts
    until = float((row or {}).get("muted_until") or 0)
    when = ("until it changes" if until == -1 else
            time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(until)) if until > 0 else "?")
    params = {"check": check_id, "mode": mode, "email": who or "?",
              "until": int(until) if until > 0 else 0}
    title = "System health: %s muted the check %s (%s)" % (who or "?", check_id, mode)
    body = ("%s muted the System health check %s until %s. Muted checks raise no alert and are "
            "left out of the attention badge. Settings → System health shows it, and an Owner "
            "can unmute it." % (who or "?", check_id, when))
    email_alerts.record_inapp_only("admin_change", "warning", title, body, key="health_muted",
                                   params=params)


# ── views ────────────────────────────────────────────────────────────────────────────────────
def _loads(s, default):
    try:
        v = json.loads(s) if s else default
        return v if isinstance(v, type(default)) else default
    except ValueError:
        return default


def view(row: dict, now: Optional[float] = None, host_names: Optional[dict] = None) -> dict:
    """One row → the API/CLI shape. Commands are rendered HERE from the templates (and dropped if
    they do not validate any more); host ids become names only for hosts the viewer may see."""
    now = time.time() if now is None else now
    hosts = [h for h in _loads(row.get("hosts"), []) if isinstance(h, int)]
    visible = [{"id": h, "name": host_names[h]} for h in hosts if host_names and h in host_names]
    cid = row["id"]
    return {
        "id": cid, "severity": row.get("severity") or "warning",
        "message_key": row.get("message_key") or "", "params": _loads(row.get("params"), {}),
        "why_key": _why_key(cid), "recommendation_key": row.get("recommendation_key") or "",
        "commands": healthcmd.render_list(_loads(row.get("commands"), [])),
        "command_where": row.get("command_where") or "",
        "requires_root": bool(row.get("requires_root")),
        "action": row.get("action") or "", "source": row.get("source") or "gateway",
        "doc": DOCS.get(row.get("doc") or "", ""),
        # only hosts the viewer may see are NAMED (id + name); the others are only counted
        "hosts": visible, "hosts_hidden": len(hosts) - len(visible),
        "checked_at": row.get("checked_at"), "first_failed_at": row.get("first_failed_at"),
        "changed_at": row.get("changed_at"),
        "muted": _is_muted(row, now),
        # -1 = "until it changes"; who muted it is shown to everyone who sees the list (L1)
        "muted_until": row.get("muted_until") or 0,
        "muted_by": (row.get("muted_by") or "") if _is_muted(row, now) else "",
        "mute_owner_only": mute_needs_owner(cid, row),
        "message": render_text(row.get("message_key") or "", _loads(row.get("params"), {})),
    }


async def rows() -> list:
    await _load()
    return [dict(r) for r in _rows.values()]


def attention(rs: list, now: Optional[float] = None) -> dict:
    """{count, severity}: warning/critical rows that are not muted (the badge)."""
    now = time.time() if now is None else now
    n, top = 0, "ok"
    for r in rs:
        sev = r.get("severity") or "ok"
        if RANK.get(sev, 0) >= RANK["warning"] and not _is_muted(r, now):
            n += 1
            if RANK[sev] > RANK[top]:
                top = sev
    return {"count": n, "severity": top}


def reset_for_tests() -> None:
    global _loaded, _last_manual, _HOST
    _rows.clear()
    _loaded = False
    _last_manual = 0.0
    _HOST = {}
    _hb.update(last_ok=0.0, last_error="", last_try=0.0)
    _probe_kick.update(at=0.0, task=None)
