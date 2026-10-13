"""The ONLY commands System health may show, copy or type into a terminal (3.6.8).

Principle (the owner's): whatever WebTerm cannot fix from the UI, it detects, explains and
recommends — with the exact command. Many of those commands need root on the gateway host, and an
Owner can have one TYPED (never run) into a terminal there. So the command text is security
critical, and it is built here and nowhere else:
  * a check never stores a command string. It stores a template id + parameters; the string is
    rendered from this table at the moment it is shown or typed, and re-validated each time;
  * each template is a fixed argv skeleton; parameters are validated against a strict pattern
    or a closed set (an allow-list of systemd units, a semver tag, a monitored certificate name);
  * the client never sends a command, a template id or a parameter: it names a CHECK, and the
    server takes that check's current result (`api.health_terminal`);
  * the rendered text must round-trip through `shlex.split` to exactly the argv we meant,
    otherwise there is no command at all (fail closed, `CommandError`);
  * status files from the host (hoststatus.py) cannot reach this module: no field of theirs is
    ever a parameter here.
"""

from __future__ import annotations

import re
import shlex
from typing import Optional

from . import certmon, config

# systemd units WebTerm installs on the gateway host (deploy/*.service) — nothing else is ever
# started or journal-read from the UI
UNITS = ("webterm-backup.service", "webterm-cert-check.service", "webterm-host-health.service",
         "webterm-docker-cleanup.service")
_TAG_RE = re.compile(r"^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
_DIR_RE = re.compile(r"^(?:/[A-Za-z0-9_][A-Za-z0-9._-]{0,63}){1,16}$")
MAX_COMMANDS = 3


class CommandError(ValueError):
    pass


def _dir(install_dir: Optional[str]) -> str:
    d = install_dir if install_dir is not None else config.INSTALL_DIR
    if not isinstance(d, str) or not _DIR_RE.match(d) or "/../" in d + "/" or "/./" in d + "/":
        raise CommandError("invalid install directory")
    return d


def _unit(p: dict) -> str:
    u = p.get("unit")
    if u not in UNITS:
        raise CommandError("unit not allowed")
    return u


def _no_params(p: dict) -> None:
    if p:
        raise CommandError("this command takes no parameters")


# template id → (builder(params, dir) → list of argv segments joined by `&&`, requires_root)
def _b_host_health(p, d):
    _no_params(p)
    return [["sudo", "-k", d + "/scripts/host-health.sh"]]


def _b_host_health_install(p, d):
    _no_params(p)
    return [["sudo", "-k", d + "/scripts/host-health.sh", "--install"]]


def _b_unit_start(p, d):
    return [["sudo", "-k", "systemctl", "start", _unit(p)]]


def _b_unit_journal(p, d):
    return [["sudo", "-k", "journalctl", "-u", _unit(p), "-n", "50", "--no-pager"]]


def _b_upgrade(p, d):
    tag = p.get("tag")
    if not isinstance(tag, str) or not _TAG_RE.match(tag):
        raise CommandError("invalid version tag")
    return [["sudo", "-k", d + "/upgrade.sh", tag]]


def _b_db_vacuum(p, d):
    _no_params(p)
    return [["cd", d], ["sudo", "-k", "docker", "compose", "-f", "docker-compose.prod.yml", "exec",
                        "-u", "webterm", "app", "python3", "-m", "app.admin", "vacuum"]]


def _b_cf_token_edit(p, d):
    _no_params(p)
    # sudoedit: the editor runs as the person, on a copy; the token is never on a command line
    return [["sudo", "-k", "-e", d + "/secrets/cf_dns_api_token"]]


def _b_traefik_recreate(p, d):
    _no_params(p)
    return [["cd", d], ["sudo", "-k", "docker", "compose", "-f", "docker-compose.prod.yml", "up",
                        "-d", "--force-recreate", "traefik"]]


def _b_ntp_status(p, d):
    _no_params(p)
    return [["timedatectl", "status"]]


def _b_ntp_on(p, d):
    _no_params(p)
    return [["sudo", "-k", "timedatectl", "set-ntp", "true"]]


def _b_cert_renew(p, d):
    dom = p.get("domain")
    if not isinstance(dom, str) or set(p) != {"domain"}:
        raise CommandError("invalid domain")
    try:
        cmd = certmon.renew_command(dom, d)
    except ValueError as e:
        raise CommandError(str(e))
    return [shlex.split(cmd)]


TEMPLATES = {
    "host_health": (_b_host_health, True),
    "host_health_install": (_b_host_health_install, True),
    "unit_start": (_b_unit_start, True),
    "unit_journal": (_b_unit_journal, True),
    "upgrade": (_b_upgrade, True),
    "db_vacuum": (_b_db_vacuum, True),
    "cf_token_edit": (_b_cf_token_edit, True),
    "traefik_recreate": (_b_traefik_recreate, True),
    "ntp_status": (_b_ntp_status, False),
    "ntp_on": (_b_ntp_on, True),
    "cert_renew": (_b_cert_renew, True),
}

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./=:@*+-]{1,255}$")


def render(template: str, params: Optional[dict] = None,
           install_dir: Optional[str] = None) -> dict:
    """→ {"text": str, "requires_root": bool}. Raises CommandError for anything off-list."""
    spec = TEMPLATES.get(template) if isinstance(template, str) else None
    if spec is None:
        raise CommandError("unknown command template")
    params = params if isinstance(params, dict) else {}
    builder, root = spec
    segments = builder(dict(params), _dir(install_dir))
    for seg in segments:
        if not seg or not all(isinstance(t, str) and _TOKEN_RE.match(t) for t in seg):
            raise CommandError("unexpected token")
    text = " && ".join(" ".join(shlex.quote(t) for t in seg) for seg in segments)
    want: list = []
    for i, seg in enumerate(segments):
        if i:
            want.append("&&")
        want.extend(seg)
    if shlex.split(text) != want or "\n" in text or len(text) > 400:
        raise CommandError("command did not round-trip")
    return {"text": text, "requires_root": root}


def render_list(commands, install_dir: Optional[str] = None) -> list:
    """A check's commands → rendered list; any invalid entry is dropped (fail closed: no command
    rather than a wrong one)."""
    out = []
    for c in (commands or [])[:MAX_COMMANDS]:
        if not isinstance(c, dict):
            continue
        try:
            r = render(c.get("t"), c.get("p") or {}, install_dir)
        except CommandError:
            continue
        out.append({"template": c.get("t"), **r})
    return out
