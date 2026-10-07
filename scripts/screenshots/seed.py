#!/usr/bin/env python3
"""Seed for the screenshots (runs INSIDE the ephemeral WebTerm container): account +
demo fleet. It extracts the agent token of the "online" hosts and prints them as
`AGENT <name> <token>` lines on stdout, so run.sh (on the host) can start the agents.
No external dependencies (stdlib only).

Every name and address here is made up (web-01, 10.x / 192.168.x): the screenshots
must never show anything from a real network."""
import json
import sys
import urllib.request
import http.cookiejar

BASE = "http://127.0.0.1:8000"
EMAIL, PASSWORD, TOKEN = sys.argv[1], sys.argv[2], sys.argv[3]

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    # the gateway's csrf_guard refuses state-changing requests without a same-origin Origin
    if method != "GET":
        req.add_header("Origin", BASE)
    with opener.open(req, timeout=15) as r:
        raw = r.read().decode()
    return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw


def get_text(path):
    with opener.open(urllib.request.Request(BASE + path), timeout=15) as r:
        return r.read().decode()


call("POST", "/api/setup", {"email": EMAIL, "password": PASSWORD, "setup_token": TOKEN})

# (name, folder, tags, online?)
FLEET = [
    ("web-01", "Production", "web prod", True),
    ("web-02", "Production", "web prod", True),
    ("db-01", "Production", "db prod", True),
    ("cache-01", "Staging", "cache", True),
    ("worker-03", "Staging", "worker", False),
    ("backup-01", "Infra", "backup", False),
]

ids = {}
for name, folder, tags, online in FLEET:
    h = call("POST", "/api/hosts", {
        "name": name, "folder": folder, "tags": tags, "note": "",
        "connection_type": "agent", "require_2fa": False})
    hid = ids[name] = h["id"]
    if name == "db-01":
        call("POST", f"/api/hosts/{hid}/require-2fa", {"enabled": True})
    if online and h.get("install_command"):
        enroll = h["install_command"].split("install/")[1].split(".sh")[0]
        sh = get_text(f"/install/{enroll}.sh")
        tok = ""
        for line in sh.splitlines():
            if line.startswith('TOKEN="'):
                tok = line.split('"', 2)[1]
                break
        if tok:
            print(f"AGENT {name} {tok}", flush=True)

# A network device reached THROUGH web-01 (SSH jump to a private address; the password is
# asked at connect time, nothing stored) — shows the bastion side of the product.
call("POST", "/api/hosts", {
    "name": "edge-router", "folder": "Infra", "tags": "network", "note": "uplink 192.168.10.1",
    "connection_type": "ssh-jump", "via_host_id": ids["web-01"], "hostname": "192.168.10.1",
    "ssh_port": 22, "ssh_username": "admin", "credential_policy": "ask"})

# Saved "Run on hosts" commands are server-side snippets (3.5.4+); one targets a tag.
for title, body, tags in [
    ("Deployed release", "cat ~/RELEASE", None),
    ("Disk usage", "df -h / | tail -1", None),
    ("Uptime and load", "uptime", ["prod"]),
    ("Failed units", "systemctl --failed --no-legend || true", None),
]:
    snip = {"title": title, "body": body}
    if tags:
        snip["targets"] = {"tags": tags}
    call("POST", "/api/snippets", snip)

# sign out, or "Python-urllib" shows up under Settings → Security → Connected devices
call("POST", "/api/logout")
