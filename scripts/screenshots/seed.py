#!/usr/bin/env python3
"""Seed for the screenshots (runs INSIDE the ephemeral WebTerm container): account +
demo fleet. It extracts the agent token of the "online" hosts and prints them as
`AGENT <name> <token>` lines on stdout, so run.sh (on the host) can start the agents.
No external dependencies (stdlib only)."""
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
    with opener.open(req, timeout=15) as r:
        raw = r.read().decode()
    return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw


def get_text(path):
    with opener.open(urllib.request.Request(BASE + path), timeout=15) as r:
        return r.read().decode()


call("POST", "/api/setup", {"email": EMAIL, "password": PASSWORD, "setup_token": TOKEN})

# (name, folder, online?)
FLEET = [
    ("prod-web-01", "Production", True),
    ("prod-web-02", "Production", True),
    ("db-eu-1", "Production", True),
    ("cache-02", "Staging", True),
    ("worker-eu-3", "Staging", False),
    ("legacy-bastion", "Infra", False),
]

for name, folder, online in FLEET:
    h = call("POST", "/api/hosts", {
        "name": name, "folder": folder, "note": "",
        "connection_type": "agent", "require_2fa": False})
    hid = h["id"]
    if name == "db-eu-1":
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
