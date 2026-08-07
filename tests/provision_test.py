"""Provisioning agent prin SSH (Faza 3): adaugă un host SSH (politică efemeră),
apelează /provision — gateway-ul se conectează prin SSH, rulează installer-ul,
AȘTEAPTĂ ca agentul să sune acasă (test), apoi trece host-ul în mod agent și
șterge credențialele. Contra sshd-ului local, user de test efemer."""
import json
import os
import subprocess
import sys
import time

import httpx

BASE = os.environ.get("BASE", "http://localhost:8010")
USER = "wtprov"
KEY = "/tmp/wt_prov_key"
ok = 0
total = 0


def check(name, cond):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}")


def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True).stdout


def setup():
    teardown()
    sh(f"ssh-keygen -t ed25519 -f {KEY} -N '' -q")
    sh(f"sudo useradd -m -s /bin/bash {USER}")
    h = f"/home/{USER}"
    sh(f"sudo mkdir -p {h}/.ssh && sudo cp {KEY}.pub {h}/.ssh/authorized_keys")
    sh(f"sudo chown -R {USER}:{USER} {h}/.ssh && sudo chmod 700 {h}/.ssh && sudo chmod 600 {h}/.ssh/authorized_keys")


def teardown():
    # Installer-ul de agent pornește supravegherea prin `systemctl --user` ȘI cere
    # `loginctl enable-linger` — adică un manager systemd care SUPRAVIEȚUIEȘTE logout-ului.
    # Fără disable-linger + terminate-user, `userdel` dă „currently used by process" și
    # contul de test rămâne pe mașină (vezi incidentul wtsshtest: 21 de zile, 13 shell-uri).
    uid = sh(f"id -u {USER} 2>/dev/null").strip()          # înainte de userdel (sh() dă stdout)
    sh(f"sudo crontab -u {USER} -r 2>/dev/null")
    sh(f"sudo loginctl disable-linger {USER} 2>/dev/null")
    sh(f"sudo loginctl terminate-user {USER} 2>/dev/null")
    sh(f"sudo pkill -9 -u {USER} 2>/dev/null")
    time.sleep(0.5)
    sh(f"sudo userdel -r {USER} 2>/dev/null")
    if uid.isdigit():
        sh(f"sudo rm -rf /tmp/tmux-{uid}")
    for p in (KEY, KEY + ".pub"):
        try:
            os.unlink(p)
        except OSError:
            pass


def main():
    setup()
    key = open(KEY).read()
    c = httpx.Client(base_url=BASE, timeout=220)
    c.post("/api/login", json={"email": "admin@example.com", "password": "parola-buna-123"})

    r = c.post("/api/hosts", json={
        "name": "provbox", "connection_type": "ssh", "hostname": "127.0.0.1",
        "ssh_username": USER, "auth_method": "key", "credential": key,
        "credential_policy": "ephemeral",
    })
    hid = r.json()["id"]
    check("host SSH efemer creat", r.status_code == 200)

    print("  … provisioning (SSH install + așteaptă agentul; poate dura ~30s)")
    r = c.post(f"/api/hosts/{hid}/provision")
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code != 200:
        print("    provision a eșuat:", r.status_code, (r.text or "")[-400:])
    check("provision reușit (agentul a sunat acasă = testat)", r.status_code == 200 and body.get("ok"))
    check("credențialele efemere au fost șterse", body.get("credentials_deleted") is True)

    time.sleep(1)
    host = next(h for h in c.get("/api/hosts").json() if h["id"] == hid)
    check("host trecut în mod agent", host["connection_type"] == "agent")
    check("host online prin agent", host["online"] is True)
    check("has_credentials = false (seif golit)", host["has_credentials"] is False)

    # curăță: șterge host-ul (are sesiuni? oprește agentul întâi)
    c.delete(f"/api/hosts/{hid}")
    c.close()
    teardown()
    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    try:
        success = main()
    finally:
        teardown()
    sys.exit(0 if success else 1)
