"""scripts/host-health.sh + scripts/docker-cleanup.sh against FAKE trees (3.6.8) — never the host.

Both scripts run as root on the gateway host (systemd timers). Everything here is hermetic: a
throw-away install directory, a fake `docker` / `systemctl` that log their argv and answer from
files, a fake systemd and cron directory, and a local HTTP server standing in for the Cloudflare
API. Test-mode runs drop to `nobody` when the suite itself runs as root (test mode is refused to
root by design).

What we check:
  * --record writes one status file per id: valid JSON, 0644, atomically; refuses an unknown id or
    status, a DATA_JSON that is too big / not an object / has bad keys or values; sanitises the
    message (control characters, newlines, 5000 chars → 200; HTML stays literal text);
  * a planted symlink at host-status/<id>.json is REPLACED, its target untouched; host-status itself
    a symlink → refused, nothing written through it;
  * not root and not test mode → --record is a quiet no-op (exit 0), a run refuses; root ignores
    the test-mode switch (and then refuses a tree that is not root's);
  * the Cloudflare token: active / expiring soon / expired / rejected (401) / API unreachable / no
    token → the right status, and the token never reaches stdout, stderr or a status file (only the
    Authorization header the fake API received);
  * the Authentik image: equal / older than the pin / newer / none running;
  * the timers: missing or disabled → `warn` with the list; --install renders the units for THIS
    directory, is idempotent, leaves another install's units alone, retires the old cron job only
    when it is the WebTerm one;
  * docker-cleanup.sh: dangling prune, the WebTerm label filter on the -a prune, keep-N WebTerm
    versions plus the running image and the rollback target, build-cache prune, never a volume /
    system / container command, --dry-run removes nothing, the status is recorded;
  * authentik-upgrade.sh: the hop rule; as root, the script / compose dir / compose file / .env
    must be root's; `restore` (audit 2026-10-17, OP-03/OP-10) refuses a backup outside the backup
    root (real path), one not owned by root, one whose dump / meta / SHA256SUMS / compose file is
    not root's, a --backup-dir under someone else's directory, and Postgres < 13 — all BEFORE
    stopping anything; the compose file comes back root:root 0644 (through the link when the
    live one is a symlink); a DROP that fails after the stop starts server+worker again; the
    Postgres version is read from the maintenance DB (a re-run after a failed CREATE works) and
    an unanswered one is "is it running?", not a version problem; a --backup-dir that is a
    symlink is refused before anything is created or chmod'ed there. These checks need root
    (CI runs the suite as the runner user and skips them: `sudo .venv/bin/python tests/host_health_script_test.py`).
"""
import http.server
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
HH = os.path.join(ROOT, "scripts", "host-health.sh")
DC = os.path.join(ROOT, "scripts", "docker-cleanup.sh")
IS_ROOT = os.geteuid() == 0
NOBODY = pwd.getpwnam("nobody").pw_uid if IS_ROOT else None
TOKEN = "cfTok_" + "Q" * 30 + "_never_print"

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


FAKE_DOCKER = r"""#!/bin/sh
echo "$*" >> "$FAKE_DIR/calls"
case "$1" in
  ps)
    case "$*" in
      *service=app*) [ -f "$FAKE_DIR/app_cid" ] && cat "$FAKE_DIR/app_cid" ;;
      *-aq*) [ -f "$FAKE_DIR/all_cids" ] && cat "$FAKE_DIR/all_cids" ;;
      *compose.project=*) [ -f "$FAKE_DIR/ak_project" ] && cat "$FAKE_DIR/ak_project" ;;
      *Image*) [ -f "$FAKE_DIR/ak_ps" ] && cat "$FAKE_DIR/ak_ps" ;;
    esac ;;
  inspect) echo sha256:running ;;
  images)
    case "$*" in
      *dangling*) echo d1; echo d2 ;;
      *--no-trunc*) [ -f "$FAKE_DIR/images" ] && cat "$FAKE_DIR/images" ;;
      *) [ -f "$FAKE_DIR/tags" ] && cat "$FAKE_DIR/tags" ;;
    esac ;;
  image)
    case "$2" in
      inspect)
        case "$*" in
          *RepoDigests*) : ;;
          *Labels*) ref=$(echo "$*" | awk '{print $NF}'); grep "^$ref " "$FAKE_DIR/labels" 2>/dev/null | awk '{print $2}' ;;
          *) ref=$(echo "$*" | awk '{print $NF}'); grep "^$ref " "$FAKE_DIR/ids" 2>/dev/null | awk '{print $2}' ;;
        esac ;;
      prune|rm) : ;;
    esac ;;
  builder) : ;;
  *) echo "fake docker: unexpected $*" >&2; exit 9 ;;
esac
"""

FAKE_SYSTEMCTL = r"""#!/bin/sh
echo "$*" >> "$FAKE_DIR/systemctl"
if [ "$1" = show ] && [ -s "$FAKE_DIR/next" ]; then echo "@$(cat "$FAKE_DIR/next")"; exit 0; fi
if [ "$1" = is-enabled ]; then
  if grep -qx "$2" "$FAKE_DIR/enabled" 2>/dev/null; then echo enabled; exit 0; fi
  echo disabled; exit 1
fi
exit 0
"""


class CF:
    """A stand-in for api.cloudflare.com/client/v4/user/tokens/verify."""
    mode = "active"
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            CF.seen.append(dict(self.headers))
            m = CF.mode
            if m == "401":
                self.send_response(401); self.end_headers(); self.wfile.write(b'{"success":false}'); return
            res = {"id": "abc", "status": "active"}
            if m == "soon":
                res["expires_on"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 10 * 86400))
            elif m == "later":
                res["expires_on"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 90 * 86400))
            elif m == "disabled":
                res["status"] = "disabled"
            body = json.dumps({"success": True, "result": res}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(body)

    def __init__(self):
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), CF.H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


def give(path):
    """Under root, hand the tree to nobody (test mode runs as nobody)."""
    if not IS_ROOT:
        return
    for d, dirs, files in os.walk(path):
        os.chown(d, NOBODY, NOBODY)
        for f in files:
            os.lchown(os.path.join(d, f), NOBODY, NOBODY)


def make_tree(base):
    inst = os.path.join(base, "inst")
    os.makedirs(os.path.join(inst, "scripts"))
    os.makedirs(os.path.join(inst, "deploy"))
    os.makedirs(os.path.join(inst, "secrets"))
    shutil.copy(os.path.join(ROOT, "docker-compose.prod.yml"), inst)
    with open(os.path.join(inst, ".env"), "w") as f:
        f.write("GHCR_USER=sm26449\nWEBTERM_IMAGE=ghcr.io/sm26449/webterm@sha256:cur\n")
    for s in ("host-health.sh", "docker-cleanup.sh"):
        shutil.copy(os.path.join(ROOT, "scripts", s), os.path.join(inst, "scripts", s))
        os.chmod(os.path.join(inst, "scripts", s), 0o755)
    for u in ("webterm-host-health", "webterm-docker-cleanup"):
        for ext in ("service", "timer"):
            shutil.copy(os.path.join(ROOT, "deploy", "%s.%s" % (u, ext)), os.path.join(inst, "deploy"))
    fake = os.path.join(base, "fake")
    os.makedirs(os.path.join(fake, "bin"))
    for name, body in (("docker", FAKE_DOCKER), ("systemctl", FAKE_SYSTEMCTL)):
        p = os.path.join(fake, "bin", name)
        open(p, "w").write(body)
        os.chmod(p, 0o755)
    for d in ("status", "systemd", "cron", "log"):
        os.makedirs(os.path.join(base, d))
    return inst, fake


def run(base, inst, fake, script, *args, test_mode=True, extra_env=None, as_root=False):
    env = {k: v for k, v in os.environ.items() if not k.startswith("WEBTERM_")}
    env.update({"FAKE_DIR": fake, "PATH": os.path.join(fake, "bin") + ":" + os.environ.get("PATH", "")})
    if test_mode:
        env.update({"WEBTERM_HOST_HEALTH_TEST": "1", "WEBTERM_DOCKER_CLEANUP_TEST": "1",
                    "DOCKER_TEST_BIN": os.path.join(fake, "bin", "docker"),
                    "WEBTERM_SYSTEMCTL": os.path.join(fake, "bin", "systemctl"),
                    "WEBTERM_STATUS_BASE": os.path.join(base, "status"),
                    "WEBTERM_SYSTEMD_DIR": os.path.join(base, "systemd"),
                    "WEBTERM_CRON_DIR": os.path.join(base, "cron"),
                    "LOG_TEST": os.path.join(base, "log", "cleanup.log")})
    env.update(extra_env or {})
    argv = ["bash", os.path.join(inst, "scripts", script), *args]
    if IS_ROOT and not as_root:
        argv = ["setpriv", "--reuid=%d" % NOBODY, "--regid=%d" % NOBODY, "--clear-groups", "--"] + argv
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=60)
    return p.returncode, p.stdout + p.stderr


def status(base, sid):
    p = os.path.join(base, "status", "host-status", sid + ".json")
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def main():
    base = tempfile.mkdtemp(prefix="hosthealth-")
    os.chmod(base, 0o755)
    try:
        inst, fake = make_tree(base)
        give(base)
        rec = lambda *a, **k: run(base, inst, fake, "host-health.sh", "--record", *a, **k)  # noqa: E731

        print("── --record")
        rc, out = rec("backup", "ok", "archive webterm-1.tar.gz.enc, off-host ok",
                      '{"archive":"webterm-1.tar.gz.enc","encrypted":true,"offhost":"ok"}')
        st = status(base, "backup")
        check("a status file is written", rc == 0 and st is not None, out[-300:])
        check("…with the contract's shape", st and st["v"] == 1 and st["id"] == "backup" and st["status"] == "ok"
              and isinstance(st["ts"], int) and abs(st["ts"] - time.time()) < 60
              and st["data"] == {"archive": "webterm-1.tar.gz.enc", "encrypted": True, "offhost": "ok"}, st)
        p = os.path.join(base, "status", "host-status", "backup.json")
        check("…mode 0644, dir 0755", stat.S_IMODE(os.stat(p).st_mode) == 0o644
              and stat.S_IMODE(os.stat(os.path.dirname(p)).st_mode) == 0o755)
        check("…no temp files left", sorted(os.listdir(os.path.dirname(p))) == ["backup.json"],
              os.listdir(os.path.dirname(p)))
        for bad_id in ("nope", "../x", "backup.json", ""):
            rc, out = rec(bad_id, "ok", "m")
            check("unknown id %r → refused" % bad_id, rc != 0 and "refused" in out, out[-200:])
        rc, out = rec("backup", "great", "m")
        check("unknown status → refused", rc != 0 and "refused" in out, out[-200:])
        rc, out = rec("cert-check", "error", "line1\nline2\x1b[31m\x07<script>alert(1)</script>" + "x" * 5000)
        st = status(base, "cert-check")
        msg = st["message"] if st else ""
        check("message: control characters and newlines stripped, cut to 200", rc == 0 and len(msg) == 200
              and "\n" not in msg and "\x1b" not in msg and "\x07" not in msg, repr(msg[:80]))
        check("message: HTML stays literal text (the gateway renders it as text)",
              "<script>alert(1)</script>" in msg, msg[:80])
        before = status(base, "docker-cleanup")
        for label, data in (("too big", json.dumps({"a": "x" * 1100})), ("not an object", "[1,2]"),
                            ("bad key", '{"Bad-Key":1}'), ("too long string", json.dumps({"a": "x" * 200})),
                            ("NaN", '{"a":NaN}'), ("two nested objects", '{"a":{"x":1},"b":{"y":2}}'),
                            ("nested object in nested", '{"a":{"x":{"y":1}}}'), ("not json", "{oops")):
            rc, out = rec("docker-cleanup", "ok", "m", data)
            check("DATA_JSON %s → refused, nothing written" % label, rc != 0 and status(base, "docker-cleanup") == before,
                  out[-200:])
        rc, out = rec("host-health", "ok", "m", json.dumps({"timers": {"webterm-backup.timer": "enabled"},
                                                            "legacy_cron": False, "script_version": 1}))
        check("one nested object is accepted (timers)", rc == 0 and status(base, "host-health")["data"]["timers"]
              == {"webterm-backup.timer": "enabled"}, out[-200:])

        print("── symlinks")
        victim = os.path.join(base, "victim")
        open(victim, "w").write("precious\n")
        give(victim)
        hs = os.path.join(base, "status", "host-status")
        link = os.path.join(hs, "authentik-image.json")
        os.symlink(victim, link)
        rc, out = rec("authentik-image", "ok", "m")
        check("a planted symlink at <id>.json is replaced, not followed", rc == 0 and not os.path.islink(link)
              and open(victim).read() == "precious\n" and status(base, "authentik-image")["id"] == "authentik-image",
              out[-200:])
        elsewhere = os.path.join(base, "elsewhere")
        os.makedirs(elsewhere)
        give(elsewhere)
        shutil.rmtree(hs)
        os.symlink(elsewhere, hs)
        rc, out = rec("backup", "ok", "m")
        check("host-status itself a symlink → refused, nothing written through it",
              rc != 0 and os.listdir(elsewhere) == [], out[-200:])
        os.unlink(hs)

        print("── who may write")
        rc, out = rec("backup", "ok", "m", test_mode=False)
        check("not root, no test mode: --record is a quiet no-op (exit 0)", rc == 0 and "not recorded" in out
              and not os.path.exists(os.path.join(hs, "backup.json")), out[-200:])
        rc, out = run(base, inst, fake, "host-health.sh", test_mode=False)
        check("not root, no test mode: a run refuses", rc != 0 and "must run as root" in out, out[-200:])
        if IS_ROOT:
            rc, out = rec("backup", "ok", "m", as_root=True)
            check("root ignores the test switch…", "ignored when running as root" in out, out[-300:])
            check("…and refuses a tree that is not root's (no override honoured)",
                  rc == 2 and not os.path.exists(os.path.join(hs, "backup.json")) and "must be owned by root" in out,
                  out[-300:])
            check("…without ever calling the fake docker through the override", not os.path.exists(
                os.path.join(fake, "calls")) or "volume" not in open(os.path.join(fake, "calls")).read(),
                open(os.path.join(fake, "calls")).read() if os.path.exists(os.path.join(fake, "calls")) else "")
        else:
            src = open(HH).read()
            check("the test switch is gated on EUID (source check: not root here)",
                  '"${EUID:-0}" = 0' in src and "ignored when running as root" in src)

        print("── the Cloudflare token")
        cf = CF()
        api = {"WEBTERM_CF_API": "http://127.0.0.1:%d" % cf.port}
        tokf = os.path.join(inst, "secrets", "cf_dns_api_token")
        open(tokf, "w").write(TOKEN + "\n")
        give(tokf)
        for mode, want_st, want_ts in (("active", "ok", "active"), ("later", "ok", "active"),
                                       ("soon", "warn", "active"), ("disabled", "error", "disabled"),
                                       ("401", "error", "invalid")):
            CF.mode = mode
            CF.seen.clear()
            rc, out = run(base, inst, fake, "host-health.sh", extra_env=api)
            st = status(base, "cloudflare-token")
            check("CF %s → %s/%s" % (mode, want_st, want_ts), st and st["status"] == want_st
                  and st["data"]["token_status"] == want_ts, (rc, st, out[-300:]))
            check("…the token reached the API only as the Authorization header",
                  any(h.get("Authorization") == "Bearer " + TOKEN for h in CF.seen), CF.seen)
            blob = json.dumps(st) + out
            check("…and never stdout/stderr/status", TOKEN not in blob and TOKEN[:12] not in blob)
        CF.mode = "soon"
        run(base, inst, fake, "host-health.sh", extra_env=api)
        st = status(base, "cloudflare-token")
        check("expiring soon: expires_on recorded", st and st["data"]["expires_on"].startswith("20"), st)
        cf.srv.shutdown()
        cf.srv.server_close()
        rc, out = run(base, inst, fake, "host-health.sh", extra_env=api)
        st = status(base, "cloudflare-token")
        check("API unreachable → warn/unknown", st and st["status"] == "warn" and st["data"]["token_status"] == "unknown",
              (st, out[-200:]))
        open(tokf, "w").write("")
        rc, out = run(base, inst, fake, "host-health.sh", extra_env=api)
        st = status(base, "cloudflare-token")
        check("no token → skipped", st and st["status"] == "skipped", st)
        open(tokf, "w").write("bad token with spaces;rm -rf /\n")
        rc, out = run(base, inst, fake, "host-health.sh", extra_env=api)
        st = status(base, "cloudflare-token")
        check("a malformed token file → error, never sent", st and st["status"] == "error" and "rm -rf" not in json.dumps(st), st)
        open(tokf, "w").write("")

        print("── the Authentik image")
        akf = os.path.join(fake, "ak_ps")
        ours = os.path.basename(inst).lower()
        for line, want, label, layout in (
                ("ghcr.io/goauthentik/server:2026.8.3|authentik|server|/srv/ak", "ok", "equal to the pin", "separate"),
                # prod's real layout (3.6.8 correction): a SEPARATE stack, project `authentik` in
                # /opt/authentik, on 2026.8.2 while the repo pins 2026.8.3 — and its worker listed first
                ("ghcr.io/goauthentik/server:2026.8.2|authentik|worker|/opt/authentik\n"
                 "ghcr.io/goauthentik/server:2026.8.2|authentik|server|/opt/authentik", "warn",
                 "a separate /opt/authentik stack older than the pin", "separate"),
                ("ghcr.io/goauthentik/server:2024.10.5|%s|authentik-server|%s" % (ours, inst), "warn",
                 "the profile inside this install, older", "profile"),
                ("ghcr.io/goauthentik/server:2027.1.0|other||", "ok", "newer than the pin", "separate")):
            open(akf, "w").write("traefik:v3|webterm|traefik|%s\n" % inst + line + "\n")
            run(base, inst, fake, "host-health.sh", extra_env=api)
            st = status(base, "authentik-image")
            check("Authentik %s → %s (%s)" % (label, want, layout), st and st["status"] == want
                  and st["data"].get("pinned") == "2026.8.3" and st["data"].get("layout") == layout, st)
            if want == "warn":
                check("older: both versions in the data, 'step by step' in the message",
                      st and st["data"].get("running") in ("2024.10.5", "2026.8.2")
                      and "step by step" in st["message"], st)
        open(akf, "w").write("evil/goauthentik/server:2026.8.3|x;rm -rf /|server|/tmp\n")
        run(base, inst, fake, "host-health.sh", extra_env=api)
        st = status(base, "authentik-image")
        check("a hostile project label is not copied into the status", st and "rm -rf" not in json.dumps(st), st)
        os.unlink(akf)
        run(base, inst, fake, "host-health.sh", extra_env=api)
        st = status(base, "authentik-image")
        check("no Authentik container → skipped", st and st["status"] == "skipped", st)

        print("── the timers")
        sysd = os.path.join(base, "systemd")
        rc, out = run(base, inst, fake, "host-health.sh", extra_env=api)
        st = status(base, "host-health")
        check("no timer installed → warn listing them", st and st["status"] == "warn" and "webterm-backup" in st["message"]
              and st["data"]["timers"]["webterm-backup.timer"] == "missing", st)
        rc, out = run(base, inst, fake, "host-health.sh", "--install")
        rendered = open(os.path.join(sysd, "webterm-host-health.service")).read() \
            if os.path.exists(os.path.join(sysd, "webterm-host-health.service")) else ""
        check("--install renders the units for THIS directory", rc == 0 and "WorkingDirectory=%s\n" % inst in rendered
              and "ExecStart=%s/scripts/host-health.sh" % inst in rendered and "/opt/webterm" not in rendered, out[-300:])
        check("…all four files", sorted(os.listdir(sysd)) == sorted(
            ["webterm-host-health.service", "webterm-host-health.timer",
             "webterm-docker-cleanup.service", "webterm-docker-cleanup.timer"]), os.listdir(sysd))
        sc = open(os.path.join(fake, "systemctl")).read()
        check("…daemon-reload + enable --now the timers", "daemon-reload" in sc
              and "enable --now webterm-host-health.timer" in sc and "enable --now webterm-docker-cleanup.timer" in sc, sc)
        mt = {f: os.stat(os.path.join(sysd, f)).st_mtime_ns for f in os.listdir(sysd)}
        open(os.path.join(fake, "enabled"), "w").write("webterm-host-health.timer\nwebterm-docker-cleanup.timer\n")
        open(os.path.join(fake, "systemctl"), "w").write("")
        rc, out = run(base, inst, fake, "host-health.sh", "--install")
        check("a second --install changes nothing", rc == 0 and mt == {f: os.stat(os.path.join(sysd, f)).st_mtime_ns
                                                                         for f in os.listdir(sysd)}
              and "daemon-reload" not in open(os.path.join(fake, "systemctl")).read()
              and "already up to date" in out, out[-300:])
        for t in ("webterm-backup", "webterm-cert-check"):
            open(os.path.join(sysd, t + ".timer"), "w").write("[Timer]\n")
        with open(os.path.join(fake, "enabled"), "a") as f:
            f.write("webterm-backup.timer\nwebterm-cert-check.timer\n")
        run(base, inst, fake, "host-health.sh", extra_env=api)
        st = status(base, "host-health")
        check("all timers enabled → ok", st and st["status"] == "ok"
              and set(st["data"]["timers"].values()) == {"enabled"}, st)
        # 3.6.9 kit report: which scripts can report, since when, next run
        kd = st["data"] if st else {}
        check("kit: docker-cleanup.sh (current) can report, backup.sh (absent) cannot",
              kd.get("kit_cleanup") is True and kd.get("kit_backup") is False and kd.get("script_version") == 2, kd)
        check("kit: install time = newest of script / timer mtime",
              kd.get("since_cleanup", 0) >= int(os.stat(os.path.join(sysd, "webterm-docker-cleanup.timer")).st_mtime) - 1, kd)
        open(os.path.join(inst, "scripts", "backup.sh"), "w").write("#!/bin/sh\n# 3.6.7: no status reporting\n")
        open(os.path.join(fake, "next"), "w").write("1893456000")
        run(base, inst, fake, "host-health.sh", extra_env=api)
        kd = (status(base, "host-health") or {}).get("data", {})
        check("kit: an old backup.sh without --record → kit_backup false; next run from systemctl show",
              kd.get("kit_backup") is False and kd.get("next_backup") == 1893456000, kd)
        open(os.path.join(inst, "scripts", "backup.sh"), "w").write(
            '#!/bin/sh\n"$BK_SELF_DIR/host-health.sh" --record backup ok done\n')
        os.unlink(os.path.join(fake, "next"))
        run(base, inst, fake, "host-health.sh", extra_env=api)
        kd = (status(base, "host-health") or {}).get("data", {})
        check("kit: a current backup.sh → kit_backup true; next unknown → 0",
              kd.get("kit_backup") is True and kd.get("next_backup") == 0, kd)
        other = os.path.join(sysd, "webterm-docker-cleanup.service")
        open(other, "w").write("[Service]\nWorkingDirectory=/opt/other\n")
        rc, out = run(base, inst, fake, "host-health.sh", "--install")
        check("another install's unit is left alone", "/opt/other" in open(other).read()
              and "belongs to /opt/other" in out, out[-300:])
        cron = os.path.join(base, "cron")
        open(os.path.join(cron, "webterm-docker-cleanup"), "w").write(
            "17 4 * * * root /usr/local/bin/webterm-docker-cleanup >/dev/null 2>&1\n")
        open(os.path.join(cron, "other-job"), "w").write("0 1 * * * root /usr/local/bin/something\n")
        rc, out = run(base, inst, fake, "host-health.sh", "--install")
        check("the old WebTerm cron job is retired (renamed, cron ignores dotted names)",
              sorted(os.listdir(cron)) == ["other-job", "webterm-docker-cleanup.disabled-by-webterm"], os.listdir(cron))
        open(os.path.join(cron, "webterm-docker-cleanup"), "w").write("0 2 * * * root /usr/local/bin/mine\n")
        run(base, inst, fake, "host-health.sh", "--install")
        check("…but a cron file of the same name that is not ours is left alone",
              os.path.exists(os.path.join(cron, "webterm-docker-cleanup")))

        print("── docker-cleanup.sh")
        tags = ["v3.%d.0" % i for i in range(1, 11)]          # 10 versions
        open(os.path.join(fake, "tags"), "w").write("\n".join(tags) + "\n")
        ids = {"ghcr.io/sm26449/webterm:%s" % t: "sha256:%s" % t for t in tags}
        ids["ghcr.io/sm26449/webterm:v3.1.0"] = "sha256:running"            # the running image
        ids["prevref"] = "sha256:v3.2.0"                                     # the rollback target
        ids["ghcr.io/sm26449/webterm@sha256:cur"] = "sha256:cur"
        open(os.path.join(fake, "ids"), "w").write("".join("%s %s\n" % kv for kv in ids.items()))
        open(os.path.join(inst, ".prev-image"), "w").write("prevref\n")
        open(os.path.join(fake, "app_cid"), "w").write("cid-app\n")
        # the other images (review L2): what must survive and what may go
        tool = "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
        ids.update({tool: "sha256:tool", "ghcr.io/goauthentik/server:2026.8.3": "sha256:akcur",
                    "docker.io/library/postgres:16.15-alpine": "sha256:pgpin",
                    "docker.io/library/postgres:16-alpine": "sha256:sepdb"})
        open(os.path.join(fake, "ids"), "w").write("".join("%s %s\n" % kv for kv in ids.items()))
        OLD, NOW = "2025-01-01 10:00:00 +0000 UTC", time.strftime("%Y-%m-%d %H:%M:%S +0000 UTC", time.gmtime())
        imgs = [("sha256:tool", "python", "<none>", OLD),                    # backup.sh's tool image (digest)
                ("sha256:akcur", "ghcr.io/goauthentik/server", "2026.8.3", OLD),   # pinned + running
                ("sha256:akprev", "ghcr.io/goauthentik/server", "2026.8.2", OLD),  # the rollback target
                ("sha256:akold", "ghcr.io/goauthentik/server", "2026.5.4", OLD),   # two steps back: may go
                ("sha256:pgpin", "docker.io/library/postgres", "16.15-alpine", OLD),   # this install's compose
                ("sha256:sepdb", "docker.io/library/postgres", "16-alpine", OLD),      # the separate Authentik project
                ("sha256:localwt", "webterm-app", "latest", OLD),             # a local WebTerm build
                ("sha256:wtlabel", "someorg/thing", "1", OLD),               # labelled as WebTerm
                ("sha256:running", "nginx", "1", OLD),                       # a container uses it
                ("sha256:junk", "busybox", "1.36", OLD),                     # unused and old: goes
                ("sha256:fresh", "alpine", "3.20", NOW),                     # unused but young: stays
                ("sha256:dang", "<none>", "<none>", NOW)]                    # dangling: goes
        open(os.path.join(fake, "images"), "w").write("".join("|".join(i) + "\n" for i in imgs))
        open(os.path.join(fake, "labels"), "w").write("sha256:wtlabel webterm\nsha256:junk <no value>\n")
        open(os.path.join(fake, "all_cids"), "w").write("c1\nc2\n")
        open(os.path.join(fake, "ak_ps"), "w").write(
            "ghcr.io/goauthentik/server:2026.8.3|authentik|server|/opt/authentik\n"
            "ghcr.io/goauthentik/server:2026.8.3|authentik|worker|/opt/authentik\n")
        open(os.path.join(fake, "ak_project"), "w").write(
            "ghcr.io/goauthentik/server:2026.8.3\ndocker.io/library/postgres:16-alpine\n")
        give(base)
        calls = os.path.join(fake, "calls")
        open(calls, "w").write("")
        rc, out = run(base, inst, fake, "docker-cleanup.sh", "--dry-run")
        c = open(calls).read()
        check("--dry-run removes nothing", rc == 0 and " rm " not in c and "prune" not in c, c)
        check("…and lists the old versions it would remove", "would remove ghcr.io/sm26449/webterm:v3.3.0" in out, out[-500:])
        check("…and the other images it would remove", "would remove busybox:1.36" in out
              and "would remove sha256:dang (dangling)" in out, out[-800:])
        open(calls, "w").write("")
        old = status(base, "docker-cleanup")
        rc, out = run(base, inst, fake, "docker-cleanup.sh")
        c = open(calls).read().splitlines()
        check("no blanket image prune at all (review L2: images are removed one by one)",
              not any(l.startswith("image prune") for l in c), c)
        removed = sorted(l.split()[2] for l in c if l.startswith("image rm "))
        check("keeps the newest 7 + the running + the rollback target; removes the rest",
              "ghcr.io/sm26449/webterm:v3.3.0" in removed
              and not any(r.startswith("ghcr.io/sm26449/webterm:") and r != "ghcr.io/sm26449/webterm:v3.3.0"
                          for r in removed), removed)
        check("other images: only the old unused one, the dangling one and the Authentik two versions back",
              sorted(r for r in removed if "sm26449" not in r)
              == ["busybox:1.36", "ghcr.io/goauthentik/server:2026.5.4", "sha256:dang"], removed)
        for what, ref in (("the python tool image backup.sh needs (by digest)", "sha256:tool"),
                          ("the previous Authentik image (rollback target)", "2026.8.2"),
                          ("the running / pinned Authentik image", "2026.8.3"),
                          ("an image this install's compose pins", "16.15-alpine"),
                          ("an image of the separate Authentik project", "16-alpine"),
                          ("a locally built WebTerm image", "webterm-app"),
                          ("an image labelled as WebTerm", "someorg/thing"),
                          ("an image a container uses", "nginx"),
                          ("a young unused image", "alpine:3.20")):
            check("preserved: %s" % what, not any(ref in r for r in removed), removed)
        check("image rm never forced (-f): an in-use image is refused by docker",
              not any(l.startswith("image rm") and " -f" in l for l in c), c)
        check("build-cache prune with its own window", "builder prune -f --filter until=72h" in c, c)
        check("never volumes, system prune or containers", not any(
            l.split()[0] in ("volume", "system", "container", "rm", "stop", "kill") or "volume" in l for l in c), c)
        st = status(base, "docker-cleanup")
        check("status recorded (images_removed, disk_free_pct)", st and st != old and st["status"] == "ok"
              and st["data"]["images_removed"] == 4 and isinstance(st["data"]["disk_free_pct"], (int, float)), st)
        # review L5: df fails → `"disk_free_pct":0`, never `"disk_free_pct":,` (refused as invalid JSON)
        dfp = os.path.join(fake, "bin", "df")
        open(dfp, "w").write("#!/bin/sh\nexit 1\n")
        os.chmod(dfp, 0o755)
        give(base)
        time.sleep(1.1)
        before = status(base, "docker-cleanup")
        rc, out = run(base, inst, fake, "docker-cleanup.sh")
        st = status(base, "docker-cleanup")
        check("df failing → the status is still recorded, with disk_free_pct 0", rc == 0 and st and st != before
              and st["data"].get("disk_free_pct") == 0, (st, out[-300:]))
        os.remove(dfp)
        tool_refs = {}
        for f in ("backup.sh", "restore.sh", "host-health.sh", "docker-cleanup.sh"):
            m = re.search(r"python:3\.12-alpine@sha256:[0-9a-f]{64}", open(os.path.join(ROOT, "scripts", f)).read())
            tool_refs[f] = m.group(0) if m else None
        check("the tool image digest docker-cleanup preserves is the one backup/restore/host-health run",
              len(set(tool_refs.values())) == 1 and None not in tool_refs.values(), tool_refs)
        rc, out = run(base, inst, fake, "docker-cleanup.sh", extra_env={"RETENTION": "1d;rm"})
        check("a bad RETENTION is refused", rc == 2 and "RETENTION" in out, out[-200:])
        rc, out = run(base, inst, fake, "docker-cleanup.sh", test_mode=False)
        check("not root, no test mode → refused", rc != 0 and "must run as root" in out, out[-200:])

        print("── authentik-upgrade.sh: the hop rule (review L3)")
        AU = os.path.join(ROOT, "scripts", "authentik-upgrade.sh")

        def hop(cur, target, unlisted=True):
            argv = ["bash", AU] + (["--unlisted-minor"] if unlisted else []) + ["check-hop", cur, target]
            p = subprocess.run(argv, capture_output=True, text=True, timeout=30, cwd="/",
                               env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
            return p.returncode, p.stdout + p.stderr
        for cur, target, allowed, why in (
                ("2026.8.3", "2025.9.0", False, "--unlisted-minor: an OLDER unknown minor is a downgrade"),
                ("2026.8.3", "2026.7.0", False, "--unlisted-minor: same year, lower minor"),
                ("2026.8.3", "2026.8.0", False, "a lower patch"),
                ("2026.5.4", "2026.2.1", False, "an older known minor"),
                ("2026.5.4", "2026.11.0", False, "skipping a known minor"),
                ("2026.8.3", "2026.8.3", False, "the same version"),
                ("2026.8.3", "bogus", False, "a malformed target"),
                ("2026.8.2", "2026.8.3", True, "a patch step"),
                ("2026.5.4", "2026.8.3", True, "the next known minor"),
                ("2026.8.3", "2026.11.0", True, "--unlisted-minor: a newer unknown minor"),
                ("2026.8.3", "2027.1.0", True, "--unlisted-minor: the next year")):
            rc, out = hop(cur, target)
            check("check-hop %s → %s %s (%s)" % (cur, target, "allowed" if allowed else "refused", why),
                  (rc == 0) == allowed, out[-300:])
        rc, out = hop("2026.8.3", "2025.9.0")
        check("…the downgrade says why", "no downgrade" in out, out)
        rc, out = hop("2026.8.3", "2026.11.0", unlisted=False)
        check("an unknown minor without --unlisted-minor → refused", rc != 0 and "--unlisted-minor" in out, out)

        print("── authentik-upgrade.sh: as root, everything it trusts must be root's")
        if IS_ROOT:
            # a root-owned tree under a private (0700) dir: bin/ for the script, ak/ for the stack
            ak_base = os.path.realpath(tempfile.mkdtemp())
            os.chmod(ak_base, 0o700)
            for d in ("bin", "ak"):
                os.mkdir(os.path.join(ak_base, d), 0o755)
            ak_script = os.path.join(ak_base, "bin", "authentik-upgrade.sh")
            shutil.copy(AU, ak_script)
            os.chmod(ak_script, 0o755)
            ak_dir = os.path.join(ak_base, "ak")
            ak_cf = os.path.join(ak_dir, "docker-compose.yml")
            with open(ak_cf, "w") as f:
                f.write("services:\n  server:\n    image: ghcr.io/goauthentik/server:2026.8.2\n")
            os.chmod(ak_cf, 0o644)

            ak_fakebin = os.path.join(ak_base, "fakebin")
            os.mkdir(ak_fakebin, 0o755)
            with open(os.path.join(ak_fakebin, "docker"), "w") as f:   # never the real docker
                f.write("#!/bin/sh\necho fake-docker >&2\nexit 1\n")
            os.chmod(os.path.join(ak_fakebin, "docker"), 0o755)

            def au(script=ak_script):
                p = subprocess.run(["bash", script, "--dir", ak_dir, "status"], capture_output=True,
                                   text=True, timeout=60, cwd="/",
                                   env={"PATH": ak_fakebin + ":/usr/sbin:/usr/bin:/sbin:/bin"})
                return p.returncode, p.stdout + p.stderr
            rc, out = au()
            check("root-owned tree → passes the ownership checks", "refusing" not in out, out[-300:])
            os.chmod(ak_cf, 0o664)
            rc, out = au()
            check("group-writable compose file → refused", rc != 0 and "refusing: " + ak_cf in out, out[-300:])
            os.chmod(ak_cf, 0o644)
            os.chown(ak_dir, 1, 0)
            rc, out = au()
            check("compose dir not owned by root → refused", rc != 0 and "refusing: " + ak_dir in out, out[-300:])
            os.chown(ak_dir, 0, 0)
            env_f = os.path.join(ak_dir, ".env")
            open(env_f, "w").close()
            os.chown(env_f, 1, 0)
            rc, out = au()
            check(".env not owned by root → refused", rc != 0 and "refusing: " + env_f in out, out[-300:])
            os.unlink(env_f)
            os.chmod(os.path.join(ak_base, "bin"), 0o757)
            rc, out = au()
            check("script in a world-writable dir → refused", rc != 0 and "refusing: parent" in out, out[-300:])
            os.chmod(os.path.join(ak_base, "bin"), 0o755)
            rc, out = au(script=AU)
            _r = os.path.realpath(ROOT)
            if not all(os.stat(d).st_uid == 0 for d in (_r, os.path.dirname(_r))):
                check("run from a checkout a user owns → refused", rc != 0 and "refusing" in out, out[-300:])

            print("── authentik-upgrade.sh restore: the backup dir is root input too (audit 2026-10-17, OP-03 / OP-10)")
            # a fake docker that answers everything `restore` asks (compose services, cids, health,
            # psql, pg_restore, the probes) and logs its argv; AK_FAKE/pg_major, drop_fails,
            # no_authentik_db (any psql -d authentik fails: the state after DROP + failed CREATE)
            # and pg_down (Postgres answers nothing) steer it. The real docker is never on PATH here.
            ak_fake2 = os.path.join(ak_base, "fakebin2")
            os.mkdir(ak_fake2, 0o755)
            with open(os.path.join(ak_fake2, "docker"), "w") as f:
                f.write(r"""#!/bin/sh
echo "$*" >> "$AK_FAKE/calls"
case "$*" in
  *"config --services"*) printf 'server\nworker\npostgresql\n' ;;
  *" ps -q "*) echo c0ffee ;;
  *" stop "*|*" up -d "*) : ;;
  *"server_version"*)
    [ -e "$AK_FAKE/pg_down" ] && exit 2
    case "$*" in *" -d authentik "*) [ -e "$AK_FAKE/no_authentik_db" ] && { echo 'psql: error: FATAL:  database "authentik" does not exist' >&2; exit 2; } ;; esac
    cat "$AK_FAKE/pg_major" ;;
  *"DROP DATABASE"*) [ -e "$AK_FAKE/drop_fails" ] && { echo "psql: FATAL fake" >&2; exit 1; }; : ;;
  *"pg_restore"*) cat >/dev/null ;;
  *"exec -T server python"*) cat >/dev/null; echo 2026.8.2 ;;
  *"exec -T server ak shell"*) echo DISCOVERY_BAD=0 ;;
  *"showmigrations"*) : ;;
  inspect*Health*) echo healthy ;;
  inspect*RestartCount*) echo 0 ;;
  inspect*Config.Image*) echo ghcr.io/goauthentik/server:2026.8.3 ;;
  inspect*) : ;;
  *) echo "fake docker: unexpected $*" >&2; exit 9 ;;
esac
""")
            os.chmod(os.path.join(ak_fake2, "docker"), 0o755)
            ak_fake_dir = os.path.join(ak_base, "fake2")
            os.mkdir(ak_fake_dir, 0o755)
            os.chmod(ak_fake_dir, 0o1777)   # nobody writes here; the fake docker appends `calls` as root
            open(os.path.join(ak_fake_dir, "pg_major"), "w").write("16.4\n")
            bk_root = os.path.join(ak_base, "bk")
            os.mkdir(bk_root, 0o700)
            OLD_CF = "services:\n  server:\n    image: ghcr.io/goauthentik/server:2026.8.2\n"
            NEW_CF = "services:\n  server:\n    image: ghcr.io/goauthentik/server:2026.8.3\n"

            def make_backup(where, name="authentik-2026.8.2-20261017-120000"):
                b = os.path.join(where, name)
                os.mkdir(b, 0o700)
                for fn, body in (("authentik.dump", "PGDMP fake\n"), ("meta", "date=x\ntag=2026.8.2\npg_major=16\n"),
                                 ("docker-compose.yml", OLD_CF)):
                    with open(os.path.join(b, fn), "w") as f:
                        f.write(body)
                    os.chmod(os.path.join(b, fn), 0o600)
                sums = subprocess.run("sha256sum -- *", shell=True, cwd=b, capture_output=True, text=True, check=True).stdout
                with open(os.path.join(b, "SHA256SUMS"), "w") as f:
                    f.write(sums)
                os.chmod(os.path.join(b, "SHA256SUMS"), 0o600)
                return b

            def restore(b, backup_root=bk_root):
                calls = os.path.join(ak_fake_dir, "calls")
                if os.path.exists(calls):
                    os.unlink(calls)
                with open(ak_cf, "w") as f:   # the live compose file: root's, on the NEW tag
                    f.write(NEW_CF)
                os.chown(ak_cf, 0, 0); os.chmod(ak_cf, 0o644)
                p = subprocess.run(["bash", ak_script, "--dir", ak_dir, "--backup-dir", backup_root, "--yes", "restore", b],
                                   stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, cwd="/",
                                   env={"PATH": ak_fake2 + ":/usr/sbin:/usr/bin:/sbin:/bin", "AK_FAKE": ak_fake_dir})
                try:
                    with open(calls) as f:
                        c = f.read()
                except OSError:
                    c = ""
                return p.returncode, p.stdout + p.stderr, c

            def before(calls, a, b):   # both present and a first (never raises: a missing call is a FAIL)
                return a in calls and b in calls and calls.index(a) < calls.rindex(b)

            def untouched(calls):
                # nothing stopped, nothing dropped, the live compose file still root's on the new tag
                st = os.stat(ak_cf)
                return (" stop " not in calls and "DROP DATABASE" not in calls and "pg_restore" not in calls
                        and open(ak_cf).read() == NEW_CF and st.st_uid == 0)

            # the good case first: a root-owned backup under --backup-dir, whose compose file carries a
            # foreign group and 0640 (what `cp -p` would have copied onto the live file)
            good = make_backup(bk_root)
            os.chown(os.path.join(good, "docker-compose.yml"), 0, 1)
            os.chmod(os.path.join(good, "docker-compose.yml"), 0o640)
            rc, out, calls = restore(good)
            check("a root-owned backup under the backup root restores (stop → drop → pg_restore → up)",
                  rc == 0 and before(calls, " stop ", "DROP DATABASE") and before(calls, "DROP DATABASE", "pg_restore")
                  and before(calls, "pg_restore", " up -d "), (rc, out[-400:], calls[-400:]))
            st = os.stat(ak_cf)
            check("…the compose file comes back root:root 0644 — the backup's owner/group/mode are not preserved",
                  open(ak_cf).read() == OLD_CF and st.st_uid == 0 and st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o644,
                  "%s %s %o" % (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)))
            check("…Postgres major was checked before stopping anything",
                  before(calls, "server_version", " stop "), calls[:300])

            # a backup dir written by another user → refused before anything is stopped
            foreign = make_backup(bk_root, "authentik-2026.8.2-foreign")
            os.chown(foreign, 1, 0)
            rc, out, calls = restore(foreign)
            check("backup dir not owned by root → refused, nothing stopped",
                  rc != 0 and "refusing: " + foreign in out and untouched(calls), (rc, out[-300:], calls))
            os.chown(foreign, 0, 0)
            os.chmod(foreign, 0o770)
            rc, out, calls = restore(foreign)
            check("backup dir group-writable → refused", rc != 0 and "refusing: " + foreign in out and untouched(calls), out[-300:])
            os.chmod(foreign, 0o700)

            # a backup outside --backup-dir, even a perfectly root-owned one, and a symlink into it
            elsewhere = os.path.join(ak_base, "elsewhere")
            os.mkdir(elsewhere, 0o700)
            outside = make_backup(elsewhere)
            rc, out, calls = restore(outside)
            check("backup outside the backup root → refused, nothing stopped",
                  rc != 0 and "not under " + bk_root in out and untouched(calls), (rc, out[-300:], calls))
            link = os.path.join(bk_root, "authentik-2026.8.2-link")
            os.symlink(outside, link)
            rc, out, calls = restore(link)
            check("a symlink under the backup root pointing outside → refused (real path)",
                  rc != 0 and "not under " + bk_root in out and untouched(calls), (rc, out[-300:], calls))
            os.unlink(link)
            rc, out, calls = restore(os.path.join(bk_root, "..", "elsewhere", os.path.basename(outside)))
            check("…and `..` does not help", rc != 0 and "not under " + bk_root in out and untouched(calls), out[-300:])

            # every file read from the backup must be root's: the compose file (what `up` will run)…
            b2 = make_backup(bk_root, "authentik-2026.8.2-badcf")
            os.chown(os.path.join(b2, "docker-compose.yml"), 1, 0)
            rc, out, calls = restore(b2)
            check("a compose file in the backup owned by another user → refused, live compose file untouched and root's",
                  rc != 0 and "refusing: " + os.path.join(b2, "docker-compose.yml") in out and untouched(calls),
                  (rc, out[-300:], calls))
            os.chown(os.path.join(b2, "docker-compose.yml"), 0, 0)
            # …the dump, meta and the checksum file (self-consistent by construction: it is in the same dir)
            for fn in ("authentik.dump", "meta", "SHA256SUMS"):
                os.chmod(os.path.join(b2, fn), 0o620)
                rc, out, calls = restore(b2)
                check("%s in the backup group-writable → refused" % fn,
                      rc != 0 and "refusing: " + os.path.join(b2, fn) in out and untouched(calls), out[-300:])
                os.chmod(os.path.join(b2, fn), 0o600)
            os.unlink(os.path.join(b2, "meta"))
            rc, out, calls = restore(b2)
            check("a backup without meta → not a backup directory", rc != 0 and "not a backup directory" in out and untouched(calls), out[-300:])

            # --backup-dir itself: under a directory another user owns → refused (chain up to /)
            user_root = os.path.join(ak_base, "userbk")
            os.mkdir(user_root, 0o755)
            os.chown(user_root, 1, 0)
            os.mkdir(os.path.join(user_root, "ak"), 0o700)
            b3 = make_backup(os.path.join(user_root, "ak"))
            rc, out, calls = restore(b3, backup_root=os.path.join(user_root, "ak"))
            check("--backup-dir under a dir owned by another user → refused (parent chain), nothing stopped",
                  rc != 0 and "refusing: parent " + user_root in out and untouched(calls), (rc, out[-300:], calls))

            # OP-10: Postgres < 13 has no `DROP DATABASE … WITH (FORCE)`: refuse BEFORE stopping
            open(os.path.join(ak_fake_dir, "pg_major"), "w").write("12.3\n")
            rc, out, calls = restore(good)
            check("Postgres 12 → refused before stop (OP-10)", rc != 0 and "13+" in out and "nothing was stopped" in out
                  and untouched(calls), (rc, out[-300:], calls))
            open(os.path.join(ak_fake_dir, "pg_major"), "w").write("16.4\n")
            # …and a DROP that fails after the stop brings server+worker back
            open(os.path.join(ak_fake_dir, "drop_fails"), "w").close()
            rc, out, calls = restore(good)
            check("DROP fails after stop → server+worker started again, dump never loaded (OP-10)",
                  rc != 0 and "pg_restore" not in calls and before(calls, " stop ", " up -d --no-deps server worker")
                  and "re-run restore" in out and open(ak_cf).read() == NEW_CF, (rc, out[-300:], calls[-400:]))
            os.unlink(os.path.join(ak_fake_dir, "drop_fails"))

            # review (MED): the version is read from the maintenance DB — a re-run after a DROP
            # whose CREATE failed (no `authentik` database) must still restore…
            open(os.path.join(ak_fake_dir, "no_authentik_db"), "w").close()
            rc, out, calls = restore(good)
            check("no authentik database (re-run after a failed CREATE) → restore still proceeds",
                  rc == 0 and before(calls, " stop ", "DROP DATABASE") and before(calls, "DROP DATABASE", "pg_restore")
                  and before(calls, "pg_restore", " up -d ") and " -d authentik " not in calls.split("server_version")[0],
                  (rc, out[-300:], calls[:300]))
            os.unlink(os.path.join(ak_fake_dir, "no_authentik_db"))
            # …and no answer at all is "is it running?", not a version problem, with nothing stopped
            open(os.path.join(ak_fake_dir, "pg_down"), "w").close()
            rc, out, calls = restore(good)
            check("Postgres not answering → 'is it running?' before stop, not a version complaint",
                  rc != 0 and "cannot read the Postgres version" in out and "13+" not in out and untouched(calls),
                  (rc, out[-300:], calls))
            os.unlink(os.path.join(ak_fake_dir, "pg_down"))

            # review (MED): --backup-dir is checked BEFORE it is created or chmod'ed, and must be a
            # plain path: a symlink owned by uid 1 in uid 1's directory, pointing at a root-owned
            # 0755 directory (the old code chmod'ed the target first, then checked the resolved
            # path — the user-owned link was never seen)
            target = os.path.join(ak_base, "target")
            os.mkdir(target, 0o755)
            lnk = os.path.join(user_root, "bk")
            os.symlink(target, lnk)
            os.lchown(lnk, 1, 0)
            rc, out, calls = restore(good, backup_root=lnk)
            check("--backup-dir is a user's symlink to a root dir → refused (plain path), target untouched, no .lock, nothing stopped",
                  rc != 0 and "refusing: --backup-dir must be a plain path" in out
                  and stat.S_IMODE(os.stat(target).st_mode) == 0o755 and not os.path.exists(os.path.join(target, ".lock"))
                  and untouched(calls), (rc, out[-300:], calls, "%o" % stat.S_IMODE(os.stat(target).st_mode)))
            rc, out, calls = restore(good, backup_root=os.path.join(bk_root, "..", "bk"))
            check("--backup-dir with `..` → refused (plain path)", rc != 0 and "plain path" in out and untouched(calls), out[-300:])
            # legit spellings still work: a trailing slash, and a root that does not exist yet
            # (created 0700, under a root-owned parent)
            rc, out, calls = restore(good, backup_root=bk_root + "/")
            check("--backup-dir with a trailing slash → fine", rc == 0 and "refusing" not in out, (rc, out[-300:]))
            new_root = os.path.join(ak_base, "bk-new")
            good2 = os.path.join(new_root, os.path.basename(good))
            rc, out, calls = restore(good2, backup_root=new_root)
            check("a --backup-dir that does not exist yet is created 0700 root (then the backup is simply not in it)",
                  os.path.isdir(new_root) and stat.S_IMODE(os.stat(new_root).st_mode) == 0o700 and os.stat(new_root).st_uid == 0
                  and rc != 0 and "not a backup directory" in out and untouched(calls), (rc, out[-300:]))

            # review (LOW): a symlinked compose file (docker-compose.yml -> compose.yml) is written
            # THROUGH — `install` replaced the link with a regular file and left the target on the new tag
            real_cf = os.path.join(ak_dir, "compose.yml")
            os.rename(ak_cf, real_cf)
            os.symlink("compose.yml", ak_cf)
            rc, out, calls = restore(good)
            st = os.stat(real_cf)
            check("live compose file is a symlink → restored through the link: link kept, target on the old tag, root:root 0644",
                  rc == 0 and os.path.islink(ak_cf) and open(real_cf).read() == OLD_CF and st.st_uid == 0 and st.st_gid == 0
                  and stat.S_IMODE(st.st_mode) == 0o644, (rc, out[-300:], os.path.islink(ak_cf), open(real_cf).read()[-40:]))
            os.unlink(ak_cf)
            os.rename(real_cf, ak_cf)
            shutil.rmtree(ak_base, ignore_errors=True)
        else:
            print("  (skipped: not root)")

        print("── shellcheck")
        sc = shutil.which("shellcheck")
        if not sc:
            print("  SKIP: shellcheck not installed (CI's lint job runs it)")
        else:
            # -S warning: the gate is warnings and errors. Info notes (SC2015 `A && B || die`, a
            # deliberate idiom here) differ between shellcheck versions — the runner's 0.9 reported
            # them while 0.10 did not, and that alone failed a release run.
            p = subprocess.run([sc, "-S", "warning", HH, DC, os.path.join(ROOT, "scripts", "authentik-upgrade.sh")],
                               capture_output=True, text=True)
            check("host-health.sh + docker-cleanup.sh + authentik-upgrade.sh are shellcheck-clean",
                  p.returncode == 0, p.stdout[-500:])
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
